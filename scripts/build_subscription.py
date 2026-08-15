#!/usr/bin/env python3

import base64
import json
import os
import random
import re
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.txt"
OUT = ROOT / "output"

OUT.mkdir(exist_ok=True)

XRAY = os.environ.get("XRAY_PATH", "xray")

FETCH_TIMEOUT = 10
TCP_TIMEOUT = 2.0

TCP_WORKERS = 40
REAL_WORKERS = 8

TCP_ATTEMPTS = 2
REAL_ATTEMPTS = 3

MAX_TOTAL = 600
MAX_REAL_TEST = 100
MAX_PUBLISHED = 100

SOCKS_BASE = 21000

HISTORY_FILE = OUT / "history.json"
MAX_HISTORY = 20

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]

SUPPORTED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
)


# ============================================================
# BASIC
# ============================================================

def log(msg):
    print(msg, flush=True)


def safe_b64decode(value):
    value = value.strip()

    value += "=" * (-len(value) % 4)

    try:
        return base64.urlsafe_b64decode(value)
    except Exception:
        try:
            return base64.b64decode(value)
        except Exception:
            return None


def random_port():
    return random.randint(SOCKS_BASE, SOCKS_BASE + 5000)


# ============================================================
# FETCH
# ============================================================

def fetch(url):
    from urllib.request import Request, urlopen

    req = Request(
        url,
        headers={
            "User-Agent": "FreeForYoung/5.0",
        },
    )

    with urlopen(req, timeout=FETCH_TIMEOUT) as response:
        raw = response.read()

    text = raw.decode("utf-8", "ignore")

    compact = re.sub(r"\s+", "", text)

    if (
        len(compact) > 40
        and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact)
    ):
        decoded = safe_b64decode(compact)

        if decoded:
            decoded_text = decoded.decode(
                "utf-8",
                "ignore",
            )

            if "://" in decoded_text:
                text = decoded_text

    return text


def extract(text):
    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss)://[^\s<>\"]+",
        re.IGNORECASE,
    )

    nodes = []

    for line in text.splitlines():

        line = line.strip().strip("`")

        if not line:
            continue

        for match in pattern.finditer(line):

            uri = match.group(0).rstrip(
                "),;\"'"
            )

            if uri.lower().startswith(SUPPORTED):
                nodes.append(uri)

                if len(nodes) >= MAX_TOTAL:
                    return nodes

    return nodes


# ============================================================
# URI / ENDPOINT
# ============================================================

def endpoint(uri):
    try:
        p = urlsplit(uri)

        host = p.hostname
        port = p.port

        if not host or not port:
            return None

        return host, port

    except Exception:
        return None


def host_key(uri):
    ep = endpoint(uri)

    if not ep:
        return uri

    return f"{ep[0]}:{ep[1]}"


# ============================================================
# TCP
# ============================================================

def tcp_ping(uri):
    ep = endpoint(uri)

    if not ep:
        return None

    host, port = ep

    started = time.perf_counter()

    try:
        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT,
        ):
            return round(
                (time.perf_counter() - started) * 1000,
                1,
            )

    except Exception:
        return None


def tcp_check(uri):

    values = []

    for _ in range(TCP_ATTEMPTS):

        value = tcp_ping(uri)

        if value is not None:
            values.append(value)

    return {
        "uri": uri,
        "tcp_success": len(values),
        "tcp_attempts": TCP_ATTEMPTS,
        "tcp_ping": (
            round(median(values), 1)
            if values
            else None
        ),
    }


# ============================================================
# VMESS
# ============================================================

def parse_vmess(uri):

    raw = uri[len("vmess://"):]

    decoded = safe_b64decode(raw)

    if not decoded:
        raise ValueError("invalid vmess base64")

    obj = json.loads(
        decoded.decode(
            "utf-8",
            "ignore",
        )
    )

    address = obj.get("add") or obj.get("address")
    port = int(obj.get("port", 443))
    uuid = obj.get("id")

    if not address or not uuid:
        raise ValueError("invalid vmess")

    network = (
        obj.get("net")
        or obj.get("type")
        or "tcp"
    )

    tls = str(
        obj.get("tls", "")
    ).lower()

    return {
        "address": address,
        "port": port,
        "uuid": uuid,
        "network": network,
        "tls": tls,
        "host": obj.get("host", ""),
        "path": obj.get("path", "/"),
        "sni": obj.get("sni") or obj.get("host", ""),
        "fp": obj.get("fp", ""),
    }


# ============================================================
# X-RAY OUTBOUND BUILDERS
# ============================================================

def query_dict(parsed):
    result = {}

    for key, values in parse_qs(
        parsed.query,
        keep_blank_values=True,
    ).items():

        if values:
            result[key.lower()] = values[-1]

    return result


def tls_settings(q, sni=None):

    result = {
        "serverName": (
            sni
            or q.get("sni")
            or q.get("host")
            or ""
        ),
    }

    fp = q.get("fp")

    if fp:
        result["fingerprint"] = fp

    alpn = q.get("alpn")

    if alpn:
        result["alpn"] = [
            x.strip()
            for x in alpn.split(",")
            if x.strip()
        ]

    insecure = q.get(
        "allowinsecure",
        q.get("insecure", "0"),
    )

    result["allowInsecure"] = (
        str(insecure).lower()
        in ("1", "true", "yes")
    )

    return result


def ws_settings(q):

    path = (
        q.get("path")
        or q.get("wspath")
        or "/"
    )

    host = (
        q.get("host")
        or q.get("Host")
    )

    ws = {
        "path": unquote(path),
    }

    if host:
        ws["headers"] = {
            "Host": host,
        }

    return ws


def vless_outbound(uri):

    p = urlsplit(uri)

    q = query_dict(p)

    if not p.hostname or not p.port:
        raise ValueError("invalid VLESS endpoint")

    uuid = unquote(
        p.username or ""
    )

    if not uuid:
        raise ValueError("missing VLESS UUID")

    stream = {
        "network": (
            q.get("type")
            or q.get("network")
            or "tcp"
        ),
    }

    security = q.get(
        "security",
        "",
    ).lower()

    if security == "reality":

        reality = {
            "show": False,
            "fingerprint": q.get(
                "fp",
                "chrome",
            ),
            "serverName": q.get(
                "sni",
                "",
            ),
            "publicKey": q.get(
                "pbk",
                "",
            ),
        }

        sid = q.get("sid")

        if sid:
            reality["shortId"] = sid

        stream["security"] = "reality"

        stream["realitySettings"] = reality

    elif security == "tls":

        stream["security"] = "tls"
        stream["tlsSettings"] = tls_settings(
            q,
            q.get("sni"),
        )

    if stream["network"] == "ws":

        stream["wsSettings"] = ws_settings(q)

    elif stream["network"] == "grpc":

        service = q.get(
            "serviceName",
            q.get("servicename", ""),
        )

        stream["grpcSettings"] = {
            "serviceName": service,
        }

    elif stream["network"] == "http":

        stream["httpSettings"] = {
            "path": q.get(
                "path",
                "/",
            ),
        }

    settings = {
        "vnext": [
            {
                "address": p.hostname,
                "port": p.port,
                "users": [
                    {
                        "id": uuid,
                        "encryption": "none",
                    }
                ],
            }
        ]
    }

    flow = q.get("flow")

    if flow:
        settings["vnext"][0]["users"][0]["flow"] = flow

    return {
        "protocol": "vless",
        "settings": settings,
        "streamSettings": stream,
    }


def trojan_outbound(uri):

    p = urlsplit(uri)

    q = query_dict(p)

    if not p.hostname or not p.port:
        raise ValueError("invalid Trojan endpoint")

    password = unquote(
        p.username or ""
    )

    if not password:
        raise ValueError("missing Trojan password")

    stream = {
        "network": (
            q.get("type")
            or q.get("network")
            or "tcp"
        ),
    }

    security = q.get(
        "security",
        "tls",
    ).lower()

    if security == "tls":

        stream["security"] = "tls"

        stream["tlsSettings"] = tls_settings(
            q,
            q.get("sni"),
        )

    if stream["network"] == "ws":

        stream["wsSettings"] = ws_settings(q)

    elif stream["network"] == "grpc":

        stream["grpcSettings"] = {
            "serviceName": q.get(
                "servicename",
                q.get("serviceName", ""),
            ),
        }

    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": p.hostname,
                    "port": p.port,
                    "password": password,
                }
            ]
        },
        "streamSettings": stream,
    }


def vmess_outbound(uri):

    data = parse_vmess(uri)

    stream = {
        "network": data["network"],
    }

    if data["tls"] in (
        "tls",
        "1",
    ):

        stream["security"] = "tls"

        stream["tlsSettings"] = {
            "serverName": (
                data["sni"]
                or data["host"]
            ),
        }

        if data["fp"]:
            stream["tlsSettings"]["fingerprint"] = (
                data["fp"]
            )

    if data["network"] == "ws":

        stream["wsSettings"] = {
            "path": data["path"],
        }

        if data["host"]:
            stream["wsSettings"]["headers"] = {
                "Host": data["host"],
            }

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": data["address"],
                    "port": data["port"],
                    "users": [
                        {
                            "id": data["uuid"],
                            "alterId": 0,
                            "security": "auto",
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


def ss_outbound(uri):

    p = urlsplit(uri)

    if not p.hostname or not p.port:
        raise ValueError("invalid SS endpoint")

    raw_user = (
        p.netloc.split("@", 1)[0]
        if "@" in p.netloc
        else ""
    )

    decoded = safe_b64decode(
        raw_user
    )

    if decoded:
        user = decoded.decode(
            "utf-8",
            "ignore",
        )
    else:
        user = unquote(raw_user)

    if ":" not in user:
        raise ValueError("invalid SS credentials")

    method, password = user.split(
        ":",
        1,
    )

    return {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": p.hostname,
                    "port": p.port,
                    "method": method,
                    "password": password,
                }
            ]
        },
    }


def make_outbound(uri):

    low = uri.lower()

    if low.startswith("vless://"):
        return vless_outbound(uri)

    if low.startswith("trojan://"):
        return trojan_outbound(uri)

    if low.startswith("vmess://"):
        return vmess_outbound(uri)

    if low.startswith("ss://"):
        return ss_outbound(uri)

    raise ValueError("unsupported protocol")


# ============================================================
# REAL XRAY TEST
# ============================================================

def wait_port(port, timeout=5):

    deadline = time.time() + timeout

    while time.time() < deadline:

        try:

            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.3,
            ):
                return True

        except Exception:
            time.sleep(0.05)

    return False


def curl_through_socks(port, url):

    started = time.perf_counter()

    command = [
        "curl",
        "-sS",
        "--max-time",
        "8",
        "--connect-timeout",
        "5",
        "--proxy",
        f"socks5h://127.0.0.1:{port}",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        url,
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            return None

        code = result.stdout.strip()

        if not code.isdigit():
            return None

        code = int(code)

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        # 2xx/3xx/204 = working proxy.
        if (
            200 <= code < 400
            or code == 204
        ):
            return round(elapsed, 1)

        return None

    except Exception:
        return None


def real_xray_attempt(uri):

    port = random_port()

    try:

        outbound = make_outbound(uri)

        config = {
            "log": {
                "loglevel": "none",
            },

            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": port,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": False,
                    },
                }
            ],

            "outbounds": [
                outbound,
                {
                    "protocol": "freedom",
                    "tag": "direct",
                },
                {
                    "protocol": "blackhole",
                    "tag": "block",
                },
            ],

            "routing": {
                "domainStrategy": "AsIs",
            },
        }

        with tempfile.TemporaryDirectory() as tmp:

            config_path = (
                Path(tmp)
                / "config.json"
            )

            config_path.write_text(
                json.dumps(
                    config,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            test = subprocess.run(
                [
                    XRAY,
                    "run",
                    "-test",
                    "-config",
                    str(config_path),
                ],
                capture_output=True,
                text=True,
                timeout=8,
            )

            if test.returncode != 0:
                return None

            process = subprocess.Popen(
                [
                    XRAY,
                    "run",
                    "-config",
                    str(config_path),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            try:

                if not wait_port(
                    port,
                    5,
                ):
                    return None

                # Try multiple URLs because one endpoint
                # can occasionally be unavailable.
                for url in TEST_URLS:

                    latency = curl_through_socks(
                        port,
                        url,
                    )

                    if latency is not None:
                        return latency

                return None

            finally:

                process.terminate()

                try:
                    process.wait(
                        timeout=2
                    )
                except subprocess.TimeoutExpired:
                    process.kill()

    except Exception:
        return None


def real_check(uri):

    values = []

    for _ in range(
        REAL_ATTEMPTS
    ):

        latency = real_xray_attempt(
            uri
        )

        if latency is not None:
            values.append(
                latency
            )

    successful = len(values)

    if values:

        med = round(
            median(values),
            1,
        )

        avg = round(
            sum(values)
            / len(values),
            1,
        )

        worst = round(
            max(values),
            1,
        )

    else:

        med = None
        avg = None
        worst = None

    return {
        "uri": uri,
        "real_successes": successful,
        "real_attempts": REAL_ATTEMPTS,
        "real_success_rate": (
            successful
            / REAL_ATTEMPTS
        ),
        "real_ping": med,
        "real_avg": avg,
        "real_worst": worst,
    }


# ============================================================
# HISTORY
# ============================================================

def load_history():

    if not HISTORY_FILE.exists():
        return {}

    try:

        return json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8",
            )
        )

    except Exception:
        return {}


def save_history(history):

    HISTORY_FILE.write_text(
        json.dumps(
            history,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def update_history(
    history,
    result,
):

    uri = result["uri"]

    old = history.get(
        uri,
        {
            "runs": 0,
            "tcp_successes": 0,
            "tcp_failures": 0,
            "real_successes": 0,
            "real_failures": 0,
            "last_ping": None,
        },
    )

    # Compatibility with old history.json
    old.setdefault(
        "runs",
        0,
    )

    old.setdefault(
        "tcp_successes",
        0,
    )

    old.setdefault(
        "tcp_failures",
        0,
    )

    old.setdefault(
        "real_successes",
        0,
    )

    old.setdefault(
        "real_failures",
        0,
    )

    old.setdefault(
        "last_ping",
        None,
    )

    old["runs"] += 1

    old["tcp_successes"] += (
        result.get(
            "tcp_success",
            0,
        )
    )

    old["tcp_failures"] += (
        result.get(
            "tcp_attempts",
            0,
        )
        - result.get(
            "tcp_success",
            0,
        )
    )

    old["real_successes"] += (
        result.get(
            "real_successes",
            0,
        )
    )

    old["real_failures"] += (
        result.get(
            "real_attempts",
            0,
        )
        - result.get(
            "real_successes",
            0,
        )
    )

    if result.get(
        "real_ping"
    ) is not None:

        old["last_ping"] = result[
            "real_ping"
        ]

    history[uri] = old

    return history


# ============================================================
# SCORE
# ============================================================

def protocol_bonus(uri):

    low = uri.lower()

    if (
        low.startswith("vless://")
        and "security=reality" in low
        and "type=tcp" in low
    ):
        return 50

    if low.startswith("vless://"):
        return 35

    if low.startswith("trojan://"):
        return 30

    if low.startswith("vmess://"):
        return 15

    if low.startswith("ss://"):
        return 10

    return 0


def calculate_score(
    result,
    history,
):

    success = result[
        "real_success_rate"
    ]

    ping = result[
        "real_ping"
    ]

    if (
        success <= 0
        or ping is None
    ):
        return -999999

    # REAL success is the most important thing.
    stability = success * 1000

    # Real proxy latency.
    if ping <= 50:
        latency = 250

    elif ping <= 100:
        latency = 220

    elif ping <= 150:
        latency = 180

    elif ping <= 250:
        latency = 130

    elif ping <= 400:
        latency = 80

    elif ping <= 700:
        latency = 40

    else:
        latency = 10

    # Consistency.
    worst = result[
        "real_worst"
    ]

    consistency = 0

    if worst is not None:

        spread = worst - ping

        if spread <= 30:
            consistency = 80

        elif spread <= 70:
            consistency = 55

        elif spread <= 150:
            consistency = 25

        else:
            consistency = 0

    # Historical real stability.
    historical = 0

    old = history.get(
        result["uri"]
    )

    if old:

        total = (
            old.get(
                "real_successes",
                0,
            )
            + old.get(
                "real_failures",
                0,
            )
        )

        if total:

            rate = (
                old.get(
                    "real_successes",
                    0,
                )
                / total
            )

            historical = rate * 120

    return round(
        stability
        + latency
        + consistency
        + historical
        + protocol_bonus(
            result["uri"]
        ),
        2,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    started = time.time()

    log("================================")
    log("       FreeForYoung v5")
    log(" REAL Xray stability checker")
    log("================================")

    if not Path(XRAY).exists():
        log(
            f"[FATAL] Xray not found: {XRAY}"
        )
        raise SystemExit(1)

    history = load_history()

    # --------------------------------------------------------
    # SOURCES
    # --------------------------------------------------------

    source_urls = []

    for line in SOURCES.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if (
            line
            and not line.startswith("#")
        ):
            source_urls.append(line)

    log(
        f"Sources: {len(source_urls)}"
    )

    all_nodes = []

    with ThreadPoolExecutor(
        max_workers=min(
            10,
            max(
                1,
                len(source_urls),
            ),
        )
    ) as executor:

        jobs = {
            executor.submit(
                fetch,
                source,
            ): source
            for source in source_urls
        }

        for future in as_completed(
            jobs
        ):

            source = jobs[
                future
            ]

            try:

                nodes = extract(
                    future.result()
                )

                all_nodes.extend(
                    nodes
                )

                log(
                    f"[OK] {len(nodes)} nodes"
                )

            except Exception as e:

                log(
                    f"[ERROR] "
                    f"{source}: "
                    f"{e}"
                )

    unique = list(
        dict.fromkeys(
            all_nodes
        )
    )

    log(
        f"Unique: {len(unique)}"
    )

    # --------------------------------------------------------
    # TCP PRECHECK
    # --------------------------------------------------------

    tcp_candidates = []

    with ThreadPoolExecutor(
        max_workers=TCP_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                tcp_check,
                uri,
            ): uri
            for uri in unique[
                :MAX_TOTAL
            ]
        }

        for future in as_completed(
            jobs
        ):

            try:

                result = future.result()

                if result[
                    "tcp_success"
                ] > 0:

                    tcp_candidates.append(
                        result
                    )

            except Exception:
                pass

    tcp_candidates.sort(
        key=lambda x: (
            x["tcp_success"],
            -(
                x["tcp_ping"]
                or 999999
            ),
        ),
        reverse=True,
    )

    log(
        f"TCP candidates: "
        f"{len(tcp_candidates)}"
    )

    # --------------------------------------------------------
    # REAL XRAY
    # --------------------------------------------------------

    real_targets = [
        item["uri"]
        for item in tcp_candidates[
            :MAX_REAL_TEST
        ]
    ]

    log(
        f"Real Xray tests: "
        f"{len(real_targets)}"
    )

    checked = []

    with ThreadPoolExecutor(
        max_workers=REAL_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                real_check,
                uri,
            ): uri
            for uri in real_targets
        }

        for future in as_completed(
            jobs
        ):

            uri = jobs[
                future
            ]

            try:

                result = future.result()

            except Exception:

                result = {
                    "uri": uri,
                    "real_successes": 0,
                    "real_attempts": REAL_ATTEMPTS,
                    "real_success_rate": 0,
                    "real_ping": None,
                    "real_avg": None,
                    "real_worst": None,
                }

            # Add TCP info.
            tcp = next(
                (
                    x
                    for x in tcp_candidates
                    if x["uri"] == uri
                ),
                None,
            )

            if tcp:
                result.update(
                    {
                        "tcp_success": tcp[
                            "tcp_success"
                        ],
                        "tcp_attempts": tcp[
                            "tcp_attempts"
                        ],
                        "tcp_ping": tcp[
                            "tcp_ping"
                        ],
                    }
                )

            history = update_history(
                history,
                result,
            )

            # ONLY REAL SUCCESSFUL CONFIGS.
            if (
                result[
                    "real_successes"
                ] > 0
            ):

                result["score"] = (
                    calculate_score(
                        result,
                        history,
                    )
                )

                checked.append(
                    result
                )

    # --------------------------------------------------------
    # RANK
    # --------------------------------------------------------

    ranked = sorted(
        checked,
        key=lambda x: (
            x["real_success_rate"],
            x["score"],
            -(
                x["real_ping"]
                or 999999
            ),
        ),
        reverse=True,
    )

    # --------------------------------------------------------
    # DEDUPE / DIVERSIFY
    # --------------------------------------------------------

    selected = []

    hosts = {}

    MAX_SAME_ENDPOINT = 2

    for item in ranked:

        key = host_key(
            item["uri"]
        )

        count = hosts.get(
            key,
            0,
        )

        if count >= MAX_SAME_ENDPOINT:
            continue

        selected.append(
            item
        )

        hosts[key] = count + 1

        if len(selected) >= MAX_PUBLISHED:
            break

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    save_history(
        history
    )

    # --------------------------------------------------------
    # SUBSCRIPTION
    # --------------------------------------------------------

    lines = [
        "#profile-title: FreeForYoung",
        "#announce: FreeForYoung - REAL Xray tested nodes",
        "#subscription-auto-update-enable: 1",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#ping-result: time",
    ]

    lines.extend(
        item["uri"]
        for item in selected
    )

    (
        OUT / "subscription.txt"
    ).write_text(
        "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    report = []

    for index, item in enumerate(
        selected,
        1,
    ):

        uri = item[
            "uri"
        ]

        protocol = (
            uri.split(
                "://",
                1,
            )[0]
            .upper()
        )

        report.append(
            (
                f"{index}. "
                f"score={item['score']} | "
                f"ping={item['real_ping']}ms | "
                f"real="
                f"{item['real_successes']}/"
                f"{item['real_attempts']} | "
                f"protocol={protocol} | "
                f"uri={uri}"
            )
        )

    (
        OUT / "servers.txt"
    ).write_text(
        "\n".join(report)
        + (
            "\n"
            if report
            else ""
        ),
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # STATS
    # --------------------------------------------------------

    stats = {
        "project": "FreeForYoung",
        "version": 5,
        "sources": len(source_urls),
        "raw_nodes": len(all_nodes),
        "unique_nodes": len(unique),
        "tcp_candidates": len(tcp_candidates),
        "real_tested": len(real_targets),
        "real_working": len(checked),
        "published": len(selected),
        "tcp_attempts": TCP_ATTEMPTS,
        "real_attempts": REAL_ATTEMPTS,
        "tcp_workers": TCP_WORKERS,
        "real_workers": REAL_WORKERS,
        "generated_at": int(time.time()),
        "duration_seconds": round(
            time.time() - started,
            2,
        ),
    }

    (
        OUT / "stats.json"
    ).write_text(
        json.dumps(
            stats,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # CONSOLE
    # --------------------------------------------------------

    log("")
    log("================================")
    log("          READY")
    log("================================")

    log(
        f"Unique: {len(unique)}"
    )

    log(
        f"TCP candidates: "
        f"{len(tcp_candidates)}"
    )

    log(
        f"REAL working: "
        f"{len(checked)}"
    )

    log(
        f"Published: "
        f"{len(selected)}"
    )

    log(
        f"Duration: "
        f"{round(time.time() - started, 2)}s"
    )

    log("")
    log("TOP REAL SERVERS:")

    for index, item in enumerate(
        selected[:20],
        1,
    ):

        protocol = (
            item["uri"]
            .split(
                "://",
                1,
            )[0]
            .upper()
        )

        log(
            f"{index}. "
            f"score={item['score']} | "
            f"ping={item['real_ping']}ms | "
            f"real="
            f"{item['real_successes']}/"
            f"{item['real_attempts']} | "
            f"{protocol}"
        )


if __name__ == "__main__":
    main()
