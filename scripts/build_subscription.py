#!/usr/bin/env python3

import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.txt"
OUT = ROOT / "output"

OUT.mkdir(exist_ok=True)

SUPPORTED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hy2://",
    "hysteria2://",
)

FETCH_TIMEOUT = 8

TCP_TIMEOUT = 2.5
TCP_ATTEMPTS = 3

REAL_TEST_ATTEMPTS = 3
REAL_TEST_TIMEOUT = 8

MAX_TOTAL_CHECK = 300
MAX_REAL_TEST = 80
MAX_PUBLISHED = 100

WORKERS = 30
REAL_WORKERS = 8

MAX_SAME_ENDPOINT = 2
MAX_SAME_IDENTITY = 3

XRAY = os.environ.get("XRAY_BIN", "xray")

TEST_URL = "https://www.gstatic.com/generate_204"

history_file = OUT / "history.json"
MAX_HISTORY = 20


# ============================================================
# FETCH
# ============================================================

def fetch(url):
    req = Request(
        url,
        headers={
            "User-Agent": "FreeForYoung/4.0"
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
        try:
            decoded = base64.b64decode(
                compact + "=" * (-len(compact) % 4),
                validate=False,
            )

            decoded_text = decoded.decode(
                "utf-8",
                "ignore",
            )

            if "://" in decoded_text:
                text = decoded_text

        except Exception:
            pass

    return text


def extract(text):
    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>\"']+",
        re.IGNORECASE,
    )

    result = []

    for line in text.splitlines():
        line = line.strip().strip("`")

        if not line:
            continue

        for match in pattern.finditer(line):
            uri = match.group(0).rstrip("),;")

            if uri.lower().startswith(SUPPORTED):
                result.append(uri)

                if len(result) >= MAX_TOTAL_CHECK:
                    return result

    return result


# ============================================================
# BASIC URI HELPERS
# ============================================================

def endpoint(uri):
    try:
        p = urlsplit(uri)

        if not p.hostname or not p.port:
            return None

        return p.hostname, p.port

    except Exception:
        return None


def endpoint_key(uri):
    ep = endpoint(uri)

    if not ep:
        return uri

    return f"{ep[0].lower()}:{ep[1]}"


def identity_key(uri):
    """
    Groups copies of the same configuration which differ only
    by IP/port where possible.
    """

    try:
        p = urlsplit(uri)
        q = parse_qs(p.query)

        scheme = p.scheme.lower()

        if scheme == "vless":
            return (
                "vless",
                unquote(p.username or ""),
                q.get("security", [""])[0],
                q.get("sni", [""])[0],
                q.get("pbk", [""])[0],
                q.get("sid", [""])[0],
            )

        if scheme == "trojan":
            return (
                "trojan",
                unquote(p.username or ""),
                q.get("security", [""])[0],
                q.get("sni", [""])[0],
                q.get("path", [""])[0],
            )

        return (
            scheme,
            unquote(p.username or ""),
            q.get("sni", [""])[0],
        )

    except Exception:
        return uri


# ============================================================
# TCP TEST
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

    if not values:
        return {
            "uri": uri,
            "tcp_success": 0,
            "tcp_attempts": TCP_ATTEMPTS,
            "tcp_rate": 0,
            "tcp_median": None,
            "tcp_worst": None,
        }

    return {
        "uri": uri,
        "tcp_success": len(values),
        "tcp_attempts": TCP_ATTEMPTS,
        "tcp_rate": len(values) / TCP_ATTEMPTS,
        "tcp_median": round(median(values), 1),
        "tcp_worst": round(max(values), 1),
    }


# ============================================================
# XRAY CONFIG
# ============================================================

def first(q, key, default=None):
    values = q.get(key)

    if not values:
        return default

    return values[0]


def make_xray_config(uri, socks_port):
    p = urlsplit(uri)
    scheme = p.scheme.lower()

    q = parse_qs(
        p.query,
        keep_blank_values=True,
    )

    host = p.hostname
    port = p.port

    if not host or not port:
        return None

    stream = {
        "network": "tcp"
    }

    security = first(q, "security", "")

    # ----------------------------
    # VLESS
    # ----------------------------

    if scheme == "vless":

        uuid = unquote(p.username or "")

        if not uuid:
            return None

        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": host,
                        "port": port,
                        "users": [
                            {
                                "id": uuid,
                                "encryption": "none",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream,
        }

        flow = first(q, "flow")

        if flow:
            outbound["settings"]["vnext"][0]["users"][0]["flow"] = flow

        network = first(q, "type", first(q, "network", "tcp"))

        stream["network"] = network

        if network == "ws":
            stream["wsSettings"] = {
                "path": unquote(first(q, "path", "/")),
                "headers": {},
            }

            ws_host = first(q, "host")

            if ws_host:
                stream["wsSettings"]["headers"]["Host"] = ws_host

        if security == "tls":
            stream["security"] = "tls"

            stream["tlsSettings"] = {
                "serverName": first(q, "sni", host),
                "allowInsecure": False,
            }

            fp = first(q, "fp")

            if fp:
                stream["tlsSettings"]["fingerprint"] = fp

        elif security == "reality":
            stream["security"] = "reality"

            pbk = first(q, "pbk")

            if not pbk:
                return None

            reality = {
                "serverName": first(q, "sni", host),
                "publicKey": pbk,
                "shortId": first(q, "sid", ""),
            }

            fp = first(q, "fp")

            if fp:
                reality["fingerprint"] = fp

            stream["realitySettings"] = reality

        else:
            stream.pop("security", None)

        return {
            "log": {
                "loglevel": "error"
            },
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {
                        "udp": True
                    },
                }
            ],
            "outbounds": [
                outbound
            ]
        }

    # ----------------------------
    # TROJAN
    # ----------------------------

    if scheme == "trojan":

        password = unquote(p.username or "")

        if not password:
            return None

        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": host,
                        "port": port,
                        "password": password,
                    }
                ]
            },
            "streamSettings": stream,
        }

        network = first(q, "type", first(q, "network", "tcp"))

        stream["network"] = network

        if network == "ws":
            stream["wsSettings"] = {
                "path": unquote(
                    first(q, "path", "/")
                ),
                "headers": {},
            }

            ws_host = first(q, "host")

            if ws_host:
                stream["wsSettings"]["headers"]["Host"] = ws_host

        if security == "tls" or port == 443:
            stream["security"] = "tls"

            stream["tlsSettings"] = {
                "serverName": first(q, "sni", host),
                "allowInsecure": False,
            }

        return {
            "log": {
                "loglevel": "error"
            },
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "protocol": "socks",
                    "settings": {
                        "udp": True
                    },
                }
            ],
            "outbounds": [
                outbound
            ]
        }

    return None


# ============================================================
# REAL XRAY TEST
# ============================================================

def wait_port(port, timeout=5):
    deadline = time.time() + timeout

    while time.time() < deadline:

        try:
            with socket.create_connection(
                ("127.0.0.1", port),
                timeout=0.25,
            ):
                return True

        except Exception:
            time.sleep(0.05)

    return False


def real_test(uri, index):
    """
    Real HTTP test through Xray.

    Only VLESS and Trojan are tested here.
    Unsupported protocols fall back to TCP result.
    """

    scheme = uri.split("://", 1)[0].lower()

    if scheme not in ("vless", "trojan"):
        return {
            "real_supported": False,
            "real_success": 0,
            "real_attempts": REAL_TEST_ATTEMPTS,
            "real_rate": 0,
            "real_median": None,
            "real_worst": None,
        }

    port = 20000 + (index % 2000)

    config = make_xray_config(
        uri,
        port,
    )

    if not config:
        return {
            "real_supported": False,
            "real_success": 0,
            "real_attempts": REAL_TEST_ATTEMPTS,
            "real_rate": 0,
            "real_median": None,
            "real_worst": None,
        }

    with tempfile.TemporaryDirectory() as tmp:

        config_path = Path(tmp) / "config.json"

        config_path.write_text(
            json.dumps(config),
            encoding="utf-8",
        )

        try:

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

        except Exception:

            return {
                "real_supported": False,
                "real_success": 0,
                "real_attempts": REAL_TEST_ATTEMPTS,
                "real_rate": 0,
                "real_median": None,
                "real_worst": None,
            }

        try:

            if not wait_port(port, 5):

                return {
                    "real_supported": True,
                    "real_success": 0,
                    "real_attempts": REAL_TEST_ATTEMPTS,
                    "real_rate": 0,
                    "real_median": None,
                    "real_worst": None,
                }

            values = []

            for _ in range(
                REAL_TEST_ATTEMPTS
            ):

                started = time.perf_counter()

                try:

                    proxy = (
                        f"socks5h://127.0.0.1:{port}"
                    )

                    result = subprocess.run(
                        [
                            "curl",
                            "-L",
                            "--silent",
                            "--show-error",
                            "--max-time",
                            str(REAL_TEST_TIMEOUT),
                            "--proxy",
                            proxy,
                            "-o",
                            "/dev/null",
                            "-w",
                            "%{http_code}",
                            TEST_URL,
                        ],
                        capture_output=True,
                        text=True,
                        timeout=REAL_TEST_TIMEOUT + 2,
                    )

                    elapsed = (
                        time.perf_counter()
                        - started
                    ) * 1000

                    code = result.stdout.strip()

                    if (
                        result.returncode == 0
                        and code.isdigit()
                        and 100 <= int(code) < 600
                    ):
                        values.append(
                            round(elapsed, 1)
                        )

                except Exception:
                    pass

            success = len(values)

            return {
                "real_supported": True,
                "real_success": success,
                "real_attempts": REAL_TEST_ATTEMPTS,
                "real_rate": (
                    success / REAL_TEST_ATTEMPTS
                ),
                "real_median": (
                    round(median(values), 1)
                    if values
                    else None
                ),
                "real_worst": (
                    round(max(values), 1)
                    if values
                    else None
                ),
            }

        finally:

            process.terminate()

            try:
                process.wait(timeout=2)
            except Exception:
                process.kill()


# ============================================================
# HISTORY
# ============================================================

def load_history():

    if not history_file.exists():
        return {}

    try:
        return json.loads(
            history_file.read_text(
                encoding="utf-8"
            )
        )

    except Exception:
        return {}


def save_history(history):

    history_file.write_text(
        json.dumps(
            history,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def update_history(history, result):

    uri = result["uri"]

    old = history.get(
        uri,
        {
            "runs": 0,
            "successes": 0,
            "failures": 0,
            "real_successes": 0,
            "real_attempts": 0,
            "last_ping": None,
        },
    )

    old["runs"] += 1

    old["successes"] += result["tcp_success"]

    old["failures"] += (
        result["tcp_attempts"]
        - result["tcp_success"]
    )

    old["real_successes"] += result.get(
        "real_success",
        0,
    )

    old["real_attempts"] += result.get(
        "real_attempts",
        0,
    )

    old["last_ping"] = (
        result.get("real_median")
        or result.get("tcp_median")
    )

    history[uri] = old

    return history


# ============================================================
# SCORE
# ============================================================

def protocol_score(uri):

    lower = uri.lower()

    if (
        lower.startswith("vless://")
        and "security=reality" in lower
        and "type=tcp" in lower
    ):
        return 10

    if lower.startswith("vless://"):
        return 7

    if lower.startswith("trojan://"):
        return 6

    if (
        lower.startswith("hy2://")
        or lower.startswith("hysteria2://")
    ):
        return 6

    if lower.startswith("vmess://"):
        return 4

    if lower.startswith("ss://"):
        return 3

    return 0


def score(result, history):

    tcp_rate = result["tcp_rate"]

    real_supported = result.get(
        "real_supported",
        False,
    )

    real_rate = result.get(
        "real_rate",
        0,
    )

    ping = (
        result.get("real_median")
        if real_supported
        and result.get("real_median") is not None
        else result.get("tcp_median")
    )

    if ping is None:
        return -999999

    # REAL TEST HAS PRIORITY
    if real_supported:

        if real_rate <= 0:
            return -999999

        stability = real_rate * 55

        latency = max(
            0,
            30
            - min(ping, 300) / 10,
        )

        worst = result.get(
            "real_worst"
        )

        consistency = 10

        if worst is not None:
            spread = worst - ping

            if spread > 1000:
                consistency = 0
            elif spread > 500:
                consistency = 2
            elif spread > 250:
                consistency = 4
            elif spread > 100:
                consistency = 6
            elif spread > 50:
                consistency = 8

        base = (
            stability
            + latency
            + consistency
            + protocol_score(result["uri"])
        )

    else:

        stability = tcp_rate * 45

        latency = max(
            0,
            35
            - min(ping, 300) / 10,
        )

        base = (
            stability
            + latency
            + protocol_score(result["uri"])
        )

    old = history.get(
        result["uri"]
    )

    historical = 0

    if old:

        total = (
            old["successes"]
            + old["failures"]
        )

        if total:
            historical = (
                old["successes"]
                / total
                * 10
            )

    return round(
        base + historical,
        3,
    )


# ============================================================
# MAIN
# ============================================================

def main():

    started = time.time()

    history = load_history()

    source_urls = []

    for line in SOURCES.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if line and not line.startswith("#"):
            source_urls.append(line)

    print(
        f"FreeForYoung v4"
    )

    print(
        f"Sources: {len(source_urls)}"
    )

    # ----------------------------
    # DOWNLOAD
    # ----------------------------

    all_nodes = []

    with ThreadPoolExecutor(
        max_workers=min(
            10,
            max(1, len(source_urls)),
        )
    ) as executor:

        jobs = {
            executor.submit(fetch, url): url
            for url in source_urls
        }

        for future in as_completed(jobs):

            source = jobs[future]

            try:

                nodes = extract(
                    future.result()
                )

                all_nodes.extend(nodes)

                print(
                    f"[OK] "
                    f"{len(nodes)} nodes"
                )

            except Exception as error:

                print(
                    f"[ERROR] "
                    f"{source}: "
                    f"{str(error)[:150]}"
                )

    unique = list(
        dict.fromkeys(all_nodes)
    )

    candidates = unique[
        :MAX_TOTAL_CHECK
    ]

    print(
        f"Unique: {len(unique)}"
    )

    print(
        f"TCP candidates: "
        f"{len(candidates)}"
    )

    # ----------------------------
    # TCP
    # ----------------------------

    tcp_results = []

    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                tcp_check,
                uri,
            ): uri
            for uri in candidates
        }

        for future in as_completed(jobs):

            try:

                result = future.result()

                if result["tcp_success"] > 0:
                    tcp_results.append(result)

            except Exception:
                pass

    tcp_results.sort(
        key=lambda x: (
            x["tcp_rate"],
            -(x["tcp_median"] or 999999),
        ),
        reverse=True,
    )

    # ----------------------------
    # REAL TEST CANDIDATES
    # ----------------------------

    real_candidates = []

    identity_counts = {}

    for item in tcp_results:

        uri = item["uri"]

        identity = identity_key(uri)

        count = identity_counts.get(
            identity,
            0,
        )

        if count >= MAX_SAME_IDENTITY:
            continue

        identity_counts[identity] = count + 1

        real_candidates.append(uri)

        if len(real_candidates) >= MAX_REAL_TEST:
            break

    print(
        f"Real Xray tests: "
        f"{len(real_candidates)}"
    )

    # ----------------------------
    # REAL TEST
    # ----------------------------

    results = []

    with ThreadPoolExecutor(
        max_workers=REAL_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                real_test,
                uri,
                i,
            ): uri
            for i, uri in enumerate(
                real_candidates
            )
        }

        for future in as_completed(jobs):

            uri = jobs[future]

            base = next(
                (
                    x for x in tcp_results
                    if x["uri"] == uri
                ),
                None,
            )

            if not base:
                continue

            try:
                real = future.result()
            except Exception:
                real = {
                    "real_supported": False,
                    "real_success": 0,
                    "real_attempts": REAL_TEST_ATTEMPTS,
                    "real_rate": 0,
                    "real_median": None,
                    "real_worst": None,
                }

            result = {
                **base,
                **real,
            }

            history = update_history(
                history,
                result,
            )

            result["score"] = score(
                result,
                history,
            )

            if result["score"] > -999000:
                results.append(result)

    # Add remaining TCP-only nodes.
    already = {
        x["uri"]
        for x in results
    }

    for item in tcp_results:

        if item["uri"] in already:
            continue

        item["real_supported"] = False
        item["real_success"] = 0
        item["real_attempts"] = 0
        item["real_rate"] = 0
        item["real_median"] = None
        item["real_worst"] = None

        history = update_history(
            history,
            item,
        )

        item["score"] = score(
            item,
            history,
        )

        if item["score"] > -999000:
            results.append(item)

    # ----------------------------
    # SORT
    # ----------------------------

    results.sort(
        key=lambda x: (
            x["score"],
            x.get("real_rate", 0),
            x.get("tcp_rate", 0),
            -(
                x.get("real_median")
                or x.get("tcp_median")
                or 999999
            ),
        ),
        reverse=True,
    )

    # ----------------------------
    # DIVERSIFIED TOP
    # ----------------------------

    selected = []

    endpoint_counts = {}

    for item in results:

        ep = endpoint_key(
            item["uri"]
        )

        count = endpoint_counts.get(
            ep,
            0,
        )

        if count >= MAX_SAME_ENDPOINT:
            continue

        endpoint_counts[ep] = count + 1

        selected.append(item)

        if len(selected) >= MAX_PUBLISHED:
            break

    # ----------------------------
    # SAVE
    # ----------------------------

    save_history(history)

    lines = [
        "#profile-title: FreeForYoung",
        "#announce: FreeForYoung - real tested public nodes",
        "#subscription-auto-update-enable: 1",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#ping-result: time",
    ]

    lines.extend(
        x["uri"]
        for x in selected
    )

    (
        OUT / "subscription.txt"
    ).write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    # ----------------------------
    # REPORT
    # ----------------------------

    report = []

    for i, item in enumerate(
        selected,
        1,
    ):

        protocol = (
            item["uri"]
            .split("://", 1)[0]
            .upper()
        )

        ping = (
            item.get("real_median")
            or item.get("tcp_median")
        )

        success = (
            f"{item.get('real_success', 0)}/"
            f"{item.get('real_attempts', 0)}"
            if item.get("real_supported")
            else
            f"{item['tcp_success']}/"
            f"{item['tcp_attempts']}"
        )

        test_type = (
            "REAL"
            if item.get("real_supported")
            else "TCP"
        )

        report.append(
            f"{i}. "
            f"score={item['score']} | "
            f"ping={ping}ms | "
            f"success={success} | "
            f"test={test_type} | "
            f"protocol={protocol} | "
            f"uri={item['uri']}"
        )

    (
        OUT / "servers.txt"
    ).write_text(
        "\n".join(report) + (
            "\n" if report else ""
        ),
        encoding="utf-8",
    )

    stats = {
        "project": "FreeForYoung",
        "sources": len(source_urls),
        "raw_nodes": len(all_nodes),
        "unique_nodes": len(unique),
        "tcp_working": len(tcp_results),
        "real_candidates": len(real_candidates),
        "final_ranked": len(results),
        "published": len(selected),
        "tcp_attempts": TCP_ATTEMPTS,
        "real_attempts": REAL_TEST_ATTEMPTS,
        "duration_seconds": round(
            time.time() - started,
            2,
        ),
        "generated_at": int(time.time()),
    }

    (
        OUT / "stats.json"
    ).write_text(
        json.dumps(
            stats,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print()
    print("=" * 50)
    print("        FreeForYoung READY")
    print("=" * 50)

    print(
        f"TCP working: {len(tcp_results)}"
    )

    print(
        f"Real candidates: "
        f"{len(real_candidates)}"
    )

    print(
        f"Published: {len(selected)}"
    )

    print(
        f"Duration: "
        f"{round(time.time() - started, 2)}s"
    )

    print()
    print("TOP SERVERS:")

    for i, item in enumerate(
        selected[:20],
        1,
    ):

        ping = (
            item.get("real_median")
            or item.get("tcp_median")
        )

        print(
            f"{i}. "
            f"score={item['score']} | "
            f"{ping}ms | "
            f"{item['uri'][:80]}"
        )


if __name__ == "__main__":
    main()
