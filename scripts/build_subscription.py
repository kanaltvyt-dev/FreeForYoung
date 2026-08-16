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


# ============================================================
# FreeForYoung v7
# REAL XRAY + HAPP OPTIMIZED
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

SOURCES = ROOT / "sources.txt"
OUT = ROOT / "output"

OUT.mkdir(exist_ok=True)

XRAY = os.environ.get("XRAY_PATH", "xray")


# ============================================================
# PERFORMANCE
# ============================================================

FETCH_TIMEOUT = 10

TCP_TIMEOUT = 2.5

TCP_WORKERS = 50
REAL_WORKERS = 8

TCP_ATTEMPTS = 2
REAL_ATTEMPTS = 3

MAX_SOURCE_NODES = 600
MAX_TOTAL_UNIQUE = 1200

MAX_REAL_TEST = 120

MAX_PUBLISHED = 80

SOCKS_BASE = 21000


# ============================================================
# FILTERING
# ============================================================

MIN_REAL_SUCCESS = 2

# For publication:
# 3/3 = preferred
# 2/3 = allowed only if score/history is good
ALLOW_TWO_OF_THREE = True

MAX_PING = 1500

# Maximum configs from the exact same host:port.
MAX_SAME_ENDPOINT = 2

# Maximum configs sharing the same IP.
MAX_SAME_IP = 3


# ============================================================
# HISTORY
# ============================================================

HISTORY_FILE = OUT / "history.json"

MAX_HISTORY = 5000


# ============================================================
# TEST URLS
# ============================================================

TEST_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
]


# ============================================================
# SUPPORTED
# ============================================================

SUPPORTED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
)


# ============================================================
# LOG
# ============================================================

def log(msg):
    print(msg, flush=True)


# ============================================================
# BASE64
# ============================================================

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


# ============================================================
# RANDOM PORT
# ============================================================

def random_port():

    return random.randint(
        SOCKS_BASE,
        SOCKS_BASE + 5000,
    )


# ============================================================
# FETCH
# ============================================================

def fetch(url):

    from urllib.request import Request, urlopen

    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 "
                "(Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 "
                "(KHTML, like Gecko) "
                "Chrome/138.0 Safari/537.36"
            )
        },
    )

    with urlopen(
        req,
        timeout=FETCH_TIMEOUT,
    ) as response:

        raw = response.read()

    text = raw.decode(
        "utf-8",
        "ignore",
    )

    compact = re.sub(
        r"\s+",
        "",
        text,
    )

    # Detect base64 subscriptions.
    if (
        len(compact) > 40
        and re.fullmatch(
            r"[A-Za-z0-9+/=_-]+",
            compact,
        )
    ):

        decoded = safe_b64decode(
            compact
        )

        if decoded:

            decoded_text = decoded.decode(
                "utf-8",
                "ignore",
            )

            if "://" in decoded_text:

                text = decoded_text

    return text


# ============================================================
# EXTRACT
# ============================================================

def extract(text):

    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss)://[^\s<>\"]+",
        re.IGNORECASE,
    )

    nodes = []

    for line in text.splitlines():

        line = (
            line
            .strip()
            .strip("`")
        )

        if not line:
            continue

        for match in pattern.finditer(line):

            uri = match.group(0).rstrip(
                "),;\"'"
            )

            if uri.lower().startswith(
                SUPPORTED
            ):

                nodes.append(uri)

                if (
                    len(nodes)
                    >= MAX_SOURCE_NODES
                ):
                    return nodes

    return nodes


# ============================================================
# ENDPOINT
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

    return (
        f"{ep[0].lower()}:"
        f"{ep[1]}"
    )


def ip_key(uri):

    ep = endpoint(uri)

    if not ep:
        return None

    return ep[0].lower()


# ============================================================
# BASIC URI VALIDATION
# ============================================================

def validate_uri(uri):

    low = uri.lower()

    if not low.startswith(SUPPORTED):
        return False

    ep = endpoint(uri)

    if not ep:
        return False

    host, port = ep

    if not host:
        return False

    if port < 1 or port > 65535:
        return False

    return True


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
                (
                    time.perf_counter()
                    - started
                ) * 1000,
                1,
            )

    except Exception:

        return None


def tcp_check(uri):

    values = []

    for _ in range(
        TCP_ATTEMPTS
    ):

        value = tcp_ping(uri)

        if value is not None:
            values.append(value)

    return {
        "uri": uri,
        "tcp_success": len(values),
        "tcp_attempts": TCP_ATTEMPTS,
        "tcp_ping": (
            round(
                median(values),
                1,
            )
            if values
            else None
        ),
    }


# ============================================================
# VMESS PARSER
# ============================================================

def parse_vmess(uri):

    raw = uri[
        len("vmess://"):
    ]

    decoded = safe_b64decode(
        raw
    )

    if not decoded:
        raise ValueError(
            "invalid vmess base64"
        )

    obj = json.loads(
        decoded.decode(
            "utf-8",
            "ignore",
        )
    )

    address = (
        obj.get("add")
        or obj.get("address")
    )

    port = int(
        obj.get(
            "port",
            443,
        )
    )

    uuid = obj.get("id")

    if not address or not uuid:
        raise ValueError(
            "invalid vmess"
        )

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
        "host": obj.get(
            "host",
            "",
        ),
        "path": obj.get(
            "path",
            "/",
        ),
        "sni": (
            obj.get("sni")
            or obj.get("host", "")
        ),
        "fp": obj.get(
            "fp",
            "",
        ),
    }


# ============================================================
# QUERY
# ============================================================

def query_dict(parsed):

    result = {}

    for key, values in parse_qs(
        parsed.query,
        keep_blank_values=True,
    ).items():

        if values:

            result[
                key.lower()
            ] = values[-1]

    return result


# ============================================================
# TLS
# ============================================================

def tls_settings(
    q,
    sni=None,
):

    result = {
        "serverName": (
            sni
            or q.get("sni")
            or q.get("host")
            or ""
        )
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
        q.get(
            "insecure",
            "0",
        ),
    )

    result["allowInsecure"] = (
        str(insecure).lower()
        in (
            "1",
            "true",
            "yes",
        )
    )

    return result


# ============================================================
# WS
# ============================================================

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


# ============================================================
# VLESS
# ============================================================

def vless_outbound(uri):

    p = urlsplit(uri)

    q = query_dict(p)

    if not p.hostname or not p.port:
        raise ValueError(
            "invalid VLESS endpoint"
        )

    uuid = unquote(
        p.username or ""
    )

    if not uuid:
        raise ValueError(
            "missing VLESS UUID"
        )

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

    # REALITY
    if security == "reality":

        public_key = q.get(
            "pbk",
            "",
        )

        server_name = q.get(
            "sni",
            "",
        )

        if not public_key or not server_name:
            raise ValueError(
                "invalid Reality"
            )

        reality = {
            "show": False,
            "fingerprint": q.get(
                "fp",
                "chrome",
            ),
            "serverName": server_name,
            "publicKey": public_key,
        }

        sid = q.get("sid")

        if sid:
            reality[
                "shortId"
            ] = sid

        stream[
            "security"
        ] = "reality"

        stream[
            "realitySettings"
        ] = reality

    # TLS
    elif security == "tls":

        stream[
            "security"
        ] = "tls"

        stream[
            "tlsSettings"
        ] = tls_settings(
            q,
            q.get("sni"),
        )

    # WS
    if stream["network"] == "ws":

        stream[
            "wsSettings"
        ] = ws_settings(q)

    # gRPC
    elif stream["network"] == "grpc":

        service = q.get(
            "serviceName",
            q.get(
                "servicename",
                "",
            ),
        )

        stream[
            "grpcSettings"
        ] = {
            "serviceName": service,
        }

    # HTTP
    elif stream["network"] == "http":

        stream[
            "httpSettings"
        ] = {
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

        settings[
            "vnext"
        ][0][
            "users"
        ][0][
            "flow"
        ] = flow

    return {
        "protocol": "vless",
        "settings": settings,
        "streamSettings": stream,
    }


# ============================================================
# TROJAN
# ============================================================

def trojan_outbound(uri):

    p = urlsplit(uri)

    q = query_dict(p)

    if not p.hostname or not p.port:
        raise ValueError(
            "invalid Trojan endpoint"
        )

    password = unquote(
        p.username or ""
    )

    if not password:
        raise ValueError(
            "missing Trojan password"
        )

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

        stream[
            "security"
        ] = "tls"

        stream[
            "tlsSettings"
        ] = tls_settings(
            q,
            q.get("sni"),
        )

    if stream["network"] == "ws":

        stream[
            "wsSettings"
        ] = ws_settings(q)

    elif stream["network"] == "grpc":

        stream[
            "grpcSettings"
        ] = {
            "serviceName": q.get(
                "servicename",
                q.get(
                    "serviceName",
                    "",
                ),
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


# ============================================================
# VMESS
# ============================================================

def vmess_outbound(uri):

    data = parse_vmess(uri)

    stream = {
        "network": data[
            "network"
        ],
    }

    if data["tls"] in (
        "tls",
        "1",
    ):

        stream[
            "security"
        ] = "tls"

        stream[
            "tlsSettings"
        ] = {
            "serverName": (
                data["sni"]
                or data["host"]
            ),
        }

        if data["fp"]:

            stream[
                "tlsSettings"
            ][
                "fingerprint"
            ] = data["fp"]

    if data["network"] == "ws":

        stream[
            "wsSettings"
        ] = {
            "path": data[
                "path"
            ],
        }

        if data["host"]:

            stream[
                "wsSettings"
            ][
                "headers"
            ] = {
                "Host": data[
                    "host"
                ],
            }

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": data[
                        "address"
                    ],
                    "port": data[
                        "port"
                    ],
                    "users": [
                        {
                            "id": data[
                                "uuid"
                            ],
                            "alterId": 0,
                            "security": "auto",
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


# ============================================================
# SHADOWSOCKS
# ============================================================

def ss_outbound(uri):

    p = urlsplit(uri)

    if not p.hostname or not p.port:
        raise ValueError(
            "invalid SS endpoint"
        )

    raw_user = (
        p.netloc.split(
            "@",
            1,
        )[0]
        if "@"
        in p.netloc
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

        user = unquote(
            raw_user
        )

    if ":" not in user:
        raise ValueError(
            "invalid SS credentials"
        )

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


# ============================================================
# OUTBOUND
# ============================================================

def make_outbound(uri):

    low = uri.lower()

    if low.startswith(
        "vless://"
    ):
        return vless_outbound(
            uri
        )

    if low.startswith(
        "trojan://"
    ):
        return trojan_outbound(
            uri
        )

    if low.startswith(
        "vmess://"
    ):
        return vmess_outbound(
            uri
        )

    if low.startswith(
        "ss://"
    ):
        return ss_outbound(
            uri
        )

    raise ValueError(
        "unsupported protocol"
    )


# ============================================================
# PROTOCOL CLASS
# ============================================================

def protocol_class(uri):

    low = uri.lower()

    if low.startswith(
        "vless://"
    ):

        p = urlsplit(uri)

        q = query_dict(p)

        security = q.get(
            "security",
            "",
        ).lower()

        network = q.get(
            "type",
            "tcp",
        ).lower()

        if (
            security == "reality"
            and network == "tcp"
        ):
            return "VLESS-REALITY"

        if security == "tls":
            return "VLESS-TLS"

        return "VLESS"

    if low.startswith(
        "trojan://"
    ):
        return "TROJAN"

    if low.startswith(
        "vmess://"
    ):
        return "VMESS"

    if low.startswith(
        "ss://"
    ):
        return "SS"

    return "OTHER"


# ============================================================
# PROTOCOL BONUS
# ============================================================

def protocol_bonus(uri):

    cls = protocol_class(uri)

    return {
        "VLESS-REALITY": 160,
        "VLESS-TLS": 100,
        "VLESS": 80,
        "TROJAN": 70,
        "SS": 45,
        "VMESS": 25,
        "OTHER": 0,
    }.get(
        cls,
        0,
    )


# ============================================================
# XRAY
# ============================================================

def wait_port(
    port,
    timeout=5,
):

    deadline = (
        time.time()
        + timeout
    )

    while time.time() < deadline:

        try:

            with socket.create_connection(
                (
                    "127.0.0.1",
                    port,
                ),
                timeout=0.3,
            ):

                return True

        except Exception:

            time.sleep(
                0.05
            )

    return False


def curl_through_socks(
    port,
    url,
):

    started = time.perf_counter()

    command = [
        "curl",
        "-sS",
        "--max-time",
        "8",
        "--connect-timeout",
        "5",
        "--proxy",
        (
            f"socks5h://"
            f"127.0.0.1:{port}"
        ),
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

        if (
            200 <= code < 400
            or code == 204
        ):

            return round(
                elapsed,
                1,
            )

        return None

    except Exception:

        return None


# ============================================================
# REAL XRAY ATTEMPT
# ============================================================

def real_xray_attempt(uri):

    port = random_port()

    try:

        outbound = make_outbound(
            uri
        )

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

                results = []

                for url in TEST_URLS:

                    latency = (
                        curl_through_socks(
                            port,
                            url,
                        )
                    )

                    if latency is not None:

                        results.append(
                            latency
                        )

                if not results:
                    return None

                return round(
                    median(results),
                    1,
                )

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


# ============================================================
# REAL CHECK
# ============================================================

def real_check(uri):

    values = []

    for _ in range(
        REAL_ATTEMPTS
    ):

        latency = (
            real_xray_attempt(
                uri
            )
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

        data = json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8",
            )
        )

        if not isinstance(
            data,
            dict,
        ):
            return {}

        return data

    except Exception:

        return {}


def save_history(history):

    # Prevent unlimited growth.
    if len(history) > MAX_HISTORY:

        ranked = sorted(
            history.items(),
            key=lambda item: (
                item[1].get(
                    "last_seen",
                    0,
                )
            ),
            reverse=True,
        )

        history = dict(
            ranked[:MAX_HISTORY]
        )

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
        {},
    )

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

    old.setdefault(
        "best_ping",
        None,
    )

    old["runs"] += 1

    tcp_success = result.get(
        "tcp_success",
        0,
    )

    tcp_attempts = result.get(
        "tcp_attempts",
        0,
    )

    real_success = result.get(
        "real_successes",
        0,
    )

    real_attempts = result.get(
        "real_attempts",
        0,
    )

    old[
        "tcp_successes"
    ] += tcp_success

    old[
        "tcp_failures"
    ] += (
        tcp_attempts
        - tcp_success
    )

    old[
        "real_successes"
    ] += real_success

    old[
        "real_failures"
    ] += (
        real_attempts
        - real_success
    )

    if result.get(
        "real_ping"
    ) is not None:

        ping = result[
            "real_ping"
        ]

        old[
            "last_ping"
        ] = ping

        best = old.get(
            "best_ping"
        )

        if (
            best is None
            or ping < best
        ):

            old[
                "best_ping"
            ] = ping

    old[
        "last_seen"
    ] = int(
        time.time()
    )

    history[
        uri
    ] = old

    return history


# ============================================================
# HISTORY SCORE
# ============================================================

def historical_score(
    history,
    uri,
):

    old = history.get(
        uri
    )

    if not old:
        return 0

    successes = old.get(
        "real_successes",
        0,
    )

    failures = old.get(
        "real_failures",
        0,
    )

    total = (
        successes
        + failures
    )

    if total <= 0:
        return 0

    rate = (
        successes
        / total
    )

    # Max 220 historical points.
    return round(
        rate * 220,
        2,
    )


# ============================================================
# SCORE
# ============================================================

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

    # REAL reliability dominates.
    reliability = (
        success * 1100
    )

    # Ping.
    if ping <= 50:
        latency = 260

    elif ping <= 80:
        latency = 240

    elif ping <= 120:
        latency = 220

    elif ping <= 180:
        latency = 190

    elif ping <= 250:
        latency = 150

    elif ping <= 350:
        latency = 110

    elif ping <= 500:
        latency = 70

    elif ping <= 800:
        latency = 30

    else:
        latency = 0

    # Stability between repeated REAL tests.
    worst = result[
        "real_worst"
    ]

    consistency = 0

    if worst is not None:

        spread = (
            worst - ping
        )

        if spread <= 25:
            consistency = 100

        elif spread <= 50:
            consistency = 80

        elif spread <= 100:
            consistency = 55

        elif spread <= 200:
            consistency = 25

    # Historical stability.
    history_points = (
        historical_score(
            history,
            result["uri"],
        )
    )

    # Protocol preference.
    protocol_points = (
        protocol_bonus(
            result["uri"]
        )
    )

    return round(
        reliability
        + latency
        + consistency
        + history_points
        + protocol_points,
        2,
    )


# ============================================================
# PUBLISH ELIGIBILITY
# ============================================================

def publishable(result):

    success = result.get(
        "real_successes",
        0,
    )

    ping = result.get(
        "real_ping"
    )

    if ping is None:
        return False

    if ping > MAX_PING:
        return False

    if success >= REAL_ATTEMPTS:
        return True

    if (
        ALLOW_TWO_OF_THREE
        and success >= MIN_REAL_SUCCESS
    ):
        return True

    return False


# ============================================================
# SERVER TITLE
# ============================================================

def server_title(
    item,
    index,
):

    cls = protocol_class(
        item["uri"]
    )

    names = {
        "VLESS-REALITY": "REALITY",
        "VLESS-TLS": "TLS",
        "VLESS": "VLESS",
        "TROJAN": "TROJAN",
        "SS": "SS",
        "VMESS": "VMESS",
    }

    label = names.get(
        cls,
        cls,
    )

    ping = item.get(
        "real_ping"
    )

    if ping is None:
        ping_text = "N/A"
    else:
        ping_text = (
            f"{round(ping)}ms"
        )

    return (
        f"FreeForYoung "
        f"{label} "
        f"{index:02d} "
        f"· {ping_text}"
    )


# ============================================================
# ADD DESCRIPTION TO URI
# ============================================================

def add_happ_description(
    uri,
    description,
):

    # HAPP supports:
    # #title?serverDescription=BASE64
    #
    # We preserve the existing fragment
    # and add serverDescription.

    if "#" in uri:

        base, fragment = uri.split(
            "#",
            1,
        )

    else:

        base = uri
        fragment = "FreeForYoung"

    encoded = base64.b64encode(
        description.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    )

    return (
        f"{base}"
        f"#{fragment}"
        f"?serverDescription="
        f"{encoded}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    started = time.time()

    log(
        "========================================"
    )
    log(
        "        FreeForYoung v7"
    )
    log(
        "   REAL XRAY + HAPP OPTIMIZED"
    )
    log(
        "========================================"
    )

    if not Path(
        XRAY
    ).exists():

        log(
            f"[FATAL] Xray not found: {XRAY}"
        )

        raise SystemExit(1)

    history = load_history()

    # ========================================================
    # SOURCES
    # ========================================================

    if not SOURCES.exists():

        log(
            f"[FATAL] Missing {SOURCES}"
        )

        raise SystemExit(1)

    source_urls = []

    for line in SOURCES.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if (
            line
            and not line.startswith("#")
        ):

            source_urls.append(
                line
            )

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
                    f"[OK] "
                    f"{len(nodes)} nodes"
                )

            except Exception as e:

                log(
                    f"[ERROR] "
                    f"{source}: "
                    f"{e}"
                )

    log(
        f"Raw nodes: "
        f"{len(all_nodes)}"
    )

    # ========================================================
    # VALIDATE + UNIQUE
    # ========================================================

    unique = []

    seen = set()

    for uri in all_nodes:

        if not validate_uri(
            uri
        ):
            continue

        if uri in seen:
            continue

        seen.add(uri)

        unique.append(uri)

        if (
            len(unique)
            >= MAX_TOTAL_UNIQUE
        ):
            break

    log(
        f"Valid unique: "
        f"{len(unique)}"
    )

    # ========================================================
    # TCP
    # ========================================================

    tcp_candidates = []

    with ThreadPoolExecutor(
        max_workers=TCP_WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                tcp_check,
                uri,
            ): uri
            for uri in unique
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
            x[
                "tcp_success"
            ],
            -(
                x[
                    "tcp_ping"
                ]
                or 999999
            ),
        ),
        reverse=True,
    )

    log(
        f"TCP candidates: "
        f"{len(tcp_candidates)}"
    )

    # ========================================================
    # REAL XRAY
    # ========================================================

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

                result = (
                    future.result()
                )

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

            else:

                result.update(
                    {
                        "tcp_success": 0,
                        "tcp_attempts": TCP_ATTEMPTS,
                        "tcp_ping": None,
                    }
                )

            history = update_history(
                history,
                result,
            )

            if publishable(
                result
            ):

                result[
                    "score"
                ] = calculate_score(
                    result,
                    history,
                )

                checked.append(
                    result
                )

    # ========================================================
    # RANK
    # ========================================================

    ranked = sorted(
        checked,
        key=lambda x: (
            x[
                "real_success_rate"
            ],
            x[
                "score"
            ],
            -(
                x[
                    "real_ping"
                ]
                or 999999
            ),
        ),
        reverse=True,
    )

    # ========================================================
    # DIVERSIFY
    # ========================================================

    selected = []

    endpoint_counts = {}

    ip_counts = {}

    protocol_counts = {}

    for item in ranked:

        uri = item[
            "uri"
        ]

        endpoint_id = host_key(
            uri
        )

        ip_id = ip_key(
            uri
        )

        protocol_id = protocol_class(
            uri
        )

        endpoint_count = (
            endpoint_counts.get(
                endpoint_id,
                0,
            )
        )

        ip_count = (
            ip_counts.get(
                ip_id,
                0,
            )
        )

        # Never overfill one endpoint.
        if (
            endpoint_count
            >= MAX_SAME_ENDPOINT
        ):
            continue

        # Don't fill the whole list with
        # one IP.
        if (
            ip_count
            >= MAX_SAME_IP
        ):
            continue

        selected.append(
            item
        )

        endpoint_counts[
            endpoint_id
        ] = (
            endpoint_count
            + 1
        )

        ip_counts[
            ip_id
        ] = (
            ip_count
            + 1
        )

        protocol_counts[
            protocol_id
        ] = (
            protocol_counts.get(
                protocol_id,
                0,
            )
            + 1
        )

        if (
            len(selected)
            >= MAX_PUBLISHED
        ):
            break

    # ========================================================
    # SAVE HISTORY
    # ========================================================

    save_history(
        history
    )

    # ========================================================
    # HAPP SUBSCRIPTION
    # ========================================================

    lines = [
        "#profile-title: FreeForYoung",
        "#announce: FreeForYoung v7 - REAL Xray tested",
        "#subscription-auto-update-enable: 1",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#ping-type: proxy",
        "#check-url-via-proxy: https://cp.cloudflare.com/generate_204",
        "#proxy-ping-mode: keepalive",
        "#ping-result: time",
    ]

    published_lines = []

    for index, item in enumerate(
        selected,
        1,
    ):

        uri = item[
            "uri"
        ]

        description = server_title(
            item,
            index,
        )

        try:

            uri = add_happ_description(
                uri,
                description,
            )

        except Exception:

            pass

        published_lines.append(
            uri
        )

    lines.extend(
        published_lines
    )

    (
        OUT / "subscription.txt"
    ).write_text(
        "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )

    # ========================================================
    # SERVERS JSON
    # ========================================================

    servers_json = []

    for index, item in enumerate(
        selected,
        1,
    ):

        servers_json.append(
            {
                "rank": index,
                "protocol": protocol_class(
                    item["uri"]
                ),
                "uri": item[
                    "uri"
                ],
                "ping": item[
                    "real_ping"
                ],
                "real_successes": item[
                    "real_successes"
                ],
                "real_attempts": item[
                    "real_attempts"
                ],
                "real_success_rate": item[
                    "real_success_rate"
                ],
                "score": item[
                    "score"
                ],
                "endpoint": host_key(
                    item["uri"]
                ),
                "ip": ip_key(
                    item["uri"]
                ),
            }
        )

    (
        OUT / "servers.json"
    ).write_text(
        json.dumps(
            servers_json,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # ========================================================
    # SERVERS TXT
    # ========================================================

    report = []

    for index, item in enumerate(
        selected,
        1,
    ):

        report.append(
            (
                f"{index}. "
                f"score={item['score']} | "
                f"ping={item['real_ping']}ms | "
                f"real="
                f"{item['real_successes']}/"
                f"{item['real_attempts']} | "
                f"protocol="
                f"{protocol_class(item['uri'])} | "
                f"endpoint="
                f"{host_key(item['uri'])}"
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

    # ========================================================
    # STATS
    # ========================================================

    stats = {
        "project": "FreeForYoung",
        "version": 7,

        "sources": len(
            source_urls
        ),

        "raw_nodes": len(
            all_nodes
        ),

        "valid_unique_nodes": len(
            unique
        ),

        "tcp_candidates": len(
            tcp_candidates
        ),

        "real_tested": len(
            real_targets
        ),

        "real_working": len(
            checked
        ),

        "published": len(
            selected
        ),

        "minimum_real_success": (
            MIN_REAL_SUCCESS
        ),

        "tcp_attempts": (
            TCP_ATTEMPTS
        ),

        "real_attempts": (
            REAL_ATTEMPTS
        ),

        "tcp_workers": (
            TCP_WORKERS
        ),

        "real_workers": (
            REAL_WORKERS
        ),

        "max_same_endpoint": (
            MAX_SAME_ENDPOINT
        ),

        "max_same_ip": (
            MAX_SAME_IP
        ),

        "happ_ping_type": "proxy",

        "happ_proxy_ping_mode": (
            "keepalive"
        ),

        "happ_check_url": (
            "https://cp.cloudflare.com/"
            "generate_204"
        ),

        "generated_at": int(
            time.time()
        ),

        "duration_seconds": round(
            time.time()
            - started,
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

    # ========================================================
    # CONSOLE
    # ========================================================

    log("")
    log(
        "========================================"
    )
    log(
        "                 READY"
    )
    log(
        "========================================"
    )

    log(
        f"Raw nodes: "
        f"{len(all_nodes)}"
    )

    log(
        f"Valid unique: "
        f"{len(unique)}"
    )

    log(
        f"TCP candidates: "
        f"{len(tcp_candidates)}"
    )

    log(
        f"REAL tested: "
        f"{len(real_targets)}"
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
    log(
        "TOP REAL SERVERS:"
    )

    for index, item in enumerate(
        selected[:20],
        1,
    ):

        log(
            f"{index}. "
            f"score={item['score']} | "
            f"ping={item['real_ping']}ms | "
            f"real="
            f"{item['real_successes']}/"
            f"{item['real_attempts']} | "
            f"{protocol_class(item['uri'])} | "
            f"{host_key(item['uri'])}"
        )


if __name__ == "__main__":
    main()
