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
# FREEFORYOUNG v6
# REAL XRAY + HAPP OPTIMIZED
# ============================================================

ROOT = Path(__file__).resolve().parents[1]

SOURCES = ROOT / "sources.txt"
OUT = ROOT / "output"

OUT.mkdir(exist_ok=True)

XRAY = os.environ.get("XRAY_PATH", "xray")


# ============================================================
# SETTINGS
# ============================================================

FETCH_TIMEOUT = 12

TCP_TIMEOUT = 2.5

TCP_WORKERS = 50
REAL_WORKERS = 8

TCP_ATTEMPTS = 2
REAL_ATTEMPTS = 3

# Must have at least this many successful
# real Xray checks to be published.
MIN_REAL_SUCCESS = 2

MAX_SOURCE_NODES = 600
MAX_REAL_TEST = 120
MAX_PUBLISHED = 100

MAX_SAME_ENDPOINT = 1

SOCKS_BASE = 21000

HISTORY_FILE = OUT / "history.json"
MAX_HISTORY = 30


# Multiple URLs make false positives much less likely.
TEST_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
]


SUPPORTED = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
)


# ============================================================
# LOG
# ============================================================

def log(message):
    print(message, flush=True)


# ============================================================
# BASE64
# ============================================================

def safe_b64decode(value):
    if not value:
        return None

    value = value.strip()

    value += "=" * (-len(value) % 4)

    candidates = [
        value,
        value.replace("-", "+").replace("_", "/"),
    ]

    for candidate in candidates:
        try:
            return base64.b64decode(
                candidate,
                validate=False,
            )
        except Exception:
            pass

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
# FETCH SOURCES
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
                "Chrome/131 Safari/537.36 "
                "FreeForYoung/6.0"
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

    # Handle Base64 subscriptions.
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

            if uri.lower().startswith(
                SUPPORTED
            ):

                nodes.append(uri)

                if len(nodes) >= MAX_SOURCE_NODES:
                    return nodes

    return nodes


# ============================================================
# URI HELPERS
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

    host, port = ep

    return f"{host.lower()}:{port}"


def protocol(uri):

    return uri.split(
        "://",
        1,
    )[0].lower()


# ============================================================
# URI SANITY CHECK
# ============================================================

def valid_uri(uri):

    try:

        low = uri.lower()

        if not low.startswith(SUPPORTED):
            return False

        p = urlsplit(uri)

        if not p.hostname or not p.port:
            return False

        # ----------------------------------------------------
        # VLESS
        # ----------------------------------------------------

        if low.startswith("vless://"):

            q = query_dict(p)

            if not p.username:
                return False

            security = q.get(
                "security",
                "",
            ).lower()

            network = q.get(
                "type",
                q.get(
                    "network",
                    "tcp",
                ),
            ).lower()

            if security == "reality":

                if not q.get("pbk"):
                    return False

                if not q.get("sni"):
                    return False

                if network == "tcp":

                    # Reality TCP should normally
                    # use Vision flow when supplied.
                    # We don't require it because
                    # some valid nodes don't have it.

                    pass

            if network == "ws":

                if not (
                    q.get("path")
                    or q.get("wspath")
                ):
                    return False

            if network == "grpc":

                if not (
                    q.get("servicename")
                    or q.get("servicename")
                ):
                    # gRPC can technically use empty
                    # service names, so don't reject it.
                    pass

            return True

        # ----------------------------------------------------
        # TROJAN
        # ----------------------------------------------------

        if low.startswith("trojan://"):

            if not p.username:
                return False

            q = query_dict(p)

            network = q.get(
                "type",
                q.get(
                    "network",
                    "tcp",
                ),
            ).lower()

            security = q.get(
                "security",
                "tls",
            ).lower()

            if network == "ws":

                if not (
                    q.get("path")
                    or q.get("wspath")
                ):
                    return False

            if security not in (
                "tls",
                "",
            ):
                return False

            return True

        # ----------------------------------------------------
        # VMESS
        # ----------------------------------------------------

        if low.startswith("vmess://"):

            parse_vmess(uri)

            return True

        # ----------------------------------------------------
        # SHADOWSOCKS
        # ----------------------------------------------------

        if low.startswith("ss://"):

            ss_outbound(uri)

            return True

    except Exception:
        return False

    return False


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
                )
                * 1000,
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
# VMESS
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
        obj.get(
            "tls",
            "",
        )
    ).lower()

    return {
        "address": address,
        "port": port,
        "uuid": uuid,
        "network": network.lower(),
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
        or q.get("host")
    )

    ws = {
        "path": unquote(
            path
        ),
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

    network = (
        q.get("type")
        or q.get(
            "network",
            "tcp",
        )
    ).lower()

    stream = {
        "network": network,
    }

    security = q.get(
        "security",
        "",
    ).lower()

    # --------------------------------------------------------
    # REALITY
    # --------------------------------------------------------

    if security == "reality":

        public_key = q.get(
            "pbk",
            "",
        )

        sni = q.get(
            "sni",
            "",
        )

        if not public_key or not sni:
            raise ValueError(
                "invalid Reality"
            )

        reality = {
            "show": False,

            "fingerprint": q.get(
                "fp",
                "chrome",
            ),

            "serverName": sni,

            "publicKey": public_key,
        }

        sid = q.get("sid")

        if sid:
            reality["shortId"] = sid

        spider = q.get("spx")

        if spider:
            reality["spiderX"] = (
                unquote(spider)
            )

        stream["security"] = "reality"

        stream[
            "realitySettings"
        ] = reality

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    elif security == "tls":

        stream["security"] = "tls"

        stream[
            "tlsSettings"
        ] = tls_settings(
            q,
            q.get("sni"),
        )

    # --------------------------------------------------------
    # WS
    # --------------------------------------------------------

    if network == "ws":

        stream[
            "wsSettings"
        ] = ws_settings(q)

    # --------------------------------------------------------
    # gRPC
    # --------------------------------------------------------

    elif network == "grpc":

        service = q.get(
            "servicename",
            q.get(
                "servicename",
                "",
            ),
        )

        grpc = {
            "serviceName": service,
        }

        mode = q.get(
            "mode"
        )

        if mode:
            grpc["multiMode"] = (
                mode.lower()
                == "multi"
            )

        stream[
            "grpcSettings"
        ] = grpc

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    elif network == "http":

        stream[
            "httpSettings"
        ] = {
            "path": unquote(
                q.get(
                    "path",
                    "/",
                )
            )
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

    network = (
        q.get("type")
        or q.get(
            "network",
            "tcp",
        )
    ).lower()

    stream = {
        "network": network,
    }

    security = q.get(
        "security",
        "tls",
    ).lower()

    if security == "tls":

        stream["security"] = "tls"

        stream[
            "tlsSettings"
        ] = tls_settings(
            q,
            q.get("sni"),
        )

    if network == "ws":

        stream[
            "wsSettings"
        ] = ws_settings(q)

    elif network == "grpc":

        stream[
            "grpcSettings"
        ] = {
            "serviceName": q.get(
                "servicename",
                "",
            )
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
# VMESS OUTBOUND
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
        "true",
    ):

        stream["security"] = "tls"

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

    method = method.lower()

    allowed = {
        "aes-128-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    }

    if method not in allowed:

        # Don't reject old methods blindly.
        # Xray will perform the final validation.
        pass

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
        "10",

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
            timeout=12,
        )

        if result.returncode != 0:
            return None

        code = (
            result.stdout.strip()
        )

        if not code.isdigit():
            return None

        code = int(code)

        elapsed = (
            time.perf_counter()
            - started
        ) * 1000

        # Successful HTTP response.
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

            # ------------------------------------------------
            # Xray config validation
            # ------------------------------------------------

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

            # ------------------------------------------------
            # Start Xray
            # ------------------------------------------------

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

                latencies = []

                # Try BOTH URLs.
                for url in TEST_URLS:

                    latency = (
                        curl_through_socks(
                            port,
                            url,
                        )
                    )

                    if latency is not None:

                        latencies.append(
                            latency
                        )

                # Important:
                # one successful URL is enough for
                # the individual attempt, but we
                # record the fastest real latency.
                if not latencies:
                    return None

                return round(
                    min(
                        latencies
                    ),
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

    successful = len(
        values
    )

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
                encoding="utf-8"
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


def save_history(
    history
):

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

    # Compatibility with ALL old versions.
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

    tcp_success = result.get(
        "tcp_success",
        0,
    )

    tcp_attempts = result.get(
        "tcp_attempts",
        0,
    )

    real_successes = result.get(
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
    ] += max(
        0,
        tcp_attempts
        - tcp_success,
    )

    old[
        "real_successes"
    ] += real_successes

    old[
        "real_failures"
    ] += max(
        0,
        real_attempts
        - real_successes,
    )

    if result.get(
        "real_ping"
    ) is not None:

        old[
            "last_ping"
        ] = result[
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
        low.startswith(
            "vless://"
        )
        and "security=reality"
        in low
        and "type=tcp"
        in low
    ):

        return 50

    if low.startswith(
        "vless://"
    ):
        return 35

    if low.startswith(
        "trojan://"
    ):
        return 30

    if low.startswith(
        "vmess://"
    ):
        return 15

    if low.startswith(
        "ss://"
    ):
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

    # --------------------------------------------------------
    # REAL reliability
    # --------------------------------------------------------

    stability = (
        success * 1000
    )

    # --------------------------------------------------------
    # Latency
    # --------------------------------------------------------

    if ping <= 40:
        latency = 300

    elif ping <= 70:
        latency = 270

    elif ping <= 100:
        latency = 240

    elif ping <= 150:
        latency = 200

    elif ping <= 250:
        latency = 150

    elif ping <= 400:
        latency = 100

    elif ping <= 700:
        latency = 50

    else:
        latency = 10

    # --------------------------------------------------------
    # Consistency
    # --------------------------------------------------------

    consistency = 0

    worst = result[
        "real_worst"
    ]

    if worst is not None:

        spread = (
            worst - ping
        )

        if spread <= 30:
            consistency = 100

        elif spread <= 70:
            consistency = 70

        elif spread <= 150:
            consistency = 40

        else:
            consistency = 10

    # --------------------------------------------------------
    # Historical reliability
    # --------------------------------------------------------

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

            historical = (
                rate * 150
            )

    # --------------------------------------------------------
    # Bonus for successful consecutive runs
    # --------------------------------------------------------

    streak = 0

    if old:

        runs = old.get(
            "runs",
            0,
        )

        if runs >= 3:

            streak = min(
                50,
                runs * 2,
            )

    return round(
        stability
        + latency
        + consistency
        + historical
        + streak
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

    log("")
    log(
        "========================================"
    )
    log(
        "        FreeForYoung v6"
    )
    log(
        "   REAL XRAY + HAPP OPTIMIZED"
    )
    log(
        "========================================"
    )
    log("")

    # --------------------------------------------------------
    # XRAY
    # --------------------------------------------------------

    if not Path(
        XRAY
    ).exists():

        log(
            f"[FATAL] Xray not found: {XRAY}"
        )

        raise SystemExit(1)

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    history = load_history()

    # --------------------------------------------------------
    # SOURCES
    # --------------------------------------------------------

    source_urls = []

    if SOURCES.exists():

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

    # --------------------------------------------------------
    # DOWNLOAD SOURCES
    # --------------------------------------------------------

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
                    f"{source}: {e}"
                )

    # --------------------------------------------------------
    # SANITIZE
    # --------------------------------------------------------

    raw_count = len(
        all_nodes
    )

    sane_nodes = []

    for uri in all_nodes:

        if valid_uri(uri):

            sane_nodes.append(
                uri
            )

    sane_nodes = list(
        dict.fromkeys(
            sane_nodes
        )
    )

    log(
        f"Raw nodes: {raw_count}"
    )

    log(
        f"Valid unique nodes: "
        f"{len(sane_nodes)}"
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

            for uri in sane_nodes[
                :MAX_SOURCE_NODES
            ]
        }

        for future in as_completed(
            jobs
        ):

            try:

                result = future.result()

                if (
                    result[
                        "tcp_success"
                    ] > 0
                ):

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

    tcp_map = {
        item["uri"]: item
        for item in tcp_candidates
    }

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

                    "real_attempts": (
                        REAL_ATTEMPTS
                    ),

                    "real_success_rate": 0,

                    "real_ping": None,

                    "real_avg": None,

                    "real_worst": None,
                }

            # Add TCP information.
            tcp = tcp_map.get(
                uri
            )

            if tcp:

                result.update(
                    {
                        "tcp_success":
                            tcp[
                                "tcp_success"
                            ],

                        "tcp_attempts":
                            tcp[
                                "tcp_attempts"
                            ],

                        "tcp_ping":
                            tcp[
                                "tcp_ping"
                            ],
                    }
                )

            history = update_history(
                history,
                result,
            )

            # ------------------------------------------------
            # STRICT PUBLISH RULE
            # ------------------------------------------------

            if (
                result[
                    "real_successes"
                ]
                >= MIN_REAL_SUCCESS
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

    # --------------------------------------------------------
    # RANK
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # DIVERSIFY
    # --------------------------------------------------------

    selected = []

    hosts = {}

    for item in ranked:

        key = host_key(
            item["uri"]
        )

        count = hosts.get(
            key,
            0,
        )

        if (
            count
            >= MAX_SAME_ENDPOINT
        ):
            continue

        selected.append(
            item
        )

        hosts[
            key
        ] = count + 1

        if (
            len(selected)
            >= MAX_PUBLISHED
        ):
            break

    # --------------------------------------------------------
    # SAVE HISTORY
    # --------------------------------------------------------

    save_history(
        history
    )

    # --------------------------------------------------------
    # HAPP SUBSCRIPTION
    # --------------------------------------------------------

    lines = [
        "#profile-title: FreeForYoung",

        "#announce: FreeForYoung - REAL Xray tested nodes",

        "#subscription-auto-update-enable: 1",

        "#subscription-auto-update-open-enable: 1",

        "#subscription-ping-onopen-enabled: 1",

        "#ping-type: proxy",

        "#check-url-via-proxy: https://cp.cloudflare.com/generate_204",

        "#proxy-ping-mode: keepalive",

        "#proxy-ping-timeout: 10",

        "#subscriptions-sort-type: ping",

        "#ping-result: time",
    ]

    lines.extend(
        item["uri"]
        for item in selected
    )

    (
        OUT
        / "subscription.txt"
    ).write_text(
        "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # SERVERS REPORT
    # --------------------------------------------------------

    report = []

    for index, item in enumerate(
        selected,
        1,
    ):

        uri = item[
            "uri"
        ]

        proto = protocol(
            uri
        ).upper()

        report.append(
            (
                f"{index}. "

                f"score="
                f"{item['score']} | "

                f"ping="
                f"{item['real_ping']}ms | "

                f"real="
                f"{item['real_successes']}/"
                f"{item['real_attempts']} | "

                f"tcp="
                f"{item.get('tcp_success', 0)}/"
                f"{item.get('tcp_attempts', 0)} | "

                f"protocol={proto} | "

                f"endpoint="
                f"{host_key(uri)} | "

                f"uri={uri}"
            )
        )

    (
        OUT
        / "servers.txt"
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
    # JSON REPORT
    # --------------------------------------------------------

    detailed = []

    for item in selected:

        detailed.append(
            {
                "uri": item[
                    "uri"
                ],

                "protocol": protocol(
                    item["uri"]
                ),

                "endpoint": host_key(
                    item["uri"]
                ),

                "score": item[
                    "score"
                ],

                "real_successes": item[
                    "real_successes"
                ],

                "real_attempts": item[
                    "real_attempts"
                ],

                "real_success_rate":
                    item[
                        "real_success_rate"
                    ],

                "real_ping": item[
                    "real_ping"
                ],

                "real_avg": item[
                    "real_avg"
                ],

                "real_worst": item[
                    "real_worst"
                ],

                "tcp_success": item.get(
                    "tcp_success",
                    0,
                ),

                "tcp_attempts": item.get(
                    "tcp_attempts",
                    0,
                ),

                "tcp_ping": item.get(
                    "tcp_ping"
                ),
            }
        )

    (
        OUT
        / "servers.json"
    ).write_text(
        json.dumps(
            detailed,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # STATS
    # --------------------------------------------------------

    stats = {
        "project": "FreeForYoung",

        "version": 6,

        "sources": len(
            source_urls
        ),

        "raw_nodes": raw_count,

        "valid_unique_nodes":
            len(sane_nodes),

        "tcp_candidates":
            len(tcp_candidates),

        "real_tested":
            len(real_targets),

        "real_working":
            len(checked),

        "published":
            len(selected),

        "minimum_real_success":
            MIN_REAL_SUCCESS,

        "tcp_attempts":
            TCP_ATTEMPTS,

        "real_attempts":
            REAL_ATTEMPTS,

        "tcp_workers":
            TCP_WORKERS,

        "real_workers":
            REAL_WORKERS,

        "happ_ping_type":
            "proxy",

        "happ_check_url":
            "https://cp.cloudflare.com/generate_204",

        "generated_at":
            int(time.time()),

        "duration_seconds":
            round(
                time.time()
                - started,
                2,
            ),
    }

    (
        OUT
        / "stats.json"
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
        f"Raw nodes: {raw_count}"
    )

    log(
        f"Valid unique: "
        f"{len(sane_nodes)}"
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

        proto = protocol(
            item["uri"]
        ).upper()

        log(
            f"{index}. "

            f"score="
            f"{item['score']} | "

            f"ping="
            f"{item['real_ping']}ms | "

            f"real="
            f"{item['real_successes']}/"
            f"{item['real_attempts']} | "

            f"{proto} | "

            f"{host_key(item['uri'])}"
        )


if __name__ == "__main__":
    main()
