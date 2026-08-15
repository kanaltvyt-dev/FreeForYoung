#!/usr/bin/env python3

import base64
import hashlib
import json
import re
import socket
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


# ============================================================
# SETTINGS
# ============================================================

FETCH_TIMEOUT = 8

PING_TIMEOUT = 2
PING_ATTEMPTS = 3

WORKERS = 40

MAX_TOTAL_CHECK = 600
MAX_PUBLISHED = 100

# Один и тот же host:port
# не может занять больше этого количества мест.
MAX_SAME_HOST = 2

# Очень похожие конфигурации
# тоже ограничиваем.
MAX_SAME_FINGERPRINT = 2

HISTORY_FILE = OUT / "history.json"

MAX_HISTORY = 12


# ============================================================
# FETCH
# ============================================================

def fetch(url):

    request = Request(
        url,
        headers={
            "User-Agent": "FreeForYoung/4.0"
        },
    )

    with urlopen(
        request,
        timeout=FETCH_TIMEOUT,
    ) as response:

        raw = response.read()

    text = raw.decode(
        "utf-8",
        "ignore",
    )

    # Некоторые источники публикуют
    # base64 вместо обычного текста.
    compact = re.sub(
        r"\s+",
        "",
        text,
    )

    if (
        len(compact) > 40
        and re.fullmatch(
            r"[A-Za-z0-9+/=_-]+",
            compact,
        )
    ):

        try:

            decoded = base64.b64decode(
                compact
                + "=" * (
                    -len(compact) % 4
                ),
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


# ============================================================
# EXTRACT
# ============================================================

def extract(text):

    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>\"']+",
        re.IGNORECASE,
    )

    nodes = []

    for line in text.splitlines():

        line = line.strip().strip("`")

        if not line:
            continue

        for match in pattern.finditer(line):

            uri = match.group(0).rstrip(
                "),;]"
            )

            if uri.lower().startswith(
                SUPPORTED
            ):

                nodes.append(uri)

                if len(nodes) >= MAX_TOTAL_CHECK:
                    return nodes

    return nodes


# ============================================================
# ENDPOINT
# ============================================================

def endpoint(uri):

    try:

        parsed = urlsplit(uri)

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None

        return host.lower(), port

    except Exception:

        return None


# ============================================================
# CONFIG FINGERPRINT
# ============================================================

def config_fingerprint(uri):

    """
    Группирует конфиги, которые очень похожи.

    Например несколько URI с одинаковым:
      - host
      - port
      - SNI
      - path
      - protocol

    Это помогает не заполнять TOP
    десятками почти одинаковых конфигураций.
    """

    try:

        parsed = urlsplit(uri)

        protocol = (
            parsed.scheme
            .lower()
        )

        host = (
            parsed.hostname
            or ""
        ).lower()

        port = (
            parsed.port
            or ""
        )

        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        sni = (
            query.get(
                "sni",
                [""],
            )[0]
            or query.get(
                "host",
                [""],
            )[0]
        )

        path = (
            query.get(
                "path",
                [""],
            )[0]
        )

        sni = unquote(
            str(sni)
        ).lower()

        path = unquote(
            str(path)
        )

        raw = (
            f"{protocol}|"
            f"{host}|"
            f"{port}|"
            f"{sni}|"
            f"{path}"
        )

        return hashlib.sha1(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()

    except Exception:

        return hashlib.sha1(
            uri.encode(
                "utf-8"
            )
        ).hexdigest()


# ============================================================
# TCP CHECK
# ============================================================

def single_ping(uri):

    target = endpoint(uri)

    if not target:
        return None

    host, port = target

    started = time.perf_counter()

    try:

        with socket.create_connection(
            (host, port),
            timeout=PING_TIMEOUT,
        ):

            elapsed = (
                time.perf_counter()
                - started
            ) * 1000

            return round(
                elapsed,
                1,
            )

    except Exception:

        return None


def check_server(uri):

    results = []

    for _ in range(
        PING_ATTEMPTS
    ):

        latency = single_ping(
            uri
        )

        if latency is not None:
            results.append(
                latency
            )

    successful = len(
        results
    )

    success_rate = (
        successful
        / PING_ATTEMPTS
    )

    if results:

        avg_ping = round(
            sum(results)
            / len(results),
            1,
        )

        median_ping = round(
            median(results),
            1,
        )

        worst_ping = round(
            max(results),
            1,
        )

        best_ping = round(
            min(results),
            1,
        )

    else:

        avg_ping = None
        median_ping = None
        worst_ping = None
        best_ping = None

    return {
        "uri": uri,
        "attempts": PING_ATTEMPTS,
        "successful": successful,
        "success_rate": success_rate,
        "avg_ping": avg_ping,
        "median_ping": median_ping,
        "worst_ping": worst_ping,
        "best_ping": best_ping,
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
            "successes": 0,
            "failures": 0,
            "last_ping": None,
            "last_success": False,
        },
    )

    old["runs"] += 1

    old["successes"] += (
        result["successful"]
    )

    old["failures"] += (
        result["attempts"]
        - result["successful"]
    )

    old["last_ping"] = (
        result["median_ping"]
    )

    old["last_success"] = (
        result["successful"] > 0
    )

    # Ограничиваем размер исторической
    # статистики примерно последними 12 запусками.
    if old["runs"] > MAX_HISTORY:

        factor = (
            MAX_HISTORY
            / old["runs"]
        )

        old["successes"] = round(
            old["successes"]
            * factor
        )

        old["failures"] = round(
            old["failures"]
            * factor
        )

        old["runs"] = MAX_HISTORY

    history[uri] = old

    return history


# ============================================================
# PROTOCOL
# ============================================================

def protocol_name(uri):

    lower = uri.lower()

    if lower.startswith(
        "vless://"
    ):
        return "VLESS"

    if lower.startswith(
        "vmess://"
    ):
        return "VMESS"

    if lower.startswith(
        "trojan://"
    ):
        return "TROJAN"

    if (
        lower.startswith("hy2://")
        or lower.startswith("hysteria2://")
    ):
        return "HYSTERIA2"

    if lower.startswith(
        "ss://"
    ):
        return "SS"

    return "OTHER"


def protocol_quality(uri):

    """
    Небольшой бонус протоколу.

    Важно:
    протокол НЕ может сам по себе
    поднять плохой сервер выше стабильного.
    """

    lower = uri.lower()

    if (
        lower.startswith("vless://")
        and "security=reality" in lower
        and "type=tcp" in lower
    ):
        return 35

    if (
        lower.startswith("vless://")
        and "security=tls" in lower
        and "type=tcp" in lower
    ):
        return 25

    if lower.startswith(
        "trojan://"
    ):
        return 20

    if (
        lower.startswith("hy2://")
        or lower.startswith("hysteria2://")
    ):
        return 25

    if (
        lower.startswith("vless://")
        and "security=tls" in lower
    ):
        return 15

    if lower.startswith(
        "vmess://"
    ):
        return 10

    if lower.startswith(
        "ss://"
    ):
        return 5

    return 0


# ============================================================
# PING SCORE
# ============================================================

def ping_score(ping):

    if ping is None:
        return 0

    if ping <= 10:
        return 450

    if ping <= 20:
        return 430

    if ping <= 30:
        return 410

    if ping <= 40:
        return 390

    if ping <= 60:
        return 360

    if ping <= 80:
        return 320

    if ping <= 100:
        return 280

    if ping <= 150:
        return 220

    if ping <= 200:
        return 150

    if ping <= 300:
        return 80

    return 20


# ============================================================
# STABILITY SCORE
# ============================================================

def stability_score(
    result
):

    rate = result[
        "success_rate"
    ]

    # 3/3 -> 600
    # 2/3 -> 400
    # 1/3 -> 200
    return rate * 600


# ============================================================
# HISTORICAL SCORE
# ============================================================

def historical_score(
    uri,
    history,
):

    old = history.get(
        uri
    )

    if not old:
        return 0

    successes = old.get(
        "successes",
        0,
    )

    failures = old.get(
        "failures",
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

    return rate * 250


# ============================================================
# CONSISTENCY
# ============================================================

def consistency_penalty(
    result
):

    median_ping = result[
        "median_ping"
    ]

    worst_ping = result[
        "worst_ping"
    ]

    best_ping = result[
        "best_ping"
    ]

    if (
        median_ping is None
        or worst_ping is None
        or best_ping is None
    ):
        return 0

    spread = (
        worst_ping
        - best_ping
    )

    if spread <= 5:
        return 0

    if spread <= 15:
        return 5

    if spread <= 30:
        return 15

    if spread <= 60:
        return 30

    if spread <= 100:
        return 60

    return 100


# ============================================================
# SMART SCORE
# ============================================================

def smart_score(
    result,
    history,
):

    ping = result[
        "median_ping"
    ]

    if ping is None:
        return -999999

    current = (
        stability_score(
            result
        )
    )

    latency = (
        ping_score(
            ping
        )
    )

    historical = (
        historical_score(
            result["uri"],
            history,
        )
    )

    protocol = (
        protocol_quality(
            result["uri"]
        )
    )

    penalty = (
        consistency_penalty(
            result
        )
    )

    score = (
        current
        + latency
        + historical
        + protocol
        - penalty
    )

    return round(
        score,
        2,
    )


# ============================================================
# DEDUPLICATION
# ============================================================

def host_key(uri):

    target = endpoint(
        uri
    )

    if not target:
        return uri

    host, port = target

    return (
        f"{host}:{port}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    started = time.time()

    history = load_history()

    # ========================================================
    # READ SOURCES
    # ========================================================

    source_urls = []

    if not SOURCES.exists():

        raise FileNotFoundError(
            "sources.txt not found"
        )

    for line in SOURCES.read_text(
        encoding="utf-8",
    ).splitlines():

        line = line.strip()

        if (
            line
            and not line.startswith("#")
        ):

            source_urls.append(
                line
            )

    print(
        f"Sources: {len(source_urls)}"
    )

    # ========================================================
    # DOWNLOAD SOURCES
    # ========================================================

    all_nodes = []

    source_stats = {}

    source_workers = min(
        10,
        max(
            1,
            len(source_urls),
        ),
    )

    with ThreadPoolExecutor(
        max_workers=source_workers
    ) as executor:

        jobs = {
            executor.submit(
                fetch,
                url,
            ): url
            for url in source_urls
        }

        for future in as_completed(
            jobs
        ):

            source = jobs[
                future
            ]

            try:

                text = future.result()

                nodes = extract(
                    text
                )

                source_stats[
                    source
                ] = {
                    "found": len(nodes)
                }

                all_nodes.extend(
                    nodes
                )

                print(
                    f"[SOURCE OK] "
                    f"{len(nodes)} nodes"
                )

            except Exception as error:

                source_stats[
                    source
                ] = {
                    "error": str(error)[
                        :200
                    ]
                }

                print(
                    f"[SOURCE ERROR] "
                    f"{source}: "
                    f"{error}"
                )

    # ========================================================
    # UNIQUE
    # ========================================================

    unique_nodes = list(
        dict.fromkeys(
            all_nodes
        )
    )

    print(
        f"Unique nodes: "
        f"{len(unique_nodes)}"
    )

    # ========================================================
    # PRE-CHECK DIVERSITY
    # ========================================================

    # Сначала стараемся получить разные
    # endpoint'ы, чтобы 600 проверок не
    # ушли на одну и ту же группу.
    candidates = []

    candidate_hosts = set()
    candidate_fingerprints = set()

    # Первый проход:
    # уникальные host + fingerprint.
    for uri in unique_nodes:

        host = host_key(
            uri
        )

        fingerprint = (
            config_fingerprint(
                uri
            )
        )

        if host in candidate_hosts:
            continue

        if fingerprint in candidate_fingerprints:
            continue

        candidates.append(
            uri
        )

        candidate_hosts.add(
            host
        )

        candidate_fingerprints.add(
            fingerprint
        )

        if len(candidates) >= MAX_TOTAL_CHECK:
            break

    # Если не набрали лимит —
    # добираем остальные.
    if len(candidates) < MAX_TOTAL_CHECK:

        selected_set = set(
            candidates
        )

        for uri in unique_nodes:

            if uri in selected_set:
                continue

            candidates.append(
                uri
            )

            if len(candidates) >= MAX_TOTAL_CHECK:
                break

    print(
        f"Candidates: "
        f"{len(candidates)}"
    )

    # ========================================================
    # CHECK
    # ========================================================

    print(
        f"Checking "
        f"{len(candidates)} nodes"
    )

    print(
        f"{PING_ATTEMPTS} attempts "
        f"per server / "
        f"{WORKERS} workers"
    )

    checked = []

    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                check_server,
                uri,
            ): uri
            for uri in candidates
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
                    "attempts": PING_ATTEMPTS,
                    "successful": 0,
                    "success_rate": 0,
                    "avg_ping": None,
                    "median_ping": None,
                    "worst_ping": None,
                    "best_ping": None,
                }

            history = update_history(
                history,
                result,
            )

            if result[
                "successful"
            ] > 0:

                result[
                    "fingerprint"
                ] = config_fingerprint(
                    uri
                )

                result[
                    "host_key"
                ] = host_key(
                    uri
                )

                result[
                    "protocol"
                ] = protocol_name(
                    uri
                )

                result[
                    "score"
                ] = smart_score(
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
        key=lambda item: (
            item["score"],
            item["success_rate"],
            -(
                item["median_ping"]
                or 999999
            ),
            -(
                item["worst_ping"]
                or 999999
            ),
        ),
        reverse=True,
    )

    # ========================================================
    # DIVERSIFIED TOP
    # ========================================================

    selected = []

    host_counts = {}

    fingerprint_counts = {}

    for item in ranked:

        host = item[
            "host_key"
        ]

        fingerprint = item[
            "fingerprint"
        ]

        if (
            host_counts.get(
                host,
                0,
            )
            >= MAX_SAME_HOST
        ):
            continue

        if (
            fingerprint_counts.get(
                fingerprint,
                0,
            )
            >= MAX_SAME_FINGERPRINT
        ):
            continue

        selected.append(
            item
        )

        host_counts[
            host
        ] = (
            host_counts.get(
                host,
                0,
            )
            + 1
        )

        fingerprint_counts[
            fingerprint
        ] = (
            fingerprint_counts.get(
                fingerprint,
                0,
            )
            + 1
        )

        if len(selected) >= MAX_PUBLISHED:
            break

    # ========================================================
    # FALLBACK
    # ========================================================

    if len(selected) < MAX_PUBLISHED:

        selected_uris = {
            item["uri"]
            for item in selected
        }

        for item in ranked:

            if (
                item["uri"]
                in selected_uris
            ):
                continue

            selected.append(
                item
            )

            if len(selected) >= MAX_PUBLISHED:
                break

    # ========================================================
    # SAVE HISTORY
    # ========================================================

    save_history(
        history
    )

    # ========================================================
    # SUBSCRIPTION
    # ========================================================

    lines = [
        "#profile-title: FreeForYoung",
        "#announce: FreeForYoung - stable public nodes",
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
        "\n".join(
            lines
        )
        + "\n",
        encoding="utf-8",
    )

    # ========================================================
    # REPORT
    # ========================================================

    diagnostic = []

    for index, item in enumerate(
        selected,
        start=1,
    ):

        diagnostic.append(
            (
                f"{index}. "
                f"score={item['score']} | "
                f"ping={item['median_ping']}ms | "
                f"success="
                f"{item['successful']}/"
                f"{item['attempts']} | "
                f"protocol="
                f"{item['protocol']} | "
                f"uri={item['uri']}"
            )
        )

    (
        OUT / "servers.txt"
    ).write_text(
        "\n".join(
            diagnostic
        )
        + (
            "\n"
            if diagnostic
            else ""
        ),
        encoding="utf-8",
    )

    # ========================================================
    # STATS
    # ========================================================

    stats = {
        "project": "FreeForYoung",
        "sources": len(
            source_urls
        ),
        "raw_nodes": len(
            all_nodes
        ),
        "unique_nodes": len(
            unique_nodes
        ),
        "candidates": len(
            candidates
        ),
        "checked_nodes": len(
            candidates
        ),
        "working_nodes": len(
            checked
        ),
        "published_nodes": len(
            selected
        ),
        "ping_attempts": PING_ATTEMPTS,
        "workers": WORKERS,
        "max_same_host": MAX_SAME_HOST,
        "max_same_fingerprint": (
            MAX_SAME_FINGERPRINT
        ),
        "generated_at": int(
            time.time()
        ),
        "duration_seconds": round(
            time.time() - started,
            2,
        ),
        "source_stats": source_stats,
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

    print()
    print(
        "================================"
    )
    print(
        "       FreeForYoung READY"
    )
    print(
        "================================"
    )

    print(
        f"Working: "
        f"{len(checked)}"
    )

    print(
        f"Published: "
        f"{len(selected)}"
    )

    print(
        f"Duration: "
        f"{round(time.time() - started, 2)}s"
    )

    print()
    print(
        "TOP SERVERS:"
    )

    for index, item in enumerate(
        selected[:20],
        start=1,
    ):

        print(
            f"{index}. "
            f"{item['protocol']} | "
            f"{item['median_ping']}ms | "
            f"{item['successful']}/"
            f"{item['attempts']} | "
            f"score={item['score']}"
        )


if __name__ == "__main__":
    main()
