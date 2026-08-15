#!/usr/bin/env python3

import base64
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from statistics import median
from urllib.parse import urlsplit
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

# =========================
# SETTINGS
# =========================

FETCH_TIMEOUT = 8
PING_TIMEOUT = 2
PING_ATTEMPTS = 3
WORKERS = 40

MAX_TOTAL_CHECK = 600
MAX_PUBLISHED = 100

# Не позволяем одному endpoint
# занять весь список.
MAX_SAME_HOST = 3

HISTORY_FILE = OUT / "history.json"
MAX_HISTORY = 12


# =========================
# FETCH SOURCES
# =========================

def fetch(url):
    request = Request(
        url,
        headers={
            "User-Agent": "FreeForYoung/3.0"
        },
    )

    with urlopen(
        request,
        timeout=FETCH_TIMEOUT
    ) as response:
        raw = response.read()

    text = raw.decode(
        "utf-8",
        "ignore"
    )

    # Некоторые источники отдают base64.
    compact = re.sub(
        r"\s+",
        "",
        text
    )

    if (
        len(compact) > 40
        and re.fullmatch(
            r"[A-Za-z0-9+/=_-]+",
            compact
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
                "ignore"
            )

            if "://" in decoded_text:
                text = decoded_text

        except Exception:
            pass

    return text


def extract(text):
    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>\"]+",
        re.IGNORECASE,
    )

    nodes = []

    for line in text.splitlines():

        line = line.strip().strip("`")

        if not line:
            continue

        for match in pattern.finditer(line):

            uri = match.group(0).rstrip(
                "),;"
            )

            if uri.lower().startswith(
                SUPPORTED
            ):
                nodes.append(uri)

                if len(nodes) >= MAX_TOTAL_CHECK:
                    return nodes

    return nodes


# =========================
# ENDPOINT
# =========================

def endpoint(uri):

    try:

        parsed = urlsplit(uri)

        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None

        return host, port

    except Exception:

        return None


# =========================
# TCP CHECK
# =========================

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
                1
            )

    except Exception:

        return None


def check_server(uri):

    results = []

    for _ in range(
        PING_ATTEMPTS
    ):

        latency = single_ping(uri)

        if latency is not None:
            results.append(latency)

    successful = len(results)

    success_rate = (
        successful
        / PING_ATTEMPTS
    )

    if results:

        avg_ping = round(
            sum(results)
            / len(results),
            1
        )

        median_ping = round(
            median(results),
            1
        )

        worst_ping = round(
            max(results),
            1
        )

    else:

        avg_ping = None
        median_ping = None
        worst_ping = None

    return {
        "uri": uri,
        "attempts": PING_ATTEMPTS,
        "successful": successful,
        "success_rate": success_rate,
        "avg_ping": avg_ping,
        "median_ping": median_ping,
        "worst_ping": worst_ping,
    }


# =========================
# HISTORY
# =========================

def load_history():

    if not HISTORY_FILE.exists():
        return {}

    try:

        return json.loads(
            HISTORY_FILE.read_text(
                encoding="utf-8"
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
    result
):

    uri = result["uri"]

    old = history.get(
        uri,
        {
            "runs": 0,
            "successes": 0,
            "failures": 0,
            "last_ping": None,
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

    # Не даём истории бесконечно расти.
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


# =========================
# PROTOCOL QUALITY
# =========================

def protocol_quality(uri):

    lower = uri.lower()

    # VLESS Reality TCP
    if (
        lower.startswith("vless://")
        and "security=reality" in lower
        and "type=tcp" in lower
    ):
        return 80

    # VLESS TLS TCP
    if (
        lower.startswith("vless://")
        and "security=tls" in lower
        and "type=tcp" in lower
    ):
        return 55

    # VLESS TLS WS
    if (
        lower.startswith("vless://")
        and "security=tls" in lower
        and "type=ws" in lower
    ):
        return 35

    # Trojan
    if lower.startswith(
        "trojan://"
    ):
        return 45

    # Hysteria
    if (
        lower.startswith("hy2://")
        or lower.startswith("hysteria2://")
    ):
        return 45

    # VMess
    if lower.startswith(
        "vmess://"
    ):
        return 20

    # Shadowsocks
    if lower.startswith(
        "ss://"
    ):
        return 15

    return 0


# =========================
# SMART SCORE
# =========================

def smart_score(
    result,
    history,
):

    uri = result["uri"]

    ping = result[
        "median_ping"
    ]

    success_rate = result[
        "success_rate"
    ]

    if (
        ping is None
        or success_rate <= 0
    ):
        return -999999

    # ---------------------
    # CURRENT STABILITY
    # ---------------------

    stability_score = (
        success_rate * 600
    )

    # ---------------------
    # PING
    # ---------------------

    if ping <= 20:
        ping_score = 450

    elif ping <= 40:
        ping_score = 400

    elif ping <= 60:
        ping_score = 350

    elif ping <= 100:
        ping_score = 280

    elif ping <= 150:
        ping_score = 200

    elif ping <= 250:
        ping_score = 100

    else:
        ping_score = 20

    ping_score += max(
        0,
        80 - ping / 5
    )

    # ---------------------
    # HISTORICAL STABILITY
    # ---------------------

    history_score = 0

    old = history.get(uri)

    if old:

        total = (
            old["successes"]
            + old["failures"]
        )

        if total > 0:

            historical_rate = (
                old["successes"]
                / total
            )

            history_score = (
                historical_rate * 300
            )

    # ---------------------
    # PROTOCOL
    # ---------------------

    protocol_score = (
        protocol_quality(uri)
    )

    # ---------------------
    # PING CONSISTENCY
    # ---------------------

    spread_penalty = 0

    worst = result[
        "worst_ping"
    ]

    if worst is not None:

        spread = (
            worst - ping
        )

        if spread > 150:
            spread_penalty = 100

        elif spread > 100:
            spread_penalty = 70

        elif spread > 50:
            spread_penalty = 40

        elif spread > 25:
            spread_penalty = 15

    return round(
        stability_score
        + ping_score
        + history_score
        + protocol_score
        - spread_penalty,
        2,
    )


# =========================
# GROUPING
# =========================

def host_key(uri):

    target = endpoint(uri)

    if not target:
        return uri

    host, port = target

    return f"{host}:{port}"


# =========================
# MAIN
# =========================

def main():

    started = time.time()

    history = load_history()

    # ---------------------
    # READ SOURCES
    # ---------------------

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

    print(
        f"Sources: {len(source_urls)}"
    )

    # ---------------------
    # DOWNLOAD
    # ---------------------

    all_nodes = []

    source_stats = {}

    with ThreadPoolExecutor(
        max_workers=min(
            10,
            max(
                1,
                len(source_urls)
            )
        )
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

            source = jobs[future]

            try:

                text = future.result()

                nodes = extract(text)

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

    # ---------------------
    # DEDUPLICATE
    # ---------------------

    unique_nodes = list(
        dict.fromkeys(
            all_nodes
        )
    )

    print(
        f"Unique nodes: "
        f"{len(unique_nodes)}"
    )

    candidates = unique_nodes[
        :MAX_TOTAL_CHECK
    ]

    # ---------------------
    # CHECK SERVERS
    # ---------------------

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

            uri = jobs[future]

            try:

                result = future.result()

            except Exception:

                result = {
                    "uri": uri,
                    "attempts": PING_ATTEMPTS,
                    "successful": 0,
                    "success_rate": 0,
                    "avg_ping": None,
                    "median_ping": None,
                    "worst_ping": None,
                }

            history = update_history(
                history,
                result
            )

            if result[
                "successful"
            ] > 0:

                result["score"] = (
                    smart_score(
                        result,
                        history
                    )
                )

                checked.append(
                    result
                )

    # ---------------------
    # SORT
    # ---------------------

    ranked = sorted(
        checked,
        key=lambda item: (
            item["score"],
            item["success_rate"],
            -(
                item["median_ping"]
                or 999999
            ),
        ),
        reverse=True,
    )

    # ---------------------
    # DIVERSIFIED SELECTION
    # ---------------------

    selected = []

    host_counts = {}

    for item in ranked:

        host = host_key(
            item["uri"]
        )

        current = host_counts.get(
            host,
            0
        )

        if current >= MAX_SAME_HOST:
            continue

        selected.append(
            item
        )

        host_counts[host] = (
            current + 1
        )

        if len(selected) >= MAX_PUBLISHED:
            break

    # Если разнообразный список
    # получился меньше лимита,
    # добираем оставшиеся.
    if len(selected) < MAX_PUBLISHED:

        selected_uris = {
            item["uri"]
            for item in selected
        }

        for item in ranked:

            if item["uri"] in selected_uris:
                continue

            selected.append(
                item
            )

            if len(selected) >= MAX_PUBLISHED:
                break

    # ---------------------
    # SAVE HISTORY
    # ---------------------

    save_history(
        history
    )

    # ---------------------
    # SUBSCRIPTION
    # ---------------------

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
        "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )

    # ---------------------
    # SERVERS REPORT
    # ---------------------

    diagnostic = []

    for index, item in enumerate(
        selected,
        start=1
    ):

        diagnostic.append(
            (
                f"{index}. "
                f"score={item['score']} | "
                f"ping={item['median_ping']}ms | "
                f"success="
                f"{item['successful']}/"
                f"{item['attempts']} | "
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

    # ---------------------
    # STATS
    # ---------------------

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

    # ---------------------
    # CONSOLE
    # ---------------------

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
        selected[:15],
        start=1
    ):

        print(
            f"{index}. "
            f"{item['median_ping']}ms | "
            f"{item['successful']}/"
            f"{item['attempts']} | "
            f"score={item['score']}"
        )


if __name__ == "__main__":
    main()
