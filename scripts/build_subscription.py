#!/usr/bin/env python3

import base64
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
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

FETCH_TIMEOUT = 8
TCP_TIMEOUT = 2
MAX_PER_SOURCE = 1000
MAX_TOTAL_CHECK = 600
MAX_PUBLISHED = 100
WORKERS = 40


def fetch(url):
    request = Request(
        url,
        headers={
            "User-Agent": "FreeForYoung/1.0"
        },
    )

    with urlopen(request, timeout=FETCH_TIMEOUT) as response:
        raw = response.read()

    text = raw.decode("utf-8", "ignore")

    compact = re.sub(r"\s+", "", text)

    if len(compact) > 40 and re.fullmatch(
        r"[A-Za-z0-9+/=_-]+",
        compact
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
    result = []

    pattern = re.compile(
        r"(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>\"]+",
        re.IGNORECASE,
    )

    for line in text.splitlines():

        line = line.strip().strip("`")

        if not line:
            continue

        for match in pattern.finditer(line):

            uri = match.group(0).rstrip(
                "),;"
            )

            if uri.lower().startswith(SUPPORTED):
                result.append(uri)

                if len(result) >= MAX_PER_SOURCE:
                    return result

    return result


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


def ping(uri):
    target = endpoint(uri)

    if not target:
        return None

    host, port = target

    started = time.perf_counter()

    try:

        with socket.create_connection(
            (host, port),
            timeout=TCP_TIMEOUT,
        ):
            elapsed = (
                time.perf_counter()
                - started
            ) * 1000

            return round(elapsed, 1)

    except Exception:
        return None


def protocol_bonus(uri):

    protocol = uri.split(
        ":",
        1
    )[0].lower()

    return {
        "vless": 30,
        "trojan": 20,
        "hy2": 15,
        "hysteria2": 15,
        "vmess": 10,
        "ss": 5,
    }.get(protocol, 0)


def main():

    started = time.time()

    sources = []

    for line in SOURCES.read_text(
        encoding="utf-8"
    ).splitlines():

        line = line.strip()

        if (
            line
            and not line.startswith("#")
        ):
            sources.append(line)

    all_nodes = []

    source_stats = {}

    print(
        f"Sources: {len(sources)}"
    )

    # Download sources concurrently
    with ThreadPoolExecutor(
        max_workers=min(
            10,
            len(sources) or 1,
        )
    ) as executor:

        jobs = {
            executor.submit(
                fetch,
                source,
            ): source
            for source in sources
        }

        for future in as_completed(jobs):

            source = jobs[future]

            try:

                text = future.result()

                nodes = extract(text)

                source_stats[source] = {
                    "found": len(nodes)
                }

                all_nodes.extend(nodes)

                print(
                    f"[OK] {source}: "
                    f"{len(nodes)} nodes"
                )

            except Exception as error:

                source_stats[source] = {
                    "error": str(error)[:160]
                }

                print(
                    f"[ERROR] {source}: "
                    f"{error}"
                )

    # Deduplicate
    unique = list(
        dict.fromkeys(all_nodes)
    )

    print(
        f"Unique nodes: {len(unique)}"
    )

    # Limit checks
    candidates = unique[
        :MAX_TOTAL_CHECK
    ]

    reachable = []

    print(
        f"Checking {len(candidates)} "
        f"nodes using {WORKERS} workers..."
    )

    # Parallel TCP checking
    with ThreadPoolExecutor(
        max_workers=WORKERS
    ) as executor:

        jobs = {
            executor.submit(
                ping,
                uri,
            ): uri
            for uri in candidates
        }

        for future in as_completed(jobs):

            uri = jobs[future]

            try:
                latency = future.result()

            except Exception:
                latency = None

            if latency is not None:

                reachable.append(
                    (
                        latency,
                        protocol_bonus(uri),
                        uri,
                    )
                )

    # Fastest first
    reachable.sort(
        key=lambda item: (
            item[0],
            -item[1],
        )
    )

    selected = reachable[
        :MAX_PUBLISHED
    ]

    print(
        f"Reachable: {len(reachable)}"
    )

    print(
        f"Published: {len(selected)}"
    )

    # Happ subscription
    lines = [
        "#profile-title: FreeForYoung",
        "#announce: FreeForYoung - automatically updated public nodes",
        "#subscription-auto-update-enable: 1",
        "#subscription-auto-update-open-enable: 1",
        "#subscription-ping-onopen-enabled: 1",
        "#subscriptions-sort-type: ping",
        "#ping-result: time",
    ]

    lines.extend(
        uri
        for latency, bonus, uri
        in selected
    )

    (
        OUT / "subscription.txt"
    ).write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    # Diagnostic file
    diagnostic = []

    for latency, bonus, uri in selected:

        diagnostic.append(
            f"{latency} ms\t{uri}"
        )

    (
        OUT / "servers.txt"
    ).write_text(
        "\n".join(diagnostic)
        + (
            "\n"
            if diagnostic
            else ""
        ),
        encoding="utf-8",
    )

    stats = {
        "project": "FreeForYoung",
        "sources": len(sources),
        "raw_nodes": len(all_nodes),
        "unique_nodes": len(unique),
        "checked_nodes": len(candidates),
        "reachable_nodes": len(reachable),
        "published_nodes": len(selected),
        "generated_at": int(time.time()),
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
        ) + "\n",
        encoding="utf-8",
    )

    print()
    print(
        "================================"
    )
    print(
        "      FreeForYoung READY"
    )
    print(
        "================================"
    )

    print(
        json.dumps(
            stats,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
