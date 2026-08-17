#!/usr/bin/env python3
import base64, ipaddress, json, re, socket, ssl, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources_sg.txt"
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

FETCH_TIMEOUT = 12
TCP_TIMEOUT = 2.5
WORKERS = 80
MAX_PER_SOURCE = 1000
MAX_TOTAL = 2500
PUBLISH = 250
COUNTRY = "SG"

UA = "Mozilla/5.0 FreeForYoung-SG"

def fetch(url):
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=FETCH_TIMEOUT) as r:
        return r.read().decode("utf-8", "ignore")

def b64decode_maybe(s):
    s = re.sub(r"\s+", "", s or "")
    if len(s) < 24 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    try:
        raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
        text = raw.decode("utf-8", "ignore")
        return text if "://" in text else None
    except Exception:
        return None

def extract(text):
    dec = b64decode_maybe(text)
    if dec:
        text = dec
    pat = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s<>'\"`]+", re.I)
    out = []
    for m in pat.finditer(text):
        u = m.group(0).rstrip("),;")
        out.append(u)
        if len(out) >= MAX_PER_SOURCE:
            break
    return out

def endpoint(uri):
    from urllib.parse import urlsplit
    try:
        p = urlsplit(uri)
        if not p.hostname:
            return None
        port = p.port
        if not port:
            port = 443
        return p.hostname, port
    except Exception:
        return None

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        try:
            return str(ipaddress.ip_address(host))
        except Exception:
            return None

def geo_batch(ips):
    # ip-api allows up to 100 addresses per batch request.
    out = {}
    ips = list(dict.fromkeys(ips))
    for i in range(0, len(ips), 100):
        chunk = ips[i:i+100]
        payload = json.dumps([{"query": x, "fields": "query,countryCode,status"} for x in chunk]).encode()
        req = Request(
            "http://ip-api.com/batch",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": UA},
            method="POST",
        )
        try:
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode())
            for row in data:
                if row.get("status") == "success":
                    out[row["query"]] = row.get("countryCode")
        except Exception:
            pass
    return out

def tcp(uri):
    ep = endpoint(uri)
    if not ep:
        return None
    host, port = ep
    ip = resolve(host)
    if not ip:
        return None
    t = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=TCP_TIMEOUT):
            return round((time.perf_counter() - t) * 1000, 1)
    except Exception:
        return None

def main():
    raw = []
    for line in SOURCES.read_text(encoding="utf-8").splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        try:
            raw.extend(extract(fetch(url)))
        except Exception as e:
            print("SOURCE_FAIL", url, e)

    # dedupe
    raw = list(dict.fromkeys(raw))[:MAX_TOTAL]
    hosts = {}
    for u in raw:
        ep = endpoint(u)
        if ep:
            hosts[u] = resolve(ep[0])

    geo = geo_batch([x for x in hosts.values() if x])
    sg = [u for u, ip in hosts.items() if ip and geo.get(ip) == COUNTRY]
    print("RAW", len(raw), "SG", len(sg))

    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(tcp, u): u for u in sg}
        for fut in as_completed(futs):
            u = futs[fut]
            try:
                ping = fut.result()
            except Exception:
                ping = None
            if ping is not None:
                results.append((ping, u))

    results.sort(key=lambda x: x[0])
    results = results[:PUBLISH]
    uris = [u for _, u in results]

    # Happ-friendly plain URI list
    (OUT / "singapore.txt").write_text(
        "#profile-title: FreeForYoung SG\n"
        "#announce: Singapore-only public nodes, sorted by TCP latency\n"
        + "\n".join(uris) + ("\n" if uris else ""),
        encoding="utf-8",
    )

    # Base64 subscription for clients like v2rayN
    b64 = base64.b64encode("\n".join(uris).encode()).decode()
    (OUT / "singapore-base64.txt").write_text(b64 + "\n", encoding="utf-8")

    stats = {
        "raw": len(raw),
        "singapore_geoip": len(sg),
        "tcp_alive": len(results),
        "published": len(uris),
        "generated_at": int(time.time()),
    }
    (OUT / "singapore-stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
