#!/usr/bin/env python3
import base64,json,re,socket,time
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[1]
SOURCES=ROOT/"sources_sg.txt"
OUT=ROOT/"output"; OUT.mkdir(exist_ok=True)

FETCH_TIMEOUT=12
TCP_TIMEOUT=2.5
TCP_ATTEMPTS=2
WORKERS=80
MAX_PER_SOURCE=1200
MAX_TOTAL=4000
MAX_PUBLISHED=250
UA="FreeForYoung-SG/3.0"

# CDN/proxy/edge networks excluded because their IP location is not proof
# that the real VPN server is physically in Singapore.
EXCLUDED=("cloudflare","fastly","akamai","cloudfront","vercel","netlify",
          "gcore","bunny","stackpath","imperva","incapsula","cdn77",
          "limelight","edgecast")

URI_RE=re.compile(r'(?:vless|vmess|trojan|ss)://[^\s<>\'"`]+',re.I)

def fetch(url):
    r=urlopen(Request(url,headers={"User-Agent":UA}),timeout=FETCH_TIMEOUT)
    return r.read().decode("utf-8","ignore")

def b64(text):
    s=re.sub(r"\s+","",text)
    if len(s)<24 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+",s): return None
    try:
        d=base64.urlsafe_b64decode(s+"="*(-len(s)%4)).decode("utf-8","ignore")
        return d if "://" in d else None
    except Exception:
        return None

def extract(text):
    d=b64(text)
    if d: text=d
    out=[]; seen=set()
    for m in URI_RE.finditer(text):
        u=m.group(0).rstrip("),;")
        if u not in seen:
            seen.add(u); out.append(u)
        if len(out)>=MAX_PER_SOURCE: break
    return out

def ep(uri):
    try:
        p=urlsplit(uri)
        return (p.hostname,p.port or 443) if p.hostname else None
    except Exception: return None

def resolve(host):
    try: return socket.gethostbyname(host)
    except Exception: return None

def geo_batch(ips):
    out={}
    for i in range(0,len(ips),100):
        chunk=ips[i:i+100]
        body=json.dumps([{"query":x,"fields":"query,status,countryCode,city,isp,org,as"} for x in chunk]).encode()
        try:
            r=urlopen(Request(
                "http://ip-api.com/batch",data=body,
                headers={"Content-Type":"application/json","User-Agent":UA},
                method="POST"),timeout=20)
            rows=json.loads(r.read().decode("utf-8"))
            for row in rows:
                if row.get("status")=="success": out[row["query"]]=row
        except Exception as e:
            print("GEO FAIL",e)
    return out

def excluded(info):
    s=" ".join(str(info.get(k,"")) for k in ("isp","org","as")).lower()
    return any(x in s for x in EXCLUDED)

def tcp(uri):
    x=ep(uri)
    if not x: return None
    host,port=x; ip=resolve(host)
    if not ip: return None
    vals=[]
    for _ in range(TCP_ATTEMPTS):
        t=time.perf_counter()
        try:
            with socket.create_connection((ip,port),timeout=TCP_TIMEOUT):
                vals.append(round((time.perf_counter()-t)*1000,1))
        except Exception: pass
    return sorted(vals)[len(vals)//2] if vals else None

def main():
    nodes=[]
    for line in SOURCES.read_text(encoding="utf-8").splitlines():
        url=line.strip()
        if not url or url.startswith("#"): continue
        try:
            got=extract(fetch(url)); print("SOURCE",url,"->",len(got)); nodes.extend(got)
        except Exception as e:
            print("SOURCE FAIL",url,e)

    nodes=list(dict.fromkeys(nodes))[:MAX_TOTAL]
    node_ip={}
    for u in nodes:
        x=ep(u)
        if x:
            ip=resolve(x[0])
            if ip: node_ip[u]=ip

    geo=geo_batch(list(dict.fromkeys(node_ip.values())))
    sg=[]
    for u,ip in node_ip.items():
        g=geo.get(ip)
        if not g: continue
        if str(g.get("countryCode","")).upper()!="SG": continue
        if excluded(g): continue
        sg.append({"uri":u,"ip":ip,"city":g.get("city"),
                   "isp":g.get("isp"),"org":g.get("org"),"as":g.get("as")})

    print("REAL SG CANDIDATES AFTER GEO+CDN FILTER:",len(sg))

    alive=[]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        fs={pool.submit(tcp,x["uri"]):x for x in sg}
        for f in as_completed(fs):
            x=fs[f]
            try: p=f.result()
            except Exception: p=None
            if p is not None:
                x["tcp_ping_ms"]=p; alive.append(x)

    alive.sort(key=lambda x:(x["tcp_ping_ms"],0 if (ep(x["uri"]) or ("",0))[1]==443 else 1))

    used={}; pub=[]
    for x in alive:
        if used.get(x["ip"],0)>=2: continue
        used[x["ip"]]=used.get(x["ip"],0)+1
        pub.append(x)
        if len(pub)>=MAX_PUBLISHED: break

    uris=[x["uri"] for x in pub]
    header="#profile-title: FreeForYoung Singapore Strict\n#announce: GeoIP SG + CDN filtered + TCP checked\n#subscriptions-sort-type: ping\n#ping-type: proxy\n#check-url-via-proxy: https://cp.cloudflare.com/generate_204\n#ping-result: time\n"
    (OUT/"singapore.txt").write_text(header+"\n".join(uris)+"\n",encoding="utf-8")
    (OUT/"singapore-base64.txt").write_text(base64.b64encode("\n".join(uris).encode()).decode()+"\n",encoding="utf-8")
    stats={"generated_at":int(time.time()),"raw":len(nodes),"sg_after_filter":len(sg),"tcp_alive":len(alive),"published":len(pub)}
    (OUT/"singapore-stats.json").write_text(json.dumps({"stats":stats,"servers":pub},indent=2,ensure_ascii=False),encoding="utf-8")
    print(json.dumps(stats,indent=2))

if __name__=="__main__": main()
