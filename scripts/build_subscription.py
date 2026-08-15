#!/usr/bin/env python3
import base64,json,re,socket,time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,urlopen

ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'output'; OUT.mkdir(exist_ok=True)
SUPPORTED=('vless://','vmess://','trojan://','ss://','hy2://','hysteria2://')
TIMEOUT=8; MAX_PER_SOURCE=5000; MAX_TOTAL=300

def fetch(url):
    req=Request(url,headers={'User-Agent':'FreeForYoung/1.0'})
    with urlopen(req,timeout=TIMEOUT) as r: raw=r.read()
    text=raw.decode('utf-8','ignore')
    compact=re.sub(r'\s+','',text)
    if len(compact)>40 and re.fullmatch(r'[A-Za-z0-9+/=_-]+',compact):
        try:
            d=base64.b64decode(compact+'='*(-len(compact)%4),validate=False).decode('utf-8','ignore')
            if '://' in d: text=d
        except Exception: pass
    return text

def extract(text):
    out=[]
    for m in re.finditer(r'(?:vless|vmess|trojan|ss|hy2|hysteria2)://[^\s<>"`]+',text,re.I):
        u=m.group(0).rstrip('),;')
        if u.lower().startswith(SUPPORTED): out.append(u)
        if len(out)>=MAX_PER_SOURCE: break
    return out

def endpoint(u):
    try:
        p=urlsplit(u); return p.hostname,p.port
    except Exception: return None

def ping(u):
    ep=endpoint(u)
    if not ep or not ep[0] or not ep[1]: return None
    t=time.perf_counter()
    try:
        with socket.create_connection(ep,timeout=3): return round((time.perf_counter()-t)*1000,1)
    except Exception: return None

def main():
    sources=[x.strip() for x in (ROOT/'sources.txt').read_text().splitlines() if x.strip() and not x.startswith('#')]
    all_nodes=[]; stats={}
    for src in sources:
        try:
            n=extract(fetch(src)); all_nodes+=n; stats[src]={'found':len(n)}
        except Exception as e: stats[src]={'error':str(e)[:160]}
    unique=list(dict.fromkeys(all_nodes)); checked=[]
    for u in unique:
        ms=ping(u)
        if ms is not None: checked.append((ms,u))
    checked.sort(key=lambda x:x[0]); selected=checked[:MAX_TOTAL]
    header=['#profile-title: FreeForYoung','#announce: FreeForYoung — automatically refreshed public nodes','#subscription-auto-update-enable: 1','#subscription-auto-update-open-enable: 1','#subscription-ping-onopen-enabled: 1','#subscriptions-sort-type: ping','#ping-result: time']
    (OUT/'subscription.txt').write_text('\n'.join(header+[u for _,u in selected])+'\n')
    (OUT/'servers.txt').write_text('\n'.join(f'{ms} ms\t{u}' for ms,u in selected)+'\n')
    result={'sources':len(sources),'raw_nodes':len(all_nodes),'unique_nodes':len(unique),'reachable_nodes':len(checked),'published_nodes':len(selected),'generated_at':int(time.time()),'source_stats':stats}
    (OUT/'stats.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n'); print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
