import re, requests, urllib.parse, ipaddress, socket, bisect
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed

BLOCK_CC={"RU","IR","CN","BY","KP","SY","CU","VE","SD","IQ","LY","YE","MM","AF","RS"}
BLOCK_ASN=set()
TRASH_DOMAINS={"gogocs.xyz","kukuss.top","wagahaha.xyz","workers.dev","pages.dev","railway.app"}
IR_WORDS={"parsashonam","ebrasha","mohsen","kian","sarina","nika","jadi","freeiran","vip_security"}
BLOCK_RE=re.compile(r"(🇷🇺|🇮🇷|🇨🇳|🇧🇾|🇰🇵|\.ru\b|\.ir\b|\.cn\b|yandex|vk\.com|mail\.ru|ok\.ru)", re.I)
US_RE=re.compile(r"(🇺🇸|\[US\]|\bUS\b|United States)",re.I)

reader_c=geoip2.database.Reader("GeoLite2-Country.mmdb")
reader_a=geoip2.database.Reader("GeoLite2-ASN.mmdb")

SOURCES=[1,3,4,5,6,7,9,10,12,14,15,16,17,18,19,20,21,22,23,24,25,26]
BASE="https://raw.githubusercontent.com/DarkRoyalty/shnajder-vpn-configs/refs/heads/main/githubmirror/{}.txt"

def load_zone(url):
    nets=[]
    try:
        for l in requests.get(url,timeout=30).text.splitlines():
            try: nets.append(ipaddress.ip_network(l.strip()))
            except: pass
    except: pass
    iv=sorted([(int(n.network_address),int(n.broadcast_address)) for n in nets if n.version==4])
    return iv, [s for s,_ in iv]
RU_IV,RU_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/ru.zone")
IR_IV,IR_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/ir.zone")
CN_IV,CN_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/cn.zone")

def in_zone(ip,IV,S):
    try:
        n=int(ipaddress.ip_address(ip.strip("[]")))
        i=bisect.bisect_right(S,n)-1
        return i>=0 and n<=IV[i][1]
    except: return False
def get_cc(ip):
    try: return reader_c.country(ip).country.iso_code
    except: return None
def get_asn(ip):
    try: return reader_a.asn(ip).autonomous_system_number
    except: return None
def is_alive(host, port):
    try:
        ip = host.strip("[]")
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and ":" not in ip:
            ip = socket.gethostbyname(ip)
        with socket.create_connection((ip, port), timeout=3):
            return True
    except: return False

pool=[]; uniq=set(); total=0
for src in SOURCES:
    try: txt=requests.get(BASE.format(src),timeout=60).text.splitlines()
    except: txt=[]
    total+=len(txt)
    for l in txt:
        if not (l.startswith("vless://") or l.startswith("trojan://")): continue
        try:
            h=l.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
        except: continue
        if h and not re.match(r"^\d+\.\d+\.\d+\.\d+$",h) and ":" not in h: uniq.add(h)
        pool.append((l,h))
pool=list({l:(l,h) for l,h in pool}.values())
cc_map={}; asn_map={}
def resolve(d):
    try:
        ip=socket.gethostbyname(d)
        return d, get_cc(ip), get_asn(ip)
    except: return d, None, None
with ThreadPoolExecutor(max_workers=100) as ex:
    for d,cc,asn in ex.map(resolve, uniq):
        cc_map[d]=cc; asn_map[d]=asn

candidates=[]; blocked=[]; blocked_ru=[]
for line,h in pool:
    low=urllib.parse.unquote(line).lower()
    if any(w in low for w in IR_WORDS): continue
    if BLOCK_RE.search(low): continue
    if any(d in low for d in TRASH_DOMAINS): continue
    try:
        hp=line.split("@",1)[1].split("?")[0].split("/")[0]
        port=int(hp.split(":")[1]) if ":" in hp else 443
        qs=urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
        sec=qs.get("security",[""])[0].lower()
    except: continue
    if sec in ("none",""): continue
    is_ip=bool(re.match(r"^\d+\.\d+\.\d+\.\d+$",h))
    cc=get_cc(h) if is_ip else cc_map.get(h)
    asn=get_asn(h) if is_ip else asn_map.get(h)
    if is_ip and in_zone(h,RU_IV,RU_S) or cc=="RU": blocked_ru.append((line,h,port)); continue
    if is_ip and (in_zone(h,IR_IV,IR_S) or in_zone(h,CN_IV,CN_S)): blocked.append((line,h,port)); continue
    if cc in BLOCK_CC or asn in BLOCK_ASN: blocked.append((line,h,port)); continue
    candidates.append((line,h,port))

alive=set()
with ThreadPoolExecutor(max_workers=200) as ex:
    fut={ex.submit(is_alive, h, p): line for line,h,p in candidates}
    for f in as_completed(fut):
        if f.result(): alive.add(fut[f])

usa={l for l in alive if US_RE.search(urllib.parse.unquote(l))}
rest=alive-usa
al=sorted(rest)
if al:
    n=(len(al)+9)//10
    for i in range(10):
        part=al[i*n:(i+1)*n]
        if part:
            with open(f"clean{i+1}.txt","w",encoding="utf-8") as f:
                f.write("\n".join(part)+"\n")
    print(f"clean1-10: {len(al)} поровну по {n} (пул {len(pool)}, US вычтены: {len(usa)})")
else:
    print("живых чистых=0, clean1-10 не тронуты")

if usa:
    with open("clean11.txt","w",encoding="utf-8") as f:
        f.write("\n".join(sorted(usa))+"\n")
print(f"clean11.txt {len(usa)}")

aliveB=set()
with ThreadPoolExecutor(max_workers=200) as ex:
    fut={ex.submit(is_alive, h, p): line for line,h,p in blocked}
    for f in as_completed(fut):
        if f.result(): aliveB.add(fut[f])
if aliveB:
    with open("clean12.txt","w",encoding="utf-8") as f:
        f.write("\n".join(sorted(aliveB))+"\n")
print(f"clean12.txt {len(aliveB)}")

aliveRU=set()
with ThreadPoolExecutor(max_workers=200) as ex:
    fut={ex.submit(is_alive, h, p): line for line,h,p in blocked_ru}
    for f in as_completed(fut):
        if f.result(): aliveRU.add(fut[f])
if aliveRU:
    with open("clean13.txt","w",encoding="utf-8") as f:
        f.write("\n".join(sorted(aliveRU))+"\n")
print(f"clean13.txt {len(aliveRU)}")
