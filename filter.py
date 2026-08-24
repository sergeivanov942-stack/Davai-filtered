import re, requests, urllib.parse, ipaddress, socket, bisect
import geoip2.database
from concurrent.futures import ThreadPoolExecutor, as_completed

BLOCK_CC={"RU","IR","CN","BY","KP","SY","CU","VE","SD","IQ","LY","YE","MM","AF","RS"} 
BLOCK_ASN={13335,54113,14061,20473,24940,16509,16276,63949,396982,8075,16265,60068,208044,45102} # +13335 Cloudflare +54113 Fastly
TRASH_DOMAINS={"gogocs.xyz","kukuss.top","wagahaha.xyz","workers.dev","pages.dev","railway.app"}
IR_WORDS={"parsashonam","ebrasha","mohsen","kian","sarina","nika","jadi","freeiran","vip_security"}
BLOCK_RE=re.compile(r"(🇷🇺|🇮🇷|🇨🇳|🇬🇧|🇧🇾|🇰🇵|\.ru\b|\.ir\b|\.cn\b|yandex|vk\.com|mail\.ru|ok\.ru)", re.I)

reader_c=geoip2.database.Reader("GeoLite2-Country.mmdb")
reader_a=geoip2.database.Reader("GeoLite2-ASN.mmdb")

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
        with socket.create_connection((ip, port), timeout=1):
            return True
    except: return False

BASE="https://raw.githubusercontent.com/Cepreu54/Davai/refs/heads/main/clean{}.txt"
all=[]; uniq=set()
for i in range(1,12):
    txt=requests.get(BASE.format(i),timeout=30).text.splitlines()
    all.append((i,txt))
    for l in txt:
        try:
            h=l.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
            if h and not re.match(r"^\d+\.\d+\.\d+\.\d+$",h) and ":" not in h: uniq.add(h)
        except: pass
cc_map={}; asn_map={}
def resolve(d):
    try:
        ip=socket.gethostbyname(d)
        return d, get_cc(ip), get_asn(ip)
    except: return d, None, None
with ThreadPoolExecutor(max_workers=100) as ex:
    for d,cc,asn in ex.map(resolve, uniq):
        cc_map[d]=cc; asn_map[d]=asn

for i,txt in all:
    # 1. сначала без alive собираем кандидатов
    candidates=[]
    for line in txt:
        if not line.startswith("vless://"): continue
        low=urllib.parse.unquote(line).lower()
        if any(w in low for w in IR_WORDS): continue
        if BLOCK_RE.search(low): continue
        if any(d in low for d in TRASH_DOMAINS): continue
        try:
            h=line.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
            hp=line.split("@",1)[1].split("?")[0].split("/")[0]
            port=int(hp.split(":")[1]) if ":" in hp else 443
            qs=urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
            sec=qs.get("security",[""])[0].lower()
        except: continue
        if sec in ("none",""): continue
        is_ip=bool(re.match(r"^\d+\.\d+\.\d+\.\d+$",h))
        cc=get_cc(h) if is_ip else cc_map.get(h)
        asn=get_asn(h) if is_ip else asn_map.get(h)
        if is_ip and (in_zone(h,RU_IV,RU_S) or in_zone(h,IR_IV,IR_S) or in_zone(h,CN_IV,CN_S)): continue
        if cc in BLOCK_CC: continue
        if asn in BLOCK_ASN: continue
        candidates.append((line,h,port))
    # 2. паралл. прозвон только кандидатов
    alive=set()
    with ThreadPoolExecutor(max_workers=200) as ex:
        fut={ex.submit(is_alive, h, p): line for line,h,p in candidates}
        for f in as_completed(fut):
            if f.result(): alive.add(fut[f])
    with open(f"clean{i}.txt","w",encoding="utf-8") as f:
        for line in alive:
            f.write(line+"\n")
    print(f"clean{i}.txt {len(alive)}/{len(txt)}")
