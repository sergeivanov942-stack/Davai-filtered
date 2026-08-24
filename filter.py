import re, requests, urllib.parse, ipaddress, socket
import geoip2.database
from concurrent.futures import ThreadPoolExecutor

GEOIP_DB="GeoLite2-Country.mmdb"
reader=geoip2.database.Reader(GEOIP_DB)

# 1. Хард-блок твоего списка реальных RU IP (GeoIP их часто метит как DE/NL)
HARD_RU_IPS={"193.124.204.145","95.173.199.80","185.162.229.20","185.162.228.3","91.107.185.96","91.99.205.10","91.99.192.185","91.98.154.118","91.99.182.155","94.131.16.12","188.245.208.177","77.42.125.134","94.156.203.153"}

# 2. Маскировка - все RU домены
RU_MASK_RE=re.compile(r"(\.ru\b|yandex\.(ru|net|cloud)|yandexcloud\.net|vk\.com|mail\.ru|ok\.ru)", re.I)

def is_ip(s):
    try: ipaddress.ip_address(s.strip("[]")); return True
    except: return False
def get_cc(ip):
    try: return reader.country(ip.strip("[]")).country.iso_code
    except: return None

BASE="https://raw.githubusercontent.com/Cepreu54/Davai/refs/heads/main/clean{}.txt"

# собираем уникальные домены для парал. резолва
all=[]
uniq=set()
for i in range(1,12):
    txt=requests.get(BASE.format(i),timeout=30).text.splitlines()
    all.append((i,txt))
    for l in txt:
        try:
            h=l.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
            if h and not is_ip(h): uniq.add(h)
            qs=urllib.parse.parse_qs(urllib.parse.urlparse(l).query)
            sni=qs.get("sni",[""])[0].split(":")[0]
            if sni and not is_ip(sni): uniq.add(sni)
        except: pass

def resolve(d):
    try: return d, get_cc(socket.gethostbyname(d))
    except: return d, None

cc_map=dict()
with ThreadPoolExecutor(max_workers=100) as ex:
    for d,cc in ex.map(resolve, uniq): cc_map[d]=cc

for i,txt in all:
    kept=0
    with open(f"clean{i}.txt","w",encoding="utf-8") as f:
        for line in txt:
            if not line.startswith("vless://"): continue
            try:
                h=line.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
                qs=urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
                sni=qs.get("sni",[""])[0]
                host_qs=qs.get("host",[""])[0]
            except: continue
            # слой 1: хард IP
            if h in HARD_RU_IPS or sni.split(":")[0] in HARD_RU_IPS: continue
            # слой 2: маскировка
            if RU_MASK_RE.search(sni) or RU_MASK_RE.search(host_qs) or RU_MASK_RE.search(h): continue
            # слой 3: GeoIP
            cc = get_cc(h) if is_ip(h) else cc_map.get(h)
            if cc=="RU": continue
            if sni:
                s_cc = get_cc(sni.split(":")[0]) if is_ip(sni.split(":")[0]) else cc_map.get(sni.split(":")[0])
                if s_cc=="RU": continue
            f.write(line+"\n"); kept+=1
    print(f"clean{i}.txt {kept}/{len(txt)}")
