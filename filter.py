import re, requests, urllib.parse, ipaddress, socket
import geoip2.database
from concurrent.futures import ThreadPoolExecutor
import bisect

GEOIP_DB="GeoLite2-Country.mmdb"
reader=geoip2.database.Reader(GEOIP_DB)

# качаем все RU сети
RU_ZONE_URL="https://www.ipdeny.com/ipblocks/data/countries/ru.zone"
nets=[]
for line in requests.get(RU_ZONE_URL,timeout=30).text.splitlines():
    try: nets.append(ipaddress.ip_network(line.strip()))
    except: pass
# для быстрого поиска делаем интервалы
v4_intervals=sorted([(int(n.network_address),int(n.broadcast_address)) for n in nets if n.version==4])
v4_starts=[s for s,_ in v4_intervals]

def ip_in_ru(ip_str):
    try:
        ip=ipaddress.ip_address(ip_str.strip("[]"))
        if ip.version!=4: return False # RU v6 почти нет в листе, можно добавить
        n=int(ip)
        i=bisect.bisect_right(v4_starts,n)-1
        return i>=0 and n<=v4_intervals[i][1]
    except: return False

RU_MASK_RE=re.compile(r"\.ru\b", re.I) # маскировку режем только *.ru, yandex.net оставляем для РКН

def get_cc(ip):
    try: return reader.country(ip.strip("[]")).country.iso_code
    except: return None

BASE="https://raw.githubusercontent.com/Cepreu54/Davai/refs/heads/main/clean{}.txt"
all=[]; uniq=set()
for i in range(1,12):
    txt=requests.get(BASE.format(i),timeout=30).text.splitlines()
    all.append((i,txt))
    for l in txt:
        try:
            h=l.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
            if h and not re.match(r"^\d+\.\d+\.\d+\.\d+$",h): uniq.add(h)
            qs=urllib.parse.parse_qs(urllib.parse.urlparse(l).query)
            sni=qs.get("sni",[""])[0].split(":")[0]
            if sni and not re.match(r"^\d+\.\d+\.\d+\.\d+$",sni): uniq.add(sni)
        except: pass

cc_map={}
def resolve(d):
    try: return d, get_cc(socket.gethostbyname(d))
    except: return d, None
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
            except: continue
            # 1. RU IP - по зоне + по GeoIP (ловит всех "черлаков" без ручного списка)
            if re.match(r"^\d+\.\d+\.\d+\.\d+$",h) and (ip_in_ru(h) or get_cc(h)=="RU"): continue
            if h in cc_map and cc_map[h]=="RU": continue
            # 2. маскировка *.ru - режем, остальное оставляем
            if RU_MASK_RE.search(sni): continue
            if sni and not re.match(r"^\d+\.\d+\.\d+\.\d+$",sni) and cc_map.get(sni)=="RU": continue
            f.write(line+"\n"); kept+=1
    print(f"clean{i}.txt {kept}/{len(txt)}")
