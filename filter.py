import re, requests, urllib.parse, ipaddress, socket, bisect
import geoip2.database
from concurrent.futures import ThreadPoolExecutor

BLOCK_CC={"RU","IR","CN","BY","KP","SY","CU","TM","GB"} # убери GB если нужен UK
BLOCK_ASN={14061,20473,24940,16509,16276,63949,396982,8075} # датацентры
# убери 8075/396982 если нужен Google/Microsoft

reader_c=geoip2.database.Reader("GeoLite2-Country.mmdb")
reader_a=geoip2.database.Reader("GeoLite2-ASN.mmdb")
RU_MASK_RE=re.compile(r"(\.ru\b|\.ir\b|\.cn\b|yandex|vk\.com|mail\.ru|ok\.ru)", re.I)

# RU/CN/IR зоны для 100% покрытия
def load_zone(url):
    nets=[]
    for l in requests.get(url,timeout=30).text.splitlines():
        try: nets.append(ipaddress.ip_network(l.strip()))
        except: pass
    iv=sorted([(int(n.network_address),int(n.broadcast_address)) for n in nets if n.version==4])
    return iv, [s for s,_ in iv]
RU_IV,RU_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/ru.zone")
IR_IV,IR_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/ir.zone")
CN_IV,CN_S = load_zone("https://www.ipdeny.com/ipblocks/data/countries/cn.zone")
def in_zone(ip_str, IV, S):
    try:
        n=int(ipaddress.ip_address(ip_str.strip("[]")))
        i=bisect.bisect_right(S,n)-1
        return i>=0 and n<=IV[i][1]
    except: return False

def is_ru_ir_cn_ip(ip):
    return in_zone(ip,RU_IV,RU_S) or in_zone(ip,IR_IV,IR_S) or in_zone(ip,CN_IV,CN_S)

def get_cc(ip):
    try: return reader_c.country(ip).country.iso_code
    except: return None
def get_asn(ip):
    try: return reader_a.asn(ip).autonomous_system_number
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
    kept=0
    with open(f"clean{i}.txt","w",encoding="utf-8") as f:
        for line in txt:
            if not line.startswith("vless://"): continue
            try:
                h=line.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
                qs=urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
                sni=qs.get("sni",[""])[0]
            except: continue
            # маскировка
            if RU_MASK_RE.search(sni): continue
            # проверка IP
            is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$",h))
            cc = get_cc(h) if is_ip else cc_map.get(h)
            asn = get_asn(h) if is_ip else asn_map.get(h)
            if is_ip and is_ru_ir_cn_ip(h): continue
            if cc in BLOCK_CC: continue
            if asn in BLOCK_ASN: continue
            f.write(line+"\n"); kept+=1
    print(f"clean{i}.txt {kept}/{len(txt)}")
