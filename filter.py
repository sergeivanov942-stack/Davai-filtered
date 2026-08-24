# pip install geoip2 requests
import re, socket, requests, urllib.parse
import geoip2.database

BLOCK_CC = {"RU"}
GEOIP_DB = "GeoLite2-Country.mmdb" # https://dev.maxmind.com/geoip/geolite2/files
RU_DOMAIN_RE = re.compile(r"\.ru($|[^a-z0-9])", re.I)

reader = geoip2.database.Reader(GEOIP_DB)

def get_cc_for_host(host: str):
    h = host.strip("[]")
    # пробуем как IP напрямую
    try:
        return reader.country(h).country.iso_code
    except: pass
    # если домен - резолвим
    try:
        ip = socket.gethostbyname(h)
        return reader.country(ip).country.iso_code
    except: return None

def is_ru_mask(parsed_qs, netloc_host):
    # sni=, host=, serverName из query
    for k in ["sni","host","serverName","authority"]:
        v = parsed_qs.get(k, [""])[0]
        if v and RU_DOMAIN_RE.search(v):
            return True
    if netloc_host and RU_DOMAIN_RE.search(netloc_host):
        return True
    return False

def filter_one(url, out_path):
    txt = requests.get(url, timeout=30).text.splitlines()
    kept = 0
    with open(out_path, "w", encoding="utf-8") as out:
        for line in txt:
            line=line.strip()
            if not line: continue
            try:
                # vless://uuid@host:port?params#name
                after_at = line.split("@",1)[1]
                host_port = after_at.split("?")[0].split("/")[0]
                host = host_port.split(":")[0].strip("[]")
                qs = urllib.parse.parse_qs(urllib.parse.urlparse(line).query)
            except: continue

            # 1. фильтр по маскировке
            if is_ru_mask(qs, host):
                continue
            # 2. фильтр по IP геолокации хоста
            cc = get_cc_for_host(host)
            if cc in BLOCK_CC:
                continue
            # SNI тоже может резолвиться в RU IP - доп проверка
            sni = qs.get("sni",[""])[0]
            if sni and get_cc_for_host(sni.split(":")[0]) in BLOCK_CC:
                continue

            out.write(line+"\n")
            kept+=1
    print(f"{out_path}: {kept}/{len(txt)}")

BASE = "https://raw.githubusercontent.com/Cepreu54/Davai/refs/heads/main/clean{}.txt"
for i in range(1,12):
    filter_one(BASE.format(i), f"clean{i}.txt")
