import re, requests, urllib.parse, ipaddress
import geoip2.database

BLOCK_CC = {"RU"}
GEOIP_DB = "GeoLite2-Country.mmdb"
RU_DOMAIN_RE = re.compile(r"\.ru(\b|/|$|:|\?|#)", re.I)

reader = geoip2.database.Reader(GEOIP_DB)
ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^\[?[a-f0-9:]+\]?$", re.I)

def is_ip(s): 
    try: ipaddress.ip_address(s.strip("[]")); return True
    except: return False

def get_cc_ip(ip):
    try: return reader.country(ip.strip("[]")).country.iso_code
    except: return None

def is_ru_mask(qs, host):
    for k in ["sni","host","serverName","authority"]:
        v = qs.get(k, [""])[0]
        if v and RU_DOMAIN_RE.search(v.lower()):
            return True
    if host and RU_DOMAIN_RE.search(host.lower()):
        return True
    return False

BASE = "https://raw.githubusercontent.com/Cepreu54/Davai/refs/heads/main/clean{}.txt"
for i in range(1,12):
    url = BASE.format(i)
    out = f"clean{i}.txt"
    print(f"Downloading {url}...")
    txt = requests.get(url, timeout=30).text.splitlines()
    print(f" {len(txt)} lines")
    kept=0
    with open(out, "w", encoding="utf-8") as f:
        for line in txt:
            line=line.strip()
            if not line or not line.startswith("vless://"): continue
            try:
                parsed = urllib.parse.urlparse(line)
                host = line.split("@",1)[1].split("?")[0].split("/")[0].split(":")[0].strip("[]")
                qs = urllib.parse.parse_qs(parsed.query)
            except: continue
            if is_ru_mask(qs, host):
                continue
            if is_ip(host) and get_cc_ip(host) in BLOCK_CC:
                continue
            # sni тоже проверяем только если это IP (без DNS)
            sni = qs.get("sni",[""])[0].split(":")[0].strip("[]")
            if sni and is_ip(sni) and get_cc_ip(sni) in BLOCK_CC:
                continue
            f.write(line+"\n")
            kept+=1
    print(f" -> {out}: {kept}/{len(txt)} kept")

print("Done")
