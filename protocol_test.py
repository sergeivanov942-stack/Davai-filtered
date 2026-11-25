"""Stage 2 filter: end-to-end protocol test through sing-box.

Stage 1 (filter.py) checks TCP reachability. This stage converts every
vless:// / trojan:// config to a sing-box outbound (the same core Karing
uses), runs a real HTTP request through it and keeps only configs that
actually answer. Everything else goes to dead.txt.

Usage:
    python protocol_test.py [source_dir]   # default: current dir
Env:
    SING_BOX_BIN   path to sing-box binary (default: ./sing-box or sing-box.exe)
    E2E_TIMEOUT    seconds per request (default 3)
    E2E_BATCH      configs per sing-box process (default 1000)
    E2E_CONCURRENCY parallel curl workers (default 200)
    E2E_BASE_PORT  first local socks port (default 20000)
    E2E_LIMIT      test only first N configs per group (0 = all), for smoke runs
    E2E_URL        probe url (default http://www.gstatic.com/generate_204)
    E2E_CONVERT_ONLY  1 = only run the converter and print stats, no testing
    E2E_AISTUDIO   1/0 - drop servers whose exit region is not supported
                   by Google AI Studio (default 1)
"""
import os, re, sys, json, time, socket, shutil, subprocess, tempfile, urllib.parse
import urllib.request, unicodedata, datetime, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

SRC_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
SB_BIN = os.environ.get("SING_BOX_BIN") or ("sing-box.exe" if os.name == "nt" else "sing-box")
TIMEOUT = float(os.environ.get("E2E_TIMEOUT", "3"))
BATCH = int(os.environ.get("E2E_BATCH", "300"))
CONC = int(os.environ.get("E2E_CONCURRENCY", "200"))
BASE_PORT = int(os.environ.get("E2E_BASE_PORT", "20000"))
LIMIT = int(os.environ.get("E2E_LIMIT", "0"))
TEST_URL = os.environ.get("E2E_URL", "http://www.gstatic.com/generate_204")
RU_URL = os.environ.get("E2E_RU_URL", "https://ya.ru")  # ru group: test RU reachability, not Google
CONVERT_ONLY = os.environ.get("E2E_CONVERT_ONLY", "") == "1"
RETRY = os.environ.get("E2E_RETRY", "1") == "1"  # re-test failures once

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
FP_OK = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
FLOW_OK = {"xtls-rprx-vision"}

# --- Google AI Studio region gate -------------------------------------------
# A server whose exit country is NOT in Google's "available regions" list shows
# the available-regions page instead of AI Studio -> useless -> dead.txt.
AI_CHECK = os.environ.get("E2E_AISTUDIO", "1") == "1"
REGIONS_URL = "https://aistudio.google.com/docs/available-regions"
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
AI_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ai_regions.cache.json")
AI_OK = set()  # filled by load_ai_regions()

# name as printed on the page -> ISO-3166 alpha-2 (Cloudflare trace "loc=")
AI_NAME2ISO = [
    ("Albania","AL"),("Algeria","DZ"),("American Samoa","AS"),("Andorra","AD"),("Angola","AO"),
    ("Anguilla","AI"),("Antarctica","AQ"),("Antigua and Barbuda","AG"),("Argentina","AR"),
    ("Armenia","AM"),("Aruba","AW"),("Australia","AU"),("Austria","AT"),("Azerbaijan","AZ"),
    ("Bahamas","BS"),("Bahrain","BH"),("Bangladesh","BD"),("Barbados","BB"),("Belgium","BE"),
    ("Belize","BZ"),("Benin","BJ"),("Bermuda","BM"),("Bhutan","BT"),("Bolivia","BO"),
    ("Bosnia and Herzegovina","BA"),("Botswana","BW"),("Brazil","BR"),
    ("British Indian Ocean Territory","IO"),("British Virgin Islands","VG"),("Brunei","BN"),
    ("Bulgaria","BG"),("Burkina Faso","BF"),("Burundi","BI"),("Cabo Verde","CV"),
    ("Cape Verde","CV"),("Cambodia","KH"),("Cameroon","CM"),("Canada","CA"),
    ("Caribbean Netherlands","BQ"),("Cayman Islands","KY"),("Central African Republic","CF"),
    ("Chad","TD"),("Chile","CL"),("Christmas Island","CX"),("Cocos Keeling Islands","CC"),
    ("Colombia","CO"),("Comoros","KM"),("Cook Islands","CK"),("Costa Rica","CR"),
    ("Ivory Coast","CI"),("Cote d'Ivoire","CI"),("Croatia","HR"),("Curacao","CW"),
    ("Cyprus","CY"),("Czech Republic","CZ"),("Czechia","CZ"),
    ("Democratic Republic of the Congo","CD"),("Denmark","DK"),("Djibouti","DJ"),
    ("Dominica","DM"),("Dominican Republic","DO"),("Ecuador","EC"),("Egypt","EG"),
    ("El Salvador","SV"),("Equatorial Guinea","GQ"),("Eritrea","ER"),("Estonia","EE"),
    ("Eswatini","SZ"),("Ethiopia","ET"),("Falkland Islands Malvinas","FK"),
    ("Falkland Islands Islas Malvinas","FK"),
    ("Faroe Islands","FO"),("Fiji","FJ"),("Finland","FI"),("France","FR"),
    ("French Guiana","GF"),("Gabon","GA"),("Gambia","GM"),("Georgia","GE"),("Germany","DE"),
    ("Ghana","GH"),("Gibraltar","GI"),("Greece","GR"),("Greenland","GL"),("Grenada","GD"),
    ("Guam","GU"),("Guatemala","GT"),("Guernsey","GG"),("Guinea","GN"),
    ("Guinea-Bissau","GW"),("Guyana","GY"),("Haiti","HT"),
    ("Heard Island and McDonald Islands","HM"),("Honduras","HN"),("Hungary","HU"),
    ("Iceland","IS"),("India","IN"),("Indonesia","ID"),("Iraq","IQ"),("Ireland","IE"),
    ("Isle of Man","IM"),("Israel","IL"),("Italy","IT"),("Jamaica","JM"),("Japan","JP"),
    ("Jersey","JE"),("Jordan","JO"),("Kazakhstan","KZ"),("Kenya","KE"),("Kiribati","KI"),
    ("Kosovo","XK"),("Kuwait","KW"),("Kyrgyzstan","KG"),("Laos","LA"),("Latvia","LV"),
    ("Lebanon","LB"),("Lesotho","LS"),("Liberia","LR"),("Libya","LY"),
    ("Liechtenstein","LI"),("Lithuania","LT"),("Luxembourg","LU"),("Madagascar","MG"),
    ("Malawi","MW"),("Malaysia","MY"),("Maldives","MV"),("Mali","ML"),("Malta","MT"),
    ("Marshall Islands","MH"),("Mauritania","MR"),("Mauritius","MU"),("Mexico","MX"),
    ("Micronesia","FM"),("Moldova","MD"),("Monaco","MC"),("Mongolia","MN"),
    ("Montenegro","ME"),("Montserrat","MS"),("Morocco","MA"),("Mozambique","MZ"),
    ("Namibia","NA"),("Nauru","NR"),("Nepal","NP"),("Netherlands","NL"),
    ("New Caledonia","NC"),("New Zealand","NZ"),("Nicaragua","NI"),("Niger","NE"),
    ("Nigeria","NG"),("Niue","NU"),("Norfolk Island","NF"),("North Macedonia","MK"),
    ("Northern Mariana Islands","MP"),("Norway","NO"),("Oman","OM"),("Pakistan","PK"),
    ("Palau","PW"),("Palestine","PS"),("Panama","PA"),("Papua New Guinea","PG"),
    ("Paraguay","PY"),("Peru","PE"),("Philippines","PH"),("Pitcairn Islands","PN"),
    ("Poland","PL"),("Portugal","PT"),("Puerto Rico","PR"),("Qatar","QA"),
    ("Republic of Cyprus","CY"),("Republic of the Congo","CG"),("Romania","RO"),
    ("Rwanda","RW"),("Reunion","RE"),("Saint Barthelemy","BL"),
    ("Saint Helena Ascension and Tristan da Cunha","SH"),("Saint Kitts and Nevis","KN"),
    ("Saint Lucia","LC"),("Saint Pierre and Miquelon","PM"),
    ("Saint Vincent and the Grenadines","VC"),("Samoa","WS"),("San Marino","SM"),
    ("Sao Tome and Principe","ST"),("Saudi Arabia","SA"),("Senegal","SN"),("Serbia","RS"),
    ("Seychelles","SC"),("Sierra Leone","SL"),("Singapore","SG"),("Slovakia","SK"),
    ("Slovenia","SI"),("Solomon Islands","SB"),("Somalia","SO"),("South Africa","ZA"),
    ("South Georgia and the South Sandwich Islands","GS"),("South Korea","KR"),
    ("South Sudan","SS"),("Spain","ES"),("Sri Lanka","LK"),("Sudan","SD"),
    ("Suriname","SR"),("Sweden","SE"),("Switzerland","CH"),("Syria","SY"),("Taiwan","TW"),
    ("Tajikistan","TJ"),("Tanzania","TZ"),("Thailand","TH"),("Timor-Leste","TL"),
    ("East Timor","TL"),("Togo","TG"),("Tokelau","TK"),("Tonga","TO"),
    ("Trinidad and Tobago","TT"),("Tunisia","TN"),("Turkmenistan","TM"),
    ("Turks and Caicos Islands","TC"),("Tuvalu","TV"),("Turkiye","TR"),("Turkey","TR"),
    ("Uganda","UG"),("Ukraine","UA"),("United Arab Emirates","AE"),
    ("United Kingdom","GB"),("Great Britain","GB"),("United States","US"),
    ("United States Minor Outlying Islands","UM"),("Uruguay","UY"),
    ("U.S. Virgin Islands","VI"),("US Virgin Islands","VI"),
    ("Virgin Islands U.S.","VI"),("Uzbekistan","UZ"),("Vanuatu","VU"),
    ("Vatican City","VA"),("Holy See","VA"),("Venezuela","VE"),("Vietnam","VN"),
    ("Wallis and Futuna","WF"),("Western Sahara","EH"),("Yemen","YE"),("Zambia","ZM"),
    ("Zimbabwe","ZW"),("Aland Islands","AX"),
]


def _norm_name(s):
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = s.replace("&", "and").lower()
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    return re.sub(r"^the ", "", s)


AI_LOOKUP = {_norm_name(n): iso for n, iso in AI_NAME2ISO}


def load_ai_regions():
    """ISO-2 set of regions where AI Studio is available; empty = check off."""
    if not AI_CHECK:
        return None
    try:
        req = urllib.request.Request(REGIONS_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            html = r.read().decode("utf-8", "replace")
        text = re.sub(r"<[^>]+>", " ", html)
        i = text.find("are available in the following countries")
        if i < 0:
            raise ValueError("marker not found")
        iso = set()
        for piece in text[i:].split("*")[1:]:
            n = re.split(r"[\n{%#]", piece)[0].strip()
            code = AI_LOOKUP.get(_norm_name(n))
            if code:
                iso.add(code)
        if len(iso) < 150:  # sanity: the real list has ~230 entries
            raise ValueError("parsed only %d regions" % len(iso))
        with open(AI_CACHE, "w") as f:
            json.dump(sorted(iso), f)
        return iso
    except Exception as e:
        if os.path.exists(AI_CACHE):
            sys.stderr.write("[warn] regions page fetch failed (%s), using cache\n" % e)
            return set(json.load(open(AI_CACHE)))
        sys.stderr.write("[warn] regions page unavailable (%s) - AI region check disabled\n" % e)
        return set()


def check_ai(port):
    """True (ok) / False (blocked) / None (inconclusive -> keep).

    Two samples: normal resolve + forced IPv4. Some servers (CDN-fronted)
    rotate exit IPs per destination - one lucky sample is not enough:
    ANY sample in an unsupported region marks the server blocked."""
    verdicts = 0
    for extra in ([], ["-4"]):
        try:
            r = subprocess.run(["curl", "-s"] + extra +
                               ["--socks5-hostname", "127.0.0.1:%d" % port,
                                "-m", "10", TRACE_URL],
                               capture_output=True, text=True, timeout=14)
            if r.returncode != 0:
                continue
            m = re.search(r"^loc=([A-Za-z0-9]{2})$", r.stdout, re.M)
            if not m:
                continue
            if m.group(1) not in AI_OK:
                return False  # any single sample outside supported regions
            verdicts += 1
        except Exception:
            continue
    return True if verdicts else None


def read_lines(name):
    p = os.path.join(SRC_DIR, name)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f if l.strip()]


def load_history():
    """Reliability records keyed by stable config hash: {hkey: {rec:[0/1...], last:iso}}."""
    try:
        return json.load(open(os.path.join(SRC_DIR, "history.json"), encoding="utf-8"))
    except Exception:
        return {}


def save_history(h):
    with open(os.path.join(SRC_DIR, "history.json"), "w", encoding="utf-8") as f:
        json.dump(h, f, ensure_ascii=False)


def parse_query(qs):
    q = {}
    for part in qs.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        q[urllib.parse.unquote(k).strip().lower()] = urllib.parse.unquote(v).strip()
    return q


def convert(line):
    """vless/trojan URI -> sing-box outbound dict, or (None, reason)."""
    m = re.match(r"^(vless|trojan)://", line.strip())
    if not m:
        return None, "scheme"
    try:
        sp = urllib.parse.urlsplit(line.strip())
    except ValueError:
        return None, "urlsplit"
    try:
        host = sp.hostname
        port = sp.port or 443
    except ValueError:
        return None, "port"
    if not host:
        return None, "no-host"
    userinfo = urllib.parse.unquote(sp.netloc.rpartition("@")[0])
    if not userinfo:
        return None, "no-userinfo"
    q = parse_query(sp.query)
    net = (q.get("type") or "tcp").lower()
    sec = (q.get("security") or "").lower()

    ob = {"type": m.group(1), "server": host, "server_port": int(port)}
    if ob["type"] == "vless":
        if re.match(r"^[0-9a-fA-F]{32}$", userinfo):  # uuid without dashes
            userinfo = "-".join([userinfo[:8], userinfo[8:12], userinfo[12:16], userinfo[16:20], userinfo[20:]])
        if not UUID_RE.match(userinfo):
            return None, "bad-uuid"
        ob["uuid"] = userinfo
    else:
        ob["password"] = userinfo

    flow = (q.get("flow") or "").strip()
    if flow:
        if ob["type"] != "vless" or flow not in FLOW_OK:
            return None, "flow"
        ob["flow"] = flow

    transport = None
    if net in ("tcp", "raw"):  # "raw" is the new xray name for plain tcp
        transport = None
    elif net == "ws":
        transport = {"type": "ws"}
        path = q.get("path") or "/"
        ed = re.search(r"[?&]ed=(\d+)$", path)
        if ed:
            transport["max_early_data"] = int(ed.group(1))
            transport["early_data_header_name"] = "Sec-WebSocket-Protocol"
            path = path[:ed.start()]
        transport["path"] = path or "/"
        if q.get("host"):
            transport["headers"] = {"Host": q["host"]}
    elif net == "grpc":
        transport = {"type": "grpc", "service_name": q.get("servicename") or ""}
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade", "path": q.get("path") or "/"}
        if q.get("host"):
            transport["host"] = q["host"]
    else:
        return None, "net:" + net  # xhttp/splithttp/h2 etc. - sing-box can't run these

    if sec == "reality":
        pbk = q.get("pbk")
        if not pbk:
            return None, "reality-no-pbk"
        tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or host,
               "utls": {"enabled": True, "fingerprint": "chrome"},
               "reality": {"enabled": True, "public_key": pbk}}
        sid = q.get("sid")
        if sid:
            tls["reality"]["short_id"] = sid
    elif sec == "tls":
        tls = {"enabled": True, "server_name": q.get("sni") or q.get("peer") or host}
    elif sec in ("none", "false", ""):
        # plain (no TLS): valid only for vless; trojan requires TLS
        if ob["type"] != "vless":
            return None, "sec:" + (sec or "none")
        tls = None
    else:
        return None, "sec:" + sec

    if (q.get("allowinsecure") or q.get("insecure") or "").lower() in ("1", "true", "yes"):
        tls["insecure"] = True
    alpn = q.get("alpn")
    if alpn:
        tls["alpn"] = [a for a in alpn.split(",") if a]
    fp = (q.get("fp") or "").strip().lower()
    if fp and fp not in ("0", "none", "unsafe"):
        if fp not in FP_OK:
            return None, "fp:" + fp
        if tls is not None:
            if "utls" not in tls:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            else:
                tls["utls"]["fingerprint"] = fp

    if tls is not None:
        ob["tls"] = tls
    if transport:
        ob["transport"] = transport
    return ob, None


def test_port(port, url, timeout):
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", os.devnull, "-w", "%{http_code} %{time_total}",
             "--socks5-hostname", "127.0.0.1:%d" % port, "-m", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 3)
        if r.returncode != 0:
            return False, 0.0
        code_s, _, t_s = r.stdout.strip().partition(" ")
        code = int(code_s or 0)
        return 200 <= code < 400, float(t_s or 0)
    except Exception:
        return False, 0.0


def wait_ready(port, proc, tmo=10):
    end = time.time() + tmo
    while time.time() < end:
        if proc.poll() is not None:
            return False  # sing-box died
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def check_one(ob):
    """True if sing-box accepts this outbound (config-level validation)."""
    cfg = {"log": {"level": "error"},
           "inbounds": [{"type": "socks", "tag": "chk", "listen": "127.0.0.1", "listen_port": 1}],
           "outbounds": [dict(ob, tag="chk")]}
    fd, p = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        r = subprocess.run([SB_BIN, "check", "-c", p], capture_output=True, text=True, timeout=20)
        return r.returncode == 0
    except Exception:
        return False
    finally:
        try:
            os.remove(p)
        except OSError:
            pass


def start_sb(cfg_path, err_path):
    ef = open(err_path, "wb")
    try:
        return subprocess.Popen([SB_BIN, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=ef)
    finally:
        ef.close()


def run_batch(batch):
    """batch: list of (line, group, outbound). Returns ({line: latency or None}, ai_dead set).

    Group "ru" is exempt from the AI region check: Russian exits never pass
    it, but these servers are useful for RU services."""
    n = len(batch)
    for i, (_, _, ob) in enumerate(batch):
        ob["tag"] = "o%d" % i
    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in%d" % i, "listen": "127.0.0.1",
                      "listen_port": BASE_PORT + i} for i in range(n)],
        "outbounds": [ob for _, _, ob in batch],
        "route": {"rules": [{"inbound": "in%d" % i, "outbound": "o%d" % i} for i in range(n)]},
    }
    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    fd, err_path = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    res = {}
    proc = None
    try:
        for attempt in (1, 2):  # one restart in case of transient port issues
            proc = start_sb(cfg_path, err_path)
            if wait_ready(BASE_PORT, proc):
                break
            tail = ""
            try:
                tail = open(err_path, "r", encoding="utf-8", errors="replace").read()[-400:]
            except Exception:
                pass
            sys.stderr.write("[warn] sing-box did not start (attempt %d, batch of %d): %s\n"
                             % (attempt, n, tail.replace("\n", " | ")))
            proc.kill()
            proc = None
            time.sleep(2)
        if proc is None or proc.poll() is not None:
            return {line: None for line, _, _ in batch}, set()
        with ThreadPoolExecutor(max_workers=CONC) as ex:
            futs = {ex.submit(test_port, BASE_PORT + i,
                              RU_URL if g == "ru" else TEST_URL,
                              TIMEOUT): line
                    for i, (line, g, _) in enumerate(batch)}
            for f in as_completed(futs):
                ok, lat = f.result()
                res[futs[f]] = lat if ok else None
        # one retry for failures (flaky networks); E2E_RETRY=0 skips it
        if RETRY:
            retry = [(i, g, line) for i, (line, g, _) in enumerate(batch) if res.get(line) is None]
            for i, g, line in retry:
                ok, lat = test_port(BASE_PORT + i, RU_URL if g == "ru" else TEST_URL, TIMEOUT)
                if ok:
                    res[line] = lat
        # AI Studio region gate: exit country must be supported (group "ru" exempt)
        ai_dead = set()
        if AI_OK:
            with ThreadPoolExecutor(max_workers=CONC) as ex:
                futs = {ex.submit(check_ai, BASE_PORT + i): line
                        for i, (line, g, _) in enumerate(batch)
                        if res.get(line) is not None and g != "ru"}
                for f in as_completed(futs):
                    if f.result() is False:
                        res[futs[f]] = None
                        ai_dead.add(futs[f])
    finally:
        if proc is not None:
            proc.terminate()
            try: proc.wait(3)
            except Exception: proc.kill()
        for p in (cfg_path, err_path):
            try: os.remove(p)
            except OSError: pass
    return res, ai_dead


def main():
    if not CONVERT_ONLY and not (os.path.isfile(SB_BIN) or shutil.which(SB_BIN)):
        sys.exit("sing-box binary not found: %r (set SING_BOX_BIN)" % SB_BIN)

    groups = {}
    main_lines = []
    for i in range(1, 11):
        main_lines += read_lines("clean%d.txt" % i)
    main_lines = list(dict.fromkeys(main_lines))
    groups["main"] = main_lines
    groups["us"] = list(dict.fromkeys(read_lines("clean11.txt")))
    groups["blocked"] = list(dict.fromkeys(read_lines("clean12.txt")))
    groups["ru"] = list(dict.fromkeys(read_lines("clean13.txt")))
    if LIMIT:
        groups = {g: ls[:LIMIT] for g, ls in groups.items()}

    # global dedup: first group wins; identical outbounds (same params, other
    # remark) are tested once
    seen, entries, unconv = {}, [], {}
    ob_seen, ob_dup, line_key = {}, set(), {}
    for g in ("main", "us", "blocked", "ru"):
        for line in groups[g]:
            if line in seen:
                continue
            seen[line] = g
            ob, why = convert(line)
            if ob is None:
                unconv[line] = why
                continue
            key = json.dumps(ob, sort_keys=True)
            if key in ob_seen:
                ob_dup.add(line)  # duplicate config, skip the test
                continue
            ob_seen[key] = line
            entries.append((line, g, ob))
            line_key[line] = hashlib.sha1(key.encode()).hexdigest()[:16]  # stable config id
    print("converted %d, duplicates skipped %d, unconvertible %d"
          % (len(entries), len(ob_dup), len(unconv)))
    if CONVERT_ONLY:
        from collections import Counter
        print("unconvert reasons:", Counter(unconv.values()))
        return

    # config-level validation: one bad outbound would kill the whole batch process
    print("checking %d configs with sing-box check ..." % len(entries))
    valid_entries = []
    with ThreadPoolExecutor(max_workers=32) as ex:
        futs = {ex.submit(check_one, ob): (line, g, ob) for line, g, ob in entries}
        for f in as_completed(futs):
            line, g, ob = futs[f]
            if f.result():
                valid_entries.append((line, g, ob))
            else:
                unconv[line] = "invalid-config"
    entries = valid_entries
    print("after check: %d valid" % len(entries))
    if os.environ.get("E2E_CHECK_ONLY", "") == "1":
        print("invalid-config total: %d" % sum(1 for v in unconv.values() if v == "invalid-config"))
        return

    regions = load_ai_regions()
    if regions:
        AI_OK.update(regions)
        print("ai-studio region check: ON (%d supported regions)" % len(AI_OK))
    else:
        print("ai-studio region check: OFF")

    ok_lat, group_of, region_blocked = {}, {}, []
    for i in range(0, len(entries), BATCH):
        chunk = entries[i:i + BATCH]
        print("batch %d-%d ..." % (i, i + len(chunk)))
        rb_res, rb_ai = run_batch(chunk)
        for line, lat in rb_res.items():
            if lat is not None:
                ok_lat[line] = lat
        region_blocked += rb_ai  # alive, but Google-blocked exit -> clean13 (chain entry)
        for l, g, _ in chunk:
            if l in ok_lat:
                group_of[l] = g

    passed = {g: [] for g in groups}
    for l, g in group_of.items():
        passed[g].append(l)
    dead = sorted((set(unconv) | (seen.keys() - ok_lat.keys())) - ob_dup - set(region_blocked))

    # safety: don't wipe lists if nothing passed at all (network/core failure)
    tested_ok = len(ok_lat)
    if len(entries) > 20 and tested_ok == 0:
        sys.exit("[abort] 0 of %d configs passed - likely local network/core problem, files untouched" % len(entries))

    # update reliability history: one record per unique config (stable across remark edits)
    today = datetime.date.today().isoformat()
    hist = load_history()
    for line, hkey in line_key.items():
        if line in region_blocked or group_of.get(line) == "ru":
            continue  # clean13 is a flat list - no reliability tracking needed
        rec = hist.setdefault(hkey, {"rec": [], "last": today})
        rec["rec"] = (rec.get("rec") or [])[-19:] + [1 if line in ok_lat or line in region_blocked else 0]
        rec["last"] = today
    cutoff = (datetime.date.today() - datetime.timedelta(days=45)).isoformat()
    hist = {k: v for k, v in hist.items() if v.get("last", "") >= cutoff}
    save_history(hist)

    def rel(line):
        r = hist.get(line_key.get(line, ""), {}).get("rec")
        return sum(r) / len(r) if r else 0.5  # unknown -> middle

    def write(name, lines):
        with open(os.path.join(SRC_DIR, name), "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(lines)) + ("\n" if lines else ""))

    # tier files: clean1 = most reliable (best pass rate, then lowest latency) ... clean10 = flakiest
    al = sorted(passed["main"], key=lambda l: (-rel(l), ok_lat.get(l, 99.0)))
    if al:
        n = (len(al) + 9) // 10
        tiers = [al[i * n:(i + 1) * n] for i in range(10)]
        for i, part in enumerate(tiers):
            write("clean%d.txt" % (i + 1), part)
        print("tiers:", "  ".join("%d:%d/%.0f%%" % (i + 1, len(t), 100 * sum(rel(l) for l in t) / len(t))
                                  for i, t in enumerate(tiers) if t))
    write("clean11.txt", passed["us"])
    write("clean12.txt", passed["blocked"])
    # sources mislabel RU servers with foreign flags - tag them explicitly
    def ru_tag(line):
        return line if line.rstrip().endswith("[RU]") else line.rstrip() + " [RU]"
    write("clean13.txt", [ru_tag(l) for l in passed["ru"] + region_blocked])
    print("region-blocked moved to clean13: %d" % len(region_blocked))
    write("dead.txt", dead)

    from collections import Counter
    print("unconvert reasons:", Counter(unconv.values()))
    lat = sorted(ok_lat.values())
    if lat:
        print("latency: avg %.2fs  median %.2fs  max %.2fs" % (sum(lat) / len(lat), lat[len(lat) // 2], lat[-1]))
    print("RESULT main=%d/%d  us=%d/%d  blocked=%d/%d  ru=%d/%d  dead=%d" % (
        len(passed["main"]), len(groups["main"]), len(passed["us"]), len(groups["us"]),
        len(passed["blocked"]), len(groups["blocked"]), len(passed["ru"]), len(groups["ru"]), len(dead)))


if __name__ == "__main__":
    main()
