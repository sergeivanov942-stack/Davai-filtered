"""Stage 2 filter: end-to-end protocol test through sing-box.

Stage 1 (filter.py) checks TCP reachability. This stage converts every
vless:// / trojan:// config to a sing-box outbound (the same core Karing
uses), runs a real HTTP request through it and keeps only configs that
actually answer. Everything else goes to dead.txt.

Usage:
    python protocol_test.py [source_dir]   # default: current dir
Env:
    SING_BOX_BIN   path to sing-box binary (default: ./sing-box or sing-box.exe)
    E2E_TIMEOUT    seconds per request (default 5)
    E2E_BATCH      configs per sing-box process (default 1000)
    E2E_CONCURRENCY parallel curl workers (default 200)
    E2E_BASE_PORT  first local socks port (default 20000)
    E2E_LIMIT      test only first N configs per group (0 = all), for smoke runs
    E2E_URL        probe url (default http://www.gstatic.com/generate_204)
    E2E_CONVERT_ONLY  1 = only run the converter and print stats, no testing
"""
import os, re, sys, json, time, socket, shutil, subprocess, tempfile, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try: sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception: pass

SRC_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
SB_BIN = os.environ.get("SING_BOX_BIN") or ("sing-box.exe" if os.name == "nt" else os.path.abspath("sing-box"))
TIMEOUT = float(os.environ.get("E2E_TIMEOUT", "5"))
BATCH = int(os.environ.get("E2E_BATCH", "1000"))
CONC = int(os.environ.get("E2E_CONCURRENCY", "200"))
BASE_PORT = int(os.environ.get("E2E_BASE_PORT", "20000"))
LIMIT = int(os.environ.get("E2E_LIMIT", "0"))
TEST_URL = os.environ.get("E2E_URL", "http://www.gstatic.com/generate_204")
CONVERT_ONLY = os.environ.get("E2E_CONVERT_ONLY", "") == "1"

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
FP_OK = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
FLOW_OK = {"xtls-rprx-vision"}


def read_lines(name):
    p = os.path.join(SRC_DIR, name)
    if not os.path.exists(p):
        return []
    with open(p, encoding="utf-8") as f:
        return [l.rstrip("\n") for l in f if l.strip()]


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


def test_port(port):
    try:
        r = subprocess.run(
            ["curl", "-s", "-o", os.devnull, "-w", "%{http_code} %{time_total}",
             "--socks5-hostname", "127.0.0.1:%d" % port, "-m", str(TIMEOUT), TEST_URL],
            capture_output=True, text=True, timeout=TIMEOUT + 3)
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


def run_batch(batch):
    """batch: list of (line, outbound). Returns {line: latency or None}."""
    n = len(batch)
    for i, (_, ob) in enumerate(batch):
        ob["tag"] = "o%d" % i
    cfg = {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "in%d" % i, "listen": "127.0.0.1",
                      "listen_port": BASE_PORT + i} for i in range(n)],
        "outbounds": [ob for _, ob in batch],
        "route": {"rules": [{"inbound": "in%d" % i, "outbound": "o%d" % i} for i in range(n)]},
    }
    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    res = {}
    proc = subprocess.Popen([SB_BIN, "run", "-c", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_ready(BASE_PORT, proc):
            sys.stderr.write("[warn] sing-box did not start (batch of %d)\n" % n)
            try: sys.stderr.write(open(cfg_path, encoding="utf-8").read()[:2000] + "\n")
            except Exception: pass
            return {line: None for line, _ in batch}
        with ThreadPoolExecutor(max_workers=CONC) as ex:
            futs = {ex.submit(test_port, BASE_PORT + i): line for i, (line, _) in enumerate(batch)}
            for f in as_completed(futs):
                ok, lat = f.result()
                res[futs[f]] = lat if ok else None
        # one retry for failures (flaky networks)
        retry = [(i, (line, ob)) for i, (line, ob) in enumerate(batch) if res.get(line) is None]
        for i, (line, ob) in retry:
            ok, lat = test_port(BASE_PORT + i)
            if ok:
                res[line] = lat
    finally:
        proc.terminate()
        try: proc.wait(3)
        except Exception: proc.kill()
        os.remove(cfg_path)
    return res


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

    # global dedup: first group wins
    seen, entries, unconv = {}, [], {}
    for g in ("main", "us", "blocked", "ru"):
        for line in groups[g]:
            if line in seen:
                continue
            seen[line] = g
            ob, why = convert(line)
            if ob is None:
                unconv[line] = why
            else:
                entries.append((line, g, ob))

    print("converted %d, unconvertible %d" % (len(entries), len(unconv)))
    if CONVERT_ONLY:
        from collections import Counter
        print("unconvert reasons:", Counter(unconv.values()))
        return

    ok_lat, group_of = {}, {}
    for i in range(0, len(entries), BATCH):
        chunk = entries[i:i + BATCH]
        print("batch %d-%d ..." % (i, i + len(chunk)))
        for line, lat in run_batch([(l, ob) for l, _, ob in chunk]).items():
            if lat is not None:
                ok_lat[line] = lat
        for l, g, _ in chunk:
            if l in ok_lat:
                group_of[l] = g

    passed = {g: [] for g in groups}
    for l, g in group_of.items():
        passed[g].append(l)
    dead = sorted(set(unconv) | (seen.keys() - ok_lat.keys()))

    # safety: don't wipe lists if nothing passed at all (network/core failure)
    tested_ok = len(ok_lat)
    if len(entries) > 20 and tested_ok == 0:
        sys.exit("[abort] 0 of %d configs passed - likely local network/core problem, files untouched" % len(entries))

    def write(name, lines):
        with open(os.path.join(SRC_DIR, name), "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(lines)) + ("\n" if lines else ""))

    al = sorted(passed["main"])
    if al:
        n = (len(al) + 9) // 10
        for i in range(10):
            write("clean%d.txt" % (i + 1), al[i * n:(i + 1) * n])
    write("clean11.txt", passed["us"])
    write("clean12.txt", passed["blocked"])
    write("clean13.txt", passed["ru"])
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
