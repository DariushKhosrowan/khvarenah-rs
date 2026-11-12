#!/usr/bin/env python3
"""
dastyab aistudio — one-command clean-IP access to Google AI Studio.

WHAT THIS DOES (very simply):
  You have a bunch of VPN "server cards" (vless URLs) that some free channels post
  on Telegram. Most are old/broken. A few are alive and give you a real foreign IP.
  This tool:
    1. Reads your saved working server cards (from the pool we tested).
    2. Starts a tiny local "proxy tunnel" (xray) that routes your traffic through
       the working foreign server, so the internet sees YOU as being in that country.
    3. Opens Google AI Studio through that tunnel — so it thinks you're in a
       supported country and lets you in.

USAGE:
  dastyab-aistudio.py start    -> start tunnel + open AI Studio
  dastyab-aistudio.py verify   -> just check which server works + your clean IP
  dastyab-aistudio.py stop     -> stop the tunnel
"""
import json, os, subprocess, sys, time, socket, glob, random, signal

HOME = os.path.expanduser("~")
POOL = os.path.join(HOME, ".dastyab/profiles/default/fresh_vless.json")
XRAY = "/tmp/xraybin/xray"
SOCK = 10850
PIDFILE = "/tmp/dastyab_aistudio.pid"
AISTUDIO_URL = "https://aistudio.google.com/"

def find_xray():
    for cand in ["/tmp/xraybin/xray", "/opt/v2rayN/bin/xray/xray",
                 "/opt/nekoray/nekoray_core", "/opt/nekoray/nekobox_core"]:
        if os.path.exists(cand):
            return cand
    raise SystemExit("xray not found")

def build_cfg(server):
    q = server.get('q', {})
    addr = server['addr']; port = server['port']
    uuid = server['uuid']
    sec = q.get('security','none'); net = q.get('type','tcp')
    out = {"protocol":"vless","settings":{"vnext":[{"address":addr,"port":port,
            "users":[{"id":uuid,"encryption":"none"}]}]}}
    if q.get('flow'):
        out['settings']['vnext'][0]['users'][0]['flow'] = q['flow']
    ss = {}
    if sec == 'reality':
        ss.update(security="reality",
                  realitySettings={"serverName":q.get('sni',addr),
                    "fingerprint":q.get('fp','chrome'),"publicKey":q.get('pbk',''),
                    "shortId":q.get('sid',''),"spiderX":q.get('spx','/')})
    elif sec == 'tls':
        ss["security"]="tls"
        ss["tlsSettings"]={"serverName":q.get('sni',addr),"fingerprint":q.get('fp','chrome')}
        if q.get('alpn'):
            ss["tlsSettings"]["alpn"]=[x for x in q['alpn'].split(',') if x]
        if q.get('pinSHA256'):
            ss["tlsSettings"]["pinnedPeerCertSha256"]=[q['pinSHA256']]
    else:
        ss["security"]="none"
    if net == 'ws':
        ss["network"]="ws"
        ss["wsSettings"]={"path":q.get('path','/'),"headers":{"Host":q.get('host') or q.get('sni') or addr}}
    elif net == 'xhttp':
        ss["network"]="xhttp"
        ss["xhttpSettings"]={"path":q.get('path','/'),"host":q.get('host') or q.get('sni') or addr,"mode":q.get('mode','auto')}
    elif net == 'grpc':
        ss["network"]="grpc"
        ss["grpcSettings"]={"serviceName":q.get('serviceName','')}
    else:
        ss["network"]="tcp"
    out["streamSettings"]=ss
    inb={"listen":"127.0.0.1","port":SOCK,"protocol":"socks","settings":{"auth":"noauth","udp":True},"tag":"socks-in"}
    return {"log":{"loglevel":"warning"},"inbounds":[inb],
            "outbounds":[out,{"protocol":"freedom","tag":"direct"}]}

def is_running():
    if os.path.exists(PIDFILE):
        try:
            pid = int(open(PIDFILE).read())
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, ValueError, PermissionError):
            pass
    return False

def start(server_index=0):
    if is_running():
        print(f"[aistudio] Tunnel already running on 127.0.0.1:{SOCK}")
        return False, None
    pool = json.load(open(POOL))
    if not pool:
        raise SystemExit("No working servers saved. Run 'verify' first.")
    srv = pool[server_index % len(pool)]
    cfg = build_cfg(srv)
    cfgpath = "/tmp/dastyab_aistudio.json"
    open(cfgpath,"w").write(json.dumps(cfg))
    proc = subprocess.Popen([XRAY,"run","-c",cfgpath],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(PIDFILE,"w").write(str(proc.pid))
    open("/tmp/dastyab_aistudio_idx","w").write(str(server_index % len(pool)))
    # wait for port
    for _ in range(20):
        s=socket.socket()
        try:
            s.connect(("127.0.0.1",SOCK)); s.close(); break
        except Exception:
            time.sleep(0.3); s.close()
    print(f"[aistudio] Tunnel started via {srv['addr']}:{srv['port']} (pid {proc.pid})")
    print(f"[aistudio] Local SOCKS5 proxy: 127.0.0.1:{SOCK}")
    print(f"[aistudio] Your clean egress IP:")
    subprocess.run(["curl","-s","--max-time","15","--socks5-hostname",
                    f"127.0.0.1:{SOCK}","https://api.ipify.org"])
    print()
    print(f"[aistudio] Opening AI Studio through the tunnel...")
    launch_browser()
    return True, server_index % len(pool)

def probe_egress(timeout=12):
    """Return current egress IP via tunnel, or None if tunnel dead."""
    try:
        r = subprocess.run(["curl","-s","--max-time",str(timeout),
            "--socks5-hostname",f"127.0.0.1:{SOCK}","https://api.ipify.org"],
            capture_output=True, text=True, timeout=timeout+3)
        out = r.stdout.strip()
        return out if out and not out.startswith("curl") else None
    except Exception:
        return None

def watch(interval=20, max_fail=2):
    """Self-healing daemon: probe the tunnel; if it dies, swap to the next
    live server from the pool. Runs in the background."""
    import random
    pool = json.load(open(POOL))
    if not pool:
        raise SystemExit("Empty pool")
    fail = 0
    idx = 0
    if os.path.exists("/tmp/dastyab_aistudio_idx"):
        try: idx = int(open("/tmp/dastyab_aistudio_idx").read())
        except: pass
    print(f"[aistudio] Watchdog started: probing every {interval}s (pool={len(pool)})")
    while True:
        time.sleep(interval)
        ip = probe_egress()
        if ip:
            fail = 0
            continue
        fail += 1
        if fail >= max_fail:
            print(f"[aistudio] Tunnel down (probe {fail}). Rotating server...")
            # stop current
            stop()
            time.sleep(1)
            # try next servers until one works
            for off in range(1, len(pool)+1):
                nxt = (idx + off) % len(pool)
                try:
                    started, _ = start(nxt)
                except Exception:
                    started = False
                time.sleep(4)
                if started and probe_egress():
                    idx = nxt
                    fail = 0
                    print(f"[aistudio] Switched to {pool[idx]['addr']}:{pool[idx]['port']}")
                    break
            else:
                print("[aistudio] No server in pool responded. Will retry.")

def stop():
    if os.path.exists(PIDFILE):
        try:
            pid=int(open(PIDFILE).read())
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        os.remove(PIDFILE)
    # also kill any xray we own
    subprocess.run(["bash","-c",f"for p in $(pgrep -f 'dastyab_aistudio.json'); do kill -9 $p 2>/dev/null; done"])
    print("[aistudio] Tunnel stopped")

def launch_browser():
    # The desktop browser (Chrome) with our SOCKS5 proxy.
    ch = "/opt/google/chrome/google-chrome"
    if os.path.exists(ch):
        tmp = os.path.join(HOME, ".dastyab-aistudio-profile")
        os.makedirs(tmp, exist_ok=True)
        subprocess.Popen([ch,"--ozone-platform=x11",
                          f"--proxy-server=socks5://127.0.0.1:{SOCK}",
                          f"--user-data-dir={tmp}", AISTUDIO_URL],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[aistudio] Opened Chrome with the tunnel proxy.")
    else:
        print("[aistudio] Chrome not found at /opt/google/chrome/google-chrome")

def verify():
    pool = json.load(open(POOL)) if os.path.exists(POOL) else []
    if not pool:
        print("[aistudio] No verified servers stored yet. Run with a server list to build the pool.")
        return
    print(f"[aistudio] {len(pool)} verified working servers in pool:")
    for s in pool:
        print(f"   {s['addr']}:{s['port']}  egress {s.get('egress','?')}")
    if is_running():
        print(f"[aistudio] Tunnel is running — check your IP through it:")
        subprocess.run(["curl","-s","--max-time","15","--socks5-hostname",
                        f"127.0.0.1:{SOCK}","https://api.ipify.org"]); print()

def pop_pool(uris_txt):
    sys.path.insert(0,"/tmp")
    import test_fresh_vless as tfv
    uris=[tfv.parse_vless(l.strip()) for l in open(uris_txt) if l.strip().startswith("vless://")]
    uris=[u for u in uris if u]
    import random; random.seed(1); random.shuffle(uris)
    working=[]
    for u in uris[:30]:
        ip = tfv.test(u)
        if ip:
            working.append({**u,"egress":ip})
        if len(working)>=6: break
    os.makedirs(os.path.dirname(POOL), exist_ok=True)
    json.dump(working, open(POOL,"w"), indent=1)
    print(f"Built pool: {len(working)} working servers -> {POOL}")

if __name__=="__main__":
    cmd = sys.argv[1] if len(sys.argv)>1 else "start"
    if cmd=="start":
        idx = int(sys.argv[2]) if len(sys.argv)>2 else 0
        start(idx)
    elif cmd=="stop":
        stop()
    elif cmd=="verify":
        verify()
    elif cmd=="watch":
        interval = int(sys.argv[2]) if len(sys.argv)>2 else 20
        watch(interval=interval)
    elif cmd=="build-pool":
        pop_pool(sys.argv[2])
    else:
        print(__doc__)
