#!/usr/bin/env python3
"""
dastyab-aistudio-cleanip.py
Structured clean-IP access to Google AI Studio on the DastYab project.

Why: AI Studio's workspace is region-gated. Iran is not a supported region, so the
product shows "your region may not be supported" from a direct Iranian IP. Google
also blocks Tor exits. The DastYab project already has 2000+ real provider
profiles (VLESS/Trojan/Hysteria2/etc.) from supported countries. This tool reuses
one of those servers as a clean-IP egress.

Usage:
  python3 dastyab-aistudio-cleanip.py test --country US   # pick US server, test AI Studio
  python3 dastyab-aistudio-cleanip.py socks --port 10850 # start SOCKS5 proxy on clean IP
  python3 dastyab-aistudio-cleanip.py stop                # stop proxy
  python3 dastyab-aistudio-cleanip.py list --country DE   # list server options
"""
import json, glob, os, re, signal, subprocess, sys, time, socket, argparse

XRAY = "/tmp/xraybin/xray"
PROFILE_DIR = os.path.expanduser("~/.config/nekoray/config/profiles")
STUDIO = "https://aistudio.google.com/"
API = "https://generativelanguage.googleapis.com/v1beta/models"
IPIFY = "https://api.ipify.org"
SOCK = 10850

def load_profiles():
    out = []
    for f in sorted(glob.glob(os.path.join(PROFILE_DIR, "*.json"))):
        try:
            d = json.load(open(f))
            b = d.get('bean', {})
            if not b.get('addr'): continue
            out.append({'file': f, 'type': d.get('type',''),
                        'name': b.get('name',''), 'addr': b.get('addr'),
                        'port': b.get('port'), 'bean': b})
        except Exception:
            pass
    return out

def flag_country(name):
    # map common emoji flags -> 2-letter code, plus text hints
    m = {
        '🇺🇸':'US','🇩🇪':'DE','🇬🇧':'GB','🇨🇦':'CA','🇫🇮':'FI','🇫🇷':'FR',
        '🇳🇱':'NL','🇵🇱':'PL','🇹🇷':'TR','🇷🇺':'RU','🇱🇹':'LT','🇯🇵':'JP',
        '🇰🇷':'KR','🇹🇼':'TW','🇸🇪':'SE','🇨🇭':'CH','🇦🇺':'AU','🇮🇹':'IT',
        '🇪🇸':'ES','🇳🇴':'NO','🇩🇰':'DK', '🇺🇦':'UA'}
    for flag, code in m.items():
        if flag in name: return code
    # text country hints
    for code in ['US','DE','GB','CA','FI','FR','NL','PL','TR','JP','KR','SE','CH','AU','IT','ES','NO','DK']:
        if code.lower() in name.lower(): return code
    return '??'

def pick_servers(country=None, limit=8):
    profs = load_profiles()
    if country:
        profs = [p for p in profs if flag_country(p['name'])==country.upper()]
    if not profs:
        return [], profs
    # prefer vless then trojan then hysteria2 (xray speaks vless/trojan/vmess/ss)
    order = {'vless':0,'trojan':1,'vmess':2,'shadowsocks':3,'hysteria2':4}
    profs.sort(key=lambda p: order.get(p['type'],9))
    return profs[:limit], profs

def bean_to_xray_outbound(p):
    """Convert a nekoray bean dict to an xray outbound JSON."""
    b = p['bean']; typ = p['type']; addr = b['addr']; port = b['port']
    stream = b.get('stream', {})
    net = stream.get('net','tcp'); sec = stream.get('sec','none')
    out = {}

    if typ == 'vless':
        v = {"protocol":"vless","settings":{"vnext":[{"address":addr,"port":port,"users":[{"id":b.get('pass'),"encryption":"none"}]}]}}
        out = v
    elif typ == 'trojan':
        out = {"protocol":"trojan","settings":{"servers":[{"address":addr,"port":port,"password":b.get('pass')}]}}
    elif typ == 'vmess':
        out = {"protocol":"vmess","settings":{"vnext":[{"address":addr,"port":port,"users":[{"id":b.get('pass'),"alterId":0}]}]}}
    elif typ == 'shadowsocks':
        out = {"protocol":"shadowsocks","settings":{"servers":[{"address":addr,"port":port,"method":b.get('method','aes-256-gcm'),"password":b.get('pass')}]}}
    else:
        return None

    # stream settings
    ss = {}
    if sec == 'tls':
        ss['security']='tls'; ss['tlsSettings']={'serverName':stream.get('sni',addr),
            'fingerprint':stream.get('utls','chrome')}
    elif sec == 'reality':
        ss['security']='reality'; ss['realitySettings']={'serverName':stream.get('sni',addr),
            'fingerprint':stream.get('utls','chrome'),'publicKey':stream.get('pbk',''),
            'shortId':stream.get('sid',''),'spiderX':'/'}
    else:
        ss['security']='none'

    if net == 'ws':
        ss['network']='ws'; ss['wsSettings']={'path':stream.get('path','/'),'headers':{'Host':stream.get('host') or stream.get('sni') or addr}}
    elif net == 'xhttp':
        ss['network']='xhttp'; ss['xhttpSettings']={'path':stream.get('path','/'),'host':stream.get('host') or stream.get('sni') or addr}
    elif net == 'grpc':
        ss['network']='grpc'; ss['grpcSettings']={'serviceName':stream.get('servicename','')}
    else:
        ss['network']='tcp'
        # tcp + reality usually needs no extra

    if 'flow' in b and b.get('flow'):
        out['settings']['vnext'][0]['users'][0]['flow'] = b.get('flow')

    out['streamSettings'] = ss
    return out

def build_config(p):
    ob = bean_to_xray_outbound(p)
    if not ob:
        return None
    # inbound SOCKS
    inb = {"listen":"127.0.0.1","port":SOCK,"protocol":"socks",
           "settings":{"auth":"noauth","udp":True},"tag":"socks-in"}
    return {"log":{"loglevel":"warning"},
            "inbounds":[inb],
            "outbounds":[ob,{"protocol":"freedom","tag":"direct"}]}

def http_code(url, proxy=None, timeout=20):
    cmd = ["curl","-s","-o","/dev/null","-w","%{http_code}","--max-time",str(timeout)]
    if proxy:
        cmd += ["--socks5-hostname", f"127.0.0.1:{proxy}"]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.stdout.strip() or "000"

def egress_ip(proxy=None):
    return http_code_simple(IPIFY if False else IPIFY, proxy)  # placeholder

def http_code_simple(url, proxy):
    cmd = ["curl","-s","--max-time","15"]
    if proxy: cmd += ["--socks5-hostname", f"127.0.0.1:{proxy}"]
    cmd.append(url)
    return subprocess.run(cmd, capture_output=True, text=True).stdout.strip()

def wait_port(port, timeout=15):
    end = time.time()+timeout
    while time.time()<end:
        try:
            socket.create_connection(("127.0.0.1",port), 0.5).close(); return True
        except OSError:
            time.sleep(0.4)
    return False

def start_proxy(server):
    cfg = build_config(server)
    if not cfg:
        return None, "no supported outbound type"
    cfgpath = "/tmp/aistudio-cleanip.json"
    with open(cfgpath,"w") as f: json.dump(cfg,f)
    pidf = "/tmp/aistudio-cleanip.pid"
    proc = subprocess.Popen([XRAY,"run","-c",cfgpath],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # daemonize isn't needed; keep proc. Write pid file.
    open(pidf,"w").write(str(proc.pid))
    if wait_port(SOCK):
        return proc, "ok"
    proc.terminate()
    return None, "xray failed to bind"

def stop_proxy():
    try:
        pid = int(open("/tmp/aistudio-cleanip.pid").read())
        os.kill(pid, signal.SIGTERM)
        open("/tmp/aistudio-cleanip.pid","w").write("")
        return "stopped"
    except Exception:
        return "no proxy running"

def cmd_test(country):
    servers, _ = pick_servers(country)
    if not servers:
        print(f"No servers found for country {country}")
        return 1
    # try up to 6 servers until one passes AI Studio
    for idx, srv in enumerate(servers[:6]):
        print(f"\n[{idx+1}] trying {srv['type']} {srv['addr']}:{srv['port']}  [{srv['name']}]")
        proc, msg = start_proxy(srv)
        if not proc:
            print("   start failed:", msg); continue
        ip = egress_ip(SOCK)
        print(f"   egress IP: {ip or '?'}")
        code = http_code(API, SOCK)
        print(f"   AI Studio API: HTTP {code} (403 no-key = reachable)")
        if code and code != "000":
            print("   ✓ clean-IP route working")
            stop_proxy()
            print(f"\nUSABLE: {srv['type']} {srv['addr']}:{srv['port']} [{srv['name']}]")
            print(f"Start SOCKS5 proxy on 127.0.0.1:{SOCK} with: python3 {sys.argv[0]} socks")
            return 0
        stop_proxy()
    print("\nNo server yielded a working route.")
    return 1

def cmd_socks(country):
    servers,_ = pick_servers(country)
    if not servers:
        print(f"No servers for {country}"); return 1
    srv = servers[0]
    proc, msg = start_proxy(srv)
    if not proc:
        print("failed:", msg); return 1
    print(f"SOCKS5 proxy running on 127.0.0.1:{SOCK}")
    print(f"via {srv['type']} {srv['addr']}:{srv['port']} [{srv['name']}]")
    print(f"egress IP: {egress_ip(SOCK)}")
    print("Point your browser at \"--proxy-server=socks5://127.0.0.1:10850\"")
    print("Stop with: python3 %s stop" % sys.argv[0])

def cmd_list(country):
    servers, allp = pick_servers(country)
    print(f"matched servers: {len(servers)} (of {len(allp)} total profiles)")
    for s in servers:
        print(f"  {s['type']:12} {s['addr']}:{s['port']}  [{s['name']}]")

def cmd_stop():
    print(stop_proxy())

def main():
    ap = argparse.ArgumentParser(description="DastYab AI Studio clean-IP access")
    ap.add_argument("cmd", choices=["test","socks","stop","list"])
    ap.add_argument("--country", default=None)
    a = ap.parse_args()
    if a.cmd=="test": return cmd_test(a.country)
    if a.cmd=="socks": return cmd_socks(a.country)
    if a.cmd=="stop": return cmd_stop()
    if a.cmd=="list": return cmd_list(a.country)

if __name__=="__main__":
    sys.exit(main())
