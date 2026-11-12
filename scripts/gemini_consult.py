#!/usr/bin/env python3
"""One-shot Gemini consult through the layered aistudio SOCKS5 tunnel (10850).
Usage: python3 scripts/gemini_consult.py "PROMPT" [MODEL]
"""
import sys, os, json, urllib.request, urllib.error

KEY = os.environ.get("DYB_GEMINI_KEY", "")
if not KEY:
    print("ERR: DYB_GEMINI_KEY env var not set")
    sys.exit(2)
PROXY = "socks5h://127.0.0.1:10850"
MODEL = sys.argv[2] if len(sys.argv) > 2 else "gemini-3-flash-preview"
PROMPT = sys.argv[1]

import socks, socket
socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 10850)
socket.socket = socks.socksocket

url = f"https://generativelanguage.googleapis.com/v1beta/models/{MODEL}:generateContent"
body = json.dumps({"contents": [{"parts": [{"text": PROMPT}]}]}).encode()
req = urllib.request.Request(url, data=body, method="POST")
req.add_header("x-goog-api-key", KEY)
req.add_header("Content-Type", "application/json")
try:
    with urllib.request.urlopen(req, timeout=90) as r:
        d = json.load(r)
    cand = d.get("candidates", [{}])[0]
    txt = cand.get("content", {}).get("parts", [{}])[0].get("text", "")
    if not txt:
        print(json.dumps(d, indent=2)[:2000])
    else:
        print(txt)
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode()[:1500])
except Exception as e:
    print("ERR", type(e).__name__, e)
