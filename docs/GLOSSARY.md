# Glossary

| Term | Meaning |
|---|---|
| **VLESS** | A lightweight, modern proxy protocol (evolution of VMess). |
| **vless:// link** | A portable URI that encodes a VLESS client config. |
| **Worker** | A Cloudflare Workers script that runs at the edge. |
| **edgetunnel** | The classic VLESS/WebSocket worker template. |
| **Clean IP** | A Cloudflare IP that is not filtered/blocked and routes your traffic. |
| **SenPaiScanner** | A tool that probes Cloudflare IPs for clean, fast endpoints. |
| **Compatibility date** | Cloudflare's per-worker API/feature compatibility marker. |
| **SNI** | Server Name Indication — the TLS hostname sent to the server. |
| **WS / WebSocket** | The transport used to carry VLESS traffic. |
| **v2rayN / v2rayNG** | Popular VLESS client apps (Windows / Android). |
| **sing-box** | A universal proxy platform with a JSON config. |
| **Clash / Clash.Meta** | Rule-based proxy clients (YAML config). |
| **Stealth pacing** | Randomized human-like delays between API calls. |
| **Fingerprint humanization** | Varying deployed worker bytes to avoid identical deployments. |
| **Profile** | An isolated set of tokens, accounts, history, and settings. |
| **CFError** | The structured error type carrying title/detail/fix. |
| **Atomic write** | A file write that is crash-safe (tempfile + rename). |
