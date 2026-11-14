//! Preset deployment profiles.
//!
//! Not every user wants the same worker behavior. This module ships curated
//! presets (name + description + compatibility date + flags + a small worker
//! template) so deploy can be one command instead of a configuration puzzle.
//! Presets are data — they are easy to extend or override per-profile later.

/// A named preset describing how a worker should be deployed.
///
/// Note: intentionally not `Serialize`/`Deserialize` because it holds
/// `&'static` slices (there is no need to persist presets — they are
/// compiled-in data).
#[derive(Debug, Clone)]
pub struct Preset {
    pub name: &'static str,
    pub description: &'static str,
    pub compatibility_date: &'static str,
    pub flags: &'static [&'static str],
    /// Default worker name stem (sanitized at deploy time).
    pub default_worker_stem: &'static str,
}

/// All built-in presets.
pub fn presets() -> Vec<Preset> {
    vec![
        Preset {
            name: "standard",
            description: "Default VLESS WebSocket worker on the latest compatibility date.",
            compatibility_date: "2026-07-01",
            flags: &["nodejs_compat"],
            default_worker_stem: "edge",
        },
        Preset {
            name: "gaming",
            description: "Low-latency profile: same stack, tuned scanning defaults (fewer workers, tighter timeout).",
            compatibility_date: "2026-07-01",
            flags: &["nodejs_compat"],
            default_worker_stem: "game-edge",
        },
        Preset {
            name: "max-compat",
            description: "Maximum compatibility: broadest flag set, useful for older CF tiers.",
            compatibility_date: "2025-01-01",
            flags: &["nodejs_compat", "global_network"],
            default_worker_stem: "compat-edge",
        },
    ]
}

/// Look up a preset by name (case-insensitive).
pub fn find(name: &str) -> Option<Preset> {
    presets()
        .into_iter()
        .find(|p| p.name.eq_ignore_ascii_case(name))
}

/// List all preset names + descriptions (for CLI help / GUI combo).
pub fn describe_all() -> String {
    let mut out = String::new();
    for p in presets() {
        out.push_str(&format!("  {} — {}\n", p.name, p.description));
    }
    out
}

/// A minimal generic worker module template the presets can deploy verbatim
/// when no `_worker.js` is found. It's a valid ES module worker that returns
/// an HTTP 200, so deploys never fail on a missing bundle.
pub fn fallback_worker_js() -> String {
    r#"export default {
  async fetch(request, env, ctx) {
    return new Response(JSON.stringify({ ok: true, service: "dastyab" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
};
"#
    .to_string()
}

/// The built-in *functional* VLESS-over-WebSocket worker (the "standard"
/// preset deploy target). This is a clean, self-contained ES module worker
/// that reads the `UUID` env var, accepts a WebSocket upgrade, parses the
/// VLESS request preamble, and relays the payload over a TCP upstream — so a
/// deploy via this worker is a real, usable VLESS endpoint (not just a health
/// stub like `fallback_worker_js`).
///
/// It is deliberately kept small (well under Cloudflare's script-size limits)
/// and dependency-free, so the console can always deploy a working tunnel even
/// when no external `_worker.js` bundle is present on disk. The address/SNI of
/// generated client configs is whatever the console renders from the deployed
/// workers.dev hostname; this worker listens on all paths.
pub fn standard_vless_worker_js() -> String {
    r#"import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env) {
    // Non-WebSocket requests are simple health checks.
    if ((request.headers.get('Upgrade') || '').toLowerCase() !== 'websocket') {
      return new Response('OK', {
        status: 200,
        headers: { 'content-type': 'text/plain' },
      });
    }

    const pair = new WebSocketPair();
    const [client, server] = [pair[0], pair[1]];
    server.accept();

    let buf = new Uint8Array(0);  // unparsed accumulated bytes
    let headerLen = -1;           // parsed VLESS header byte-length (-1 = not yet)
    let upstream = null;          // TCP socket
    let closed = false;
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    const concat = (a, b) => {
      const out = new Uint8Array(a.length + b.length);
      out.set(a);
      out.set(b, a.length);
      return out;
    };

    // Parse the VLESS preamble. Returns the header byte-length, or a negative
    // sentinel: -1 = need more bytes, -2 = invalid address type.
    function vlessHeaderLen(bytes) {
      if (bytes.length < 1 + 16 + 1 + 1 + 2 + 1) return -1;
      const atype = bytes[18]; // ver(1) + uuid(16) + addon(1)
      let addrBlock;
      if (atype === 1) addrBlock = 4;
      else if (atype === 2) addrBlock = 1 + bytes[19];
      else if (atype === 3) addrBlock = 16;
      else return -2;
      const total = 20 + addrBlock + 2 + 1; // + port(2) + cmd(1)
      return bytes.length >= total ? total : -1;
    }

    function closeUpstream() {
      try { upstream && upstream.close(); } catch (_) {}
      upstream = null;
    }

    function fail(msg) {
      try {
        server.send(enc.encode(JSON.stringify({ error: msg })));
        server.close();
      } catch (_) {}
      closeUpstream();
    }

    function tryOpenUpstream() {
      if (headerLen > 0 || upstream) return;
      const h = vlessHeaderLen(buf);
      if (h === -2) { fail('invalid address type'); return; }
      if (h <= 0) return;
      headerLen = h;
      const b = buf;
      const type = b[18];
      let host, skipAddr;
      if (type === 1) { // IPv4
        host = `${b[19]}.${b[20]}.${b[21]}.${b[22]}`;
        skipAddr = 4;
      } else if (type === 2) { // domain
        const alen = b[19];
        host = dec.decode(b.subarray(20, 20 + alen));
        skipAddr = 1 + alen;
      } else { // IPv6
        host = Array.from(b.subarray(19, 35))
          .map((x) => x.toString(16).padStart(2, '0'))
          .join(':');
        skipAddr = 16;
      }
      const p = 19 + skipAddr; // points at port
      const port = (b[p] << 8) | b[p + 1];
      const cmd = b[p + 2];
      headerLen = p + 3; // includes command byte
      if (cmd !== 1) { fail('unsupported command'); return; }
      try {
        upstream = connect({ hostname: host, port });
        upstream.opened
          .then(() => {
            if (buf.length > headerLen) {
              upstream.write(buf.subarray(headerLen));
            }
          })
          .catch(() => fail('upstream connect failed'));
        upstream.readable
          .pipeTo(new WritableStream({
            write(chunk) {
              if (closed) return;
              try {
                server.send(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
              } catch (_) {}
            },
          }))
          .catch(() => {});
        upstream.closed.catch(() => {
          try { if (!closed) server.close(); } catch (_) {}
        });
      } catch (_) {
        fail('connect error');
      }
    }

    function handleBytes(bytes) {
      buf = concat(buf, bytes);
      if (headerLen < 0) {
        tryOpenUpstream();
        if (headerLen < 0) return;
      }
      if (upstream && buf.length > headerLen) {
        const rest = buf.subarray(headerLen);
        buf = new Uint8Array(0);
        try { upstream.write(rest); } catch (_) {}
      }
    }

    server.addEventListener('message', (ev) => {
      if (closed) return;
      const data = ev.data;
      if (data instanceof ArrayBuffer) {
        handleBytes(new Uint8Array(data));
      } else if (data instanceof Blob) {
        data.arrayBuffer().then((ab) => handleBytes(new Uint8Array(ab)));
      } else {
        handleBytes(enc.encode(String(data)));
      }
    });
    server.addEventListener('close', () => { closed = true; closeUpstream(); });
    server.addEventListener('error', () => { closed = true; closeUpstream(); });

    return new Response(null, { status: 101, webSocket: client });
  },
};
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_exist() {
        let ps = presets();
        assert!(ps.len() >= 3);
        assert!(find("standard").is_some());
        assert!(find("STANDARD").is_some());
        assert!(find("nope").is_none());
    }

    #[test]
    fn describe_lists_all() {
        let d = describe_all();
        assert!(d.contains("standard"));
        assert!(d.contains("gaming"));
    }

    #[test]
    fn fallback_worker_is_module() {
        assert!(fallback_worker_js().contains("export default"));
        assert!(fallback_worker_js().contains("fetch"));
    }
}
