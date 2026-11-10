//! Embedded Cloudflare Worker script for the worker-hosted DNS tunnel.
//!
//! Mirrors the presets.rs idiom: the bundle is a raw string constant compiled
//! into the crate (no runtime file reads). The Worker serves two roles:
//!
//! 1. **Control plane** (flags 1/2/3) — the liveness/status/bootstrap protocol
//!    over HTTPS GET `/?q=<encoded-qname>` with the `X-DastYab-Session`
//!    header. Decodes the `dnstunnel::TunnelFrame` qname and answers per
//!    `flags`.
//!
//! 2. **Data plane / dumb pipe** (`/ws` WebSocket upgrade) — the raw relay.
//!    The user's external VLESS client (v2rayN/sing-box/Clash) speaks
//!    VLESS-over-WS to this endpoint; the Worker authenticates the session
//!    header, then pipes every binary WS frame verbatim to the configured
//!    `DYB_VLESS_UPSTREAM` host:port over TCP and forwards every TCP read back
//!    as a binary WS frame. No VLESS parsing anywhere — it is a byte pipe, so
//!    it needs no VLESS codec.

/// The worker script, verbatim (module syntax, `export default { fetch }`).
pub const WORKER_TUNNEL_JS: &str = r#"// DastYab worker-hosted tunnel.
// Control plane: GET /?q=<encoded-qname> → flags 1/2/3.
// Data plane:   /ws WebSocket upgrade → dumb WS<->TCP pipe to DYB_VLESS_UPSTREAM.

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

function b32encode(data) {
  const bytes = new TextEncoder().encode(data);
  let out = "", buf = 0, bits = 0;
  for (const b of bytes) {
    buf = (buf << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += B32[(buf >> bits) & 31]; }
  }
  if (bits > 0) out += B32[(buf << (5 - bits)) & 31];
  return out;
}

function b32decode(s) {
  const s2 = s.toLowerCase(); const bytes = [];
  let buf = 0, bits = 0;
  for (const c of s2) {
    const v = B32.indexOf(c);
    if (v < 0) return null;
    buf = (buf << 5) | v; bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((buf >> bits) & 255); }
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function encFrame(seq, flags, payload, session, base) {
  const nonce = Math.floor(Math.random() * 65535).toString(16);
  const p = b32encode(payload);
  const labels = [];
  for (let i = 0; i < p.length; i += 63) labels.push(p.slice(i, i + 63));
  const mid = labels.join(".");
  let name = nonce + "." + seq + "." + flags;
  if (mid) name += "." + mid;
  return name + "." + session + "." + base;
}

function decFrame(name) {
  const core = name.replace(/\.$/, "");
  const labels = core.split(".");
  if (labels.length < 5) return null;
  const seq = parseInt(labels[1], 10);
  const flags = parseInt(labels[2], 10) || 0;
  const session = labels[labels.length - 2];
  const payload = b32decode(labels.slice(3, labels.length - 2).join(""));
  if (payload === null) return null;
  return { seq, flags, session, payload };
}

function json(status, obj) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function authed(request, env) {
  if (!env.DYB_SESSION_SECRET) return false;
  return (request.headers.get("X-DastYab-Session") || "") === env.DYB_SESSION_SECRET;
}

// ---- /ws dumb pipe ----
async function handleWs(request, env) {
  if (!authed(request, env)) {
    return new Response("forbidden", { status: 401 });
  }
  const upstream = (env.DYB_VLESS_UPSTREAM || "").trim();
  if (!upstream) {
    return json(500, { error: "no-upstream" });
  }
  const parts = upstream.split(":");
  if (parts.length !== 2) {
    return json(500, { error: "bad-upstream" });
  }
  const hostname = parts[0];
  const port = parseInt(parts[1], 10);
  if (!hostname || !port || port <= 0 || port > 65535) {
    return json(500, { error: "bad-upstream" });
  }

  const pair = new WebSocketPair();
  const { 0: client, 1: server } = pair;

  server.accept();
  let tcp;
  try {
    tcp = connect({ hostname, port });
  } catch (e) {
    server.close(1011, "upstream unavailable");
    return new Response("upstream unavailable", { status: 502 });
  }

  const tcpReader = tcp.readable.getReader();
  const tcpWriter = tcp.writable.getWriter();

  // TCP -> WS
  (async () => {
    try {
      while (true) {
        const { value, done } = await tcpReader.read();
        if (done) break;
        server.send(value);
      }
    } catch (e) {}
    try { server.close(); } catch (e) {}
  })();

  // WS -> TCP
  server.addEventListener("message", (ev) => {
    const data = ev.data;
    if (typeof data === "string") {
      tcpWriter.write(new TextEncoder().encode(data));
    } else {
      tcpWriter.write(data);
    }
  });
  server.addEventListener("close", () => {
    try { tcp.close(); } catch (e) {}
  });
  server.addEventListener("error", () => {
    try { tcp.close(); } catch (e) {}
  });

  return new Response(null, { status: 101, webSocket: client });
}

// ---- /ctl carrier-snapshot relay (flags 4/5) ----
async function handleCtl(request, env) {
  if (!authed(request, env)) {
    return json(401, { error: "session" });
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json(400, { error: "json" });
  }
  if (body.flag === 4) {
    const snap = await env.DYB_CARRIER_SNAPSHOT.get("snapshot", { type: "json" });
    if (!snap) return json(200, { snapshot: null, server_generation: 0 });
    const serverGen = Number((await env.DYB_CARRIER_SNAPSHOT.get("server_generation")) ?? "0");
    return json(200, { snapshot: snap, server_generation: serverGen });
  }
  if (body.flag === 5) {
    const snap = body.snapshot;
    if (!snap || snap.schema_version !== 1) {
      return json(400, { error: "bad-schema" });
    }
    await env.DYB_CARRIER_SNAPSHOT.put("snapshot", JSON.stringify(snap));
    const cur = Number((await env.DYB_CARRIER_SNAPSHOT.get("server_generation")) ?? "0");
    await env.DYB_CARRIER_SNAPSHOT.put("server_generation", String(cur + 1));
    return json(200, { stored_generation: cur + 1 });
  }
  return json(400, { error: "unknown-flag" });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/ws") {
      return handleWs(request, env);
    }
    if (url.pathname === "/ctl" && request.method === "POST") {
      return handleCtl(request, env);
    }

    // Control plane (flags 1/2/3).
    if (!authed(request, env)) return json(401, { error: "session" });
    const q = url.searchParams.get("q");
    if (!q) return json(400, { error: "frame" });
    const f = decFrame(q);
    if (!f) return json(400, { error: "frame" });
    const base = env.DYB_TUNNEL_BASE || "tun.dastyab.dev";
    const text = (s) => new Response(s, {
      status: 200,
      headers: { "content-type": "text/plain" },
    });
    if (f.flags === 1) {
      return text(encFrame(f.seq, 0x81, "pong", f.session, base));
    }
    if (f.flags === 2) {
      const status = JSON.stringify({ ok: true, service: "dastyab-worker-tunnel" });
      return text(encFrame(f.seq, 0x82, status, f.session, base));
    }
    if (f.flags === 3) {
      const sub = (env.CF_SUBDOMAIN || url.hostname).replace(env.CF_WORKER ? env.CF_WORKER + "." : "", "");
      return text(encFrame(f.seq, 0x83, sub, f.session, base));
    }
    return json(501, { error: "data-plane-not-yet" });
  },
};
"#;

#[cfg(test)]
mod tests {
    use super::WORKER_TUNNEL_JS;

    #[test]
    fn bundle_contains_flag4_flag5_ctl_relay() {
        assert!(WORKER_TUNNEL_JS.contains("pathname === \"/ctl\""));
        assert!(WORKER_TUNNEL_JS.contains("body.flag === 4"));
        assert!(WORKER_TUNNEL_JS.contains("body.flag === 5"));
        assert!(WORKER_TUNNEL_JS.contains("DYB_CARRIER_SNAPSHOT"));
        assert!(WORKER_TUNNEL_JS.contains("server_generation"));
    }

    #[test]
    fn bundle_still_serves_control_plane_and_ws() {
        assert!(WORKER_TUNNEL_JS.contains("pathname === \"/ws\""));
        assert!(WORKER_TUNNEL_JS.contains("f.flags === 1"));
        assert!(WORKER_TUNNEL_JS.contains("f.flags === 2"));
        assert!(WORKER_TUNNEL_JS.contains("f.flags === 3"));
    }
}
