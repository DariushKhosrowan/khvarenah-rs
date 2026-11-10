//! Embedded Cloudflare Worker script for the control-plane DNS tunnel.
//!
//! Mirrors the presets.rs idiom: the bundle is a raw string constant compiled
//! into the crate (no runtime file reads). The Worker implements the
//! tunnel-server side of the `dnstunnel::TunnelFrame` protocol over HTTPS:
//! it authenticates via the `DYB_SESSION_SECRET` secret var, decodes the
//! incoming qname frame, and answers per `flags`.

/// The worker script, verbatim (module syntax, `export default { fetch }`).
pub const WORKER_TUNNEL_JS: &str = r#"// DastYab control-plane DNS-tunnel Worker (flags 1/2/3).
// Protocol: client sends GET /?q=<encoded-qname> with header
// X-DastYab-Session: <secret>. Worker decodes the frame, answers per flags
// (1=ping→pong, 2=status, 3=bootstrap, 0=data-plane→501). Reply is the
// encoded reply qname as text/plain.

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
  // [nonce, seq, flags, ...payload..., session, base]
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

export default {
  async fetch(request, env, ctx) {
    const secret = env.DYB_SESSION_SECRET;
    if (!secret) return json(500, { error: "no-secret" });
    const h = request.headers.get("X-DastYab-Session") || "";
    if (h !== secret) return json(401, { error: "session" });
    const u = new URL(request.url);
    const q = u.searchParams.get("q");
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
      const sub = (env.CF_SUBDOMAIN || u.hostname).replace(env.CF_WORKER ? env.CF_WORKER + "." : "", "");
      return text(encFrame(f.seq, 0x83, sub, f.session, base));
    }
    return json(501, { error: "data-plane-not-yet" });
  },
};
"#;
