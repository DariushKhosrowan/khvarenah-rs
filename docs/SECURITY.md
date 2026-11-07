# Security

This page covers Khvarenah's threat model, hardening, and the built-in audit.

## What we protect

1. **Cloudflare API tokens** — the keys to your account.
2. **VLESS profiles** — your proxy UUIDs and endpoints.
3. **The local machine** — any file that could leak the above.

## Storage hardening

| Item | Location | Mode |
|---|---|---|
| Memory root | `~/.khvarenah/` | 0700 |
| Profile dirs | `~/.khvarenah/profiles/` | 0700 |
| Token files | `.../token.json` | 0600 |
| Everything else | `.../*.json` | 0644 |

Writes are atomic; a crash never leaves a half-written token file.

## Threat model

| Threat | Mitigation |
|---|---|
| Token leaked to a world-readable file | Security audit + 0600 defaults |
| Token exfiltrated via logs | No token ever printed (masked only) |
| Malicious JSON in import | Import only parses known profile shape; tokens are never shown |
| API abuse detection | Stealth pacing; randomized worker fingerprints |
| Replay of deploy | Humanized per-deploy byte variation |

## The security audit

`khvarenah security` (and the GUI **Tools** tab) runs `security::audit()`:

- Checks directory modes are 0700.
- Checks token files are 0600.
- Scans all JSON under `~/.khvarenah/` for `"token"` fields outside
  legitimate token stores.
- Prints a verdict: **HEALTHY** or **ACTION REQUIRED** with concrete fixes.

## Disabling stealth

Set `KHVARENAH_STEALTH=0` in the environment, or use `khvarenah --no-stealth`
for a single run. Some users disable pacing for local testing or where the
anti-bot behavior is unnecessary.

## Reporting a vulnerability

Open a security issue on the repository. Do **not** disclose token-related
issues publicly with real values.

## Keep tokens off the wire

Tokens are only ever sent as `Authorization: Bearer` to
`api.cloudflare.com` over TLS. They are never embedded in share links, worker
code, or exported configs.
