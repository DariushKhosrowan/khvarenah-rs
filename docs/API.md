# Cloudflare API Coverage

DastYab talks to the **Cloudflare v4 API** through `dastyab-core::cf`.
This page documents exactly which endpoints are covered, why, and how the
client is structured.

## Base URL

```
https://api.cloudflare.com/client/v4
```

All requests carry `Authorization: Bearer <token>` and `Content-Type:
application/json`. The client uses **reqwest + rustls** (no OpenSSL system
dependency).

## Error envelope

Cloudflare returns errors as:

```json
{
  "success": false,
  "errors": [{ "code": 9109, "message": "..." }]
}
```

DastYab translates these into a `CFError { title, detail, fix }` via
`error::explain_response`. Every non-2xx response goes through this path, so
the user always sees an actionable message.

## Covered endpoints

### Account & token

| Method | Path | Purpose |
|---|---|---|
| GET | `/user/tokens/verify` | Validate token |
| GET | `/accounts` | List accessible accounts |
| GET | `/accounts/{id}/workers/subdomain` | Get workers.dev subdomain |

### Workers

| Method | Path | Purpose |
|---|---|---|
| GET | `/accounts/{id}/workers/scripts` | List scripts |
| PUT | `/accounts/{id}/workers/scripts/{name}` | Deploy (multipart) |
| PATCH | `/accounts/{id}/workers/scripts/{name}/settings` | Set vars |
| DELETE | `/accounts/{id}/workers/scripts/{name}` | Delete script |
| GET | `/accounts/{id}/workers/scripts/{name}/analytics/summary` | Usage |

### Zones & DNS

| Method | Path | Purpose |
|---|---|---|
| GET | `/zones` | List zones |
| GET | `/zones/{id}/dns_records` | List records |
| POST | `/zones/{id}/dns_records` | Create record |
| DELETE | `/zones/{id}/dns_records/{rid}` | Delete record |

### Worker routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/accounts/{id}/workers/routes` | List routes |
| POST | `/accounts/{id}/workers/routes` | Create route |
| DELETE | `/accounts/{id}/workers/routes/{rid}` | Delete route |

## The `Client` type

```rust
pub struct Client {
    token: String,
    http: reqwest::Client,
    timeout: Duration,
}
```

- `Client::new(token)` — builds the HTTP client with rustls.
- Every public method is `async fn … -> Result<T, CFError>`.
- Deploy uses multipart with `metadata` (compatibility date + flags) and
  `_worker.js` parts.

## Rate limiting & retries

- `deploy_script` retries on 429 / 5xx with exponential backoff.
- All writes go through stealth pacing (see `stealth.rs`).

## Throttling notes

The client is deliberately simple: one request at a time, with human-shaped
pauses. This keeps it invisible to Cloudflare's abuse heuristics and is easy
to reason about.
