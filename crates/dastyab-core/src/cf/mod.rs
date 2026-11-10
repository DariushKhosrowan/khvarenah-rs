//! Cloudflare v4 API client (async, reqwest + rustls).

pub mod ips;

use reqwest::{multipart, StatusCode};

use crate::error::{explain_response, CFError};
use crate::stealth::{pre_request_pause, retry_backoff};

pub const API: &str = "https://api.cloudflare.com/client/v4";
pub const DEFAULT_COMPAT_DATE: &str = "2026-07-01";

/// A Cloudflare account.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Account {
    pub id: String,
    pub name: String,
}

/// A deployed worker script record.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Script {
    pub id: String,
    pub name: String,
    pub modified_on: Option<String>,
    pub etag: Option<String>,
    pub created_on: Option<String>,
}

/// A Cloudflare zone.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub name_servers: Vec<String>,
}

/// A single DNS record.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DnsRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub zone_id: String,
    #[serde(default)]
    pub name: String,
    /// Record type: A / AAAA / CNAME / TXT / SRV / etc.
    #[serde(rename = "type", default)]
    pub record_type: String,
    #[serde(default)]
    pub content: String,
    /// Time-to-live in seconds (1 = automatic).
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// Whether the record is proxied through Cloudflare (orange-cloud).
    #[serde(default = "default_proxied")]
    pub proxied: bool,
}

fn default_ttl() -> u32 {
    120
}
fn default_proxied() -> bool {
    true
}

/// A worker custom route (e.g. `*example.com/*`).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct WorkerRoute {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub script: String,
}

/// Result of verifying a Cloudflare API token.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VerifyResult {
    /// Token status: `"active"` or `"disabled"`.
    pub status: String,
    /// The token id from Cloudflare.
    pub id: String,
    /// Optional token expiry (`"YYYY-MM-DDTHH:MM:SSZ"` or similar).
    pub expires_on: Option<String>,
}

/// Async Cloudflare client.
#[derive(Clone)]
pub struct Client {
    token: String,
    http: reqwest::Client,
    timeout: std::time::Duration,
    base_url: String,
}

impl Client {
    pub fn new(token: &str) -> Self {
        Self::with_base(token, API)
    }

    /// Test helper / advanced use: point the client at a different base URL
    /// (e.g. a local mock server).
    pub fn with_base(token: &str, base_url: &str) -> Self {
        Self {
            token: token.trim().to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(25))
                .user_agent("dastyab")
                .build()
                .expect("failed to build HTTP client"),
            timeout: std::time::Duration::from_secs(25),
            base_url: base_url.to_string(),
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        json_body: Option<serde_json::Value>,
        files: Option<multipart::Form>,
        action: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<serde_json::Value, CFError> {
        // stealth pacing: writes pause longer
        let is_write = matches!(method, "PUT" | "PATCH" | "DELETE" | "POST");
        pre_request_pause(if is_write { "write" } else { "read" }).await;

        let url = format!("{}{path}", self.base_url);
        let mut req = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes())
                    .map_err(|e| CFError::new("Internal", format!("{e}"), ""))?,
                &url,
            )
            .bearer_auth(&self.token)
            .header("Content-Type", "application/json");

        let eff_timeout = timeout.unwrap_or(self.timeout);
        req = req.timeout(eff_timeout);

        if let Some(form) = files {
            req = req.multipart(form);
        } else if let Some(body) = json_body {
            req = req.json(&body);
        }

        let resp = req.send().await.map_err(|e| {
            if e.is_timeout() {
                crate::error::wrap("timeout", &e)
            } else {
                crate::error::wrap("network", &e)
            }
        })?;

        let status = resp.status();
        let body = resp
            .json::<serde_json::Value>()
            .await
            .unwrap_or_else(|_| serde_json::json!({}));

        if status.is_success() {
            Ok(body)
        } else {
            Err(explain_response(status.as_u16(), Some(&body), action))
        }
    }

    /// Verify the token is valid and return structured details.
    pub async fn verify_token(&self) -> Result<VerifyResult, CFError> {
        let body = self
            .request(
                "GET",
                "/user/tokens/verify",
                None,
                None,
                "verify token",
                None,
            )
            .await?;
        let result = body.get("result").cloned().unwrap_or_default();
        Ok(VerifyResult {
            status: result
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string(),
            id: result
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            expires_on: result
                .get("expires_on")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        })
    }

    /// Create a new user-level API token via the Cloudflare API. Returns the
    /// raw token string (shown only once). The caller must persist it.
    ///
    /// The new token is scoped to the given account and grants worker +
    /// worker-routes permissions (the privileges the auto-rotation and
    /// deploy paths need). Requires the calling token to have the "User API
    /// Tokens Write" permission; if not the API returns 403 and
    /// `explain_response` surfaces the missing permission.
    pub async fn create_api_token(&self, account_id: &str, name: &str) -> Result<String, CFError> {
        // Cloudflare POST /user/tokens expects `permission_groups` as an
        // ARRAY of { id, name } objects (the framework tags), not an object.
        let body = serde_json::json!({
            "name": name,
            "policies": [{
                "effect": "allow",
                "resources": {
                    "com.cloudflare.api.account": {
                        account_id: {
                            "*": "*"
                        }
                    }
                },
                "permission_groups": [
                    { "id": "e5c7f8e9f1c64d0e8e2e3f4a5b6c7d8" },
                    { "id": "f6d8e9f0a2b75e1f9f3f4a5b6c7d8e9" }
                ]
            }]
        });
        let resp = self
            .request(
                "POST",
                "/user/tokens",
                Some(body),
                None,
                "create api token",
                None,
            )
            .await?;
        let result = resp.get("result").cloned().unwrap_or_default();
        result
            .get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                CFError::new(
                    "create-api-token",
                    "API response missing the new token value",
                    "The token was created but its value was not returned; verify in the CF dashboard.",
                )
            })
    }

    /// List accessible accounts.
    pub async fn list_accounts(&self) -> Result<Vec<Account>, CFError> {
        let body = self
            .request(
                "GET",
                "/accounts?per_page=100",
                None,
                None,
                "list accounts",
                None,
            )
            .await?;
        let list = body
            .get("result")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for a in list {
            out.push(Account {
                id: a
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: a
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
        Ok(out)
    }

    /// Get the workers subdomain for an account.
    pub async fn get_subdomain(&self, account_id: &str) -> Result<String, CFError> {
        let body = self
            .request(
                "GET",
                &format!("/accounts/{account_id}/workers/subdomain"),
                None,
                None,
                "get workers subdomain",
                None,
            )
            .await?;
        Ok(body
            .get("result")
            .and_then(|r| r.get("subdomain"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    /// List worker scripts.
    pub async fn list_scripts(&self, account_id: &str) -> Result<Vec<Script>, CFError> {
        let body = self
            .request(
                "GET",
                &format!("/accounts/{account_id}/workers/scripts?per_page=50"),
                None,
                None,
                "list scripts",
                None,
            )
            .await?;
        let list = body
            .get("result")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for s in list {
            out.push(Script {
                id: s
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: s
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                modified_on: s
                    .get("modified_on")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                etag: s
                    .get("etag")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                created_on: s
                    .get("created_on")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            });
        }
        Ok(out)
    }

    /// Worker analytics summary for a window (ISO-8601 since/until).
    pub async fn script_analytics(
        &self,
        account_id: &str,
        name: &str,
        since: &str,
        until: &str,
    ) -> Result<serde_json::Value, CFError> {
        let path = format!(
            "/accounts/{account_id}/workers/scripts/{name}/analytics/summary?since={since}&until={until}"
        );
        let body = self
            .request("GET", &path, None, None, "get worker analytics", None)
            .await?;
        Ok(body.get("result").cloned().unwrap_or(serde_json::json!({})))
    }

    /// Deploy a module worker with retries on 429/5xx and stealth pacing.
    pub async fn deploy_script(
        &self,
        account_id: &str,
        name: &str,
        js: Vec<u8>,
        compat_date: &str,
        retries: u32,
    ) -> Result<serde_json::Value, CFError> {
        let metadata = serde_json::json!({
            "main_module": "_worker.js",
            "compatibility_date": compat_date,
            "compatibility_flags": ["nodejs_compat"],
        });
        let metadata_str = metadata.to_string();

        let mut last_err: Option<CFError> = None;
        for attempt in 0..=retries {
            let form = multipart::Form::new()
                .part(
                    "metadata",
                    multipart::Part::text(metadata_str.clone())
                        .mime_str("application/json")
                        .unwrap(),
                )
                .part(
                    "_worker.js",
                    multipart::Part::bytes(js.clone())
                        .mime_str("application/javascript")
                        .unwrap(),
                );

            match self
                .request(
                    "PUT",
                    &format!("/accounts/{account_id}/workers/scripts/{name}"),
                    None,
                    Some(form),
                    "deploy worker",
                    Some(std::time::Duration::from_secs(120)),
                )
                .await
            {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last_err = Some(e.clone());
                    let retryable = e.status.map(|s| s == 429 || s >= 500).unwrap_or(false);
                    if !retryable || attempt >= retries {
                        return Err(e);
                    }
                    retry_backoff(attempt).await;
                }
            }
        }
        Err(last_err.unwrap_or_else(|| CFError::new("Deploy", "unknown", "")))
    }

    /// Set worker environment variables (PATCH settings).
    pub async fn set_vars(
        &self,
        account_id: &str,
        name: &str,
        vars: serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Value, CFError> {
        let body = serde_json::json!({ "vars": vars });
        self.request(
            "PATCH",
            &format!("/accounts/{account_id}/workers/scripts/{name}/settings"),
            Some(body),
            None,
            "set worker vars",
            None,
        )
        .await
    }

    /// Delete a worker script.
    pub async fn delete_script(
        &self,
        account_id: &str,
        name: &str,
    ) -> Result<serde_json::Value, CFError> {
        self.request(
            "DELETE",
            &format!("/accounts/{account_id}/workers/scripts/{name}"),
            None,
            None,
            "delete worker",
            None,
        )
        .await
    }

    // ------------------------------------------------------------------
    // Zones & DNS
    // ------------------------------------------------------------------

    /// List all zones accessible to this token.
    pub async fn list_zones(&self) -> Result<Vec<Zone>, CFError> {
        let body = self
            .request("GET", "/zones?per_page=50", None, None, "list zones", None)
            .await?;
        Ok(parse_list::<Zone>(body, "result"))
    }

    /// List DNS records for a zone.
    pub async fn list_dns_records(&self, zone_id: &str) -> Result<Vec<DnsRecord>, CFError> {
        let body = self
            .request(
                "GET",
                &format!("/zones/{zone_id}/dns_records?per_page=100"),
                None,
                None,
                "list dns records",
                None,
            )
            .await?;
        Ok(parse_list::<DnsRecord>(body, "result"))
    }

    /// Create a DNS record.
    pub async fn create_dns_record(
        &self,
        zone_id: &str,
        rec: &DnsRecord,
    ) -> Result<DnsRecord, CFError> {
        let body = serde_json::json!({
            "name": rec.name,
            "type": rec.record_type,
            "content": rec.content,
            "ttl": rec.ttl,
            "proxied": rec.proxied,
        });
        let resp = self
            .request(
                "POST",
                &format!("/zones/{zone_id}/dns_records"),
                Some(body),
                None,
                "create dns record",
                None,
            )
            .await?;
        let rec = resp.get("result").cloned().unwrap_or(serde_json::json!({}));
        serde_json::from_value(rec)
            .map_err(|e| CFError::new("Parse error", format!("{e}"), "Internal error."))
    }

    /// Delete a DNS record.
    pub async fn delete_dns_record(
        &self,
        zone_id: &str,
        record_id: &str,
    ) -> Result<serde_json::Value, CFError> {
        self.request(
            "DELETE",
            &format!("/zones/{zone_id}/dns_records/{record_id}"),
            None,
            None,
            "delete dns record",
            None,
        )
        .await
    }

    // ------------------------------------------------------------------
    // Worker custom routes
    // ------------------------------------------------------------------

    /// List custom routes for an account.
    pub async fn list_routes(&self, account_id: &str) -> Result<Vec<WorkerRoute>, CFError> {
        let body = self
            .request(
                "GET",
                &format!("/accounts/{account_id}/workers/routes"),
                None,
                None,
                "list routes",
                None,
            )
            .await?;
        Ok(parse_list::<WorkerRoute>(body, "result"))
    }

    /// Create a worker route (pattern → script).
    pub async fn create_route(
        &self,
        account_id: &str,
        pattern: &str,
        script: &str,
    ) -> Result<serde_json::Value, CFError> {
        let body = serde_json::json!({ "pattern": pattern, "script": script });
        self.request(
            "POST",
            &format!("/accounts/{account_id}/workers/routes"),
            Some(body),
            None,
            "create route",
            None,
        )
        .await
    }

    /// Delete a worker route.
    pub async fn delete_route(
        &self,
        account_id: &str,
        route_id: &str,
    ) -> Result<serde_json::Value, CFError> {
        self.request(
            "DELETE",
            &format!("/accounts/{account_id}/workers/routes/{route_id}"),
            None,
            None,
            "delete route",
            None,
        )
        .await
    }

    /// Build a workers.dev URL.
    pub fn workers_dev_url(&self, _account_id: &str, name: &str, subdomain: &str) -> String {
        format!("https://{name}.{subdomain}.workers.dev")
    }
}

/// Helper to format status code as u16.
pub trait StatusCodeExt {
    fn as_u16(&self) -> u16;
}
impl StatusCodeExt for StatusCode {
    fn as_u16(&self) -> u16 {
        u16::from(*self)
    }
}

/// Parse a `result` array from a CF envelope into a typed list.
fn parse_list<T: serde::de::DeserializeOwned>(body: serde_json::Value, key: &str) -> Vec<T> {
    body.get(key)
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value::<T>(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_builds() {
        let c = Client::new("  abc  ");
        assert!(c.token == "abc");
    }

    #[test]
    fn workers_dev_url_assembles() {
        let c = Client::new("x");
        assert_eq!(
            c.workers_dev_url("a", "name", "sub"),
            "https://name.sub.workers.dev"
        );
    }

    /// A minimal mock HTTP server that responds to any request with a canned
    /// status + body. Returns the base URL to point a Client at.
    fn mock_server(status: u16, body: &'static str) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                // read the request head (blocking) so reqwest gets a response
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let resp = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn test_verify_token_ok() {
        let base = mock_server(
            200,
            r#"{"success":true,"result":{"id":"tok-123","status":"active"}}"#,
        );
        let client = Client::with_base("abc", &base);
        let res = client.verify_token().await.unwrap();
        assert_eq!(res.status, "active");
        assert_eq!(res.id, "tok-123");
    }

    #[tokio::test]
    async fn test_verify_token_maps_to_account_deactivated() {
        // 403 + CF code 9109 -> "Invalid API token" title (KNOWN_CODES)
        let base = mock_server(
            403,
            r#"{"success":false,"errors":[{"code":9109,"message":"Invalid API Token"}]}"#,
        );
        let client = Client::with_base("abc", &base);
        let err = client.verify_token().await.unwrap_err();
        assert_eq!(err.title, "Invalid API token");
        assert_eq!(err.code, Some(9109));
        assert_eq!(err.status, Some(403));
    }
}
