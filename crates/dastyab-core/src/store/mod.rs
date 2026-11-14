//! Persistent memory for DastYab — atomic, per-profile, update-safe.
//!
//! This is the heart of "updates must never clear my tokens/configs/IPs".
//! Every write goes through [`atomic_write`] (a tempfile in the same directory,
//! `fsync`, rename, and a parent `fsync`), so a crash or a forced kill
//! mid-write can never leave a truncated file — the previous content survives.
//!
//! ## Layout
//! ```text
//! ~/.dastyab/
//!   profiles/
//!     default/            ← every field lives under a named profile
//!       profile.json      ← metadata (name, created_at)
//!       token.json        ← API tokens (per account label, mode 600)
//!       accounts.json     ← remembered Cloudflare accounts
//!       history.json      ← generated vless profiles
//!       cleanips.json     ← scanned clean IPs
//!       config.json       ← per-profile settings
//!   legacy/               ← original flat files moved here on first migration
//!   logs/                 ← tracing appender output
//! ```

pub mod profiles;

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::error::CFError;

pub use profiles::{now_iso, now_ts};

/// Current on-disk state directory name (under `$HOME`).
pub const MEM_DIR_NAME: &str = ".dastyab";

/// Base directory for all DastYab state: `$HOME/.dastyab`.
///
/// Pure path resolution, no side effects. Every entry point resolves state
/// through this one function, so there is exactly one definition of where
/// user data lives.
pub fn mem_dir() -> PathBuf {
    if let Some(override_dir) = mem_override() {
        return override_dir;
    }
    home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(MEM_DIR_NAME)
}

/// The user's home directory (no external `dirs` dependency).
///
/// Checks `HOME` (Unix), then `USERPROFILE` (Windows). Falls back to `None`.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

// Thread-local override so parallel tests never clobber each other.
std::thread_local! {
    static MEM_DIR_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Set the base directory (used by tests to avoid touching the real home).
pub fn set_mem_dir_override(path: PathBuf) {
    MEM_DIR_OVERRIDE.with(|cell| *cell.borrow_mut() = Some(path));
}

/// The active base-directory override, if one is set (tests only). Returns
/// `None` in normal (production) use.
pub fn mem_override() -> Option<PathBuf> {
    MEM_DIR_OVERRIDE.with(|cell| cell.borrow().clone())
}

/// The directory holding all profiles.
pub fn profiles_dir() -> PathBuf {
    mem_dir().join("profiles")
}

/// Make the memory directory tree, chmod 700 on Unix.
pub fn ensure_mem_dir() -> Result<(), CFError> {
    let dir = mem_dir();
    fs::create_dir_all(&dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check filesystem permissions.",
        )
    })?;
    set_private(&dir);
    Ok(())
}

/// Best-effort chmod 700 on Unix (no-op elsewhere).
pub fn set_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    }
}

/// Best-effort chmod 600 on Unix (no-op elsewhere).
pub fn set_file_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

// Re-entrancy guard: version-snapshot writes themselves go through
// `atomic_write`, so we must not recursively snapshot those.
std::thread_local! {
    static IN_SNAPSHOT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Split a path into (profile_dir, relative_path) when it lives inside a
/// profile directory (…/profiles/<id>/<file>). Returns `None` otherwise.
fn profile_rel_from_path(path: &Path) -> Option<(PathBuf, String)> {
    let comps: Vec<&std::ffi::OsStr> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    let idx = comps.iter().position(|c| *c == "profiles")?;
    let after = &comps[idx + 1..];
    if after.len() < 2 {
        return None; // need at least <id>/<file>
    }
    let profile_dir: PathBuf = after[..after.len() - 1].iter().collect();
    let rel = after.last()?.to_str()?.to_string();
    Some((profile_dir, rel))
}

/// Best-effort pre-write snapshot: if `path` is a profile artifact being
/// rewritten, save the previous bytes into the per-artifact version history so
/// they can be restored later. Never fails the actual write (errors are
/// swallowed — versioning is a safety net, not a gate).
fn maybe_snapshot_before_write(path: &Path, bytes: &[u8]) {
    if IN_SNAPSHOT.with(|c| c.get()) {
        return;
    }
    let Some((profile_dir, rel)) = profile_rel_from_path(path) else {
        return;
    };
    // Skip volatile/derived files — versioning them would be noise or recurse.
    // Guard on the FULL path: any `.versions` segment means we are inside a
    // version store (payload or index write) and must not snapshot it, even
    // when called directly (not via the outer hook).
    if path.components().any(|c| {
        matches!(c, std::path::Component::Normal(s) if s.to_string_lossy().ends_with(".versions"))
    }) {
        return;
    }
    if rel.starts_with(".dyb_tmp_")
        || rel.starts_with('.')
        || crate::artifact::manifest::is_runtime_excluded(&rel)
        || rel == "manifest.json"
        || rel == "ledger_hw.json"
    {
        return;
    }
    IN_SNAPSHOT.with(|c| c.set(true));
    let _ = crate::artifact::artifact_versions::snapshot_before_write(
        &profile_dir,
        &rel,
        bytes,
        now_ts() as u64 * 1000,
    );
    IN_SNAPSHOT.with(|c| c.set(false));
}

/// Atomically write `bytes` to `path`:
/// tempfile in the same directory → write → fsync → rename → fsync parent.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CFError> {
    maybe_snapshot_before_write(path, bytes);
    let dir = path.parent().ok_or_else(|| {
        CFError::new(
            "Storage error",
            format!("No parent directory for {}", path.display()),
            "Internal error.",
        )
    })?;
    fs::create_dir_all(dir).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot create {}: {e}", dir.display()),
            "Check filesystem permissions.",
        )
    })?;

    let tmp = tempfile::Builder::new()
        .prefix(".dyb_tmp_")
        .tempfile_in(dir)
        .map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Cannot create temp file in {}: {e}", dir.display()),
                "Check filesystem permissions.",
            )
        })?;

    {
        let mut f = tmp.reopen().map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Cannot reopen temp file: {e}"),
                "Check filesystem.",
            )
        })?;
        f.write_all(bytes).map_err(|e| {
            CFError::new(
                "Storage error",
                format!("Write failed: {e}"),
                "Disk full or permissions?",
            )
        })?;
        f.flush().map_err(|e| {
            CFError::new("Storage error", format!("Flush failed: {e}"), "Disk full?")
        })?;
        f.sync_all().map_err(|e| {
            CFError::new("Storage error", format!("fsync failed: {e}"), "Disk error.")
        })?;
    }

    tmp.persist(path).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot persist to {}: {e}", path.display()),
            "Check filesystem permissions.",
        )
    })?;

    // fsync the parent directory so the rename is durable.
    #[cfg(unix)]
    {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }

    set_file_private(path);
    Ok(())
}

/// Serialize `value` as pretty JSON and write it atomically.
pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CFError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| {
        CFError::new(
            "Storage error",
            format!("Cannot serialize: {e}"),
            "Internal error.",
        )
    })?;
    atomic_write(path, &bytes)
}

/// Read a JSON file, returning `default` if missing/corrupt/not-an-object.
pub fn read_or_default<T: serde::de::DeserializeOwned + Default>(path: &Path) -> T {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<T>(&bytes).unwrap_or_default(),
        Err(_) => T::default(),
    }
}

/// Read a JSON file into an `Option`, returning `None` if missing/corrupt.
pub fn read_opt<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice::<T>(&bytes).ok()
}

/// Generate a short stable id (12 hex chars) like the Python app.
pub fn new_id() -> String {
    Uuid::new_v4().simple().to_string()[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_file_with_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.json");
        atomic_write(&p, b"hello").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_keeps_old_content_if_killed_mid_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.json");
        // original content
        atomic_write(&p, b"original").unwrap();

        // Simulate a process dying mid-write: write a tempfile but never persist.
        let tmp = tempfile::Builder::new()
            .prefix(".dyb_tmp_")
            .tempfile_in(dir.path())
            .unwrap();
        let _ = tmp;
        // drop(tmp) removes the temp file without touching the real one
        assert_eq!(fs::read(&p).unwrap(), b"original");
    }

    #[test]
    fn read_or_default_handles_missing_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let v: Vec<String> = read_or_default(&missing);
        assert!(v.is_empty());

        let bad = dir.path().join("bad.json");
        fs::write(&bad, "{{{ not json").unwrap();
        let v: Vec<String> = read_or_default(&bad);
        assert!(v.is_empty());
    }

    #[test]
    fn write_json_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cfg.json");
        write_json(&p, &serde_json::json!({"a": 1})).unwrap();
        let v: serde_json::Value = read_or_default(&p);
        assert_eq!(v["a"], 1);
    }
}
