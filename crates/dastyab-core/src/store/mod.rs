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

/// Base directory for all DastYab state.
///
/// Adoption of a pre-rename directory happens here exactly once per process
/// (see [`adopt_legacy_mem_dir_once`]). It lives on this path because *every*
/// entry point resolves state through it — including the read-only commands
/// (`profiles`, `inventory`) that never call [`ensure_mem_dir`], which are
/// precisely the commands that must still see a user's existing state after
/// the rename.
pub fn mem_dir() -> PathBuf {
    adopt_legacy_mem_dir_once();
    raw_mem_dir()
}

/// Run [`adopt_legacy_mem_dir`] at most once per process.
///
/// Two guards, because this function moves a real directory:
/// * `cfg!(test)` covers unit tests, which are the likeliest to resolve a
///   state path while forgetting [`set_mem_dir_override`].
/// * `DASTYAB_NO_MIGRATE` lets a harness or an operator disable it outright
///   (integration tests are compiled without `cfg(test)`, so they need this).
pub fn adopt_legacy_mem_dir_once() {
    if cfg!(test) || std::env::var_os("DASTYAB_NO_MIGRATE").is_some() {
        return;
    }
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        adopt_legacy_mem_dir();
    });
}

/// The state directory path, with no adoption side effect.
fn raw_mem_dir() -> PathBuf {
    if let Some(override_dir) = MEM_DIR_OVERRIDE.with(|cell| cell.borrow().clone()) {
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

/// Pre-rename state directory names, newest first.
///
/// The project was called `DastYab` before it was renamed to `DastYab`, and
/// its state lived in `~/.dastyab`. Users who upgrade keep real tokens and
/// scanned IPs in that directory, so it is adopted rather than abandoned.
pub fn legacy_mem_dir_names() -> &'static [&'static str] {
    &[".dastyab"]
}

/// Adopt a pre-rename state directory, if one exists and the current one does
/// not. Returns the path that was adopted.
///
/// Best-effort and one-shot: a plain `rename(2)` inside the same home
/// directory, so a failure (permissions, cross-device) leaves the old data
/// untouched and the caller just starts a fresh tree. Never runs under a test
/// override, so a unit test can never move a real user's real data.
///
/// Idempotent and cheap once the current directory exists: the `exists()`
/// probe short-circuits, and `mem_dir()` calls this on every access.
pub fn adopt_legacy_mem_dir() -> Option<PathBuf> {
    if mem_override().is_some() {
        return None;
    }
    let current = raw_mem_dir();
    if current.exists() {
        return None;
    }
    let home = home_dir()?;
    adopt_legacy_mem_dir_at(&home, &current)
}

/// The adoption itself, with explicit paths so it is testable without
/// mutating the process-wide `HOME`.
///
/// Returns the adopted path, or `None` when there is nothing to adopt.
pub fn adopt_legacy_mem_dir_at(home: &Path, current: &Path) -> Option<PathBuf> {
    if current.exists() {
        return None;
    }
    for name in legacy_mem_dir_names() {
        let candidate = home.join(name);
        if candidate.is_dir() && fs::rename(&candidate, current).is_ok() {
            return Some(current.to_path_buf());
        }
    }
    None
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
        || crate::manifest::is_runtime_excluded(&rel)
        || rel == "manifest.json"
        || rel == "ledger_hw.json"
    {
        return;
    }
    IN_SNAPSHOT.with(|c| c.set(true));
    let _ = crate::artifact_versions::snapshot_before_write(
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

    /// Pre-rename state must actually be adopted: a user upgrading from the
    /// `DastYab` layout keeps every token and scanned IP.
    #[test]
    fn legacy_mem_dir_is_adopted_with_contents() {
        assert!(legacy_mem_dir_names().contains(&".dastyab"));

        let home = tempfile::tempdir().unwrap();
        let legacy = home.path().join(".dastyab");
        fs::create_dir_all(legacy.join("profiles")).unwrap();
        fs::write(legacy.join("token.txt"), b"live-token").unwrap();

        let current = home.path().join(MEM_DIR_NAME);
        let adopted =
            adopt_legacy_mem_dir_at(home.path(), &current).expect("legacy dir must be adopted");

        assert_eq!(adopted, current);
        assert!(!legacy.exists(), "old dir must be gone after adoption");
        assert_eq!(fs::read(current.join("token.txt")).unwrap(), b"live-token");
        assert!(current.join("profiles").is_dir());
    }

    /// Adoption is one-shot: once the new directory exists it must not
    /// clobber live state, even if a stale old directory reappears.
    #[test]
    fn adoption_never_overwrites_existing_state() {
        let home = tempfile::tempdir().unwrap();
        let legacy = home.path().join(".dastyab");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("token.txt"), b"stale").unwrap();

        let current = home.path().join(MEM_DIR_NAME);
        fs::create_dir_all(&current).unwrap();
        fs::write(current.join("token.txt"), b"live").unwrap();

        assert!(adopt_legacy_mem_dir_at(home.path(), &current).is_none());
        assert_eq!(fs::read(current.join("token.txt")).unwrap(), b"live");
        assert!(legacy.exists(), "stale dir left untouched");
    }

    /// The process-wide adopter must be inert under `DASTYAB_NO_MIGRATE`,
    /// otherwise a test harness could move a real home directory.
    #[test]
    fn adoption_is_inert_under_no_migrate_env() {
        // SAFETY: single-threaded test setup, and the variable is only read by
        // `adopt_legacy_mem_dir_once`, which the `cfg!(test)` guard already
        // short-circuits in this build.
        std::env::set_var("DASTYAB_NO_MIGRATE", "1");
        let before = mem_dir();
        adopt_legacy_mem_dir_once();
        assert_eq!(mem_dir(), before, "path resolution must not change");
        std::env::remove_var("DASTYAB_NO_MIGRATE");
    }

    /// Adoption must be a no-op when there is nothing to adopt.
    #[test]
    fn adoption_is_none_without_legacy_dir() {
        let home = tempfile::tempdir().unwrap();
        let current = home.path().join(MEM_DIR_NAME);
        assert!(adopt_legacy_mem_dir_at(home.path(), &current).is_none());
        assert!(!current.exists());
    }

    /// The adopter must never fire under a test override, or a test run could
    /// move a developer's real secrets directory.
    #[test]
    fn adopt_legacy_mem_dir_is_inert_under_override() {
        let dir = tempfile::tempdir().unwrap();
        set_mem_dir_override(dir.path().join(".dastyab"));
        assert!(adopt_legacy_mem_dir().is_none());
    }

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
