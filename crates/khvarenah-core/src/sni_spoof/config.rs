//! Per-profile persistence for the SNI allowlist scanner.
//!
//! The scanner writes the last observed allowlist (SNIs that passed) so the
//! result survives across runs and can be reused as the fake-SNI candidate set
//! by a later injector round. A profile with no saved list simply returns
//! `None`.

use crate::error::CFError;
use crate::store::profiles;

/// Where the allowlist is persisted, per profile.
pub fn allowlist_path(profile_id: &str) -> Result<std::path::PathBuf, CFError> {
    Ok(profiles::profile_dir(profile_id).join("sni-allowlist.json"))
}

/// Save the allowed SNIs for `profile_id` (de-duplicated, sorted).
pub fn persist_allowlist(profile_id: &str, allowed: &[String]) -> Result<(), CFError> {
    let mut list: Vec<String> = allowed.to_vec();
    list.sort();
    list.dedup();
    crate::store::write_json(&allowlist_path(profile_id)?, &list)
}

/// Load the persisted allowlist, if any.
pub fn load_allowlist(profile_id: &str) -> Option<Vec<String>> {
    crate::store::read_opt::<Vec<String>>(&allowlist_path(profile_id).ok()?)
}

/// Remove the persisted allowlist (forces a re-scan).
pub fn clear_allowlist(profile_id: &str) -> Result<(), CFError> {
    let p = allowlist_path(profile_id)?;
    if p.exists() {
        std::fs::remove_file(&p).map_err(|e| {
            CFError::new(
                "SniSpoof",
                e.to_string(),
                "Cannot remove the allowlist file.",
            )
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_mem() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let tmp = std::env::temp_dir().join(format!("kvrvn-sni-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        crate::store::set_mem_dir_override(tmp.join(".khvarenah"));
        tmp
    }

    #[test]
    fn test_persist_allowlist_roundtrip() {
        let tmp = temp_mem();
        let id = profiles::create_profile("p1", "").unwrap();
        persist_allowlist(&id, &["b.com".into(), "a.com".into(), "b.com".into()]).unwrap();
        let loaded = load_allowlist(&id).unwrap();
        assert_eq!(loaded, vec!["a.com".to_string(), "b.com".to_string()]);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_load_allowlist_returns_none_when_missing() {
        let tmp = temp_mem();
        let id = profiles::create_profile("p2", "").unwrap();
        assert!(load_allowlist(&id).is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_clear_allowlist_removes() {
        let tmp = temp_mem();
        let id = profiles::create_profile("p3", "").unwrap();
        persist_allowlist(&id, &["a.com".into()]).unwrap();
        clear_allowlist(&id).unwrap();
        assert!(load_allowlist(&id).is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
