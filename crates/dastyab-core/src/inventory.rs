//! Configs inventory — the "configs manager" surface.
//!
//! Answers "what has this app generated, where is it, and is it intact?" in
//! one table across all profiles. Consumes the manifest/verification primitive
//! (`crate::manifest`); every item carries an [`IntegrityStatus`] decided by
//! [`crate::manifest::verify_profile`]. Exportable as deterministic Markdown
//! or JSON (for the CLI `inventory` command and the GUI Inventory tab).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::manifest::{ArtifactKind, IntegrityStatus};

/// One row in the inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryItem {
    pub profile_id: String,
    pub kind: ArtifactKind,
    pub rel_path: String,
    pub display_name: String,
    pub size_bytes: u64,
    pub modified_unix: u64,
    pub integrity: IntegrityStatus,
}

/// Totals (per-kind and per-profile aggregates).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InventoryTotals {
    pub item_count: usize,
    pub total_bytes: u64,
    pub per_kind: BTreeMap<String, (usize, u64)>,
    pub per_profile: BTreeMap<String, (usize, u64)>,
}

/// The full inventory snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub generated_unix: u64,
    pub items: Vec<InventoryItem>,
    pub totals: InventoryTotals,
}

/// Filter for [`filter_inventory`].
#[derive(Debug, Clone, Default)]
pub struct InventoryFilter {
    pub profile_id: Option<String>,
    pub kinds: Option<Vec<ArtifactKind>>,
    pub integrity: Option<IntegrityStatus>,
}

/// Iterate the profile directory and collect file metadata.
fn file_meta(dir: &Path, rel: &str) -> Option<(u64, u64)> {
    let p = dir.join(rel);
    let meta = std::fs::metadata(&p).ok()?;
    if !meta.is_file() {
        return None;
    }
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some((meta.len(), modified))
}

/// Build the inventory for the whole workspace.
pub fn build_inventory(workspace_root: &Path, now_unix: u64) -> Inventory {
    let _ = workspace_root; // profile dirs are resolved via the store
    let mut items = Vec::new();
    let mut totals = InventoryTotals::default();

    let profiles = crate::store::profiles::list_profiles();

    for meta in &profiles {
        let dir = crate::store::profiles::profile_dir(&meta.id);
        let report = crate::manifest::verify_profile(&meta.id);

        // Kinds to surface: all tracked per-profile artifacts, ordered.
        let kinds = crate::manifest::profile_artifact_kinds();
        for kind in kinds {
            let rel = kind.filename().to_string();
            let (size, modified) = match file_meta(&dir, &rel) {
                Some(m) => m,
                None => continue,
            };
            let status = if report.has_manifest {
                if report.missing.contains(&rel) {
                    IntegrityStatus::Missing
                } else if report.changed.contains(&rel) {
                    IntegrityStatus::Changed
                } else if report.extra.contains(&rel) {
                    IntegrityStatus::Extra
                } else {
                    IntegrityStatus::Verified
                }
            } else {
                IntegrityStatus::NoManifest
            };
            items.push(InventoryItem {
                profile_id: meta.id.clone(),
                kind,
                rel_path: format!("profiles/{}/{}", meta.id, rel),
                display_name: kind.label().to_string(),
                size_bytes: size,
                modified_unix: modified,
                integrity: status,
            });
            totals.item_count += 1;
            totals.total_bytes += size;
            {
                use std::collections::btree_map::Entry;
                let k = kind.label().to_string();
                match totals.per_kind.entry(k) {
                    Entry::Vacant(e) => {
                        e.insert((1, size));
                    }
                    Entry::Occupied(mut e) => {
                        let v = e.get_mut();
                        v.0 += 1;
                        v.1 += size;
                    }
                }
                let p = meta.id.clone();
                match totals.per_profile.entry(p) {
                    Entry::Vacant(e) => {
                        e.insert((1, size));
                    }
                    Entry::Occupied(mut e) => {
                        let v = e.get_mut();
                        v.0 += 1;
                        v.1 += size;
                    }
                }
            }
        }
    }

    // Sort deterministically: profile id, kind, rel_path.
    items.sort_by(|a, b| {
        a.profile_id
            .cmp(&b.profile_id)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.rel_path.cmp(&b.rel_path))
    });

    Inventory {
        generated_unix: now_unix,
        items,
        totals,
    }
}

/// Filter an inventory by profile/kind/integrity.
pub fn filter_inventory<'a>(inv: &'a Inventory, f: &InventoryFilter) -> Vec<&'a InventoryItem> {
    inv.items
        .iter()
        .filter(|it| {
            if let Some(pid) = &f.profile_id {
                if &it.profile_id != pid {
                    return false;
                }
            }
            if let Some(kinds) = &f.kinds {
                if !kinds.contains(&it.kind) {
                    return false;
                }
            }
            if let Some(st) = &f.integrity {
                if &it.integrity != st {
                    return false;
                }
            }
            true
        })
        .collect()
}

/// Render the inventory as deterministic Markdown.
pub fn inventory_to_markdown(inv: &Inventory) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# DastYab inventory (generated {})\n\n",
        inv.generated_unix
    ));
    out.push_str(&format!(
        "Total: {} items, {}\n\n",
        inv.totals.item_count,
        crate::backup::human_size(inv.totals.total_bytes)
    ));
    out.push_str("| Profile | Kind | Path | Size | Integrity |\n");
    out.push_str("|---------|------|------|------|-----------|\n");
    for it in &inv.items {
        out.push_str(&format!(
            "| {} | {} | `{}` | {} | {} |\n",
            it.profile_id,
            it.display_name,
            it.rel_path,
            crate::backup::human_size(it.size_bytes),
            it.integrity.label()
        ));
    }
    out
}

/// Serialize the inventory as JSON.
pub fn inventory_to_json(inv: &Inventory) -> Result<String, crate::error::CFError> {
    serde_json::to_string_pretty(inv).map_err(|e| {
        crate::error::CFError::new(
            "Inventory error",
            format!("Cannot serialize inventory: {e}"),
            "Internal error.",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::set_mem_dir_override;

    fn with_home(f: impl FnOnce()) {
        let tmp = tempfile::tempdir().unwrap();
        set_mem_dir_override(tmp.path().join(".dastyab"));
        f();
    }

    fn fresh_profile_id() -> String {
        crate::store::profiles::create_profile("t", "test").unwrap()
    }

    fn seed_artifacts(id: &str) {
        let dir = crate::store::profiles::profile_dir(id);
        std::fs::write(dir.join("accounts.json"), b"{\"a\":1}").unwrap();
        std::fs::write(dir.join("config.json"), b"{\"x\":1}").unwrap();
    }

    #[test]
    fn build_inventory_aggregates_multiple_profiles() {
        with_home(|| {
            let a = fresh_profile_id();
            let b = fresh_profile_id();
            seed_artifacts(&a);
            seed_artifacts(&b);
            let inv = build_inventory(Path::new("/"), 1000);
            assert!(inv.items.iter().any(|i| i.profile_id == a));
            assert!(inv.items.iter().any(|i| i.profile_id == b));
            assert!(inv.totals.item_count >= 4);
        });
    }

    #[test]
    fn inventory_integrity_uses_manifest_when_present() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            crate::manifest::write_manifest(&crate::manifest::build_manifest(&id).unwrap()).unwrap();
            let inv = build_inventory(Path::new("/"), 1000);
            let item = inv
                .items
                .iter()
                .find(|i| i.profile_id == id && i.rel_path.ends_with("config.json"))
                .unwrap();
            assert_eq!(item.integrity, IntegrityStatus::Verified);
        });
    }

    #[test]
    fn inventory_marks_no_manifest_for_profiles_without() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let inv = build_inventory(Path::new("/"), 1000);
            let item = inv
                .items
                .iter()
                .find(|i| i.profile_id == id)
                .unwrap();
            assert_eq!(item.integrity, IntegrityStatus::NoManifest);
        });
    }

    #[test]
    fn filter_by_profile_id_returns_only_that_profile() {
        with_home(|| {
            let a = fresh_profile_id();
            let b = fresh_profile_id();
            seed_artifacts(&a);
            seed_artifacts(&b);
            let inv = build_inventory(Path::new("/"), 1000);
            let f = InventoryFilter {
                profile_id: Some(a.clone()),
                ..Default::default()
            };
            let out = filter_inventory(&inv, &f);
            assert!(!out.is_empty());
            assert!(out.iter().all(|i| i.profile_id == a));
        });
    }

    #[test]
    fn filter_by_kind_returns_only_matching() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let inv = build_inventory(Path::new("/"), 1000);
            let f = InventoryFilter {
                kinds: Some(vec![ArtifactKind::Config]),
                ..Default::default()
            };
            let out = filter_inventory(&inv, &f);
            assert!(!out.is_empty());
            assert!(out.iter().all(|i| i.kind == ArtifactKind::Config));
        });
    }

    #[test]
    fn filter_by_integrity_returns_drift_only() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let inv = build_inventory(Path::new("/"), 1000);
            let f = InventoryFilter {
                integrity: Some(IntegrityStatus::NoManifest),
                ..Default::default()
            };
            let out = filter_inventory(&inv, &f);
            assert_eq!(out.len(), inv.items.len());
        });
    }

    #[test]
    fn inventory_to_markdown_deterministic_for_same_input() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let inv = build_inventory(Path::new("/"), 1000);
            let m1 = inventory_to_markdown(&inv);
            let m2 = inventory_to_markdown(&inv);
            assert_eq!(m1, m2);
            assert!(m1.contains("| Profile | Kind |"));
        });
    }

    #[test]
    fn inventory_json_roundtrips() {
        with_home(|| {
            let id = fresh_profile_id();
            seed_artifacts(&id);
            let inv = build_inventory(Path::new("/"), 1000);
            let json = inventory_to_json(&inv).unwrap();
            let back: Inventory = serde_json::from_str(&json).unwrap();
            assert_eq!(back.items.len(), inv.items.len());
            assert_eq!(back.totals.item_count, inv.totals.item_count);
        });
    }
}
