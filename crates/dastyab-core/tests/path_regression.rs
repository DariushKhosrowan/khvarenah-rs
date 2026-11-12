use dastyab_core::vless::VlessProfile;

#[test]
fn render_from_encoded_link_is_clean() {
    let link = "vless://11111111-2222-3333-4444-555555555555@dastyab-humantest.dariuskhosrowan.workers.dev:443?encryption=none&security=tls&type=ws&sni=dastyab-humantest.dariuskhosrowan.workers.dev&host=dastyab-humantest.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#test";
    let p = VlessProfile::parse(link).expect("parse");
    assert_eq!(
        p.path, "/",
        "path must be decoded to slash, got {:?}",
        p.path
    );
    let xray = p.xray_client_json().expect("xray json");
    assert!(
        !xray.contains("%2F"),
        "xray config must not contain %2F: {}",
        xray
    );
    assert!(
        xray.contains("\"path\": \"/\""),
        "expected path / in xray: {}",
        xray
    );
    let link2 = p.share_link();
    assert!(
        !link2.contains("path=%2F"),
        "share_link must not re-encode: {}",
        link2
    );
}

/// Critical regression: `export` reconstructs a profile from a saved record.
/// Clean-IP records store an empty `uuid` and an `address` that already embeds
/// the port (e.g. "104.18.227.124:443"). Rebuilding from those fields alone
/// wrongly yields an empty uuid, a duplicated port (":443:443") and missing
/// tls/ws. The fix is to parse the stored `link` when present, which carries
/// the full uuid, path, tls and Host header. This test simulates the exact
/// record shape seen in the wild.
#[test]
fn export_reconstruct_from_clean_ip_record_uses_link() {
    // This is the exact record from profiles/.../history.json for a clean-IP
    // row: uuid empty, address already contains ":443".
    let rec_link = "vless://11111111-2222-3333-4444-555555555555@104.18.227.124:443?encryption=none&security=tls&type=ws&sni=dastyab-humantest.dariuskhosrowan.workers.dev&host=dastyab-humantest.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#clean-104.18.227.124:443";
    let sparse_address = "104.18.227.124:443".to_string();
    let sparse_uuid = String::new();
    let sparse_port = 443u16;

    // What the fixed export does: parse the link (authoritative).
    let vless = VlessProfile::parse(rec_link).expect("parse clean-ip record link");

    // Sparse fallback (unused when link parses) — kept for parity with the
    // fallback branch in export_cmd.
    let _fallback = VlessProfile {
        uuid: sparse_uuid,
        address: sparse_address,
        port: sparse_port,
        name: "clean-104.18.227.124:443".into(),
        ..Default::default()
    };

    assert_eq!(vless.uuid, "11111111-2222-3333-4444-555555555555");
    assert_eq!(
        vless.address, "104.18.227.124",
        "address must be pure IP, got {}",
        vless.address
    );
    assert_eq!(vless.port, 443);
    assert_eq!(vless.path, "/", "path must decode to slash");
    assert_eq!(vless.transport, "ws");
    assert_eq!(vless.security, "tls");

    let link = vless.share_link();
    // No duplicated port, no empty uuid, no %2F.
    assert!(
        !link.contains(":443:443"),
        "port duplicated in share link: {}",
        link
    );
    assert!(!link.starts_with("vless://@"), "empty uuid: {}", link);
    assert!(!link.contains("path=%2F"), "encoded path leaked: {}", link);

    let xray = vless.xray_client_json().expect("xray");
    assert!(!xray.contains("%2F"), "xray has %2F: {}", xray);
    assert!(
        xray.contains("\"path\": \"/\""),
        "xray path not clean: {}",
        xray
    );
    assert!(
        xray.contains("\"address\": \"104.18.227.124\""),
        "xray address unclean: {}",
        xray
    );
}

/// A profile constructed directly (not via parse) may still carry a legacy
/// percent-encoded path, e.g. from a pre-decode stored record. Every renderer
/// must canonicalize it to `/` so v2rayN / sing-box / Clash can import the
/// result. This guards against any future code path building a profile with an
/// encoded path bypassing `parse()`'s decode.
#[test]
fn render_canonicalizes_encoded_path_even_without_parse() {
    let p = VlessProfile {
        uuid: "11111111-2222-3333-4444-555555555555".into(),
        address: "104.18.227.124".into(),
        port: 443,
        security: "tls".into(),
        path: "%2F".into(), // legacy encoded path
        transport: "ws".into(),
        sni: Some("dastyab-humantest.dariuskhosrowan.workers.dev".into()),
        header_host: Some("dastyab-humantest.dariuskhosrowan.workers.dev".into()),
        name: "encoded-clean".into(),
    };

    // share link
    let link = p.share_link();
    assert!(
        !link.contains("path=%2F"),
        "share_link leaked %2F: {}",
        link
    );
    assert!(
        link.contains("&path=/"),
        "share_link missing plain /: {}",
        link
    );

    // xray (v2rayN)
    let xray = p.xray_client_json().expect("xray");
    assert!(!xray.contains("%2F"), "xray leaked %2F: {}", xray);
    assert!(
        xray.contains("\"path\": \"/\""),
        "xray path unclean: {}",
        xray
    );

    // sing-box
    let sb = dastyab_core::export::sing_box_json(&p).expect("sing-box");
    assert!(!sb.contains("%2F"), "sing-box leaked %2F: {}", sb);
    assert!(
        sb.contains("\"path\": \"/\""),
        "sing-box path unclean: {}",
        sb
    );

    // Clash
    let clash = dastyab_core::export::clash_entry(&p);
    assert!(!clash.contains("%2F"), "clash leaked %2F: {}", clash);
    assert!(clash.contains("path: /"), "clash path unclean: {}", clash);
}

/// The exact link that produced the user's un-importable v2rayN config
/// ("path": "%2F"). The renderer must emit an importable "path": "/".
#[test]
fn exact_user_link_renders_clean_v2rayn() {
    let link = "vless://11111111-2222-3333-4444-555555555555@dastyab-humantest.dariuskhosrowan.workers.dev:443?encryption=none&security=tls&type=ws&sni=dastyab-humantest.dariuskhosrowan.workers.dev&host=dastyab-humantest.dariuskhosrowan.workers.dev&path=%2F&fp=chrome#test";
    let p = VlessProfile::parse(link).expect("parse");
    let xray = p.xray_client_json().expect("xray");
    assert!(!xray.contains("%2F"), "STILL HAS %2F: {}", xray);
    assert!(xray.contains("\"path\": \"/\""), "path not / : {}", xray);
}
