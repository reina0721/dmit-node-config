use crate::{
    config::{self, Config, Secrets},
    render,
    store::{self, Store},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs};

fn fixture() -> (Config, Secrets) {
    (
        {
            let mut c: Config = toml::from_str(config::EXAMPLE).unwrap();
            c.vless = None;
            c.distribution = None;
            c.cn_warp = None;
            c.web_services = None;
            c
        },
        Secrets {
            xhttp_uuid: "10a6cfe1-d381-4c46-865e-998b28b801a1".into(),
            ws_uuid: "20a6cfe1-d381-4c46-865e-998b28b801a2".into(),
            reality_uuid: "30a6cfe1-d381-4c46-865e-998b28b801a3".into(),
            reality_private_key: URL_SAFE_NO_PAD.encode([7; 32]),
            reality_short_id: "0123456789abcdef".into(),
            vless: None,
        },
    )
}
pub(crate) fn sandbox() -> (tempfile::TempDir, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::new(tmp.path().join("config"), tmp.path().join("state")).unwrap();
    store::private_dir(&store.config_dir).unwrap();
    store::private_dir(&store.state_dir).unwrap();
    let (c, s) = fixture();
    save(&store, &c, &s);
    (tmp, store)
}
fn save(store: &Store, c: &Config, s: &Secrets) {
    store::atomic_write(
        &store.config_dir.join("node.toml"),
        toml::to_string(c).unwrap().as_bytes(),
    )
    .unwrap();
    store::atomic_write(
        &store.config_dir.join("secrets.json"),
        &serde_json::to_vec(s).unwrap(),
    )
    .unwrap();
}
fn json_file(files: &BTreeMap<String, Vec<u8>>, name: &str) -> Value {
    serde_json::from_slice(&files[name]).unwrap()
}

#[test]
fn web_virtual_hosts_preserve_transports_subscription_and_private_storage() {
    let (mut c, s) = fixture();
    c.distribution = Some(config::Distribution { enabled: true });
    c.web_services = Some(config::WebServices {
        enabled: true,
        librespeed_port: 8989,
        openlist_port: 5244,
        openlist_data_dir: "/var/lib/nodectl-openlist".into(),
        openlist_files_dir: "/var/lib/nodectl-openlist-files".into(),
        download_size_mib: 256,
    });
    config::validate(&c, &s).unwrap();
    let files = render::files(&c, &s).unwrap();
    let nginx = String::from_utf8(files["nginx.conf"].clone()).unwrap();
    assert!(nginx.contains("server_name speedtest.example.com;"));
    assert!(nginx.contains("server_name files.example.com;"));
    assert_eq!(nginx.matches("grpc_pass unix:").count(), 2);
    assert_eq!(
        nginx
            .matches("proxy_pass http://unix:/run/nodectl-share")
            .count(),
        3
    );
    assert!(nginx.contains("proxy_pass http://127.0.0.1:5244"));
    assert!(!nginx.contains("root /var/lib/nodectl-openlist"));
    assert!(nginx.contains("proxy_request_buffering off"));
    let files_host = nginx
        .split("server_name files.example.com;")
        .nth(1)
        .unwrap();
    assert!(!files_host.contains("location = /nodes/api"));
    assert!(files_host.contains("return 302 https://speedtest.example.com/nodes/"));
    assert!(files_host.contains("location = /nodes/sub/mihomo"));
    assert!(files_host.contains("Content-Security-Policy \"sandbox;"));
    assert!(files.contains_key("website/index.html"));
    assert!(
        !String::from_utf8(files["website/index.html"].clone())
            .unwrap()
            .contains("example.com/nodes/sub")
    );
    let old = crate::render_v3::files(
        &{
            let mut c = c.clone();
            c.web_services = None;
            c
        },
        &s,
    )
    .unwrap();
    assert!(
        !String::from_utf8(old["nginx.conf"].clone())
            .unwrap()
            .contains("librespeed")
    );
    c.web_services.as_mut().unwrap().openlist_files_dir = c.website.root.clone();
    assert!(config::validate(&c, &s).is_err());
}

#[test]
fn legacy_snapshot_requires_complete_regeneration_and_known_generator() {
    let (_tmp, store) = sandbox();
    let id = store.render().unwrap();
    let mut path = store.release(&id).unwrap();
    let (c, s) = store.inputs().unwrap();
    let legacy = crate::render_legacy::files(&c, &s).unwrap();
    for (name, data) in &legacy {
        store::atomic_write(&path.join(name), data).unwrap();
    }
    for (version, expected) in [("0.1.0", true), ("0.2.0", true), ("99.0.0", false)] {
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        manifest["generator_version"] = json!(version);
        manifest["template_version"] = json!("1");
        manifest["files"] = json!(
            legacy
                .iter()
                .map(|(name, data)| (name, store::digest(data)))
                .collect::<BTreeMap<_, _>>()
        );
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let next = store::digest(&bytes)[..32].to_owned();
        store::atomic_write(&path.join("manifest.json"), &bytes).unwrap();
        let destination = store.release(&next).unwrap();
        fs::rename(&path, &destination).unwrap();
        assert_eq!(store.verify(&next).is_ok(), expected);
        path = destination;
    }
}

#[test]
fn certificate_operations_do_not_require_or_generate_encryption_keys() {
    let c: Config = toml::from_str(config::EXAMPLE).unwrap();
    assert!(c.encrypted());
    let operations = render::operations(&c);
    assert_eq!(
        operations["certificates"]["domain"]["sans"],
        json!(["files.example.com", "speedtest.example.com"])
    );
    assert_eq!(operations["certificates"]["ip"]["sans"], json!(c.ips()));
    assert!(
        !serde_json::to_string(&operations)
            .unwrap()
            .contains("decryption")
    );
}

#[test]
fn template_two_explicit_versions_preserve_strict_snapshot_integrity() {
    for (version, accepted) in [("0.3.0", true), ("0.3.1", true), ("0.3.2", false)] {
        let (_tmp, store) = sandbox();
        let id = store.render().unwrap();
        let path = store.release(&id).unwrap();
        let (c, s) = store.inputs().unwrap();
        let v2 = crate::render_v2::files(&c, &s).unwrap();
        for (name, data) in &v2 {
            store::atomic_write(&path.join(name), data).unwrap();
        }
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        manifest["generator_version"] = json!(version);
        manifest["template_version"] = json!("2");
        manifest["files"] = serde_json::to_value(
            v2.iter()
                .map(|(name, data)| (name, store::digest(data)))
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap();
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let next = store::digest(&bytes)[..32].to_owned();
        store::atomic_write(&path.join("manifest.json"), &bytes).unwrap();
        fs::rename(&path, store.release(&next).unwrap()).unwrap();
        assert_eq!(store.verify(&next).is_ok(), accepted);
        store::atomic_write(&store.release(&next).unwrap().join("xray.json"), b"{}").unwrap();
        assert!(store.verify(&next).is_err());
    }
}
#[test]
fn rejects_unknown_fields_at_every_level() {
    let (c, s) = fixture();
    for field in [
        "root",
        "node",
        "ports",
        "transport",
        "tls",
        "website",
        "runtime",
        "clients",
        "warp",
    ] {
        let mut value = serde_json::to_value(&c).unwrap();
        if field == "root" {
            value["typo"] = json!(true);
        } else {
            value[field]["typo"] = json!(true);
        }
        assert!(serde_json::from_value::<Config>(value).is_err(), "{field}");
    }
    let mut value = serde_json::to_value(s).unwrap();
    value["typo"] = json!(true);
    assert!(serde_json::from_value::<Secrets>(value).is_err());
}

#[test]
fn legacy_init_never_enables_distribution_and_its_route_cannot_overlap() {
    for vless in [None, Some(config::Vless { encryption: false })] {
        let (_tmp, store) = sandbox();
        let (mut c, s) = store.inputs().unwrap();
        c.vless = vless;
        save(&store, &c, &s);
        config::init(&store.config_dir, None, &[]).unwrap();
        assert!(store.inputs().unwrap().0.distribution.is_none());
        c.distribution = Some(config::Distribution { enabled: true });
        config::validate(&c, &s).unwrap();
        c.transport.xhttp.path = "/nodes/stream/".into();
        assert!(config::validate(&c, &s).is_err());
    }
}

#[test]
fn validates_all_safety_boundaries() {
    let (c, s) = fixture();
    config::validate(&c, &s).unwrap();
    let mutations: Vec<fn(&mut Config)> = vec![
        |c| c.schema_version = 2,
        |c| c.ports.https = 0,
        |c| c.ports.https = c.ports.http,
        |c| c.node.domain = "a.com;include".into(),
        |c| c.node.domain = "127.0.0.1".into(),
        |c| c.node.ipv4 = "invalid".into(),
        |c| c.node.ipv6 = "invalid".into(),
        |c| c.node.reality_domain = c.node.domain.clone(),
        |c| c.transport.ws.socket = c.transport.xhttp.socket.clone(),
        |c| c.transport.ws.path = c.transport.xhttp.path.clone() + "child",
        |c| c.transport.xhttp.path = "/hello/../path/".into(),
        |c| c.transport.xhttp.path = "/hello/%2f/path/".into(),
        |c| c.transport.xhttp.path = "/hello/a?b/".into(),
        |c| c.transport.xhttp.path = "/hello/xhttp/".into(),
        |c| c.transport.xhttp.path = "/single/".into(),
        |c| c.transport.xhttp.path = "/.well-known/acme-challenge/".into(),
        |c| c.transport.ws.path = "/hello/channel\nfoo".into(),
        |c| c.transport.xhttp.mode = "auto".into(),
        |c| c.tls.http2 = false,
        |c| c.tls.http3 = false,
        |c| c.tls.protocols.push("TLSv1.2".into()),
        |c| c.clients.ws_weight = 16,
        |c| c.clients.ws_weight = u32::MAX,
        |c| {
            c.clients.fingerprint_weights.insert("unknown".into(), 1);
        },
        |c| c.clients.fingerprint_weights.clear(),
        |c| c.warp.take_over_default_route = true,
        |c| c.website.root = "/var/www/$host".into(),
        |c| c.runtime.xray_binary = "/path/%n".into(),
        |c| c.runtime.xray_user = "root".into(),
        |c| c.runtime.xray_user = "0".into(),
        |c| c.runtime.nginx_user = "-option".into(),
    ];
    for (i, change) in mutations.into_iter().enumerate() {
        let mut bad = c.clone();
        change(&mut bad);
        assert!(config::validate(&bad, &s).is_err(), "mutation {i}");
    }
    for field in ["xhttp_uuid", "reality_short_id", "reality_private_key"] {
        let mut value = serde_json::to_value(&s).unwrap();
        value[field] = json!("PLACEHOLDER");
        let bad: Secrets = serde_json::from_value(value).unwrap();
        assert!(config::validate(&c, &bad).is_err());
    }
    let mut bad = s.clone();
    bad.ws_uuid = bad.xhttp_uuid.clone();
    assert!(config::validate(&c, &bad).is_err());
}

#[test]
fn paths_and_ports_propagate_to_every_consumer() {
    let (mut c, s) = fixture();
    let old = c.transport.xhttp.path.clone();
    c.transport.xhttp.path = "/resources/123/new/".into();
    c.ports.https = 9443;
    let files = render::files(&c, &s).unwrap();
    let xray = json_file(&files, "xray.json");
    assert_eq!(
        xray["inbounds"][0]["streamSettings"]["xhttpSettings"]["path"],
        c.transport.xhttp.path
    );
    assert_eq!(
        xray["inbounds"][2]["streamSettings"]["realitySettings"]["target"],
        "127.0.0.1:9443"
    );
    let nginx = String::from_utf8(files["nginx.conf"].clone()).unwrap();
    for expected in [
        "listen 9443 ssl",
        "h3=\":9443\"",
        "https://$host:9443$request_uri",
        c.transport.xhttp.path.as_str(),
    ] {
        assert!(nginx.contains(expected), "{expected}");
    }
    assert!(nginx.contains(&format!("location = {}", c.transport.ws.path)));
    assert!(!nginx.contains(&old));
    assert!(!nginx.contains(&c.transport.reality.path));
    let clients = json_file(&files, "clients/profiles.json");
    let profile = &clients["profiles"][0]["outbound"];
    assert_eq!(profile["settings"]["vnext"][0]["port"], 9443);
    assert_eq!(
        profile["streamSettings"]["xhttpSettings"]["path"],
        c.transport.xhttp.path
    );
    assert!(!serde_json::to_string(&clients).unwrap().contains(&old));
    let operations = json_file(&files, "operations.json");
    assert_eq!(operations["listeners"]["udp"][0], 9443);
    assert_eq!(operations["reality_target"], "127.0.0.1:9443");
}

#[test]
fn optional_ipv6_and_http3_remove_all_related_output() {
    let (mut c, s) = fixture();
    c.node.ipv6.clear();
    c.tls.http3 = false;
    c.tls.alt_svc_max_age = 0;
    config::validate(&c, &s).unwrap();
    let files = render::files(&c, &s).unwrap();
    let nginx = String::from_utf8(files["nginx.conf"].clone()).unwrap();
    for absent in ["[::]", "quic", "http3 on", "Alt-Svc"] {
        assert!(!nginx.contains(absent));
    }
    assert_eq!(
        json_file(&files, "xray.json")["inbounds"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(c.ips().len(), 1);
}

#[test]
fn client_credentials_and_alpn_are_correct() {
    let (c, s) = fixture();
    let files = render::files(&c, &s).unwrap();
    let clients = json_file(&files, "clients/profiles.json");
    let text = serde_json::to_string(&clients).unwrap();
    assert!(!text.contains(&s.reality_private_key));
    assert!(!text.contains("privkey"));
    assert!(!text.contains("warp"));
    let ws = render::outbound(&c, &s, "ws", "chrome").unwrap();
    assert_eq!(
        ws["streamSettings"]["tlsSettings"]["alpn"],
        json!(["http/1.1"])
    );
    let reality = render::outbound(&c, &s, "reality", "chrome").unwrap();
    assert_eq!(
        reality["streamSettings"]["realitySettings"]["password"],
        s.public_key().unwrap()
    );
    assert_eq!(
        reality["streamSettings"]["realitySettings"]["serverName"],
        c.node.reality_domain
    );
    let weights = c.clients.fingerprint_weights.values().sum::<u32>();
    assert_eq!(weights, 11);
    assert_eq!(clients["profiles"].as_array().unwrap().len(), 6);
}

#[test]
fn encrypted_profiles_share_only_client_parameters_and_preserve_udp443() {
    let (mut c, mut s) = fixture();
    c.vless = Some(config::Vless { encryption: true });
    let pair = |byte| config::EncryptionPair {
        decryption: format!(
            "mlkem768x25519plus.native.600s.{}",
            URL_SAFE_NO_PAD.encode([byte; 64])
        ),
        encryption: format!(
            "mlkem768x25519plus.native.0rtt.{}",
            URL_SAFE_NO_PAD.encode([byte; 1184])
        ),
    };
    s.vless = Some(config::EncryptionSecrets {
        xhttp: pair(1),
        ws: pair(2),
        reality: pair(3),
    });
    config::validate(&c, &s).unwrap();
    let server = render::xray(&c, &s);
    for inbound in server["inbounds"].as_array().unwrap() {
        assert_eq!(
            inbound["settings"]["clients"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_ne!(inbound["settings"]["decryption"], "none");
    }
    let mihomo: Value = serde_json::from_slice(&render::mihomo(&c, &s).unwrap()).unwrap();
    let text = mihomo.to_string();
    for kind in ["xhttp", "ws", "reality"] {
        assert!(!text.contains(&s.vless.as_ref().unwrap().pair(kind).decryption));
        let xray = render::outbound(&c, &s, kind, "chrome").unwrap();
        assert_eq!(
            xray["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision-udp443"
        );
    }
    for proxy in mihomo["proxies"].as_array().unwrap() {
        assert_eq!(proxy["udp"], true);
        assert_eq!(proxy["packet-encoding"], "xudp");
        assert_eq!(proxy["flow"], "xtls-rprx-vision");
        assert_eq!(proxy["skip-cert-verify"], false);
        assert_eq!(
            proxy["alpn"],
            if proxy["network"] == "ws" {
                json!(["http/1.1"])
            } else {
                json!(["h2", "http/1.1"])
            }
        );
    }
    s.vless = None;
    assert!(config::validate(&c, &s).is_err());
    assert!(config::validate_preview(&c, &s).is_ok());
}

#[test]
#[ignore = "Requires locked XRAY_TEST_BINARY and MIHOMO_TEST_BINARY"]
fn upstream_encrypted_xray_and_mihomo_configs_are_valid() {
    let binary = std::env::var("XRAY_TEST_BINARY").unwrap();
    let mihomo = std::env::var("MIHOMO_TEST_BINARY").unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (mut c, mut s) = fixture();
    c.vless = Some(config::Vless { encryption: true });
    c.runtime.xray_binary = binary.clone();
    c.runtime.log_root = tmp.path().to_str().unwrap().into();
    fs::create_dir(tmp.path().join("xray")).unwrap();
    config::encryption_keys(&c, &mut s).unwrap();
    let first = serde_json::to_vec(&s).unwrap();
    config::encryption_keys(&c, &mut s).unwrap();
    assert_eq!(first, serde_json::to_vec(&s).unwrap());
    let file = tmp.path().join("config.json");
    store::atomic_write(&file, &serde_json::to_vec(&render::xray(&c, &s)).unwrap()).unwrap();
    crate::host::command(
        &binary,
        &["run", "-test", "-config", file.to_str().unwrap()],
    )
    .unwrap();
    for p in render::profiles(&c, &s).unwrap()["profiles"]
        .as_array()
        .unwrap()
    {
        store::atomic_write(
            &file,
            &serde_json::to_vec(&json!({"outbounds":[p["outbound"]]})).unwrap(),
        )
        .unwrap();
        crate::host::command(
            &binary,
            &["run", "-test", "-config", file.to_str().unwrap()],
        )
        .unwrap();
    }
    store::atomic_write(&file, &render::mihomo(&c, &s).unwrap()).unwrap();
    crate::host::command(
        &mihomo,
        &[
            "-t",
            "-d",
            tmp.path().to_str().unwrap(),
            "-f",
            file.to_str().unwrap(),
        ],
    )
    .unwrap();
}

#[test]
fn strict_templates_preserve_nginx_variables_and_reject_missing_values() {
    assert!(render::template("{{ MISSING }}", &BTreeMap::new()).is_err());
    assert_eq!(
        render::template(
            "$host $uri {{ X }}",
            &BTreeMap::from([("X", "value".into())])
        )
        .unwrap(),
        "$host $uri value"
    );
}

#[test]
fn render_is_deterministic_and_tampering_is_rejected() {
    let (_tmp, store) = sandbox();
    let first = store.render().unwrap();
    assert_eq!(first, store.render().unwrap());
    store.verify(&first).unwrap();
    let path = store.release(&first).unwrap();
    store::atomic_write(&path.join("nginx.conf"), b"tampered").unwrap();
    assert!(store.verify(&first).is_err());
    assert!(store.render().is_err());
}

#[test]
fn extra_files_and_symlinks_cannot_bypass_manifest() {
    let (_tmp, store) = sandbox();
    let id = store.render().unwrap();
    let path = store.release(&id).unwrap();
    store::atomic_write(&path.join("extra"), b"unexpected").unwrap();
    assert!(store.verify(&id).is_err());
    fs::remove_file(path.join("extra")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", path.join("extra")).unwrap();
        assert!(store.verify(&id).is_err());
    }
}

#[test]
fn release_ids_cannot_escape_state_directory() {
    let (_tmp, store) = sandbox();
    for id in [
        "../current",
        "/etc/passwd",
        "CURRENT",
        "abcdef",
        &"a".repeat(33),
    ] {
        assert!(store.release(id).is_err());
    }
}

#[test]
fn export_requires_current_and_diff_never_prints_credentials() {
    let (tmp, store) = sandbox();
    assert!(store.export(&tmp.path().join("exports")).is_err());
    let id = store.render().unwrap();
    let (_, s) = store.inputs().unwrap();
    let diff = store.diff(&id).unwrap();
    for value in s.sensitive() {
        assert!(!diff.contains(value));
    }
    #[cfg(unix)]
    {
        store.set_pointer("current", Some(&id)).unwrap();
        let (mut c, mut s) = store.inputs().unwrap();
        let old = s.clone();
        s.xhttp_uuid = uuid::Uuid::new_v4().to_string();
        c.transport.ws.path = "/new/events/channel".into();
        save(&store, &c, &s);
        let next = store.render().unwrap();
        let diff = store.diff(&next).unwrap();
        for value in s.sensitive().into_iter().chain(old.sensitive()) {
            assert!(!diff.contains(value));
        }
        let out = tmp.path().join("exports");
        store.export(&out).unwrap();
        let exported = fs::read_to_string(out.join("profiles.json")).unwrap();
        assert!(exported.contains(&old.xhttp_uuid));
        assert!(!exported.contains(&s.xhttp_uuid));
        store::check_private(&out, true).unwrap();
        store::check_private(&out.join("profiles.json"), false).unwrap();
    }
}

#[test]
fn process_lock_and_interrupted_journal_block_mutations() {
    let (_tmp, store) = sandbox();
    let lock = store.lock().unwrap();
    assert!(store.lock().is_err());
    drop(lock);
    store::atomic_write(&store.state_dir.join("transaction.json"), b"{}").unwrap();
    assert!(store.lock().is_err());
    assert!(store.recovery_lock().is_ok());
}

#[cfg(unix)]
#[test]
fn initialization_is_idempotent_and_rotation_is_explicit() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let binary = tmp.path().join("xray");
    let key = URL_SAFE_NO_PAD.encode([7; 32]);
    fs::write(
        &binary,
        format!("#!/bin/sh\nprintf 'PrivateKey: {key}\\nPassword (PublicKey): unused\\n'\n"),
    )
    .unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let (mut c, _) = fixture();
    c.runtime.xray_binary = binary.to_str().unwrap().into();
    let example = tmp.path().join("example.toml");
    fs::write(&example, toml::to_string(&c).unwrap()).unwrap();
    let dir = tmp.path().join("config");
    config::init(&dir, Some(&example), &[]).unwrap();
    let (first, secrets) = config::load(&dir).unwrap();
    let source = fs::read(dir.join("node.toml")).unwrap();
    let protected = fs::read(dir.join("secrets.json")).unwrap();
    config::init(&dir, Some(&example), &[]).unwrap();
    assert_eq!(source, fs::read(dir.join("node.toml")).unwrap());
    assert_eq!(protected, fs::read(dir.join("secrets.json")).unwrap());
    assert_ne!(first.transport.xhttp.path, c.transport.xhttp.path);
    config::init(
        &dir,
        Some(&example),
        &["ws_uuid".into(), "transport.ws.path".into()],
    )
    .unwrap();
    let (next, new) = config::load(&dir).unwrap();
    assert_ne!(next.transport.ws.path, first.transport.ws.path);
    assert_ne!(new.ws_uuid, secrets.ws_uuid);
    assert_eq!(new.xhttp_uuid, secrets.xhttp_uuid);
    assert_eq!(new.reality_private_key, secrets.reality_private_key);
    assert_eq!(next.transport.xhttp.path, first.transport.xhttp.path);
    assert!(config::init(&dir, Some(&example), &["all".into()]).is_err());
}

#[cfg(unix)]
#[test]
fn world_readable_input_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let (_tmp, store) = sandbox();
    fs::set_permissions(
        store.config_dir.join("secrets.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(store.inputs().is_err());
}

#[test]
#[ignore = "Requires XRAY_TEST_BINARY pointing to the official v26.10.10 binary"]
fn upstream_xray_accepts_server_and_all_client_configs() {
    let binary = std::env::var("XRAY_TEST_BINARY").expect("Set XRAY_TEST_BINARY");
    let tmp = tempfile::tempdir().unwrap();
    let (mut c, _) = fixture();
    c.runtime.xray_binary = binary.clone();
    c.runtime.log_root = tmp.path().to_str().unwrap().into();
    fs::create_dir(tmp.path().join("xray")).unwrap();
    let example = tmp.path().join("example.toml");
    fs::write(&example, toml::to_string(&c).unwrap()).unwrap();
    let dir = tmp.path().join("config");
    config::init(&dir, Some(&example), &[]).unwrap();
    let (c, s) = config::load(&dir).unwrap();
    let derived = crate::host::command(&binary, &["x25519", "-i", &s.reality_private_key]).unwrap();
    assert!(
        derived.lines().any(|line| line
            .split_once(':')
            .is_some_and(|(label, value)| label.contains("PublicKey")
                && value.trim() == s.public_key().unwrap()))
    );
    let server = tmp.path().join("server.json");
    store::atomic_write(&server, &serde_json::to_vec(&render::xray(&c, &s)).unwrap()).unwrap();
    crate::host::command(
        &binary,
        &["run", "-test", "-config", server.to_str().unwrap()],
    )
    .unwrap();
    let clients = render::profiles(&c, &s).unwrap();
    for profile in clients["profiles"].as_array().unwrap() {
        let config = json!({"outbounds":[profile["outbound"].clone()]});
        let file = tmp.path().join("client.json");
        store::atomic_write(&file, &serde_json::to_vec(&config).unwrap()).unwrap();
        crate::host::command(
            &binary,
            &["run", "-test", "-config", file.to_str().unwrap()],
        )
        .unwrap();
    }
}
