use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use uuid::Uuid;

macro_rules! model {
    ($name:ident { $($(#[$attr:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $($(#[$attr])* pub $field: $ty),* }
    };
}
model!(Config {
    schema_version: u32,
    node: Node,
    ports: Ports,
    transport: Transport,
    tls: Tls,
    website: Website,
    runtime: Runtime,
    clients: Clients,
    warp: Warp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vless: Option<Vless>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    distribution: Option<Distribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cn_warp: Option<CnWarp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    web_services: Option<WebServices>
});
model!(CnWarp {
    enabled: bool,
    interface: String,
    config_file: String,
    routing_table: u32,
    rule_priority: u32,
    socket_mark: u32,
    geodata_dir: String
});
model!(WebServices {
    enabled: bool,
    librespeed_port: u16,
    openlist_port: u16,
    openlist_data_dir: String,
    openlist_files_dir: String,
    download_size_mib: u32
});
impl CnWarp {
    pub fn managed(enabled: bool) -> Self {
        Self {
            enabled,
            interface: "warp-cn".into(),
            config_file: "/etc/usque-cn/config.json".into(),
            routing_table: 5271,
            rule_priority: 15271,
            socket_mark: 5271,
            geodata_dir: "/var/lib/nodectl-geodata/202610172205".into(),
        }
    }
}
impl WebServices {
    pub fn managed(enabled: bool) -> Self {
        Self {
            enabled,
            librespeed_port: 8989,
            openlist_port: 5244,
            openlist_data_dir: "/var/lib/nodectl-openlist".into(),
            openlist_files_dir: "/var/lib/nodectl-openlist-files".into(),
            download_size_mib: 256,
        }
    }
}
model!(Distribution { enabled: bool });
model!(Vless { encryption: bool });
model!(Node { domain: String, aliases: Vec<String>, reality_domain: String, ipv4: String, ipv6: String });
model!(Ports {
    http: u16,
    https: u16,
    reality: u16
});
model!(Transport {
    xhttp: Xhttp,
    ws: Ws,
    reality: Reality
});
model!(Xhttp {
    path: String,
    mode: String,
    socket: String
});
model!(Ws {
    path: String,
    socket: String
});
model!(Reality {
    path: String,
    mode: String
});
model!(Tls { protocols: Vec<String>, http2: bool, http3: bool, alt_svc_max_age: u32,
    domain_cert_dir: String, ip_cert_dir: String });
#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Website {
    pub root: String,
    #[serde(default)]
    pub reserved_paths: Vec<String>,
}
model!(Runtime {
    xray_binary: String,
    nginx_binary: String,
    usque_binary: String,
    xray_user: String,
    nginx_user: String,
    log_root: String
});
model!(Clients { xhttp_weight: u32, ws_weight: u32, reality_weight: u32,
    fingerprint_weights: BTreeMap<String, u32> });
model!(Warp {
    enabled: bool,
    config_file: String,
    take_over_default_route: bool
});

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Secrets {
    pub xhttp_uuid: String,
    pub ws_uuid: String,
    pub reality_uuid: String,
    pub reality_private_key: String,
    pub reality_short_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vless: Option<EncryptionSecrets>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionPair {
    pub decryption: String,
    pub encryption: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionSecrets {
    pub xhttp: EncryptionPair,
    pub ws: EncryptionPair,
    pub reality: EncryptionPair,
}
impl Config {
    pub fn routes_cn(&self) -> bool {
        self.cn_warp.as_ref().is_some_and(|c| c.enabled)
    }
    pub fn serves_web(&self) -> bool {
        self.web_services.as_ref().is_some_and(|c| c.enabled)
    }
    pub fn distributes(&self) -> bool {
        self.distribution.as_ref().is_some_and(|d| d.enabled)
    }
    pub fn encrypted(&self) -> bool {
        self.vless.as_ref().is_some_and(|v| v.encryption)
    }
}
impl EncryptionSecrets {
    pub fn pair(&self, kind: &str) -> &EncryptionPair {
        match kind {
            "xhttp" => &self.xhttp,
            "ws" => &self.ws,
            "reality" => &self.reality,
            _ => unreachable!("validated transport"),
        }
    }
}

pub const EXAMPLE: &str = include_str!("../config/node.example.toml");

pub fn key_bytes(key: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(key)
        .context("Invalid REALITY key encoding")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("REALITY key must have 32 bytes"))?;
    ensure!(key != [0; 32], "Zero REALITY private key is not allowed");
    Ok(key)
}

impl Secrets {
    pub fn public_key(&self) -> Result<String> {
        let private = x25519_dalek::StaticSecret::from(key_bytes(&self.reality_private_key)?);
        Ok(URL_SAFE_NO_PAD.encode(x25519_dalek::PublicKey::from(&private).as_bytes()))
    }
    pub fn sensitive(&self) -> Vec<&str> {
        let mut values: Vec<&str> = vec![
            &self.xhttp_uuid,
            &self.ws_uuid,
            &self.reality_uuid,
            &self.reality_private_key,
            &self.reality_short_id,
        ];
        if let Some(keys) = &self.vless {
            for kind in ["xhttp", "ws", "reality"] {
                values.push(&keys.pair(kind).decryption);
                values.push(&keys.pair(kind).encryption);
            }
        }
        values
    }
}

pub fn load(dir: &Path) -> Result<(Config, Secrets)> {
    for name in ["node.toml", "secrets.json"] {
        super::store::check_private(&dir.join(name), false)?;
    }
    // Do not attach parser diagnostics that may reproduce credentials or raw input.
    let c =
        toml::from_str::<Config>(&fs::read_to_string(dir.join("node.toml"))?).map_err(|_| {
            anyhow::anyhow!("Invalid node.toml: check types, required fields and unknown fields")
        })?;
    let s =
        serde_json::from_slice::<Secrets>(&fs::read(dir.join("secrets.json"))?).map_err(|_| {
            anyhow::anyhow!("Invalid secrets.json: check field names and string values")
        })?;
    validate(&c, &s)?;
    Ok((c, s))
}

pub fn domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s == s.to_ascii_lowercase()
        && s.parse::<std::net::IpAddr>().is_err()
        && s.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 63
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

pub fn abs_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() > 1
        && !s.contains("//")
        && !s.split('/').any(|c| c == "." || c == "..")
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
}

pub fn route(s: &str, trailing: bool) -> bool {
    let lower = s.to_ascii_lowercase();
    abs_path(s)
        && s.split('/').filter(|p| !p.is_empty()).count() >= 2
        && (!trailing || s.ends_with('/'))
        && !["vless", "xhttp", "splithttp", "websocket", "reality"]
            .iter()
            .any(|v| lower.contains(v))
}

pub fn overlap(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('/');
    let b = b.trim_end_matches('/');
    a == b
        || a.strip_prefix(b).is_some_and(|s| s.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|s| s.starts_with('/'))
}

impl Config {
    pub fn domains(&self) -> Vec<String> {
        let mut names = vec![self.node.domain.clone(), self.node.reality_domain.clone()];
        names.extend(self.node.aliases.clone());
        names.sort();
        names.dedup();
        names
    }
    pub fn ips(&self) -> Vec<String> {
        let mut ips = vec![self.node.ipv4.clone()];
        if !self.node.ipv6.is_empty() {
            ips.push(self.node.ipv6.clone());
        }
        ips
    }
    pub fn sans(&self) -> Vec<String> {
        let mut names = self.domains();
        names.extend(self.ips());
        names
    }
}

pub fn validate(c: &Config, s: &Secrets) -> Result<()> {
    if let Some(cn) = &c.cn_warp {
        ensure!(
            cn.interface.len() <= 15
                && cn.interface.starts_with("warp-")
                && cn
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "CN WARP interface must be a distinct warp- name (at most 15 bytes)"
        );
        ensure!(
            cn.config_file != c.warp.config_file,
            "CN WARP credentials must be independent"
        );
        for path in [&cn.config_file, &cn.geodata_dir] {
            ensure!(abs_path(path), "Unsafe CN WARP path");
        }
        ensure!(
            (1000..=30000).contains(&cn.routing_table)
                && (1000..=30000).contains(&cn.rule_priority)
                && (1024..=65535).contains(&cn.socket_mark),
            "CN WARP policy identifiers are outside the managed range"
        );
    }
    if let Some(web) = &c.web_services {
        let mut ports = BTreeSet::from([c.ports.http, c.ports.https, c.ports.reality]);
        ensure!(
            web.librespeed_port >= 1024
                && web.openlist_port >= 1024
                && ports.insert(web.librespeed_port)
                && ports.insert(web.openlist_port),
            "Website backend ports must be distinct unprivileged ports"
        );
        for path in [&web.openlist_data_dir, &web.openlist_files_dir] {
            ensure!(abs_path(path), "Unsafe OpenList path");
            ensure!(
                !overlap(path, &c.website.root),
                "OpenList private data must be outside the public website root"
            );
            for protected in [
                c.tls.domain_cert_dir.as_str(),
                c.tls.ip_cert_dir.as_str(),
                c.warp.config_file.as_str(),
                "/etc/nodectl-services",
                "/var/www/nodectl-services",
                "/var/lib/nodectl-web-guard",
                "/var/lib/nodectl-cn-assets",
            ]
            .into_iter()
            .chain(
                c.cn_warp
                    .as_ref()
                    .into_iter()
                    .flat_map(|cn| [cn.config_file.as_str(), cn.geodata_dir.as_str()]),
            ) {
                ensure!(
                    !overlap(path, protected),
                    "OpenList directories overlap protected deployment material"
                );
            }
        }
        ensure!(
            !overlap(&web.openlist_data_dir, &web.openlist_files_dir),
            "OpenList database and storage must be separate"
        );
        ensure!(
            (16..=4096).contains(&web.download_size_mib),
            "Test download size must be 16..4096 MiB"
        );
        ensure!(
            !c.node.reality_domain.is_empty() && c.node.reality_domain != c.node.domain,
            "OpenList requires a distinct files/REALITY domain"
        );
        for reserved in ["/librespeed/", "/downloads/"] {
            for path in [
                &c.transport.xhttp.path,
                &c.transport.ws.path,
                &c.transport.reality.path,
            ] {
                ensure!(
                    !overlap(path, reserved),
                    "Website route overlaps a transport path"
                );
            }
            ensure!(
                !c.website
                    .reserved_paths
                    .iter()
                    .any(|p| overlap(p, reserved)),
                "Website route overlaps an operator-reserved route"
            );
        }
    }
    if c.distribution.is_some() {
        for path in [
            &c.transport.xhttp.path,
            &c.transport.ws.path,
            &c.transport.reality.path,
        ] {
            ensure!(
                !overlap(path, "/nodes/"),
                "Distribution route overlaps a transport path"
            );
        }
        ensure!(
            !c.website
                .reserved_paths
                .iter()
                .any(|p| overlap(p, "/nodes/")),
            "Distribution route overlaps a reserved website path"
        );
    }
    if c.encrypted() {
        let keys = s.vless.as_ref().context(
            "VLESS Encryption keys missing; initialize them explicitly before rendering",
        )?;
        let mut unique = BTreeSet::new();
        for kind in ["xhttp", "ws", "reality"] {
            let pair = keys.pair(kind);
            for (value, prefix, size) in [
                (&pair.decryption, "mlkem768x25519plus.native.600s.", 64),
                (&pair.encryption, "mlkem768x25519plus.native.0rtt.", 1184),
            ] {
                let bytes = value
                    .strip_prefix(prefix)
                    .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok());
                ensure!(
                    bytes.is_some_and(|b| b.len() == size && b.iter().any(|&v| v != 0)),
                    "Invalid VLESS Encryption parameter"
                );
            }
            ensure!(
                unique.insert(&pair.decryption),
                "VLESS Encryption keys must be independent per transport"
            );
        }
    }
    ensure!(c.schema_version == 1, "Unsupported schema_version");
    ensure!(
        c.domains().iter().all(|d| domain(d)),
        "Domains must be lowercase DNS names"
    );
    ensure!(
        c.node.domain != c.node.reality_domain && !c.node.aliases.contains(&c.node.reality_domain),
        "REALITY requires a separate primary SNI"
    );
    ensure!(c.node.ipv4.parse::<Ipv4Addr>().is_ok(), "Invalid IPv4");
    ensure!(
        c.node.ipv6.is_empty() || c.node.ipv6.parse::<Ipv6Addr>().is_ok(),
        "Invalid IPv6"
    );
    let ports = [c.ports.http, c.ports.https, c.ports.reality];
    ensure!(
        !ports.contains(&0) && ports.into_iter().collect::<BTreeSet<_>>().len() == 3,
        "Ports must be nonzero and distinct"
    );
    let ids = [&s.xhttp_uuid, &s.ws_uuid, &s.reality_uuid];
    ensure!(
        ids.iter()
            .all(|s| Uuid::parse_str(s).is_ok_and(|u| !u.is_nil() && u.to_string() == **s)),
        "Credentials require canonical, nonzero UUIDs"
    );
    ensure!(
        ids.into_iter().collect::<BTreeSet<_>>().len() == 3,
        "Three UUIDs must be different"
    );
    s.public_key()?;
    ensure!(
        !s.reality_short_id.is_empty()
            && s.reality_short_id.len() <= 16
            && s.reality_short_id.len().is_multiple_of(2)
            && hex::decode(&s.reality_short_id).is_ok(),
        "Short ID must be 1–8 hex bytes"
    );
    let paths = [
        &c.transport.xhttp.path,
        &c.transport.ws.path,
        &c.transport.reality.path,
    ];
    ensure!(
        route(paths[0], true)
            && route(paths[1], false)
            && !paths[1].ends_with('/')
            && route(paths[2], true),
        "Invalid transport paths: require multi-level safe paths, trailing / only for XHTTP"
    );
    for i in 0..3 {
        for j in i + 1..3 {
            ensure!(!overlap(paths[i], paths[j]), "Transport routes overlap");
        }
    }
    for reserved in c
        .website
        .reserved_paths
        .iter()
        .chain(std::iter::once(&"/.well-known/".to_owned()))
    {
        ensure!(abs_path(reserved), "Invalid reserved website route");
        ensure!(
            paths.iter().all(|p| !overlap(p, reserved)),
            "Transport route conflicts with website route"
        );
    }
    ensure!(
        c.transport.xhttp.mode == "stream-one" && c.transport.reality.mode == "stream-one",
        "Only stream-one XHTTP mode is supported in this template"
    );
    ensure!(c.tls.protocols == ["TLSv1.3"], "TLSv1.3 is required");
    ensure!(c.tls.http2, "XHTTP stream-one requires HTTP/2");
    ensure!(
        (c.tls.http3 && c.tls.alt_svc_max_age > 0) || (!c.tls.http3 && c.tls.alt_svc_max_age == 0),
        "HTTP/3 and Alt-Svc max age must agree"
    );
    ensure!(
        !c.warp.take_over_default_route,
        "WARP default route takeover is unsupported"
    );
    for value in [
        &c.transport.xhttp.socket,
        &c.transport.ws.socket,
        &c.tls.domain_cert_dir,
        &c.tls.ip_cert_dir,
        &c.website.root,
        &c.runtime.xray_binary,
        &c.runtime.nginx_binary,
        &c.runtime.usque_binary,
        &c.runtime.log_root,
        &c.warp.config_file,
    ] {
        ensure!(
            abs_path(value),
            "Filesystem paths must be absolute safe Linux paths"
        );
    }
    ensure!(
        c.transport.xhttp.socket.len() < 100
            && c.transport.ws.socket.len() < 100
            && c.transport.xhttp.socket != c.transport.ws.socket,
        "UDS paths must be distinct and fit sockaddr_un"
    );
    ensure!(
        !overlap(&c.tls.domain_cert_dir, &c.tls.ip_cert_dir),
        "Certificate directories must be separate"
    );
    for user in [&c.runtime.xray_user, &c.runtime.nginx_user] {
        ensure!(
            !user.is_empty()
                && user.len() < 32
                && user
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
                && user
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
                && user != "root",
            "Invalid service user"
        );
    }
    let weights = &c.clients;
    ensure!(
        u64::from(weights.xhttp_weight)
            + u64::from(weights.ws_weight)
            + u64::from(weights.reality_weight)
            == 100,
        "Client weights must sum to 100"
    );
    ensure!(
        weights
            .fingerprint_weights
            .keys()
            .all(|s| ["chrome", "ios", "firefox", "qq"].contains(&s.as_str())),
        "Unsupported fingerprint"
    );
    let total: u64 = weights
        .fingerprint_weights
        .values()
        .map(|&x| u64::from(x))
        .sum();
    ensure!(
        total > 0 && total <= 1000,
        "Fingerprint weights must total 1–1000"
    );
    Ok(())
}

fn merge_missing(current: &mut toml::Value, defaults: &toml::Value) {
    if let (Some(current), Some(defaults)) = (current.as_table_mut(), defaults.as_table()) {
        for (key, value) in defaults {
            if let Some(existing) = current.get_mut(key) {
                merge_missing(existing, value);
            } else {
                current.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Preview validates structure without manufacturing usable encryption material.
pub fn validate_preview(c: &Config, s: &Secrets) -> Result<()> {
    let mut structural = c.clone();
    if s.vless.is_none() {
        structural.vless = None;
    }
    validate(&structural, s)
}

pub fn encryption_keys(c: &Config, s: &mut Secrets) -> Result<()> {
    if !c.encrypted() || s.vless.is_some() {
        return Ok(());
    }
    let version = super::host::command(&c.runtime.xray_binary, &["version"])?;
    let lock: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let expected = lock["xray"]["version"].as_str().unwrap_or("26.10.21");
    ensure!(
        version.split_whitespace().any(|v| v == expected || v == "26.10.10"),
        "Encryption key generation requires locked Xray {expected}"
    );
    let pair = || -> Result<EncryptionPair> {
        let output = super::host::command(&c.runtime.xray_binary, &["vlessenc"])?;
        let section = output
            .split("Authentication: ML-KEM-768")
            .nth(1)
            .context("Xray did not return ML-KEM-768 parameters")?;
        let field = |name: &str| -> Result<String> {
            section
                .lines()
                .find_map(|line| {
                    let (label, value) = line.trim().split_once(':')?;
                    (label.trim_matches('"') == name)
                        .then(|| value.trim().trim_matches('"').to_owned())
                })
                .context("Incomplete VLESS Encryption pair")
        };
        Ok(EncryptionPair {
            decryption: field("decryption")?,
            encryption: field("encryption")?,
        })
    };
    s.vless = Some(EncryptionSecrets {
        xhttp: pair()?,
        ws: pair()?,
        reality: pair()?,
    });
    validate(c, s)
}

pub fn init(dir: &Path, example: Option<&Path>, rotate: &[String]) -> Result<()> {
    let allowed = [
        "xhttp_uuid",
        "ws_uuid",
        "reality_uuid",
        "reality_private_key",
        "reality_short_id",
        "transport.xhttp.path",
        "transport.ws.path",
        "transport.reality.path",
    ];
    ensure!(
        rotate.iter().all(|s| allowed.contains(&s.as_str())),
        "Unknown rotation field"
    );
    super::store::private_dir(dir)?;
    let input = example
        .map(fs::read_to_string)
        .transpose()?
        .unwrap_or_else(|| EXAMPLE.to_owned());
    let mut defaults: toml::Value =
        toml::from_str(&input).map_err(|_| anyhow::anyhow!("Invalid initialization template"))?;
    for (transport, path) in [
        (
            "xhttp",
            format!(
                "/assets/modules/{}/stream/",
                hex::encode(rand::random::<[u8; 8]>())
            ),
        ),
        (
            "ws",
            format!(
                "/api/events/{}/channel",
                hex::encode(rand::random::<[u8; 8]>())
            ),
        ),
        (
            "reality",
            format!(
                "/assets/modules/{}/stream/",
                hex::encode(rand::random::<[u8; 8]>())
            ),
        ),
    ] {
        defaults["transport"][transport]["path"] = toml::Value::String(path);
    }
    let config_path = dir.join("node.toml");
    let mut config = if config_path.exists() {
        super::store::check_private(&config_path, false)?;
        toml::from_str::<toml::Value>(&fs::read_to_string(&config_path)?)
            .map_err(|_| anyhow::anyhow!("Invalid existing node.toml"))?
    } else {
        defaults.clone()
    };
    // Re-running init must not silently enable encryption in a legacy deployment.
    if config_path.exists() && config.get("vless").is_none() {
        defaults.as_table_mut().unwrap().remove("vless");
    }
    if config_path.exists() && config.get("distribution").is_none() {
        defaults.as_table_mut().unwrap().remove("distribution");
    }
    for section in ["cn_warp", "web_services"] {
        if config_path.exists() && config.get(section).is_none() {
            defaults.as_table_mut().unwrap().remove(section);
        }
    }
    merge_missing(&mut config, &defaults);
    for field in rotate.iter().filter(|s| s.starts_with("transport.")) {
        let p: Vec<_> = field.split('.').collect();
        config[p[0]][p[1]][p[2]] = defaults[p[0]][p[1]][p[2]].clone();
    }
    let c: Config = config
        .clone()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid config fields"))?;
    let secrets_path = dir.join("secrets.json");
    let mut s: Secrets = if secrets_path.exists() {
        super::store::check_private(&secrets_path, false)?;
        serde_json::from_slice(&fs::read(&secrets_path)?)
            .map_err(|_| anyhow::anyhow!("Invalid existing secrets.json"))?
    } else {
        Secrets::default()
    };
    for (field, value) in [
        ("xhttp_uuid", &mut s.xhttp_uuid),
        ("ws_uuid", &mut s.ws_uuid),
        ("reality_uuid", &mut s.reality_uuid),
    ] {
        if value.is_empty() || rotate.iter().any(|s| s == field) {
            *value = Uuid::new_v4().to_string();
        }
    }
    if s.reality_private_key.is_empty() || rotate.iter().any(|s| s == "reality_private_key") {
        let output = super::host::command(&c.runtime.xray_binary, &["x25519"])?;
        let key = output.lines().find_map(|line| {
            let (label, key) = line.split_once(':')?;
            (label.replace(' ', "").eq_ignore_ascii_case("privatekey"))
                .then(|| key.trim().to_owned())
        });
        s.reality_private_key = key.context("Installed Xray did not return a private key")?;
    }
    if s.reality_short_id.is_empty() || rotate.iter().any(|s| s == "reality_short_id") {
        s.reality_short_id = hex::encode(rand::random::<[u8; 8]>());
    }
    encryption_keys(&c, &mut s)?;
    if let Err(e) = validate(&c, &s) {
        bail!("Initialization validation failed: {e}");
    }
    let text = toml::to_string_pretty(&config)?;
    if !config_path.exists() || fs::read_to_string(&config_path)? != text {
        super::store::atomic_write(&config_path, text.as_bytes())?;
    }
    let bytes = serde_json::to_vec_pretty(&s)?;
    if !secrets_path.exists() || fs::read(&secrets_path)? != bytes {
        super::store::atomic_write(&secrets_path, &bytes)?;
    }
    Ok(())
}
