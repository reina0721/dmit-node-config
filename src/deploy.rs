//! DMIT orchestration using the existing Config, renderer, receipts and transactions.
use crate::{
    config::{self, Config, Secrets},
    dns::{self, Change, Cloudflare},
    host, provision,
    store::{self, Store},
};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

#[derive(Args)]
pub struct Deploy {
    /// Collect inputs once, review and confirm in the same terminal.
    #[arg(long, conflicts_with_all = ["non_interactive", "execute", "approve"])]
    pub wizard: bool,
    /// Optional complete node.toml candidate; existing secrets are always retained.
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Root domain for new DMIT names (for example example.com).
    #[arg(long)]
    pub domain_suffix: Option<String>,
    #[arg(long, default_value = "")]
    pub subdomain_prefix: String,
    #[arg(long)]
    pub domain: Option<String>,
    #[arg(long)]
    pub reality_domain: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub aliases: Option<Vec<String>>,
    /// Explicitly retire old names instead of retaining compatibility aliases.
    #[arg(long)]
    pub replace_domain_set: bool,
    /// Explicit encryption migration; existing configurations are never silently changed.
    #[arg(long, action=clap::ArgAction::Set)]
    pub vless_encryption: Option<bool>,
    /// Enable protected node distribution; missing legacy fields remain disabled.
    #[arg(long, action=clap::ArgAction::Set)]
    pub distribution: Option<bool>,
    /// Route CN domains and IPs through a second independent usque instance.
    #[arg(long, action=clap::ArgAction::Set)]
    pub cn_warp: Option<bool>,
    /// Enable the LibreSpeed landing page and OpenList files virtual host.
    #[arg(long, action=clap::ArgAction::Set)]
    pub web_services: Option<bool>,
    /// Optional initial access token in an owner-only file; use share rotate later.
    #[arg(long)]
    pub access_token_file: Option<PathBuf>,
    #[arg(long)]
    pub ipv4: Option<String>,
    /// Empty string explicitly disables IPv6.
    #[arg(long)]
    pub ipv6: Option<String>,
    #[arg(long)]
    pub http_port: Option<u16>,
    #[arg(long)]
    pub https_port: Option<u16>,
    #[arg(long)]
    pub reality_port: Option<u16>,
    #[arg(long,action=clap::ArgAction::Set)]
    pub warp: Option<bool>,
    #[arg(long)]
    pub non_interactive: bool,
    /// Keep dependency provisioning manual.
    #[arg(long)]
    pub skip_dependencies: bool,
    /// Omit for manual DNS; public DNS validation still runs.
    #[arg(long)]
    pub dns_zone: Option<String>,
    /// Owner-only file, never a token on argv. Otherwise read from /dev/tty without echo.
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    #[arg(long)]
    pub manual_certificates: bool,
    #[arg(long)]
    pub acme_email: Option<String>,
    /// Let acme.sh discover zones for SANs spanning retained legacy domains.
    #[arg(long)]
    pub acme_discover_zones: bool,
    #[arg(long)]
    pub accept_ca_terms: bool,
    #[arg(long)]
    pub accept_warp_terms: bool,
    /// Explicit consent to back up and replace unmanaged entrypoints.
    #[arg(long)]
    pub takeover: bool,
    #[arg(long, default_value = "https://www.cloudflare.com/cdn-cgi/trace")]
    pub probe_url: String,
    /// Wait for public A/AAAA propagation before failing and restoring DNS.
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=900))]
    pub dns_wait_seconds: u64,
    /// Delete newly created DNS records on deployment failure (defaults to retaining them for retry).
    #[arg(long)]
    pub delete_dns_on_failure: bool,
    /// Execute only the exact preview with this digest.
    #[arg(long)]
    pub approve: Option<String>,
    #[arg(long)]
    pub execute: bool,
}
pub(crate) fn preview_secrets() -> Secrets {
    Secrets {
        xhttp_uuid: "10a6cfe1-d381-4c46-865e-998b28b801a1".into(),
        ws_uuid: "20a6cfe1-d381-4c46-865e-998b28b801a2".into(),
        reality_uuid: "30a6cfe1-d381-4c46-865e-998b28b801a3".into(),
        reality_private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".into(),
        reality_short_id: "0123456789abcdef".into(),
        vless: None,
    }
}
fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut input = String::new();
    ensure!(
        io::stdin().read_line(&mut input)? > 0,
        "Input ended while reading {label}"
    );
    Ok(if input.trim().is_empty() {
        default.into()
    } else {
        input.trim().into()
    })
}
pub(crate) fn secret_prompt(label: &str) -> Result<String> {
    #[cfg(unix)]
    {
        use std::{
            io::{BufRead, BufReader},
            os::fd::AsRawFd,
        };
        let mut tty = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .context("Credential input requires a terminal or --token-file")?;
        let fd = tty.as_raw_fd();
        let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
        ensure!(
            unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } == 0,
            "Cannot read terminal mode"
        );
        let original = unsafe { original.assume_init() };
        struct Echo(i32, libc::termios);
        impl Drop for Echo {
            fn drop(&mut self) {
                unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
            }
        }
        let guard = Echo(fd, original);
        let mut hidden = original;
        hidden.c_lflag &= !libc::ECHO;
        ensure!(
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } == 0,
            "Cannot disable credential echo"
        );
        write!(tty, "{label}: ")?;
        tty.flush()?;
        let mut input = String::new();
        ensure!(
            BufReader::new(&tty).read_line(&mut input)? > 0,
            "Credential input ended"
        );
        writeln!(tty)?;
        drop(guard);
        Ok(input.trim().into())
    }
    #[cfg(not(unix))]
    {
        let _ = label;
        bail!("Secure terminal credential input requires Linux; use --token-file");
    }
}
fn detected_ip(v6: bool) -> Result<String> {
    let data = host::command(
        "ip",
        &[
            if v6 { "-6" } else { "-4" },
            "-j",
            "address",
            "show",
            "scope",
            "global",
        ],
    )?;
    let interfaces: Vec<Value> = serde_json::from_str(&data)?;
    let mut found = vec![];
    for interface in interfaces {
        let name = interface["ifname"].as_str().unwrap_or("");
        if ["tun", "warp", "docker", "br-", "veth"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        if let Some(addresses) = interface["addr_info"].as_array() {
            for ip in addresses {
                if let Some(ip) = ip["local"].as_str() {
                    found.push(ip.to_owned());
                }
            }
        }
    }
    found.sort();
    found.dedup();
    ensure!(
        found.len() <= 1,
        "Multiple global IPs detected; specify address explicitly"
    );
    Ok(found.pop().unwrap_or_default())
}
pub(crate) fn candidate(store: &Store, args: &Deploy) -> Result<(Config, Secrets, bool)> {
    let exists = store.config_dir.exists();
    let (mut c, s) = if exists {
        store.inputs()?
    } else {
        (toml::from_str(config::EXAMPLE)?, preview_secrets())
    };
    if let Some(input) = &args.input {
        store::check_private(input, false)?;
        c = toml::from_str(&fs::read_to_string(input)?)
            .map_err(|_| anyhow::anyhow!("Invalid candidate node.toml"))?;
    }
    if !exists && args.input.is_none() {
        let suffix = match &args.domain_suffix {
            Some(v) => v.clone(),
            None if args.domain.is_some() => args
                .domain
                .as_ref()
                .and_then(|v| v.split_once('.').map(|(_, suffix)| suffix.to_owned()))
                .context("Domain must include a suffix")?,
            None if args.non_interactive => {
                bail!("New deployment requires --domain-suffix or --domain")
            }
            None => prompt("Root domain", "")?,
        };
        if !suffix.is_empty() {
            ensure!(config::domain(&suffix), "Invalid root domain");
            let prefix = if args.wizard {
                prompt(
                    "Subdomain prefix (empty uses speedtest/files)",
                    &args.subdomain_prefix,
                )?
            } else {
                args.subdomain_prefix.clone()
            };
            c.node.domain = format!("{prefix}speedtest.{suffix}");
            c.node.reality_domain = format!("{prefix}files.{suffix}");
            c.node.aliases = vec![];
        }
        c.node.ipv4 = if args.ipv4.is_some() {
            String::new()
        } else {
            match detected_ip(false) {
                Ok(ip) => ip,
                Err(error) if args.wizard => {
                    println!("IPv4 requires explicit selection: {error}");
                    String::new()
                }
                Err(error) => return Err(error),
            }
        };
        c.node.ipv6 = if args.ipv6.is_some() {
            String::new()
        } else {
            match detected_ip(true) {
                Ok(ip) => ip,
                Err(error) if args.wizard => {
                    println!("IPv6 requires explicit selection: {error}");
                    String::new()
                }
                Err(error) => return Err(error),
            }
        };
        // Optional WARP defaults to the repository baseline, not a simplified profile.
    }
    macro_rules! set {
        ($field:expr,$arg:expr) => {
            if let Some(v) = &$arg {
                $field = v.clone();
            }
        };
    }
    set!(c.node.domain, args.domain);
    set!(c.node.reality_domain, args.reality_domain);
    set!(c.node.aliases, args.aliases);
    if args.replace_domain_set && args.aliases.is_none() {
        c.node.aliases.clear();
    }
    set!(c.node.ipv4, args.ipv4);
    set!(c.node.ipv6, args.ipv6);
    c.canonicalize_ips();
    if let Some(encryption) = args.vless_encryption {
        c.vless = Some(config::Vless { encryption });
    }
    if let Some(enabled) = args.distribution
        && (enabled || c.distribution.is_some())
    {
        c.distribution = Some(config::Distribution { enabled });
    }
    if let Some(enabled) = args.cn_warp
        && (enabled || c.cn_warp.is_some())
    {
        c.cn_warp
            .get_or_insert_with(|| config::CnWarp::managed(enabled))
            .enabled = enabled;
    }
    if let Some(enabled) = args.web_services
        && (enabled || c.web_services.is_some())
    {
        c.web_services
            .get_or_insert_with(|| config::WebServices::managed(enabled))
            .enabled = enabled;
    }
    if let Some(v) = args.http_port {
        c.ports.http = v;
    }
    if let Some(v) = args.https_port {
        c.ports.https = v;
    }
    if let Some(v) = args.reality_port {
        c.ports.reality = v;
    }
    if let Some(v) = args.warp {
        c.warp.enabled = v;
    }
    if !args.non_interactive {
        c.node.domain = prompt("TLS domain", &c.node.domain)?;
        c.node.reality_domain = prompt("REALITY domain", &c.node.reality_domain)?;
        let aliases = prompt(
            "Aliases (comma separated; '-' clears)",
            &c.node.aliases.join(","),
        )?;
        c.node.aliases = if aliases == "-" {
            vec![]
        } else {
            aliases
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_owned())
                .collect()
        };
        c.node.ipv4 = prompt("Public IPv4", &c.node.ipv4)?;
        let ip6 = prompt("Public IPv6 ('-' disables)", &c.node.ipv6)?;
        c.node.ipv6 = if ip6 == "-" { String::new() } else { ip6 };
        c.canonicalize_ips();
        c.ports.http = prompt("HTTP port", &c.ports.http.to_string())?.parse()?;
        c.ports.https = prompt("HTTPS port", &c.ports.https.to_string())?.parse()?;
        c.ports.reality = prompt("REALITY port", &c.ports.reality.to_string())?.parse()?;
        c.warp.enabled =
            prompt("Independent WARP (true/false)", &c.warp.enabled.to_string())?.parse()?;
        if args.wizard {
            let enabled = prompt(
                "Protected node page and subscriptions (true/false)",
                &c.distributes().to_string(),
            )?
            .parse()?;
            if enabled || c.distribution.is_some() {
                c.distribution = Some(config::Distribution { enabled });
            }
            let enabled = prompt(
                "CN traffic via a second isolated WARP (true/false)",
                &c.routes_cn().to_string(),
            )?
            .parse()?;
            if enabled || c.cn_warp.is_some() {
                c.cn_warp
                    .get_or_insert_with(|| config::CnWarp::managed(enabled))
                    .enabled = enabled;
            }
            let enabled = prompt(
                "Speedtest, LibreSpeed and OpenList websites (true/false)",
                &c.serves_web().to_string(),
            )?
            .parse()?;
            if enabled || c.web_services.is_some() {
                c.web_services
                    .get_or_insert_with(|| config::WebServices::managed(enabled))
                    .enabled = enabled;
            }
        }
    }
    config::validate_preview(&c, &s)?;
    if exists {
        let (old, _) = store.inputs()?;
        // Preserve old TLS and REALITY names when changing the primary domain.
        for domain in [&old.node.domain, &old.node.reality_domain]
            .into_iter()
            .filter(|_| !args.replace_domain_set)
        {
            if domain != &c.node.domain
                && domain != &c.node.reality_domain
                && !c.node.aliases.contains(domain)
            {
                c.node.aliases.push(domain.clone());
            }
        }
        config::validate_preview(&c, &s)?;
        ensure!(
            old.runtime.xray_binary == c.runtime.xray_binary
                && old.runtime.nginx_binary == c.runtime.nginx_binary
                && old.runtime.usque_binary == c.runtime.usque_binary,
            "Runtime path migration requires manual provisioning"
        );
    }
    Ok((c, s, exists))
}
fn preserves_clients(old: &Config, old_s: &Secrets, new: &Config, new_s: &Secrets) -> Result<bool> {
    Ok(old.encrypted() == new.encrypted()
        && old.ports.https == new.ports.https
        && old.ports.reality == new.ports.reality
        && old.transport.xhttp.path == new.transport.xhttp.path
        && old.transport.ws.path == new.transport.ws.path
        && old.transport.reality.path == new.transport.reality.path
        && old
            .domains()
            .iter()
            .all(|name| new.domains().contains(name))
        && serde_json::to_value(old_s)? == serde_json::to_value(new_s)?)
}
fn fingerprint(path: &Path) -> Result<Value> {
    fn attributes(mut value: Value, m: &fs::Metadata) -> Value {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            value["mode"] = json!(m.mode() & 0o7777);
            value["uid"] = json!(m.uid());
            value["gid"] = json!(m.gid());
        }
        #[cfg(not(unix))]
        let _ = m;
        value
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => {
            Ok(attributes(json!({"link":fs::read_link(path)?}), &m))
        }
        Ok(m) if m.is_file() => Ok(attributes(json!({"sha256":store::file_digest(path)?}), &m)),
        Ok(m) if m.is_dir() => {
            let mut children = BTreeMap::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                children.insert(
                    entry.file_name().to_string_lossy().to_string(),
                    fingerprint(&entry.path())?,
                );
            }
            Ok(attributes(
                json!({"tree_sha256":store::digest(&serde_json::to_vec(&children)?)}),
                &m,
            ))
        }
        Ok(_) => bail!("Unsupported deployment backup file: {}", path.display()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Value::Null),
        Err(e) => Err(e.into()),
    }
}
fn feature_entry_paths(c: &Config) -> Vec<PathBuf> {
    let mut paths = vec![];
    if c.routes_cn() {
        paths.extend([
            "/etc/systemd/system/usque-cn.service",
            "/etc/xray/geoip.dat",
            "/etc/xray/geosite.dat",
        ]);
    }
    if c.serves_web() {
        paths.extend([
            "/etc/systemd/system/librespeed.service",
            "/etc/systemd/system/openlist.service",
            "/var/www/nodectl-services/current",
        ]);
    }
    paths.into_iter().map(PathBuf::from).collect()
}
fn backup_paths(store: &Store, c: &Config) -> Vec<PathBuf> {
    let mut paths = vec![
        store.config_dir.clone(),
        PathBuf::from(&c.tls.domain_cert_dir),
        PathBuf::from(&c.tls.ip_cert_dir),
        PathBuf::from(&c.warp.config_file),
        PathBuf::from(&c.runtime.xray_binary),
        PathBuf::from(&c.runtime.nginx_binary),
        PathBuf::from(&c.runtime.usque_binary),
        PathBuf::from("/root/.acme.sh"),
        PathBuf::from("/etc/apt/sources.list.d/nginx.list"),
        PathBuf::from("/usr/share/keyrings/nginx-archive-keyring.gpg"),
        PathBuf::from("/usr/sbin/policy-rc.d"),
        PathBuf::from("/usr/local/go"),
        PathBuf::from("/var/spool/cron/crontabs/root"),
        Path::new(&c.website.root).join("index.html"),
    ];
    if c.distribution.is_some() {
        paths.push(PathBuf::from(host::SHARE_ENTRY));
    }
    if let Some(cn) = c.cn_warp.as_ref().filter(|cn| cn.enabled) {
        paths.extend([
            PathBuf::from(&cn.config_file),
            PathBuf::from(&cn.geodata_dir),
        ]);
    }
    if let Some(web) = c.web_services.as_ref().filter(|web| web.enabled) {
        paths.extend([
            PathBuf::from("/usr/local/bin/speedtest-backend"),
            PathBuf::from("/usr/local/bin/openlist"),
            PathBuf::from("/usr/local/bin/speedtest-backend.nodectl-sha256"),
            PathBuf::from("/usr/local/bin/openlist.nodectl-sha256"),
            PathBuf::from("/etc/nodectl-services"),
            PathBuf::from(&web.openlist_data_dir),
        ]);
    }
    paths.extend(feature_entry_paths(c));
    paths.sort();
    paths.dedup();
    paths
}
fn completed_paths(store: &Store, c: &Config) -> Vec<PathBuf> {
    let mut paths = backup_paths(store, c);
    paths.extend(
        host::ENTRIES
            .into_iter()
            .map(|(path, _)| PathBuf::from(path)),
    );
    if c.serves_web() {
        paths.extend(
            host::WEB_ENTRIES
                .into_iter()
                .map(|(path, _)| PathBuf::from(path)),
        );
    }
    if c.routes_cn() {
        paths.extend(
            [
                "/etc/systemd/system/usque-cn.service",
                "/etc/xray/geoip.dat",
                "/etc/xray/geosite.dat",
            ]
            .into_iter()
            .map(PathBuf::from),
        );
    }
    paths.sort();
    paths.dedup();
    paths
}
fn inventory(store: &Store, c: &Config) -> Result<Value> {
    for path in backup_paths(store, c) {
        ensure!(
            path.is_absolute()
                && path.components().count() >= 3
                && !store.state_dir.starts_with(&path),
            "Deployment backup path overlaps the state directory or an unsafe filesystem root"
        );
    }
    if let Some(web) = c.web_services.as_ref().filter(|web| web.enabled) {
        for path in [&web.openlist_data_dir, &web.openlist_files_dir] {
            ensure!(
                !config::overlap(path, store.state_dir.to_str().context("State path")?)
                    && !config::overlap(
                        path,
                        store.config_dir.to_str().context("Configuration path")?
                    ),
                "OpenList data cannot overlap nodectl state or configuration"
            );
        }
    }
    ensure!(
        cfg!(target_os = "linux"),
        "Deployment planning requires Linux/systemd"
    );
    let os = fs::read_to_string("/etc/os-release")?;
    ensure!(
        os.lines()
            .any(|l| ["ID=debian", "ID=ubuntu", "ID=\"debian\"", "ID=\"ubuntu\""].contains(&l)),
        "Automatic deployment supports Debian/Ubuntu only; manual mode remains available"
    );
    host::command("systemctl", &["show-environment"])?;
    crate::cn_warp::platform(c)?;
    let addresses: Value = serde_json::from_str(&host::command("ip", &["-j", "address", "show"])?)?;
    for wanted in c.ips() {
        ensure!(
            addresses
                .as_array()
                .context("Host interfaces")?
                .iter()
                .any(|v| v["addr_info"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|v| v["local"]
                        .as_str()
                        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                        == wanted.parse::<std::net::IpAddr>().ok()))),
            "Configured IP is not assigned to this DMIT host; correct inputs before deployment"
        );
    }
    let current = store.pointer("current")?;
    let mut files = BTreeMap::new();
    for path in backup_paths(store, c).into_iter().chain(
        host::ENTRIES
            .into_iter()
            .map(|(path, _)| PathBuf::from(path)),
    ) {
        files.insert(path.display().to_string(), fingerprint(&path)?);
    }
    files.insert(
        c.runtime.nginx_binary.clone(),
        fingerprint(Path::new(&c.runtime.nginx_binary))?,
    );
    files.insert(
        crate::share::credential_path(store).display().to_string(),
        fingerprint(&crate::share::credential_path(store))?,
    );
    let mut binary_digests = BTreeMap::new();
    for path in [
        &c.runtime.xray_binary,
        &c.runtime.nginx_binary,
        &c.runtime.usque_binary,
    ] {
        binary_digests.insert(
            path,
            if Path::new(path).is_file() {
                Some(store::file_digest(Path::new(path))?)
            } else {
                None
            },
        );
    }
    let mut services = BTreeMap::new();
    for service in host::SERVICES
        .into_iter()
        .chain(c.distribution.is_some().then_some(host::SHARE_SERVICE))
        .chain(c.routes_cn().then_some("usque-cn"))
        .chain(
            c.serves_web()
                .then_some(host::WEB_SERVICES)
                .into_iter()
                .flatten(),
        )
    {
        services.insert(
            service,
            host::command(
                "systemctl",
                &[
                    "show",
                    service,
                    "-p",
                    "LoadState",
                    "-p",
                    "ActiveState",
                    "-p",
                    "UnitFileState",
                ],
            )?,
        );
    }
    let listeners = host::command("ss", &["-H", "-lntu"])?;
    let mut listeners = listeners.lines().map(str::to_owned).collect::<Vec<_>>();
    listeners.sort();
    Ok(
        json!({"os":os,"architecture":std::env::consts::ARCH,"current":current,"files":files,"binary_digests":binary_digests,"services":services,"listeners":listeners,"routes4":host::default_routes(false)?,"routes6":host::default_routes(true)?}),
    )
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Backup {
    path: PathBuf,
    copy: PathBuf,
    existed: bool,
    fingerprint: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u32,
    backup: PathBuf,
    config: Config,
    previous: Option<String>,
    reference: host::Reference,
    files: Vec<Backup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    feature_entry_backups: Option<bool>,
    dns_zone: Option<String>,
    dns: Vec<(Change, Value)>,
    pending_dns: Option<Change>,
    routes4: String,
    routes6: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cn_policy: Option<crate::cn_route::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_metadata: Option<crate::web_services::StorageMetadata>,
    phase: String,
    config_existed: bool,
    services: BTreeMap<String, host::Service>,
    #[serde(default)]
    after_files: Option<BTreeMap<PathBuf, Value>>,
    #[serde(default)]
    completed_release: Option<String>,
}

fn restore_service_states(services: &BTreeMap<String, host::Service>) -> Result<()> {
    for (name, expected) in services {
        ensure!(
            [
                "nginx",
                "xray",
                "usque-warp",
                "usque-cn",
                "librespeed",
                "openlist",
                host::SHARE_SERVICE
            ]
            .contains(&name.as_str()),
            "Unexpected recovery service"
        );
        let current = host::service_state(name)?;
        if current.active != expected.active {
            host::command(
                "systemctl",
                &[if expected.active { "start" } else { "stop" }, name],
            )?;
        }
        let current = host::service_state(name)?;
        if current.enabled != expected.enabled {
            let entry = Path::new("/etc/systemd/system").join(format!("{name}.service"));
            // Disabling an externally linked unit also removes its entrypoint.
            // Preserve the already restored link when the original state was
            // linked but not enabled; never invent an unrecorded unit target.
            let original_link = (expected.enabled == "linked")
                .then(|| fs::read_link(&entry))
                .transpose()
                .context("Original linked service entrypoint is missing")?;
            if current.enabled == "enabled-runtime" {
                host::command("systemctl", &["disable", "--runtime", name])?;
            } else if current.enabled == "enabled" {
                host::command("systemctl", &["disable", name])?;
            }
            match expected.enabled.as_str() {
                "enabled" => {
                    host::command("systemctl", &["enable", name])?;
                }
                "enabled-runtime" => {
                    host::command("systemctl", &["enable", "--runtime", name])?;
                }
                "linked" => {
                    store::replace_link(original_link.as_ref().unwrap(), &entry)?;
                    host::command("systemctl", &["daemon-reload"])?;
                }
                _ => {}
            }
        }
        let actual = host::service_state(name)?;
        ensure!(
            actual.active == expected.active && actual.enabled == expected.enabled,
            "Original service state could not be restored for {name}"
        );
    }
    Ok(())
}

/// Host-only recovery cannot restart a database until its provisioning material
/// has been restored. The outer recovery journal remains the authority.
pub(crate) fn database_recovery_pending(store: &Store) -> Result<bool> {
    let path = store.state_dir.join("deployment.json");
    if !path.exists() {
        return Ok(false);
    }
    store::check_private(&path, false)?;
    let journal: Journal = serde_json::from_slice(&fs::read(path)?)?;
    Ok(journal.schema_version == 3
        && !["materials-restored", "restored", "committed"].contains(&journal.phase.as_str()))
}

pub(crate) fn service_before_preparation(
    store: &Store,
    name: &str,
) -> Result<Option<host::Service>> {
    let path = store.state_dir.join("deployment.json");
    if !path.exists() {
        return Ok(None);
    }
    store::check_private(&path, false)?;
    let journal: Journal = serde_json::from_slice(&fs::read(path)?)?;
    Ok((journal.schema_version == 3)
        .then(|| journal.services.get(name).cloned())
        .flatten())
}
fn same_native_routes(
    before: &str,
    after: &str,
    policy: Option<&crate::cn_route::Policy>,
) -> Result<bool> {
    if let Some(policy) = policy {
        Ok(policy.without_routes(before)? == policy.without_routes(after)?)
    } else {
        Ok(before == after)
    }
}
// Older managed installations can lack installation.json. The outer journal
// still proves whether this deployment introduced the owned CN policy. Once
// the original services are restored, remove only that newly owned policy;
// otherwise its rejecting defaults would prevent the final exact route check.
fn release_new_cn_policy(
    policy: Option<&crate::cn_route::Policy>,
    routes4: &str,
    routes6: &str,
) -> Result<()> {
    if let Some(policy) = policy
        && policy.without_routes(routes4)? == routes4
        && policy.without_routes(routes6)? == routes6
    {
        policy.release()?;
    }
    Ok(())
}
fn save(store: &Store, journal: &Journal) -> Result<()> {
    store::atomic_write(
        &store.state_dir.join("deployment.json"),
        &serde_json::to_vec_pretty(journal)?,
    )
}
fn save_phase(store: &Store, journal: &Journal, phase: &str) -> Result<()> {
    let mut value = serde_json::to_value(journal)?;
    value["phase"] = json!(phase);
    store::atomic_write(
        &store.state_dir.join("deployment.json"),
        &serde_json::to_vec_pretty(&value)?,
    )
}
fn recovery_paths(store: &Store, journal: &Journal) -> Result<Vec<PathBuf>> {
    let mut paths = backup_paths(store, &journal.config);
    // Keep historical journals' exact backup lists. New journals explicitly
    // record the added entrypoint coverage; never infer or relax their hashes.
    match journal.feature_entry_backups {
        Some(true) => ensure!(
            journal.config.routes_cn() || journal.config.serves_web(),
            "Feature entrypoint backups without enabled features"
        ),
        None => paths.retain(|p| !feature_entry_paths(&journal.config).contains(p)),
        Some(false) => bail!("Invalid feature entrypoint backup marker"),
    }
    match journal.schema_version {
        1 => {
            ensure!(
                journal.config.vless.is_none()
                    && journal.config.distribution.is_none()
                    && journal.config.cn_warp.is_none()
                    && journal.config.web_services.is_none()
                    && journal.cn_policy.is_none()
                    && journal.storage_metadata.is_none()
                    && journal.after_files.is_none()
                    && journal.completed_release.is_none(),
                "Legacy journal contains newer material fields"
            );
            // 0.2 did not modify or back up the website. Preserve the exact
            // original backup list; all recorded digests remain mandatory.
            paths.retain(|p| p != &Path::new(&journal.config.website.root).join("index.html"));
        }
        2 => {
            ensure!(
                !journal.config.serves_web() && journal.storage_metadata.is_none(),
                "Website lifecycle requires recovery format 3"
            );
        }
        3 => {
            ensure!(
                journal.config.serves_web(),
                "Website journal has no website configuration"
            );
        }
        _ => bail!("Unknown deployment recovery format"),
    }
    Ok(paths)
}
fn copy_tree(source: &Path, dest: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        std::os::unix::fs::symlink(fs::read_link(source)?, dest)?;
        #[cfg(not(unix))]
        bail!("Deployment backups require Linux");
    } else if metadata.is_dir() {
        fs::create_dir(dest)?;
        for file in fs::read_dir(source)? {
            let file = file?;
            copy_tree(&file.path(), &dest.join(file.file_name()))?;
        }
        fs::set_permissions(dest, metadata.permissions())?;
    } else if metadata.is_file() {
        fs::copy(source, dest)?;
        fs::set_permissions(dest, metadata.permissions())?;
    } else {
        bail!("Cannot back up special file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        let name = std::ffi::CString::new(dest.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::lchown(name.as_ptr(), metadata.uid(), metadata.gid()) } == 0,
            "Cannot preserve backup ownership"
        );
    }
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    if let Ok(m) = fs::symlink_metadata(path) {
        if m.is_dir() && !m.file_type().is_symlink() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}
fn initialize(store: &Store, c: &Config, explicit_input: bool, work: &Path) -> Result<()> {
    let template = work.join("candidate.toml");
    store::atomic_write(&template, toml::to_string_pretty(c)?.as_bytes())?;
    config::init(&store.config_dir, Some(&template), &[])?;
    if explicit_input {
        store::atomic_write(
            &store.config_dir.join("node.toml"),
            toml::to_string_pretty(c)?.as_bytes(),
        )?;
    }
    store.inputs()?;
    Ok(())
}

pub fn run(store: &Store, mut args: Deploy) -> Result<()> {
    if args.wizard {
        ensure!(
            io::stdin().is_terminal(),
            "Wizard requires a terminal; use explicit non-interactive preview and approval instead"
        );
        host::linux_root()?;
    }
    ensure!(
        !store.state_dir.join("deployment.json").exists(),
        "Interrupted provisioning exists; run recover first"
    );
    let (c, mut s, exists) = candidate(store, &args)?;
    let mut access_token = if let Some(path) = &args.access_token_file {
        store::check_private(path, false)?;
        ensure!(
            fs::metadata(path)?.len() <= 128,
            "Invalid access token file"
        );
        Some(fs::read_to_string(path)?.trim().to_owned())
    } else {
        None
    };
    if args.wizard
        && c.distributes()
        && !crate::share::credential_path(store).exists()
        && access_token.is_none()
        && prompt(
            "Set an initial custom access token (true/false; otherwise generated securely)",
            "false",
        )?
        .parse::<bool>()?
    {
        access_token = Some(secret_prompt(
            "Initial access token (64 lowercase hex characters)",
        )?);
    }
    if let Some(token) = &access_token {
        ensure!(
            c.distributes(),
            "Enable distribution before setting an access token"
        );
        ensure!(
            !crate::share::credential_path(store).exists(),
            "Access credentials already exist; use nodectl share rotate explicitly"
        );
        crate::share::validate_custom(token)?;
    }
    ensure!(
        config::abs_path(store.config_dir.to_str().context("Config path")?)
            && config::abs_path(store.state_dir.to_str().context("State path")?),
        "Automatic deployment requires safe absolute Linux config/state paths"
    );
    let mut wizard_token = None;
    let inherited = if exists {
        Some(store.inputs()?.0)
    } else {
        None
    };
    if !args.non_interactive {
        let mode = prompt(
            "DNS mode (manual/cloudflare)",
            if args.dns_zone.is_some() || args.wizard {
                "cloudflare"
            } else {
                "manual"
            },
        )?;
        ensure!(
            ["manual", "cloudflare"].contains(&mode.as_str()),
            "Unknown DNS mode"
        );
        if mode == "cloudflare" {
            let zone = prompt(
                "Cloudflare Zone ID",
                args.dns_zone
                    .as_deref()
                    .unwrap_or(if args.wizard { "auto" } else { "" }),
            )?;
            if args.wizard {
                let cached = store.config_dir.join("credentials/cloudflare-token");
                let token = dns::token(
                    args.token_file
                        .as_deref()
                        .or_else(|| cached.is_file().then_some(cached.as_path())),
                )?;
                args.dns_zone = Some(if zone == "auto" {
                    Cloudflare::discover_zone(&c.node.domain, &token)?
                } else {
                    zone
                });
                wizard_token = Some(token);
            } else {
                args.dns_zone = Some(zone);
            }
        } else {
            args.dns_zone = None;
        }
        args.manual_certificates = prompt(
            "Use manually provisioned certificates (true/false)",
            &args.manual_certificates.to_string(),
        )?
        .parse()?;
        if !args.manual_certificates
            && host::certificates(&c).is_err()
            && !provision::existing_acme_account()
        {
            args.acme_email = Some(prompt(
                "ACME email",
                args.acme_email.as_deref().unwrap_or(""),
            )?);
            if args.wizard {
                args.accept_ca_terms = prompt("Accept Let's Encrypt subscriber agreement https://letsencrypt.org/repository/ (true/false)", "false")?.parse()?;
            }
        }
        if args.wizard && crate::cn_warp::needs_registration(&c) {
            args.accept_warp_terms = prompt("Accept Cloudflare WARP terms https://www.cloudflare.com/application/terms/ (true/false)", "true")?.parse()?;
        }
        if args.wizard
            && store.pointer("current")?.is_none()
            && host::ENTRIES
                .iter()
                .any(|(p, _)| fs::symlink_metadata(p).is_ok())
        {
            args.takeover = prompt(
                "Back up and take over existing service entrypoints (true/false)",
                "true",
            )?
            .parse()?;
        }
    }
    let paths = backup_paths(store, &c);
    for path in &paths {
        ensure!(
            path.is_absolute()
                && path.components().count() >= 3
                && !store.state_dir.starts_with(path),
            "Unsafe or overlapping automatic backup path; use a dedicated config/certificate directory"
        );
    }
    let cf = if let Some(zone) = &args.dns_zone {
        Some(Cloudflare::new(
            zone,
            match wizard_token {
                Some(token) => token,
                None => dns::token(args.token_file.as_deref())?,
            },
        )?)
    } else {
        None
    };
    let changes = cf
        .as_ref()
        .map(|cf| cf.plan(&c, inherited.as_ref()))
        .transpose()?
        .unwrap_or_default();
    if args.wizard
        && !args.manual_certificates
        && let Some(cf) = &cf
    {
        let zone = cf.zone_name()?;
        if c.domains()
            .iter()
            .any(|name| name != &zone && !name.ends_with(&format!(".{zone}")))
        {
            for name in c.domains() {
                Cloudflare::discover_zone(&name, cf.credential())?;
            }
            args.acme_discover_zones = true;
            println!(
                "Retained SANs span multiple zones; authorized ACME zone discovery is included in the plan."
            );
        }
    }
    let inventory = inventory(store, &c)?;
    let previous = store.pointer("current")?;
    let active_config = previous
        .as_ref()
        .map(|id| store.verify(id).map(|(c, _)| c))
        .transpose()?
        .or_else(|| inherited.clone());
    let superseded_acme = active_config
        .as_ref()
        .filter(|old| {
            old.node.domain != c.node.domain && old.tls.domain_cert_dir == c.tls.domain_cert_dir
        })
        .map(|old| old.node.domain.clone());
    let entrypoints_absent = host::ENTRIES
        .iter()
        .all(|(path, _)| inventory["files"][path].is_null());
    let preserve_clients = if let Some(old) = &previous {
        let (old, old_s) = store.verify(old)?;
        preserves_clients(&old, &old_s, &c, &s)?
    } else {
        false
    };
    let domain_cert_valid = host::certificates_part(&c, Some(false)).is_ok();
    let ip_cert_valid = host::certificates_part(&c, Some(true)).is_ok();
    let needs_cert = !domain_cert_valid || !ip_cert_valid;
    let mut required_actions = vec![];
    let mut known_acme = c.sans();
    if let Some(old) = &active_config {
        known_acme.extend(old.sans());
    }
    if !args.manual_certificates && provision::acme_scope(&known_acme).is_err() {
        required_actions.push("ACME home is shared or unreadable; preserve unrelated certificates with --manual-certificates or a dedicated client");
    }
    if previous.is_none() && !entrypoints_absent && !args.takeover {
        required_actions
            .push("Review existing entrypoints and provide --takeover before replacement");
    }
    if args.manual_certificates && needs_cert {
        required_actions.push("Provision valid domain/IP certificates, then preview again");
    }
    if !args.manual_certificates && !domain_cert_valid && cf.is_none() {
        required_actions.push("Provide Cloudflare --dns-zone and a protected token for domain DNS-01, or use manually provisioned certificates");
    }
    if !args.manual_certificates && needs_cert && !provision::existing_acme_account() {
        if args.acme_email.is_none() {
            required_actions.push("Provide --acme-email for the new ACME account");
        }
        if !args.accept_ca_terms {
            required_actions.push("Review CA terms and supply --accept-ca-terms for a new account");
        }
    }
    if crate::cn_warp::needs_registration(&c) && !args.accept_warp_terms {
        required_actions.push("Review WARP terms and supply --accept-warp-terms for new device registration, or disable each unregistered WARP profile (--warp false / --cn-warp false)");
    }
    let configuration_diff = if let Some(old) = &inherited {
        similar::TextDiff::from_lines(&toml::to_string_pretty(old)?, &toml::to_string_pretty(&c)?)
            .unified_diff()
            .header("existing node.toml", "candidate node.toml")
            .to_string()
    } else {
        "New DMIT configuration; credentials generated on execution".into()
    };
    let mut plan = json!({"schema_version":1,"configuration_diff":configuration_diff,"required_actions":required_actions,"certificate_status":{"domain_valid":domain_cert_valid,"ip_valid":ip_cert_valid},"configuration":c,"preserve_existing_secrets":exists,"generate_transport_paths":!exists && args.input.is_none(),"previous_client_compatibility":if previous.is_none(){"no_previous_managed_release"}else if preserve_clients{"preserved_and_live_test_required"}else{"explicit_input_changes_require_client_updates"},"secret_digest":if exists{Some(store::digest(&serde_json::to_vec(&s)?))}else{None},"inventory":inventory,"dns_changes":changes,"manual_dns":cf.is_none(),"manual_certificates":args.manual_certificates,"provision_dependencies":!args.skip_dependencies,"takeover":args.takeover,"new_package_defaults_may_be_claimed":entrypoints_absent && !args.skip_dependencies,"probe_url":args.probe_url,"dns_wait_seconds":args.dns_wait_seconds,"delete_dns_on_failure":args.delete_dns_on_failure,"acme_email":args.acme_email,"acme_discover_zones":args.acme_discover_zones,"retire_superseded_acme_renewal":if args.manual_certificates{None}else{superseded_acme.as_deref()},"accept_ca_terms":args.accept_ca_terms,"accept_warp_terms":args.accept_warp_terms,"generator":env!("CARGO_PKG_VERSION"),"executable_sha256":store::file_digest(&std::env::current_exe()?)?,"versions_lock_sha256":store::digest(include_bytes!("../versions.lock.toml")),"stages":["backup","dependencies","inputs","dns","certificates","warp","warp-socks-handshake-with-temporary-tun-stop","render","diff","check","takeover-if-authorized","apply-with-live-handshakes","renewal"],"recovery_limits":["Package transactions and CA issuance cannot be undone by a configuration rollback; backups and DNS recovery are retained","Unknown unmanaged service credentials are never inferred: import verified node.toml/secrets.json before takeover"]});
    plan["website_placeholder_replacement"] = json!(provision::website_change(&c)?);
    plan["generate_independent_vless_keys"] = json!(c.encrypted() && s.vless.is_none());
    plan["replace_domain_set"] = json!(args.replace_domain_set);
    plan["distribution"] = json!({"enabled":c.distributes(),"initial_custom_token":access_token.is_some(),"initial_token_sha256":access_token.as_ref().map(|s| store::digest(s.as_bytes())),"credential_file":crate::share::credential_path(store),"page_path":"/nodes/","server_error_logging_suppressed":c.distribution.is_some()});
    plan["distribution"]["revoke_access_when_disabled"] = json!(!c.distributes());
    if args.wizard {
        plan["export_client_formats"] = json!(["xray", "mihomo"]);
        plan["persist_cloudflare_credential"] = json!(cf.is_some());
        if cf.is_some() {
            plan["credential_file"] = json!(store.config_dir.join("credentials/cloudflare-token"));
            plan["stages"]
                .as_array_mut()
                .unwrap()
                .insert(3, json!("private-credential-storage"));
        }
        plan["stages"]
            .as_array_mut()
            .unwrap()
            .push(json!("private-client-export"));
    }
    let digest = store::digest(&serde_json::to_vec(&plan)?);
    println!(
        "{}\nPlan SHA256: {digest}",
        serde_json::to_string_pretty(&plan)?
    );
    if args.wizard {
        ensure!(
            required_actions.is_empty(),
            "Plan has unmet prerequisites; resolve required_actions before deployment"
        );
        ensure!(
            prompt("Apply this exact plan? Type yes to continue", "no")? == "yes",
            "Deployment cancelled; no deployment changes made"
        );
        args.execute = true;
        args.approve = Some(digest.clone());
    }
    if !args.execute {
        println!(
            "Preview only. Review this plan; rerun with the same options --execute --approve {digest}"
        );
        return Ok(());
    }
    ensure!(
        args.approve.as_deref() == Some(&digest),
        "Plan approval missing or stale; review a fresh preview"
    );
    ensure!(
        required_actions.is_empty(),
        "Plan has unmet prerequisites; resolve required_actions and preview again"
    );
    host::linux_root()?;
    let _lock = store.lock()?;
    let _lease = provision::Lease::hold(&_lock);
    ensure!(
        plan["executable_sha256"] == json!(store::file_digest(&std::env::current_exe()?)?),
        "nodectl changed after preview; review a fresh plan"
    );
    ensure!(
        inventory == self::inventory(store, &c)?,
        "Host changed while acquiring lock; preview again"
    );
    if let Some(cf) = &cf {
        ensure!(
            serde_json::to_vec(&changes)? == serde_json::to_vec(&cf.plan(&c, inherited.as_ref())?)?,
            "DNS changed after preview"
        );
    }
    // Refuse a fresh deployment over live legacy service identities without imported inputs.
    if !exists {
        ensure!(
            host::command("systemctl", &["is-active", "--quiet", "xray"]).is_err(),
            "Existing Xray is active without node.toml/secrets.json; import validated inputs before takeover to retain client compatibility"
        );
    }
    let backup = store
        .state_dir
        .join("deployment-backups")
        .join(uuid::Uuid::new_v4().to_string());
    store::private_dir(&backup)?;
    let reference = host::Reference {
        binary: PathBuf::from(&c.runtime.xray_binary),
        sha256: String::new(),
        version:
            toml::from_str::<toml::Value>(include_str!("../versions.lock.toml"))?["xray"]["version"]
                .as_str()
                .unwrap()
                .into(),
        probe_url: args.probe_url.clone(),
    };
    let mut journal = Journal {
        schema_version: if c.serves_web() { 3 } else { 2 },
        backup: backup.clone(),
        config: c.clone(),
        previous: store.pointer("current")?,
        reference,
        files: vec![],
        feature_entry_backups: (c.routes_cn() || c.serves_web()).then_some(true),
        dns_zone: args.dns_zone.clone(),
        dns: vec![],
        pending_dns: None,
        routes4: host::default_routes(false)?,
        routes6: host::default_routes(true)?,
        cn_policy: host::managed_cn_policy(store, &c)?,
        storage_metadata: crate::web_services::storage_metadata(&c)?,
        phase: if c.serves_web() {
            "snapshot-pending"
        } else {
            "backed-up"
        }
        .into(),
        config_existed: exists,
        services: host::SERVICES
            .into_iter()
            .chain(c.distribution.is_some().then_some(host::SHARE_SERVICE))
            .chain(c.routes_cn().then_some("usque-cn"))
            .chain(
                c.serves_web()
                    .then_some(host::WEB_SERVICES)
                    .into_iter()
                    .flatten(),
            )
            .map(|name| Ok((name.to_owned(), host::service_state(name)?)))
            .collect::<Result<_>>()?,
        after_files: None,
        completed_release: None,
    };
    if journal.schema_version == 3 {
        save(store, &journal)?;
    }
    let preparation = (|| -> Result<()> {
        if journal.schema_version == 3 {
            crate::web_services::begin_maintenance(store, &backup)?;
            for name in ["nginx", "openlist", "librespeed"] {
                if journal.services.get(name).is_some_and(|state| state.active) {
                    host::command("systemctl", &["stop", name])?;
                }
            }
            #[cfg(feature = "integration-test")]
            if std::env::var("NODECTL_DEPLOY_FAILPOINT").as_deref() == Ok("website-snapshot") {
                std::process::exit(87);
            }
        }
        for (i, path) in backup_paths(store, &c).into_iter().enumerate() {
            let copy = backup.join(format!("file-{i}"));
            let existed = fs::symlink_metadata(&path).is_ok();
            if existed {
                copy_tree(&path, &copy)?;
            }
            journal.files.push(Backup {
                fingerprint: if existed {
                    fingerprint(&copy)?
                } else {
                    Value::Null
                },
                path,
                copy,
                existed,
            });
        }
        journal.phase = "backed-up".into();
        save(store, &journal)?;
        Ok(())
    })();
    if let Err(error) = preparation {
        if journal.schema_version == 3 {
            restore_service_states(&journal.services)?;
            crate::web_services::finish_maintenance(store, &backup)?;
            fs::remove_file(store.state_dir.join("deployment.json"))?;
        }
        return Err(error)
            .context("Consistent website backup preparation failed before material changes");
    }
    #[cfg(feature = "integration-test")]
    if std::env::var("NODECTL_DEPLOY_FAILPOINT").as_deref() == Ok("journal") {
        bail!("Injected deployment journal interruption");
    }
    let result = (|| -> Result<()> {
        let mut created_nginx_default = None;
        if !args.skip_dependencies {
            // Prevent package maintainer scripts from starting/stopping live services.
            store::atomic_write(Path::new("/usr/sbin/policy-rc.d"), b"#!/bin/sh\nexit 101\n")?;
            host::command("chmod", &["0755", "/usr/sbin/policy-rc.d"])?;
            let provision = provision::dependencies(&c, &backup);
            let policy = journal
                .files
                .iter()
                .find(|b| b.path == Path::new("/usr/sbin/policy-rc.d"))
                .unwrap();
            remove(&policy.path)?;
            if policy.existed {
                copy_tree(&policy.copy, &policy.path)?;
            }
            created_nginx_default = provision?;
        }
        crate::web_services::prepare(&c)?;
        if exists {
            config::encryption_keys(&c, &mut s)?;
            config::validate(&c, &s)?;
            store::atomic_write(
                &store.config_dir.join("node.toml"),
                toml::to_string_pretty(&c)?.as_bytes(),
            )?;
            store::atomic_write(
                &store.config_dir.join("secrets.json"),
                &serde_json::to_vec_pretty(&s)?,
            )?;
        } else {
            initialize(store, &c, args.input.is_some(), &backup)?;
        }
        if args.wizard
            && let Some(cf) = &cf
        {
            let credentials = store.config_dir.join("credentials");
            store::private_dir(&credentials)?;
            store::atomic_write(
                &credentials.join("cloudflare-token"),
                cf.credential().as_bytes(),
            )?;
        }
        provision::website(&c)?;
        for change in &changes {
            cf.as_ref()
                .context("Cloudflare client")?
                .ensure_unchanged(change)?;
            journal.pending_dns = Some(change.clone());
            save(store, &journal)?;
            let record = cf.as_ref().context("Cloudflare client")?.apply(change)?;
            journal.dns.push((change.clone(), record));
            journal.pending_dns = None;
            save(store, &journal)?;
        }
        dns::wait(&c, args.dns_wait_seconds)?;
        let token =
            if !args.manual_certificates && host::certificates_part(&c, Some(false)).is_err() {
                Some(
                    cf.as_ref()
                        .context("Automatic DNS-01 requires --dns-zone")?
                        .credential()
                        .to_owned(),
                )
            } else {
                None
            };
        provision::certificates(
            &c,
            &args,
            &backup,
            token.as_deref(),
            superseded_acme.as_deref(),
        )?;
        #[cfg(feature = "integration-test")]
        if std::env::var("NODECTL_DEPLOY_FAILPOINT").as_deref() == Ok("certificate-material") {
            bail!("Injected deployment certificate material interruption");
        }
        provision::warp(&c, &args)?;
        journal.phase = "warp-probe".into();
        save(store, &journal)?;
        provision::warp_probe(&c)?;
        let release = store.render()?;
        print!("{}", store.diff(&release)?);
        journal.reference.sha256 = store::file_digest(&journal.reference.binary)?;
        journal.phase = "checking".into();
        save(store, &journal)?;
        host::check(store, &release, journal.reference.clone())?;
        let owned_defaults = entrypoints_absent && created_nginx_default.is_some();
        if owned_defaults {
            for (path, _) in host::ENTRIES {
                if path == "/etc/nginx/nginx.conf" {
                    ensure!(
                        Some(store::file_digest(Path::new(path))?) == created_nginx_default,
                        "New package default changed before apply"
                    );
                } else {
                    ensure!(
                        fs::symlink_metadata(path).is_err(),
                        "Unexpected entrypoint appeared during provisioning; review a new takeover plan"
                    );
                }
            }
        }
        if args.takeover || owned_defaults {
            let record = store.state_dir.join("takeover").join(&release);
            if !record.exists() {
                host::takeover(store, &release)?;
            }
        }
        journal.phase = "applying".into();
        save(store, &journal)?;
        host::apply_with_access_token(store, &release, access_token.as_deref())?;
        if preserve_clients {
            host::previous_clients(
                store,
                previous.as_deref().context("Previous release")?,
                &journal.reference,
            )?;
            println!("Previous client profiles: all three protocol handshakes passed");
        }
        journal.phase = "applied".into();
        save(store, &journal)?;
        if !args.manual_certificates {
            provision::renewal(&c, store, superseded_acme.as_deref())?;
        }
        ensure!(
            same_native_routes(
                &journal.routes4,
                &host::default_routes(false)?,
                journal.cn_policy.as_ref()
            )? && same_native_routes(
                &journal.routes6,
                &host::default_routes(true)?,
                journal.cn_policy.as_ref()
            )?,
            "DMIT default routes changed"
        );
        if args.wizard {
            let output = store
                .state_dir
                .join("client-exports")
                .join(uuid::Uuid::new_v4().to_string());
            store::private_dir(output.parent().unwrap())?;
            store.export_format(&output, store::ClientFormat::All)?;
            println!(
                "Private Xray/Mihomo clients and weights: {}",
                output.display()
            );
        }
        store::atomic_write(
            &backup.join("completed.json"),
            &serde_json::to_vec_pretty(
                &json!({"release":release,"plan_sha256":digest,"dns":journal.dns,"routes_preserved":true}),
            )?,
        )?;
        let records = store.state_dir.join("deployments");
        store::private_dir(&records)?;
        journal.completed_release = Some(release.clone());
        journal.after_files = Some(
            completed_paths(store, &c)
                .into_iter()
                .map(|p| Ok((p.clone(), fingerprint(&p)?)))
                .collect::<Result<_>>()?,
        );
        store::atomic_write(
            &records.join(format!("{release}.json")),
            &serde_json::to_vec_pretty(&journal)?,
        )?;
        if journal.schema_version == 3 {
            journal.phase = "committed".into();
            save(store, &journal)?;
            #[cfg(feature = "integration-test")]
            if std::env::var("NODECTL_DEPLOY_FAILPOINT").as_deref() == Ok("website-committed") {
                std::process::exit(87);
            }
            crate::web_services::finish_maintenance(store, &backup)?;
            crate::web_services::public_health(&c)?;
        }
        fs::remove_file(store.state_dir.join("deployment.json"))?;
        println!(
            "Deployment {release} completed; all three protocol handshakes passed. Backup: {}",
            backup.display()
        );
        if crate::share::deployment_result(store).is_err() {
            eprintln!(
                "nodectl: deployment succeeded; inspect protected distribution credentials with nodectl share status"
            );
        }
        Ok(())
    })();
    if let Err(error) = result {
        if journal.schema_version == 3 && journal.phase == "committed" {
            let path = store.state_dir.join("deployment.json");
            if path.is_file() {
                store::check_private(&path, false)?;
                let saved: Journal = serde_json::from_slice(&fs::read(path)?)?;
                if saved.phase == "committed" {
                    bail!(
                        "Deployment is committed; final maintenance cleanup requires recover. Program and journals retained: {error:#}"
                    );
                }
            }
        }
        // Service apply has its own transaction. Provisioning uses the saved journal.
        match restore(store, &journal, cf.as_ref(), args.delete_dns_on_failure) {
            Ok(()) => bail!(
                "Deployment failed and saved host inputs were restored: {error:#}. Package/CA side effects remain recorded at {}",
                backup.display()
            ),
            Err(restore) => bail!(
                "Deployment failed: {error:#}; recovery also failed: {restore:#}. Retain journal and run recover"
            ),
        }
    }
    Ok(())
}
fn restore(store: &Store, journal: &Journal, cf: Option<&Cloudflare>, delete_new_dns: bool) -> Result<()> {
    ensure!(
        journal
            .backup
            .starts_with(store.state_dir.join("deployment-backups")),
        "Invalid deployment recovery record"
    );
    let allowed = recovery_paths(store, journal)?;
    config::validate_preview(&journal.config, &preview_secrets())?;
    for path in &allowed {
        ensure!(
            path.is_absolute()
                && path.components().count() >= 3
                && !store.state_dir.starts_with(path),
            "Unsafe recovery path"
        );
    }
    ensure!(
        journal.services.len()
            == host::SERVICES.len()
                + usize::from(journal.config.distribution.is_some())
                + usize::from(journal.config.routes_cn())
                + if journal.config.serves_web() {
                    host::WEB_SERVICES.len()
                } else {
                    0
                }
            && (!journal.config.serves_web()
                || host::WEB_SERVICES
                    .iter()
                    .all(|name| journal.services.contains_key(*name)))
            && (!journal.config.routes_cn() || journal.services.contains_key("usque-cn"))
            && (journal.config.distribution.is_none()
                || journal.services.contains_key(host::SHARE_SERVICE))
            && host::SERVICES
                .iter()
                .all(|name| journal.services.contains_key(*name)),
        "Incomplete provisioning service state baseline"
    );
    ensure!(
        journal.backup.parent() == Some(store.state_dir.join("deployment-backups").as_path())
            && journal
                .backup
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s)),
        "Invalid recovery directory"
    );
    store::check_private(&journal.backup, true)?;
    if journal.schema_version == 3
        && ["snapshot-pending", "restored", "committed"].contains(&journal.phase.as_str())
    {
        let expected = if journal.phase == "committed" {
            journal.completed_release.as_ref()
        } else {
            journal.previous.as_ref()
        };
        ensure!(
            store.pointer("current")?.as_ref() == expected,
            "Website finalization pointer differs from the recorded state"
        );
        if journal.phase == "snapshot-pending" {
            ensure!(
                journal.files.is_empty()
                    && journal.dns.is_empty()
                    && journal.pending_dns.is_none()
                    && journal.after_files.is_none()
                    && journal.completed_release.is_none(),
                "Incomplete website backup journal has material mutations"
            );
            ensure!(
                !store.state_dir.join("transaction.json").exists()
                    && !store.state_dir.join("uninstall.json").exists(),
                "Host recovery cannot be skipped during snapshot preparation"
            );
            restore_service_states(&journal.services)?;
            ensure!(
                journal.routes4 == host::default_routes(false)?
                    && journal.routes6 == host::default_routes(true)?,
                "Native routes drifted during website backup"
            );
            save_phase(store, journal, "restored")?;
        } else if journal.phase == "restored" {
            restore_service_states(&journal.services)?;
            ensure!(
                journal.routes4 == host::default_routes(false)?
                    && journal.routes6 == host::default_routes(true)?,
                "Restored website routes have drifted"
            );
        } else if journal.phase == "committed" {
            let id = journal
                .completed_release
                .as_deref()
                .context("Committed website deployment has no release")?;
            host::verify_live_success(store, id)?;
        }
        crate::web_services::finish_maintenance(store, &journal.backup)?;
        fs::remove_file(store.state_dir.join("deployment.json"))?;
        return Ok(());
    }
    let paths = journal
        .files
        .iter()
        .map(|f| f.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    ensure!(
        journal.files.len() == allowed.len()
            && paths.len() == allowed.len()
            && allowed.iter().all(|p| paths.contains(p)),
        "Incomplete or duplicated provisioning backup list"
    );
    let mut changed_binaries = vec![];
    for file in &journal.files {
        ensure!(
            allowed.contains(&file.path) && file.copy.parent() == Some(journal.backup.as_path()),
            "Invalid recovery backup path"
        );
        if file.existed {
            ensure!(
                fingerprint(&file.copy)? == file.fingerprint,
                "Provisioning backup integrity failure; retain recovery journal"
            );
        }
    }
    // Stop the newly managed tunnel while its unit and stop hook still exist.
    // Removing the unit first can leave an active process with LoadState=not-found,
    // so the inner recovery cannot reliably stop it or restore its old state.
    if journal.config.routes_cn() {
        host::stop_service("usque-cn")?;
    }
    if journal.schema_version == 3 {
        crate::web_services::begin_maintenance(store, &journal.backup)?;
        for name in ["xray", "nginx", "openlist", "librespeed"] {
            host::stop_service(name)?;
        }
    }
    // Retain newly generated identities/certificates before undoing preparation,
    // so an operator can reuse a completed issuance/registration after failure.
    let retained = journal.backup.join("failed-material");
    if !retained.exists() {
        let stage = tempfile::Builder::new()
            .prefix(".failed-material-")
            .tempdir_in(&journal.backup)?;
        let mut inventory = BTreeMap::new();
        for (index, file) in journal.files.iter().enumerate() {
            let relevant = file.path == store.config_dir
                || file.path == Path::new(&journal.config.tls.domain_cert_dir)
                || file.path == Path::new(&journal.config.tls.ip_cert_dir)
                || file.path == Path::new(&journal.config.warp.config_file)
                || journal
                    .config
                    .cn_warp
                    .as_ref()
                    .is_some_and(|cn| file.path == Path::new(&cn.config_file))
                || file.path == Path::new("/root/.acme.sh");
            if relevant
                && fs::symlink_metadata(&file.path).is_ok()
                && fingerprint(&file.path)? != file.fingerprint
            {
                let copy = stage.path().join(format!("file-{index}"));
                copy_tree(&file.path, &copy)?;
                inventory.insert(
                    file.path.display().to_string(),
                    json!({"backup":format!("file-{index}"),"fingerprint":fingerprint(&copy)?}),
                );
            }
        }
        store::atomic_write(
            &stage.path().join("inventory.json"),
            &serde_json::to_vec_pretty(&inventory)?,
        )?;
        fs::rename(stage.path(), retained)?;
    }
    // Restore original binaries/certificates before checking and switching back.
    for file in &journal.files {
        if file.existed && fingerprint(&file.path)? == fingerprint(&file.copy)? {
            continue;
        }
        // A newly installed package remains installed on provisioning failure.
        // Keep its executable consistent with dpkg; restore disabled/inactive state below.
        if !file.existed && file.path == Path::new(&journal.config.runtime.nginx_binary) {
            continue;
        }
        for (name, path) in [
            ("nginx", &journal.config.runtime.nginx_binary),
            ("xray", &journal.config.runtime.xray_binary),
            ("usque-warp", &journal.config.runtime.usque_binary),
        ] {
            if file.path == Path::new(path) && journal.services.get(name).is_some_and(|s| s.active)
            {
                changed_binaries.push(name);
            }
        }
        remove(&file.path)?;
        if file.existed {
            copy_tree(&file.copy, &file.path)?;
        }
    }
    if journal.schema_version == 3 {
        crate::web_services::restore_storage_metadata(
            &journal.config,
            journal.storage_metadata.as_ref(),
        )?;
        save_phase(store, journal, "materials-restored")?;
    }
    if store.state_dir.join("transaction.json").exists()
        || store.state_dir.join("uninstall.json").exists()
    {
        host::recover(store)?;
    } else {
        for name in changed_binaries {
            host::command("systemctl", &["restart", name])?;
            host::command("systemctl", &["is-active", "--quiet", name])?;
        }
    }
    let current = store.pointer("current")?;
    if current != journal.previous {
        if let Some(previous) = &journal.previous {
            let (c, _) = store.verify(previous)?;
            let mut reference = journal.reference.clone();
            reference.binary = PathBuf::from(c.runtime.xray_binary);
            reference.sha256 = store::file_digest(&reference.binary)?;
            host::check(store, previous, reference)?;
            // Sharing is also backed up as deployment material. Its restored
            // link can already name the previous snapshot while `current`
            // still names the failed/new one. Authorize only this exact link
            // from the validated journal; never approve arbitrary entry drift.
            let sharing = journal
                .files
                .iter()
                .find(|f| f.path == Path::new(host::SHARE_ENTRY));
            let sharing_restored = if let Some(sharing) = sharing {
                sharing.existed
                    && sharing.fingerprint["link"]
                        == json!(
                            store
                                .release(previous)?
                                .join("systemd/nodectl-share.service")
                        )
                    && fingerprint(&sharing.path)? == sharing.fingerprint
            } else {
                false
            };
            host::apply_after_material_restore(store, previous, sharing_restored)?;
        } else if current.is_some() {
            host::uninstall(store, true)?;
        }
    }
    restore_service_states(&journal.services)?;
    if let Some(change) = &journal.pending_dns {
        if change.before.is_some() || delete_new_dns {
            cf.context("DNS recovery requires Cloudflare token")?
                .restore_pending(change)?;
        } else {
            println!(
                "Retaining pending newly created DNS record {} ({}) on Cloudflare",
                change.name, change.kind
            );
        }
    }
    for (change, record) in journal.dns.iter().rev() {
        if change.before.is_some() || delete_new_dns {
            cf.context("DNS recovery requires Cloudflare token")?
                .restore(change, record)?;
        } else {
            println!(
                "Retaining newly created DNS record {} ({}) on Cloudflare to allow propagation and retry",
                change.name, change.kind
            );
        }
    }
    release_new_cn_policy(
        journal.cn_policy.as_ref(),
        &journal.routes4,
        &journal.routes6,
    )?;
    ensure!(
        journal.routes4 == host::default_routes(false)?
            && journal.routes6 == host::default_routes(true)?,
        "Default routes differ; inspect routing before clearing recovery journal"
    );
    if journal.schema_version == 3 {
        save_phase(store, journal, "restored")?;
        crate::web_services::finish_maintenance(store, &journal.backup)?;
    }
    fs::remove_file(store.state_dir.join("deployment.json"))?;
    Ok(())
}
pub fn recover(store: &Store, token_file: Option<&Path>) -> Result<()> {
    host::linux_root()?;
    let path = store.state_dir.join("deployment.json");
    store::check_private(&path, false)?;
    let journal: Journal = serde_json::from_slice(&fs::read(path)?)
        .map_err(|_| anyhow::anyhow!("Invalid deployment recovery journal"))?;
    if journal.schema_version == 3
        && ["snapshot-pending", "restored", "committed"].contains(&journal.phase.as_str())
    {
        return restore(store, &journal, None, false);
    }
    let cf = if journal.pending_dns.is_some() || !journal.dns.is_empty() {
        Some(Cloudflare::new(
            journal.dns_zone.as_deref().context("Recovery DNS zone")?,
            dns::token(token_file)?,
        )?)
    } else {
        None
    };
    restore(store, &journal, cf.as_ref(), false)
}

/// Roll back the entire automatic deployment, including certificate and DNS
/// material. Ordinary manual releases retain their existing apply rollback.
pub fn rollback(store: &Store, token_file: Option<&Path>) -> Result<bool> {
    host::linux_root()?;
    let current = store.pointer("current")?.context("No current release")?;
    let path = store
        .state_dir
        .join("deployments")
        .join(format!("{current}.json"));
    if !path.exists() {
        return Ok(false);
    }
    store.verify(&current)?;
    store::check_private(&path, false)?;
    let journal: Journal = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|_| anyhow::anyhow!("Invalid completed deployment record"))?;
    ensure!(
        [2, 3].contains(&journal.schema_version)
            && journal.completed_release.as_deref() == Some(current.as_str()),
        "Completed deployment record belongs to another release"
    );
    ensure!(
        journal.previous.is_some() && journal.previous == store.pointer("previous")?,
        "Deployment rollback baseline differs; inspect history before proceeding"
    );
    let after = journal
        .after_files
        .as_ref()
        .context("Completed deployment has no material baseline")?;
    ensure!(
        after.len() == completed_paths(store, &journal.config).len(),
        "Incomplete completed material baseline"
    );
    for path in completed_paths(store, &journal.config) {
        ensure!(
            after.get(&path) == Some(&fingerprint(&path)?),
            "Deployment materials changed after completion; inspect drift before rollback"
        );
    }
    // Acquire the credential before persisting an interruption record.
    let cf = if journal.pending_dns.is_some() || !journal.dns.is_empty() {
        Some(Cloudflare::new(
            journal.dns_zone.as_deref().context("Recovery zone")?,
            dns::token(token_file)?,
        )?)
    } else {
        None
    };
    save(store, &journal)?;
    restore(store, &journal, cf.as_ref(), false)?;
    println!("Deployment materials, previous release and DNS restored and verified.");
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "Requires explicit fresh mount/network namespaces and private /run"]
    fn kernel_restore_releases_only_new_cn_policy_without_installation_baseline() {
        assert_eq!(
            std::env::var("NODECTL_CN_POLICY_TEST").as_deref(),
            Ok("isolated")
        );
        for namespace in ["net", "mnt"] {
            assert_ne!(
                fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap(),
                fs::read_link(format!("/proc/1/ns/{namespace}")).unwrap()
            );
        }
        let links: Vec<Value> =
            serde_json::from_str(&host::command("ip", &["-j", "link", "show"]).unwrap()).unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0]["ifname"], "lo");
        let policy = crate::cn_route::Policy::from(&config::CnWarp::managed(true));
        let before4 = host::default_routes(false).unwrap();
        let before6 = host::default_routes(true).unwrap();
        policy.reconcile(crate::cn_route::Phase::Prepare).unwrap();
        let existing4 = host::default_routes(false).unwrap();
        let existing6 = host::default_routes(true).unwrap();
        release_new_cn_policy(Some(&policy), &existing4, &existing6).unwrap();
        assert!(
            policy.guarded().unwrap(),
            "An existing policy must survive restore"
        );
        release_new_cn_policy(Some(&policy), &before4, &before6).unwrap();
        assert!(!policy.inspect().unwrap());
        assert_eq!(before4, host::default_routes(false).unwrap());
        assert_eq!(before6, host::default_routes(true).unwrap());
        release_new_cn_policy(Some(&policy), &before4, &before6).unwrap();
        println!("LEGACY_RESTORE_RELEASES_ONLY_NEW_CN_POLICY_AND_REMAINS_IDEMPOTENT_PASS");
    }
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Deploy,
    }
    fn args(extra: &[&str]) -> Deploy {
        let mut v = vec!["test", "--non-interactive"];
        v.extend(extra);
        Cli::parse_from(v).args
    }
    fn existing() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("config"), tmp.path().join("state")).unwrap();
        store::private_dir(&store.config_dir).unwrap();
        store::atomic_write(
            &store.config_dir.join("node.toml"),
            {
                let mut c: Config = toml::from_str(config::EXAMPLE).unwrap();
                c.vless = None;
                toml::to_string_pretty(&c).unwrap()
            }
            .as_bytes(),
        )
        .unwrap();
        store::atomic_write(
            &store.config_dir.join("secrets.json"),
            &serde_json::to_vec(&preview_secrets()).unwrap(),
        )
        .unwrap();
        (tmp, store)
    }
    #[test]
    fn existing_config_and_client_identities_are_preserved() {
        let (_tmp, store) = existing();
        let before = store.inputs().unwrap();
        let (c, s, exists) = candidate(&store, &args(&[])).unwrap();
        assert!(exists);
        assert_eq!(
            serde_json::to_value(&before.0).unwrap(),
            serde_json::to_value(&c).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&before.1).unwrap(),
            serde_json::to_value(&s).unwrap()
        );
        let (c, s, _) = candidate(
            &store,
            &args(&["--https-port", "4443", "--warp", "false", "--ipv6", ""]),
        )
        .unwrap();
        assert_eq!(c.ports.https, 4443);
        assert!(!c.warp.enabled);
        assert!(c.node.ipv6.is_empty());
        assert_eq!(c.transport.xhttp.path, before.0.transport.xhttp.path);
        assert_eq!(s.reality_private_key, before.1.reality_private_key);
        assert_eq!(
            fs::read_to_string(store.config_dir.join("node.toml")).unwrap(),
            toml::to_string_pretty(&before.0).unwrap()
        );
    }
    #[test]
    fn new_defaults_keep_the_full_dmit_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("config"), tmp.path().join("state")).unwrap();
        let (c, _, exists) = candidate(
            &store,
            &args(&[
                "--domain-suffix",
                "example.com",
                "--subdomain-prefix",
                "test-",
                "--ipv4",
                "192.0.2.10",
                "--ipv6",
                "",
            ]),
        )
        .unwrap();
        assert!(!exists);
        assert_eq!(c.node.domain, "test-speedtest.example.com");
        assert_eq!(c.node.reality_domain, "test-files.example.com");
        assert!(c.node.aliases.is_empty());
        assert!(c.encrypted());
        assert_eq!(
            (
                c.clients.xhttp_weight,
                c.clients.ws_weight,
                c.clients.reality_weight
            ),
            (80, 15, 5)
        );
        assert_eq!(
            c.clients.fingerprint_weights,
            toml::from_str::<Config>(config::EXAMPLE)
                .unwrap()
                .clients
                .fingerprint_weights
        );
        assert_eq!(c.tls.protocols, vec!["TLSv1.3"]);
        assert!(c.tls.http2 && c.tls.http3 && c.warp.enabled && !c.warp.take_over_default_route);
        assert_eq!(c.ports.reality, 8443);
        assert!(!store.config_dir.exists() && !store.state_dir.exists());
    }
    #[test]
    fn invalid_existing_inputs_are_never_replaced_with_new_defaults() {
        let (_tmp, store) = existing();
        store::atomic_write(&store.config_dir.join("node.toml"), b"schema_version=999\n").unwrap();
        assert!(candidate(&store, &args(&[])).is_err());
    }
    #[test]
    fn domain_migration_keeps_legacy_snis_and_keys() {
        let (_tmp, store) = existing();
        let (old, secrets) = store.inputs().unwrap();
        let (c, s, _) = candidate(
            &store,
            &args(&[
                "--domain",
                "new.example.net",
                "--reality-domain",
                "reality.example.net",
            ]),
        )
        .unwrap();
        assert!(c.node.aliases.contains(&old.node.domain));
        assert!(c.node.aliases.contains(&old.node.reality_domain));
        assert_eq!(s.reality_private_key, secrets.reality_private_key);
        assert_eq!(c.transport.ws.path, old.transport.ws.path);
        assert!(preserves_clients(&old, &secrets, &c, &s).unwrap());
        let mut changed = c.clone();
        changed.ports.https = 4443;
        assert!(!preserves_clients(&old, &secrets, &changed, &s).unwrap());
    }
    #[test]
    fn explicit_replacement_removes_legacy_names_without_rotating_identity() {
        let (_tmp, store) = existing();
        let (old, secrets) = store.inputs().unwrap();
        let original = fs::read(store.config_dir.join("node.toml")).unwrap();
        let (c, s, _) = candidate(
            &store,
            &args(&[
                "--domain",
                "speedtest.example.net",
                "--reality-domain",
                "files.example.net",
                "--replace-domain-set",
                "--vless-encryption",
                "true",
            ]),
        )
        .unwrap();
        assert_eq!(
            c.domains(),
            vec!["files.example.net", "speedtest.example.net"]
        );
        assert!(c.node.aliases.is_empty() && c.encrypted());
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::to_value(&secrets).unwrap()
        );
        assert_eq!(c.transport.xhttp.path, old.transport.xhttp.path);
        assert!(!preserves_clients(&old, &secrets, &c, &s).unwrap());
        assert_eq!(
            fs::read(store.config_dir.join("node.toml")).unwrap(),
            original
        );
    }
    #[test]
    fn provisioning_journal_blocks_all_ordinary_mutations() {
        let (_tmp, store) = existing();
        store::private_dir(&store.state_dir).unwrap();
        store::atomic_write(&store.state_dir.join("deployment.json"), b"{}").unwrap();
        assert!(store.lock().is_err());
        // Another parallel test may fork while the failed ordinary lock still
        // exists; CLOEXEC closes the inherited fd when that child execs.
        let started = std::time::Instant::now();
        loop {
            if store.recovery_lock().is_ok() {
                break;
            }
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    #[test]
    fn legacy_provisioning_journal_keeps_its_original_backup_scope() {
        let (_tmp, store) = existing();
        let (mut c, _) = store.inputs().unwrap();
        c.vless = None;
        c.distribution = None;
        c.cn_warp = None;
        c.web_services = None;
        let mut journal: Journal = serde_json::from_value(json!({
            "schema_version":1,"backup":"/var/lib/dmit-node/deployment-backups/fixture",
            "config":c,"previous":null,"reference":{"binary":"/usr/local/bin/xray","sha256":"fixture","version":"26.10.10","probe_url":"https://example.com/"},
            "files":[],"dns_zone":null,"dns":[],"pending_dns":null,"routes4":"","routes6":"","phase":"prepared","config_existed":true,"services":{}
        })).unwrap();
        let page = Path::new(&journal.config.website.root).join("index.html");
        assert!(!recovery_paths(&store, &journal).unwrap().contains(&page));
        journal.schema_version = 2;
        assert!(recovery_paths(&store, &journal).unwrap().contains(&page));
        journal.config.cn_warp = Some(config::CnWarp::managed(true));
        let geoip = PathBuf::from("/etc/xray/geoip.dat");
        assert!(!recovery_paths(&store, &journal).unwrap().contains(&geoip));
        journal.feature_entry_backups = Some(true);
        assert!(recovery_paths(&store, &journal).unwrap().contains(&geoip));
        journal.feature_entry_backups = Some(false);
        assert!(recovery_paths(&store, &journal).is_err());
        journal.feature_entry_backups = None;
        journal.config.cn_warp = None;
        journal.schema_version = 1;
        journal.config.vless = Some(config::Vless { encryption: true });
        assert!(recovery_paths(&store, &journal).is_err());
        journal.schema_version = 999;
        assert!(recovery_paths(&store, &journal).is_err());
    }
    #[test]
    fn backup_round_trip_keeps_private_modes_and_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        store::private_dir(&source).unwrap();
        store::atomic_write(&source.join("key"), b"fixture").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("key", source.join("link")).unwrap();
        let backup = tmp.path().join("backup");
        copy_tree(&source, &backup).unwrap();
        assert_eq!(fingerprint(&source).unwrap(), fingerprint(&backup).unwrap());
        store::check_private(&backup.join("key"), false).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn orphaned_provisioning_child_keeps_recovery_locked() {
        let (_tmp, store) = existing();
        let lock = store.lock().unwrap();
        let lease = provision::Lease::hold(&lock);
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("0.2");
        provision::inherit_lease(&mut command);
        let mut child = command.spawn().unwrap();
        drop(lease);
        drop(lock);
        assert!(store.recovery_lock().is_err());
        assert!(child.wait().unwrap().success());
        assert!(store.recovery_lock().is_ok());
    }
    #[test]
    #[cfg(unix)]
    fn explicit_manual_input_paths_survive_first_deployment_initialization() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("config"), tmp.path().join("state")).unwrap();
        let fake = tmp.path().join("xray");
        fs::write(
            &fake,
            "#!/bin/sh\nprintf 'PrivateKey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\\n'\n",
        )
        .unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        let mut c: Config = toml::from_str(config::EXAMPLE).unwrap();
        c.runtime.xray_binary = fake.to_str().unwrap().into();
        c.vless = None;
        c.transport.xhttp.path = "/chosen/modules/stream/".into();
        initialize(&store, &c, true, tmp.path()).unwrap();
        let (actual, secrets) = store.inputs().unwrap();
        assert_eq!(actual.transport.xhttp.path, c.transport.xhttp.path);
        assert!(!secrets.xhttp_uuid.is_empty());
    }
}
