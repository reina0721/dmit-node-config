use crate::{
    config::{self, Config, Secrets},
    store::{self, Store},
};
use anyhow::{Context, Result, ensure};
use clap::Args;
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

#[derive(Args)]
pub struct Setup {
    #[arg(long)]
    pub domain: Option<String>,
    #[arg(long)]
    pub reality_domain: Option<String>,
    #[arg(long, value_delimiter = ',')]
    pub aliases: Vec<String>,
    #[arg(long)]
    pub ipv4: Option<String>,
    #[arg(long, default_value = "")]
    pub ipv6: String,
    #[arg(long, default_value = "/etc/ssl/dmit/domain")]
    pub domain_cert_dir: String,
    #[arg(long, default_value = "/etc/ssl/dmit/ip")]
    pub ip_cert_dir: String,
    #[arg(long)]
    pub warp: Option<bool>,
    #[arg(long)]
    pub cn_warp: Option<bool>,
    #[arg(long)]
    pub web_services: Option<bool>,
    #[arg(long)]
    pub distribution: Option<bool>,
    #[arg(long)]
    pub non_interactive: bool,
    /// Without this flag, only show the proposed non-secret configuration.
    #[arg(long)]
    pub execute: bool,
    #[arg(long, default_value = "/usr/local/bin/xray")]
    pub xray_binary: PathBuf,
}

fn answer(value: Option<String>, label: &str, non_interactive: bool) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    ensure!(
        !non_interactive,
        "Missing {label}; supply its command-line option"
    );
    print!("{label}: ");
    io::stdout().flush()?;
    let mut value = String::new();
    ensure!(
        io::stdin().read_line(&mut value)? > 0,
        "Input ended while reading {label}"
    );
    Ok(value.trim().into())
}

pub fn run(store: &Store, setup: Setup) -> Result<()> {
    ensure!(
        !store.config_dir.exists(),
        "Configuration directory exists; refusing to replace existing inputs. Use validate/migrate or edit node.toml."
    );
    let mut c: Config = toml::from_str(config::EXAMPLE)?;
    c.node.domain = answer(setup.domain, "domain", setup.non_interactive)?;
    c.node.reality_domain = answer(
        setup.reality_domain,
        "reality-domain",
        setup.non_interactive,
    )?;
    c.node.ipv4 = answer(setup.ipv4, "ipv4", setup.non_interactive)?;
    c.node.ipv6 = setup.ipv6;
    c.node.aliases = setup.aliases;
    c.tls.domain_cert_dir = setup.domain_cert_dir;
    c.tls.ip_cert_dir = setup.ip_cert_dir;
    if let Some(v) = setup.warp {
        c.warp.enabled = v;
    }
    if let Some(v) = setup.cn_warp {
        c.cn_warp
            .get_or_insert_with(|| config::CnWarp::managed(v))
            .enabled = v;
    }
    if let Some(v) = setup.web_services {
        c.web_services
            .get_or_insert_with(|| config::WebServices::managed(v))
            .enabled = v;
    }
    if let Some(v) = setup.distribution {
        c.distribution = Some(config::Distribution { enabled: v });
    }
    if !setup.non_interactive {
        let prompt_bool = |label: &str, current: bool| -> Result<bool> {
            print!("{label} [{current}]: ");
            io::stdout().flush()?;
            let mut line = String::new();
            if io::stdin().read_line(&mut line)? == 0 || line.trim().is_empty() {
                Ok(current)
            } else {
                Ok(line.trim().parse()?)
            }
        };
        if setup.warp.is_none() {
            c.warp.enabled = prompt_bool("Independent WARP (true/false)", c.warp.enabled)?;
        }
        if setup.cn_warp.is_none() {
            let enabled = prompt_bool(
                "CN traffic via a second isolated WARP (true/false)",
                c.routes_cn(),
            )?;
            c.cn_warp
                .get_or_insert_with(|| config::CnWarp::managed(enabled))
                .enabled = enabled;
        }
        if setup.web_services.is_none() {
            let enabled = prompt_bool(
                "Speedtest, LibreSpeed and OpenList websites (true/false)",
                c.serves_web(),
            )?;
            c.web_services
                .get_or_insert_with(|| config::WebServices::managed(enabled))
                .enabled = enabled;
        }
        if setup.distribution.is_none() {
            let enabled = prompt_bool(
                "Protected node page and subscriptions (true/false)",
                c.distributes(),
            )?;
            c.distribution = Some(config::Distribution { enabled });
        }
    }
    c.runtime.xray_binary = setup
        .xray_binary
        .to_str()
        .context("Non-UTF8 Xray path")?
        .into();
    // Validation uses throwaway values; real credentials are generated only on execute.
    let secrets = Secrets {
        xhttp_uuid: uuid::Uuid::new_v4().to_string(),
        ws_uuid: uuid::Uuid::new_v4().to_string(),
        reality_uuid: uuid::Uuid::new_v4().to_string(),
        reality_private_key: {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7; 32])
        },
        reality_short_id: "0123456789abcdef".into(),
        vless: None,
    };
    config::validate_preview(&c, &secrets)?;
    println!("{}", toml::to_string_pretty(&c)?);
    if !setup.execute {
        println!(
            "Preview only. Rerun with --execute to generate credentials and create configuration; no DNS, certificates or services are changed."
        );
        return Ok(());
    }
    let _lock = store.lock()?;
    ensure!(
        !store.config_dir.exists(),
        "Configuration appeared concurrently; refusing overwrite"
    );
    let parent = store.config_dir.parent().context("Missing config parent")?;
    ensure!(
        parent.is_dir(),
        "Create the configuration parent directory first"
    );
    let staging = tempfile::Builder::new()
        .prefix(".nodectl-setup-")
        .tempdir_in(parent)?;
    let template = staging.path().join("example.toml");
    store::atomic_write(&template, toml::to_string_pretty(&c)?.as_bytes())?;
    let input = staging.path().join("config");
    config::init(&input, Some(&template), &[])?;
    config::load(&input)?;
    fs::rename(input, &store.config_dir)?;
    fs::File::open(parent)?.sync_all()?;
    println!(
        "Configuration created. Provision dependencies/DNS/certificates, then doctor, render, diff, check and apply. See docs/getting-started.md."
    );
    Ok(())
}
