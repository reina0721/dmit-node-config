//! Zone-scoped DNS changes; credentials only cross stdin, never argv or logs.
use crate::{config::Config, host, store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub struct Cloudflare {
    zone: String,
    token: String,
    #[cfg(test)]
    fixture: Option<Box<TestTransport>>,
}
#[cfg(test)]
type TestTransport = dyn Fn(&str, &str, Option<&Value>) -> Result<Value>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub name: String,
    pub kind: String,
    pub before: Option<Value>,
    pub after: Value,
}
fn id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
impl Cloudflare {
    pub(crate) fn credential(&self) -> &str {
        &self.token
    }
    pub fn new(zone: &str, token: String) -> Result<Self> {
        ensure!(
            id(zone),
            "Cloudflare Zone ID must have 32 hexadecimal characters"
        );
        ensure!(
            !token.is_empty()
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b)),
            "Invalid Cloudflare token format"
        );
        Ok(Self {
            zone: zone.into(),
            token,
            #[cfg(test)]
            fixture: None,
        })
    }
    fn request(&self, method: &str, suffix: &str, body: Option<&Value>) -> Result<Value> {
        #[cfg(test)]
        if let Some(fixture) = &self.fixture {
            return fixture(method, suffix, body);
        }
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}{suffix}",
            self.zone
        );
        self.send(method, &url, body)
    }
    fn send(&self, method: &str, url: &str, body: Option<&Value>) -> Result<Value> {
        let mut config = format!(
            "header = \"Authorization: Bearer {}\"\nheader = \"Content-Type: application/json\"\n",
            self.token
        );
        if let Some(body) = body {
            // curl config quoting is separate from JSON quoting.
            let json = serde_json::to_string(body)?
                .replace('\\', "\\\\")
                .replace('"', "\\\"");
            config.push_str(&format!("data = \"{json}\"\n"));
        }
        let output = host::run(
            "curl",
            &[
                "--disable",
                "--config",
                "-",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "30",
                "--request",
                method,
                url,
            ],
            Some(config.as_bytes()),
        )?;
        let value: Value = serde_json::from_slice(&output)
            .map_err(|_| anyhow::anyhow!("Invalid Cloudflare API response"))?;
        ensure!(
            value["success"] == true,
            "Cloudflare API rejected request; response withheld"
        );
        Ok(value)
    }
    pub fn discover_zone(domain: &str, token: &str) -> Result<String> {
        ensure!(
            crate::config::domain(domain),
            "Invalid domain for zone discovery"
        );
        let client = Self::new(&"0".repeat(32), token.into())?;
        let mut suffix = domain;
        while suffix.contains('.') {
            let value = client.send(
                "GET",
                &format!("https://api.cloudflare.com/client/v4/zones?name={suffix}&per_page=50"),
                None,
            )?;
            let matches = value["result"]
                .as_array()
                .context("Cloudflare zone list")?
                .iter()
                .filter(|z| z["name"] == suffix && z["status"] == "active")
                .collect::<Vec<_>>();
            ensure!(
                matches.len() <= 1,
                "Ambiguous Cloudflare zone; specify Zone ID"
            );
            if let Some(zone) = matches.first() {
                let zone = zone["id"].as_str().context("Cloudflare zone ID")?;
                ensure!(id(zone), "Invalid Cloudflare zone ID");
                return Ok(zone.into());
            }
            suffix = suffix.split_once('.').unwrap().1;
        }
        anyhow::bail!(
            "No authorized active Cloudflare zone found; use a Zone Read token or specify Zone ID"
        )
    }
    pub fn zone_name(&self) -> Result<String> {
        let value = self.request("GET", "", None)?;
        let name = value["result"]["name"]
            .as_str()
            .context("Cloudflare zone name")?;
        ensure!(crate::config::domain(name), "Invalid Cloudflare zone name");
        Ok(name.into())
    }
    pub fn plan(&self, c: &Config, inherited: Option<&Config>) -> Result<Vec<Change>> {
        let zone = self.request("GET", "", None)?;
        ensure!(
            zone["result"]["status"] == "active",
            "Cloudflare zone must be active"
        );
        let zone = zone["result"]["name"]
            .as_str()
            .context("Cloudflare zone name")?;
        let mut changes = vec![];
        for name in c.domains() {
            if name != zone && !name.ends_with(&format!(".{zone}")) {
                ensure!(
                    inherited.is_some_and(|old| old.domains().contains(&name)),
                    "New domain outside selected Cloudflare zone"
                );
                continue; // Retained legacy zones remain operator-managed; public DNS is still verified.
            }
            let listed = self.request(
                "GET",
                &format!("/dns_records?name={name}&per_page=100"),
                None,
            )?;
            ensure!(
                listed["result_info"]["total_pages"].as_u64().unwrap_or(1) <= 1,
                "Too many DNS records for {name}; resolve manually"
            );
            let records = listed["result"]
                .as_array()
                .context("Cloudflare DNS records")?;
            changes.extend(record_changes(&name, records, c)?);
        }
        Ok(changes)
    }
    pub fn apply(&self, change: &Change) -> Result<Value> {
        let suffix = if let Some(old) = &change.before {
            format!("/dns_records/{}", old["id"].as_str().context("Record ID")?)
        } else {
            "/dns_records".into()
        };
        // PATCH preserves comments, tags and provider settings on existing records.
        let value = self.request(
            if change.before.is_some() {
                "PATCH"
            } else {
                "POST"
            },
            &suffix,
            Some(&change.after),
        )?;
        let record = &value["result"];
        ensure!(
            record["id"].as_str().is_some_and(id),
            "Invalid Cloudflare result ID"
        );
        Ok(record.clone())
    }
    pub fn ensure_unchanged(&self, change: &Change) -> Result<()> {
        let list = self.request(
            "GET",
            &format!("/dns_records?name={}&per_page=100", change.name),
            None,
        )?;
        let records = list["result"].as_array().context("DNS pre-write records")?;
        ensure!(
            !records.iter().any(|v| v["type"] == "CNAME"),
            "DNS acquired a conflicting CNAME after preview"
        );
        let found = records
            .iter()
            .filter(|v| v["type"] == change.kind)
            .collect::<Vec<_>>();
        if let Some(before) = &change.before {
            ensure!(
                found.len() == 1
                    && [
                        "id", "name", "type", "content", "proxied", "ttl", "comment", "tags",
                        "settings"
                    ]
                    .iter()
                    .all(|field| before[field] == found[0][field]),
                "DNS changed after preview; refusing stale write"
            );
        } else {
            ensure!(
                found.is_empty(),
                "DNS record appeared after preview; refusing duplicate create"
            );
        }
        Ok(())
    }
    pub fn restore(&self, change: &Change, created: &Value) -> Result<()> {
        let record_id = created["id"].as_str().context("Recovery record ID")?;
        ensure!(id(record_id), "Invalid recovery record ID");
        let suffix = format!("/dns_records/{record_id}");
        let list = self.request(
            "GET",
            &format!(
                "/dns_records?name={}&type={}&per_page=100",
                change.name, change.kind
            ),
            None,
        )?;
        let records = list["result"].as_array().context("DNS recovery list")?;
        let Some(current) = records.iter().find(|v| v["id"] == record_id) else {
            ensure!(
                change.before.is_none(),
                "Previous DNS record missing; inspect zone manually"
            );
            return Ok(());
        };
        if change.before.as_ref().is_some_and(|old| {
            [
                "name", "type", "content", "proxied", "ttl", "comment", "tags", "settings",
            ]
            .iter()
            .all(|f| old[f] == current[f])
        }) {
            return Ok(());
        }
        for field in [
            "name", "type", "content", "proxied", "ttl", "comment", "tags", "settings",
        ] {
            ensure!(
                current[field] == created[field],
                "DNS drift; refusing to overwrite concurrent changes"
            );
        }
        if let Some(old) = &change.before {
            let mut restore = json!({});
            for field in [
                "name", "type", "content", "ttl", "proxied", "comment", "tags", "settings",
            ] {
                if let Some(v) = old.get(field) {
                    restore[field] = v.clone();
                }
            }
            self.request("PATCH", &suffix, Some(&restore))?;
        } else {
            self.request("DELETE", &suffix, None)?;
        }
        Ok(())
    }
    pub fn restore_pending(&self, change: &Change) -> Result<()> {
        let value = self.request(
            "GET",
            &format!(
                "/dns_records?name={}&type={}&per_page=100",
                change.name, change.kind
            ),
            None,
        )?;
        let records = value["result"]
            .as_array()
            .context("Pending DNS recovery records")?;
        ensure!(
            records.len() <= 1,
            "Ambiguous pending DNS recovery; inspect zone manually"
        );
        if let Some(current) = records.first() {
            if change.before.as_ref().is_some_and(|old| {
                ["content", "proxied"]
                    .iter()
                    .all(|field| old[field] == current[field])
            }) {
                return Ok(());
            }
            ensure!(
                ["name", "type", "content", "proxied", "ttl"]
                    .iter()
                    .all(|field| current[field] == change.after[field]),
                "Pending DNS request has concurrent drift; inspect zone manually"
            );
            if let Some(before) = &change.before {
                ensure!(
                    ["comment", "tags", "settings"]
                        .iter()
                        .all(|field| before[field] == current[field]),
                    "Pending DNS recovery has metadata drift"
                );
            } else {
                ensure!(
                    current["comment"].is_null()
                        && current["tags"].as_array().is_none_or(|v| v.is_empty()),
                    "Pending DNS creation has operator metadata; inspect manually"
                );
            }
            self.restore(change, current)?;
        } else {
            ensure!(
                change.before.is_none(),
                "Previous DNS record disappeared during recovery"
            );
        }
        Ok(())
    }
}

fn record_changes(name: &str, records: &[Value], c: &Config) -> Result<Vec<Change>> {
    let mut changes = vec![];
    ensure!(
        !records.iter().any(|r| r["type"] == "CNAME"),
        "Conflicting CNAME for {name}; resolve manually"
    );
    for (kind, ip) in [("A", c.node.ipv4.as_str()), ("AAAA", c.node.ipv6.as_str())] {
        let found = records
            .iter()
            .filter(|r| r["type"] == kind)
            .collect::<Vec<_>>();
        ensure!(
            found.len() <= 1,
            "Ambiguous duplicate {kind} records for {name}; resolve manually"
        );
        ensure!(
            !ip.is_empty() || found.is_empty(),
            "Stale AAAA for {name}; explicitly remove or configure IPv6 before deployment"
        );
        if ip.is_empty() {
            continue;
        }
        let mut after = json!({"type":kind,"name":name,"content":ip,"ttl":1,"proxied":false});
        if let Some(old) = found.first() {
            if old["content"] == ip && old["proxied"] == false {
                continue;
            }
            ensure!(
                old["id"].as_str().is_some_and(id),
                "Invalid Cloudflare record ID"
            );
            ensure!(old["ttl"].as_u64().is_some(), "Invalid existing DNS TTL");
            after["ttl"] = old["ttl"].clone();
        }
        changes.push(Change {
            name: name.to_owned(),
            kind: kind.into(),
            before: found.first().map(|v| (*v).clone()),
            after,
        });
    }

    Ok(changes)
}

pub fn verify(c: &Config) -> Result<()> {
    #[cfg(not(feature = "integration-test"))]
    let resolvers: Vec<Vec<String>> = vec![
        vec!["@1.1.1.1".to_owned()],
        vec!["@8.8.8.8".to_owned()],
        vec![],
    ];
    #[cfg(feature = "integration-test")]
    let resolvers: Vec<Vec<String>> = if std::env::var("NODECTL_TEST_DNS").as_deref() == Ok("yes") {
        vec![vec!["@127.0.0.1".to_owned(), "-p".into(), "1053".into()]]
    } else {
        vec![vec!["@1.1.1.1".into()]]
    };
    for name in c.domains() {
        for (kind, wanted) in [("A", c.node.ipv4.as_str()), ("AAAA", c.node.ipv6.as_str())] {
            if wanted.is_empty() {
                continue;
            }
            let expected = vec![wanted.parse::<std::net::IpAddr>()?];
            let mut verified = false;
            let mut last_err = None;
            for resolver in &resolvers {
                let mut query = vec!["+short", "+time=3", "+tries=2", kind, name.as_str()];
                query.extend(resolver.iter().map(String::as_str));
                if let Ok(result) = host::command("dig", &query) {
                    if let Ok(actual) = result
                        .lines()
                        .filter(|l| !l.trim().is_empty())
                        .map(|l| l.parse::<std::net::IpAddr>())
                        .collect::<std::result::Result<Vec<_>, _>>()
                    {
                        if actual == expected {
                            verified = true;
                            break;
                        } else if !actual.is_empty() {
                            last_err = Some(anyhow::anyhow!(
                                "Public DNS {kind} for {name} returned {actual:?}, expected {expected:?}"
                            ));
                        }
                    }
                }
            }
            ensure!(
                verified,
                last_err.unwrap_or_else(|| anyhow::anyhow!(
                    "Public DNS {kind} for {name} does not match {wanted}; wait for propagation or resolve conflicting records"
                ))
            );
        }
    }
    Ok(())
}
pub fn wait(c: &Config, seconds: u64) -> Result<()> {
    let start = std::time::Instant::now();
    let mut last_log = std::time::Instant::now();
    println!("Waiting for public DNS propagation (up to {seconds}s)...");
    loop {
        match verify(c) {
            Ok(()) => {
                println!("Public DNS propagation confirmed for all domains");
                return Ok(());
            }
            Err(error) if start.elapsed().as_secs() >= seconds => {
                eprintln!("DNS propagation timed out after {seconds}s: {error:#}");
                return Err(error);
            }
            Err(error) => {
                if last_log.elapsed().as_secs() >= 15 {
                    println!(
                        "Still waiting for DNS propagation ({}/{}s): {}",
                        start.elapsed().as_secs(),
                        seconds,
                        error
                    );
                    last_log = std::time::Instant::now();
                }
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        }
    }
}
pub fn token(file: Option<&Path>) -> Result<String> {
    if let Some(file) = file {
        store::check_private(file, false)?;
        return Ok(fs::read_to_string(file)?.trim().into());
    }
    crate::deploy::secret_prompt("Cloudflare DNS Token")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_compensation_handles_completed_pending_and_concurrent_changes() {
        use std::{cell::RefCell, rc::Rc};
        let records = Rc::new(RefCell::new(Vec::<Value>::new()));
        let mut cf = Cloudflare::new(&"a".repeat(32), "fixture".into()).unwrap();
        let state = records.clone();
        cf.fixture = Some(Box::new(move |method, suffix, body| {
            let mut state = state.borrow_mut();
            let result = match method {
                "GET" => json!(state.clone()),
                "POST" => {
                    let mut value = body.unwrap().clone();
                    value["id"] = json!("b".repeat(32));
                    state.push(value.clone());
                    value
                }
                "PATCH" => {
                    let value = state
                        .iter_mut()
                        .find(|r| suffix.ends_with(r["id"].as_str().unwrap()))
                        .unwrap();
                    for (k, v) in body.unwrap().as_object().unwrap() {
                        value[k] = v.clone();
                    }
                    value.clone()
                }
                "DELETE" => {
                    state.retain(|r| !suffix.ends_with(r["id"].as_str().unwrap()));
                    json!({})
                }
                _ => anyhow::bail!("Unexpected fixture method"),
            };
            Ok(json!({"success":true,"result":result}))
        }));
        let mut c: Config = toml::from_str(crate::config::EXAMPLE).unwrap();
        c.node.ipv6.clear();
        let create = record_changes(&c.node.domain, &[], &c).unwrap().remove(0);
        let created = cf.apply(&create).unwrap();
        records.borrow_mut()[0]["comment"] = json!("operator-change");
        assert!(cf.restore(&create, &created).is_err());
        assert_eq!(records.borrow().len(), 1);
        records.borrow_mut()[0]
            .as_object_mut()
            .unwrap()
            .remove("comment");
        cf.restore_pending(&create).unwrap();
        cf.restore(&create, &created).unwrap(); // idempotent after DELETE
        assert!(records.borrow().is_empty());
        let old = json!({"id":"c".repeat(32),"type":"A","name":c.node.domain,"content":"192.0.2.20","ttl":3600,"proxied":false,"comment":"preserve","tags":["owner:fixture"],"settings":{}});
        records.borrow_mut().push(old.clone());
        let update = record_changes(&c.node.domain, std::slice::from_ref(&old), &c)
            .unwrap()
            .remove(0);
        cf.ensure_unchanged(&update).unwrap();
        let changed = cf.apply(&update).unwrap();
        assert_eq!(changed["comment"], "preserve");
        assert!(cf.ensure_unchanged(&update).is_err());
        cf.restore_pending(&update).unwrap();
        cf.restore(&update, &changed).unwrap();
        assert_eq!(records.borrow()[0], old);
    }
    #[test]
    fn reject_url_and_header_injection_before_any_request() {
        assert!(Cloudflare::new("../other-zone", "fixture".into()).is_err());
        assert!(Cloudflare::new(&"a".repeat(32), "fixture\nheader = evil".into()).is_err());
        assert!(Cloudflare::new(&"a".repeat(32), "fixture-token_123".into()).is_ok());
    }
    #[test]
    fn token_input_rejects_symlinks_and_public_files() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("token");
        store::atomic_write(&file, b"fixture-token").unwrap();
        assert_eq!(token(Some(&file)).unwrap(), "fixture-token");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(token(Some(&file)).is_err());
            std::os::unix::fs::symlink(&file, tmp.path().join("link")).unwrap();
            assert!(token(Some(&tmp.path().join("link"))).is_err());
        }
    }
    #[test]
    fn existing_dns_ttl_and_metadata_are_preserved_and_ambiguous_records_refused() {
        let mut c: Config = toml::from_str(crate::config::EXAMPLE).unwrap();
        c.node.ipv6.clear();
        let name = c.node.domain.clone();
        let old = json!({"id":"a".repeat(32),"type":"A","name":name,"content":"192.0.2.20","ttl":3600,"proxied":false,"comment":"operator-owned","tags":["purpose:node"]});
        let changes = record_changes(&name, std::slice::from_ref(&old), &c).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].after["ttl"], 3600);
        assert_eq!(
            changes[0].before.as_ref().unwrap()["comment"],
            "operator-owned"
        );
        assert!(changes[0].after.get("comment").is_none());
        let mut matching = old.clone();
        matching["content"] = json!(c.node.ipv4);
        assert!(record_changes(&name, &[matching], &c).unwrap().is_empty());
        assert!(record_changes(&name, &[old.clone(), old.clone()], &c).is_err());
        assert!(
            record_changes(
                &name,
                &[old.clone(), json!({"type":"AAAA","content":"2001:db8::1"})],
                &c
            )
            .is_err()
        );
        assert!(
            record_changes(
                &name,
                &[old, json!({"type":"CNAME","content":"other.example.com"})],
                &c
            )
            .is_err()
        );
    }
}
