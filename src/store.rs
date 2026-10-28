use crate::{
    config::{self, Config, Secrets},
    render,
};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum ClientFormat {
    Xray,
    Mihomo,
    All,
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn file_digest(path: &Path) -> Result<String> {
    Ok(digest(&fs::read(path)?))
}

pub fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return check_private(path, true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    check_private(path, true)
}

pub fn check_private(path: &Path, dir: bool) -> Result<()> {
    let m =
        fs::symlink_metadata(path).with_context(|| format!("Cannot inspect {}", path.display()))?;
    ensure!(
        !m.file_type().is_symlink() && if dir { m.is_dir() } else { m.is_file() },
        "Expected a regular protected {}: {}",
        if dir { "directory" } else { "file" },
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            m.mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() },
            "Require owner-only permissions and current user ownership: {}",
            path.display()
        );
    }
    Ok(())
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("Missing file parent")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub template_version: String,
    pub generator_version: String,
    pub input_digest: String,
    pub files: BTreeMap<String, String>,
}

pub struct Store {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}
impl Store {
    pub fn new(config_dir: PathBuf, state_dir: PathBuf) -> Result<Self> {
        ensure!(
            config_dir.is_absolute() && state_dir.is_absolute(),
            "Configuration and state directories must be absolute"
        );
        Ok(Self {
            config_dir,
            state_dir,
        })
    }
    pub fn lock(&self) -> Result<File> {
        let file = self.recovery_lock()?;
        ensure!(
            !self.state_dir.join("transaction.json").exists()
                && !self.state_dir.join("uninstall.json").exists()
                && !self.state_dir.join("deployment.json").exists(),
            "An interrupted deployment exists: run nodectl recover (see README recovery)"
        );
        ensure!(
            !self.state_dir.join("admin-input.json").exists(),
            "Interrupted Web configuration commit exists: run nodectl recover"
        );
        Ok(file)
    }
    pub fn recovery_lock(&self) -> Result<File> {
        private_dir(&self.state_dir)?;
        let path = self.state_dir.join("lock");
        if path.exists() {
            check_private(&path, false)?;
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        // A bounded wait lets administration acquire the exclusive lock between
        // short subscription reads, without changing legacy fail-fast behavior.
        let wait_for_readers = self.state_dir.join("distribution/access.json").exists();
        let started = std::time::Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error)
                    if wait_for_readers
                        && error.kind() == std::io::ErrorKind::WouldBlock
                        && started.elapsed() < std::time::Duration::from_secs(4) =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => return Err(error).context("Another nodectl operation is running"),
            }
        }
        Ok(file)
    }
    pub fn inputs(&self) -> Result<(Config, Secrets)> {
        check_private(&self.config_dir, true)?;
        config::load(&self.config_dir)
    }
    pub fn release(&self, id: &str) -> Result<PathBuf> {
        ensure!(
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "Invalid release ID"
        );
        Ok(self.state_dir.join("releases").join(id))
    }
    pub fn render(&self) -> Result<String> {
        let (c, s) = self.inputs()?;
        let files = render::files(&c, &s)?;
        let hashes = files
            .iter()
            .map(|(name, data)| (name.clone(), digest(data)))
            .collect::<BTreeMap<_, _>>();
        let input_digest = digest(&serde_json::to_vec(&(&c, &s))?);
        let manifest = Manifest {
            schema_version: 1,
            template_version: render::TEMPLATE_VERSION.into(),
            generator_version: env!("CARGO_PKG_VERSION").into(),
            input_digest,
            files: hashes,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let id = digest(&manifest_bytes)[..32].to_owned();
        let destination = self.release(&id)?;
        if destination.exists() {
            self.verify(&id)?;
            return Ok(id);
        }
        private_dir(&self.state_dir.join("releases"))?;
        let temp = tempfile::Builder::new()
            .prefix(".render-")
            .tempdir_in(self.state_dir.join("releases"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        }
        for (name, data) in files {
            let path = temp.path().join(name);
            private_dir(path.parent().unwrap())?;
            atomic_write(&path, &data)?;
        }
        atomic_write(&temp.path().join("manifest.json"), &manifest_bytes)?;
        fs::rename(temp.path(), &destination)?;
        File::open(self.state_dir.join("releases"))?.sync_all()?;
        Ok(id)
    }
    pub fn verify(&self, id: &str) -> Result<(Config, Secrets)> {
        let path = self.release(id)?;
        check_private(&self.state_dir, true)?;
        check_private(&self.state_dir.join("releases"), true)?;
        check_private(&path, true)?;
        check_private(&path.join("manifest.json"), false)?;
        let manifest_bytes = fs::read(path.join("manifest.json"))?;
        ensure!(
            &digest(&manifest_bytes)[..32] == id,
            "Manifest digest does not match release ID"
        );
        let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
        let legacy = manifest.template_version == "1"
            && ["0.1.0", "0.2.0"].contains(&manifest.generator_version.as_str());
        let v2 = manifest.template_version == "2"
            && ["0.3.0", "0.3.1"].contains(&manifest.generator_version.as_str());
        let v3 = manifest.template_version == "3" && manifest.generator_version == "0.4.0";
        ensure!(
            manifest.schema_version == 1
                && (legacy
                    || v2
                    || v3
                    || (manifest.template_version == render::TEMPLATE_VERSION
                        && ["0.5.0", "0.5.1", "0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4"]
                            .contains(&manifest.generator_version.as_str()))),
            "Release requires its original nodectl/template version"
        );
        check_private(&path.join("source"), true)?;
        let (c, s) = config::load(&path.join("source"))?;
        ensure!(
            !(legacy || v2 || v3) || (c.cn_warp.is_none() && c.web_services.is_none()),
            "Legacy release contains unsupported CN WARP or website fields"
        );
        ensure!(
            !(legacy || v2) || c.distribution.is_none(),
            "Legacy release contains unsupported distribution fields"
        );
        ensure!(
            !legacy || (c.vless.is_none() && s.vless.is_none()),
            "Legacy release contains unsupported encryption fields"
        );
        ensure!(
            manifest.input_digest == digest(&serde_json::to_vec(&(&c, &s))?),
            "Source digest mismatch"
        );
        let expected = if legacy {
            crate::render_legacy::files(&c, &s)?
        } else if v2 {
            crate::render_v2::files(&c, &s)?
        } else if v3 {
            crate::render_v3::files(&c, &s)?
        } else {
            render::files_with_geodata(&c, &s, Some(&path.join("geodata")))?
        };
        ensure!(
            manifest.files.len() == expected.len(),
            "Unexpected release file list"
        );
        for (name, data) in expected {
            let file = path.join(&name);
            check_private(file.parent().unwrap(), true)?;
            check_private(&file, false)?;
            ensure!(
                manifest.files.get(&name) == Some(&digest(&data))
                    && file_digest(&file)? == digest(&data),
                "Release integrity check failed for {name}"
            );
        }
        let mut actual = vec![];
        collect_files(&path, &path, &mut actual)?;
        actual.sort();
        let mut listed: Vec<_> = manifest
            .files
            .keys()
            .cloned()
            .chain(std::iter::once("manifest.json".into()))
            .collect();
        listed.sort();
        ensure!(actual == listed, "Untracked files in release");
        Ok((c, s))
    }
    pub fn pointer(&self, name: &str) -> Result<Option<String>> {
        ensure!(["current", "previous"].contains(&name), "Invalid pointer");
        let link = self.state_dir.join(name);
        match fs::read_link(&link) {
            Ok(target) => {
                let id = target
                    .file_name()
                    .and_then(|s| s.to_str())
                    .context("Invalid release pointer")?;
                ensure!(
                    target == PathBuf::from("releases").join(id),
                    "Pointer escapes release store"
                );
                self.verify(id)?;
                Ok(Some(id.into()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn set_pointer(&self, name: &str, id: Option<&str>) -> Result<()> {
        ensure!(["current", "previous"].contains(&name), "Invalid pointer");
        let dest = self.state_dir.join(name);
        if let Some(id) = id {
            self.verify(id)?;
            let target = PathBuf::from("releases").join(id);
            replace_link(&target, &dest)?;
        } else if fs::symlink_metadata(&dest).is_ok() {
            fs::remove_file(dest)?;
        }
        Ok(())
    }
    pub fn diff(&self, id: &str) -> Result<String> {
        let (_, s) = self.verify(id)?;
        let previous = self.pointer("current")?;
        let mut secrets = s
            .sensitive()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if let Some(old) = &previous {
            let (_, s) = self.verify(old)?;
            secrets.extend(s.sensitive().into_iter().map(str::to_owned));
        }
        let redact = |data: &str| {
            let mut value = data.to_owned();
            for secret in &secrets {
                if !secret.is_empty() {
                    value = value.replace(secret, "<redacted>");
                }
            }
            value
        };
        let mut output = format!("Candidate: {id}\n");
        for (name, service) in [
            ("xray.json", "xray"),
            ("nginx.conf", "nginx"),
            ("systemd/xray.service", "xray"),
            ("systemd/nginx.service", "nginx"),
            ("systemd/usque-warp.service", "usque-warp"),
            ("operations.json", "operations"),
            ("clients/profiles.json", "clients"),
        ] {
            let before = previous
                .as_ref()
                .map(|old| -> Result<String> {
                    Ok(fs::read_to_string(self.release(old)?.join(name))?)
                })
                .transpose()?
                .unwrap_or_default();
            let after = fs::read_to_string(self.release(id)?.join(name))?;
            if before != after {
                output.push_str(&format!("Affected: {service} ({name})\n"));
                let before = redact(&before);
                let after = redact(&after);
                output.push_str(
                    &similar::TextDiff::from_lines(&before, &after)
                        .unified_diff()
                        .context_radius(3)
                        .header("current", name)
                        .to_string(),
                );
                // Credential-only changes deliberately have no printable values.
                if before == after {
                    output.push_str("Protected credential changed.\n");
                }
            }
        }
        Ok(output)
    }
    pub fn export(&self, output: &Path) -> Result<()> {
        self.export_format(output, ClientFormat::Xray)
    }
    pub fn export_format(&self, output: &Path, format: ClientFormat) -> Result<()> {
        let current = self
            .pointer("current")?
            .context("No successful applied release; candidate exports are unavailable")?;
        let (c, s) = self.verify(&current)?;
        private_dir(output)?;
        if matches!(format, ClientFormat::Xray | ClientFormat::All) {
            atomic_write(
                &output.join("profiles.json"),
                &fs::read(self.release(&current)?.join("clients/profiles.json"))?,
            )?;
        }
        if matches!(format, ClientFormat::Mihomo | ClientFormat::All) {
            atomic_write(&output.join("proxies.yaml"), &render::mihomo(&c, &s)?)?;
            let profiles = render::profiles(&c, &s)?;
            let weights: Vec<_> = profiles["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| serde_json::json!({"name":p["name"],"weight":p["weight"]}))
                .collect();
            atomic_write(
                &output.join("weights.json"),
                &serde_json::to_vec_pretty(&weights)?,
            )?;
        }
        Ok(())
    }
    pub fn prune(&self) -> Result<()> {
        // Only prune previously successful versions, always keeping both pointers.
        let current = self.pointer("current")?;
        let previous = self.pointer("previous")?;
        let receipts = self.state_dir.join("success");
        private_dir(&receipts)?;
        let mut entries = fs::read_dir(&receipts)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(|e| std::cmp::Reverse(e.metadata().and_then(|m| m.modified()).ok()));
        for entry in entries.into_iter().skip(5) {
            let id = entry.file_name().to_string_lossy().into_owned();
            if current.as_deref() == Some(&id) || previous.as_deref() == Some(&id) {
                continue;
            }
            let dir = self.release(&id)?;
            self.verify(&id)?;
            fs::remove_dir_all(dir)?;
            fs::remove_file(entry.path())?;
            let check = self.state_dir.join("checks").join(&id);
            if check.exists() {
                fs::remove_file(check)?;
            }
        }
        Ok(())
    }
}

fn collect_files(base: &Path, path: &Path, result: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        ensure!(
            !kind.is_symlink(),
            "Symlinks are not allowed inside releases"
        );
        if kind.is_dir() {
            check_private(&entry.path(), true)?;
            collect_files(base, &entry.path(), result)?;
        } else {
            result.push(
                entry
                    .path()
                    .strip_prefix(base)?
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    Ok(())
}

pub fn replace_link(target: &Path, destination: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let temp = destination.with_file_name(format!(".nodectl-link-{}", uuid::Uuid::new_v4()));
        std::os::unix::fs::symlink(target, &temp)?;
        if let Err(e) = fs::rename(&temp, destination) {
            let _ = fs::remove_file(&temp);
            return Err(e.into());
        }
        File::open(destination.parent().unwrap())?.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (target, destination);
        anyhow::bail!("Release pointers require Linux");
    }
}
