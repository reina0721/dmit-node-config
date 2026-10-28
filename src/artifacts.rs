use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, process::Command};
fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .envs(
            [
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "NO_PROXY",
                "https_proxy",
                "http_proxy",
                "no_proxy",
            ]
            .into_iter()
            .filter_map(|key| std::env::var_os(key).map(|value| (key, value))),
        )
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!("Artifact tool failed: {program}; exit code: {:?}", output.status.code());
        } else {
            bail!("Artifact tool failed: {program}: {detail}");
        }
    }
    Ok(output.stdout)
}

/// Fetch exactly one pinned upstream asset. Never unpack archive pathnames onto
/// the host; callers select a single known executable member and publish it.
pub(crate) fn locked_asset(component: &str, asset: &str) -> Result<Vec<u8>> {
    let locks: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let lock = locks.get(component).context("Unknown pinned component")?;
    let url = lock
        .get(format!("{asset}_url"))
        .and_then(toml::Value::as_str)
        .context("Pinned URL missing")?;
    let digest = lock
        .get(format!("{asset}_sha256"))
        .or_else(|| lock.get(format!("{asset}_archive_sha256")))
        .and_then(toml::Value::as_str)
        .context("Pinned SHA256 missing")?;
    ensure!(
        url.starts_with("https://github.com/") && digest.len() == 64,
        "Invalid artifact lock"
    );
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("asset");
    command(
        "curl",
        &[
            "--disable",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "20",
            "--max-time",
            "600",
            "-o",
            path.to_str().unwrap(),
            url,
        ],
    )?;
    let bytes = fs::read(&path)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == digest,
        "Pinned artifact digest mismatch"
    );
    if component == "geodata" {
        return Ok(bytes);
    }
    let member = lock["archive_member"]
        .as_str()
        .context("Pinned archive member missing")?;
    let binary = command("tar", &["-xOzf", path.to_str().unwrap(), "--", member])?;
    validate_service_elf(&binary, asset)?;
    Ok(binary)
}

fn validate_service_elf(binary: &[u8], asset: &str) -> Result<()> {
    let machine: u16 = match asset {
        "linux_amd64" => 62,
        "linux_arm64" => 183,
        _ => bail!("Unsupported service asset architecture"),
    };
    ensure!(
        binary.len() >= 64
            && binary.starts_with(b"\x7fELF")
            && binary[4] == 2
            && binary[5] == 1
            && binary[6] == 1
            && u16::from_le_bytes([binary[18], binary[19]]) == machine,
        "Pinned service executable has an invalid ELF format or architecture"
    );
    Ok(())
}

pub(crate) fn install_component(component: &str, path: &Path) -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "Native services require Linux");
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("Unsupported service architecture"),
    };
    let expected = component_digest(component)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Refusing to replace an unmanaged service pathname"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o022 == 0 && metadata.nlink() == 1,
                "Unsafe existing service executable"
            );
        }
        let observed = hex::encode(Sha256::digest(fs::read(path)?));
        if observed == expected {
            component_receipt(path, &expected)?;
            return Ok(());
        }
        // Only a previously installed, unchanged managed executable can be
        // upgraded. A foreign binary or local edits require explicit resolution.
        let record = path.with_extension("nodectl-sha256");
        let metadata = fs::symlink_metadata(&record)
            .context("Existing service has no managed binary receipt")?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Unsafe service binary receipt"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o077 == 0 && metadata.nlink() == 1,
                "Unsafe service binary receipt ownership"
            );
        }
        ensure!(
            fs::read_to_string(record)?.trim() == observed,
            "Existing service binary differs from its managed receipt"
        );
    }
    let bytes = locked_asset(component, &format!("linux_{architecture}"))?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == expected,
        "Service executable digest differs from its lock"
    );
    let mut staged =
        tempfile::NamedTempFile::new_in(path.parent().context("Service binary parent")?)?;
    staged.write_all(&bytes)?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.persist(path)?;
    component_receipt(path, &expected)?;
    Ok(())
}

fn component_receipt(path: &Path, expected: &str) -> Result<()> {
    let mut receipt = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    receipt.write_all(expected.as_bytes())?;
    receipt.as_file().sync_all()?;
    receipt.persist(path.with_extension("nodectl-sha256"))?;
    Ok(())
}

pub(crate) fn component_digest(component: &str) -> Result<String> {
    let locks: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("Unsupported service architecture"),
    };
    Ok(locks
        .get(component)
        .and_then(|lock| lock.get(format!("linux_{arch}_binary_sha256")))
        .and_then(toml::Value::as_str)
        .context("Missing pinned service executable digest")?
        .to_owned())
}
pub fn download_xray(output: &Path) -> Result<()> {
    let locks: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("Unsupported Xray architecture"),
    };
    ensure!(
        cfg!(target_os = "linux"),
        "Xray helper installs Linux binaries only"
    );
    let lock = &locks["xray"];
    let url = lock[format!("linux_{arch}_url")]
        .as_str()
        .context("Xray URL")?;
    let work = tempfile::tempdir()?;
    let archive = work.path().join("xray.zip");
    command(
        "curl",
        &[
            "--disable",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "20",
            "--max-time",
            "600",
            "-o",
            archive.to_str().context("archive path")?,
            url,
        ],
    )?;
    ensure!(
        hex::encode(Sha256::digest(fs::read(&archive)?))
            == lock[format!("linux_{arch}_archive_sha256")]
                .as_str()
                .context("Xray digest")?,
        "Xray archive digest mismatch"
    );
    let binary = command("unzip", &["-p", archive.to_str().unwrap(), "xray"])?;
    ensure!(!binary.is_empty(), "Empty Xray archive");
    let mut staged = tempfile::NamedTempFile::new_in(output.parent().context("Output parent")?)?;
    staged.write_all(&binary)?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.persist(output)?;
    println!(
        "Verified official Xray {} {arch}",
        lock["version"].as_str().unwrap()
    );
    Ok(())
}

/// Test client only; not installed or started by production provisioning.
#[allow(dead_code)]
pub fn download_mihomo(output: &Path) -> Result<()> {
    let locks: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("Unsupported Mihomo architecture"),
    };
    ensure!(
        cfg!(target_os = "linux"),
        "Mihomo helper installs Linux binaries only"
    );
    let lock = &locks["mihomo"];
    let work = tempfile::tempdir()?;
    let archive = work.path().join("mihomo.gz");
    command(
        "curl",
        &[
            "--disable",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "20",
            "--retry",
            "2",
            "--retry-all-errors",
            "--max-time",
            "180",
            "-o",
            archive.to_str().unwrap(),
            lock[format!("linux_{arch}_url")]
                .as_str()
                .context("Mihomo URL")?,
        ],
    )?;
    ensure!(
        hex::encode(Sha256::digest(fs::read(&archive)?))
            == lock[format!("linux_{arch}_archive_sha256")]
                .as_str()
                .context("Mihomo digest")?,
        "Mihomo archive digest mismatch"
    );
    let binary = command("gzip", &["-dc", archive.to_str().unwrap()])?;
    ensure!(!binary.is_empty(), "Empty Mihomo archive");
    let mut staged = tempfile::NamedTempFile::new_in(output.parent().context("Output parent")?)?;
    staged.write_all(&binary)?;
    staged.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    staged.persist(output)?;
    println!(
        "Verified official Mihomo {} {arch}",
        lock["version"].as_str().unwrap()
    );
    Ok(())
}
