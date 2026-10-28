//! Explicit provisioning, separate from the immutable service apply transaction.
use crate::{artifacts, config::Config, deploy::Deploy, host, store};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const NEUTRAL_PAGE: &str = "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Welcome</title><h1>Welcome</h1><p>This site is available.</p></html>\n";

pub(crate) fn website_change(c: &Config) -> Result<bool> {
    let path = Path::new(&c.website.root).join("index.html");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    };
    if !metadata.is_file() || metadata.len() > 512 {
        return Ok(false);
    }
    // Replace only the exact known placeholder, never an operator's website.
    let bytes = fs::read(&path)?;
    Ok([
        "<!doctype html><html><meta charset=\"utf-8\"><title>DMIT</title><h1>DMIT node</h1></html>",
        "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><title>DMIT</title><h1>DMIT node</h1></html>",
    ].iter().any(|page| bytes.strip_suffix(b"\n").unwrap_or(&bytes) == page.as_bytes()))
}

pub(crate) fn website(c: &Config) -> Result<()> {
    if website_change(c)? {
        fs::create_dir_all(&c.website.root)?;
        let path = Path::new(&c.website.root).join("index.html");
        let mut page = tempfile::NamedTempFile::new_in(&c.website.root)?;
        page.write_all(NEUTRAL_PAGE.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Set public mode on the open file before rename; never chmod an
            // operator-writable pathname after publishing it.
            page.as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        page.as_file().sync_all()?;
        page.persist(path)?;
        fs::File::open(&c.website.root)?.sync_all()?;
    }
    Ok(())
}

// An orphaned provisioning tool must finish before recover can acquire the host
// lock. Only children inherit this descriptor; the parent retains CLOEXEC.
#[cfg(unix)]
thread_local! {static LEASE:std::cell::Cell<Option<i32>>=const{std::cell::Cell::new(None)};}
pub(crate) struct Lease {
    #[cfg(unix)]
    previous: Option<i32>,
}
impl Lease {
    pub(crate) fn hold(file: &fs::File) -> Self {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            Self {
                previous: LEASE.replace(Some(file.as_raw_fd())),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Self {}
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        #[cfg(unix)]
        LEASE.set(self.previous);
    }
}
pub(crate) fn inherit_lease(command: &mut Command) {
    #[cfg(unix)]
    if let Some(fd) = LEASE.get() {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(unix))]
    let _ = command;
}

pub(crate) fn long_command(binary: &str, args: &[&str], env: &[(&str, &str)]) -> Result<()> {
    long_command_in(binary, args, env, None, &[0])
}

pub(crate) fn long_command_in(
    binary: &str,
    args: &[&str],
    env: &[(&str, &str)],
    dir: Option<&Path>,
    allowed_exit_codes: &[i32],
) -> Result<()> {
    let out = tempfile::tempfile()?;
    let mut command = Command::new(binary);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    command
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .env("HOME", "/root")
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("GOTOOLCHAIN", "local")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out.try_clone()?);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    inherit_lease(&mut command);
    let mut child = command
        .spawn()
        .with_context(|| format!("Cannot start {binary}"))?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let code = status.code().unwrap_or(-1);
            let success = status.success() || allowed_exit_codes.contains(&code);
            #[cfg(unix)]
            if !success {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            }
            if !success {
                use std::io::Seek;
                let mut out_file = out;
                let _ = out_file.seek(std::io::SeekFrom::Start(0));
                let mut captured = String::new();
                let _ = out_file.read_to_string(&mut captured);
                let tail: Vec<&str> = captured.lines().rev().take(5).collect();
                let detail = if tail.is_empty() {
                    format!("exit code {code}")
                } else {
                    let mut lines = tail;
                    lines.reverse();
                    lines.join("; ")
                };
                bail!("Provisioning tool failed: {binary} ({detail})");
            }
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(1800) {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL)
            };
            child.kill()?;
            child.wait()?;
            bail!("Provisioning tool timed out: {binary}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn locked_source(kind: &str, destination: &Path) -> Result<()> {
    let lock: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let component = &lock[kind];
    ensure!(!destination.exists(), "Source staging directory exists");
    long_command(
        "git",
        &[
            "clone",
            "--depth",
            "1",
            "--branch",
            component["ref"].as_str().context("Locked source ref")?,
            component["repository"]
                .as_str()
                .context("Locked repository")?,
            destination.to_str().context("Source path")?,
        ],
        &[],
    )?;
    let actual = host::command(
        "git",
        &["-C", destination.to_str().unwrap(), "rev-parse", "HEAD"],
    )?;
    ensure!(
        actual.trim()
            == component["source_commit"]
                .as_str()
                .context("Locked commit")?,
        "Locked source commit mismatch"
    );
    Ok(())
}
fn nginx_features(c: &Config) -> bool {
    host::command_stderr(&c.runtime.nginx_binary, &["-V"]).is_ok_and(|v| {
        [
            "--with-http_ssl_module",
            "--with-http_v2_module",
            "--with-http_v3_module",
        ]
        .iter()
        .all(|f| v.contains(f))
    })
}
pub fn dependencies(c: &Config, work: &Path) -> Result<Option<String>> {
    let had_nginx_config = fs::symlink_metadata("/etc/nginx/nginx.conf").is_ok();
    let mut installed_default = None;
    let tools = [
        ("curl", "curl"),
        ("openssl", "openssl"),
        ("unzip", "unzip"),
        ("git", "git"),
        ("dig", "dnsutils"),
        ("ip", "iproute2"),
        ("runuser", "util-linux"),
        ("gpg", "gnupg"),
        ("cc", "build-essential"),
        ("pkg-config", "pkg-config"),
        ("crontab", "cron"),
    ];
    let mut packages = vec![];
    for (tool, package) in tools {
        if host::command("which", &[tool]).is_err() {
            packages.push(package);
        }
    }
    if !packages.is_empty() {
        long_command("apt-get", &["update"], &[])?;
        let mut args = vec![
            "-y",
            "-o",
            "Dpkg::Options::=--force-confold",
            "install",
            "ca-certificates",
        ];
        args.extend(packages);
        long_command("apt-get", &args, &[])?;
    }
    if !nginx_features(c) {
        ensure!(
            c.runtime.nginx_binary == "/usr/sbin/nginx",
            "Automatic Nginx package install requires /usr/sbin/nginx; provision custom path manually"
        );
        let os = fs::read_to_string("/etc/os-release")?;
        let field = |name: &str| {
            os.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .map(|v| v.trim_matches('"').to_string())
        };
        let distro = field("ID").context("OS ID")?;
        let codename = field("VERSION_CODENAME").context("OS codename")?;
        ensure!(
            ["debian", "ubuntu"].contains(&distro.as_str())
                && codename.bytes().all(|b| b.is_ascii_lowercase()),
            "Unsupported Nginx package platform"
        );
        let key = work.join("nginx.key");
        host::command(
            "curl",
            &[
                "--disable",
                "--proto",
                "=https",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "30",
                "-o",
                key.to_str().unwrap(),
                "https://nginx.org/keys/nginx_signing.key",
            ],
        )?;
        let fingerprints = host::command(
            "gpg",
            &["--show-keys", "--with-colons", key.to_str().unwrap()],
        )?;
        ensure!(
            fingerprints
                .lines()
                .any(|l| l.split(':').nth(9) == Some("573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62")),
            "Nginx signing key fingerprint mismatch"
        );
        host::command(
            "gpg",
            &[
                "--batch",
                "--yes",
                "--dearmor",
                "-o",
                "/usr/share/keyrings/nginx-archive-keyring.gpg",
                key.to_str().unwrap(),
            ],
        )?;
        host::command(
            "chmod",
            &["0644", "/usr/share/keyrings/nginx-archive-keyring.gpg"],
        )?;
        store::atomic_write(Path::new("/etc/apt/sources.list.d/nginx.list"),format!("deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/{distro} {codename} nginx\n").as_bytes())?;
        host::command("chmod", &["0644", "/etc/apt/sources.list.d/nginx.list"])?;
        long_command("apt-get", &["update"], &[])?;
        long_command(
            "apt-get",
            &[
                "-y",
                "-o",
                "Dpkg::Options::=--force-confold",
                "install",
                "nginx",
            ],
            &[],
        )?;
        ensure!(
            nginx_features(c),
            "Installed Nginx lacks required H2/H3/TLS modules"
        );
        if !had_nginx_config {
            ensure!(
                fs::symlink_metadata("/etc/nginx/nginx.conf")?.is_file(),
                "New package Nginx configuration is not a regular file"
            );
            let conffiles = host::command("dpkg-query", &["-W", "-f=${Conffiles}", "nginx"])?;
            let expected = conffiles
                .lines()
                .find_map(|line| {
                    let mut fields = line.split_whitespace();
                    (fields.next() == Some("/etc/nginx/nginx.conf"))
                        .then(|| fields.next())
                        .flatten()
                })
                .context("Nginx package default checksum")?;
            let actual = host::command("md5sum", &["/etc/nginx/nginx.conf"])?;
            ensure!(
                actual.split_whitespace().next() == Some(expected),
                "New Nginx default was changed concurrently; explicit takeover required"
            );
            installed_default = Some(store::file_digest(Path::new("/etc/nginx/nginx.conf"))?);
        }
    }
    let lock: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let version = lock["xray"]["version"].as_str().unwrap();
    let installed = host::command(&c.runtime.xray_binary, &["version"]);
    if Path::new(&c.runtime.xray_binary).exists() {
        ensure!(
            installed
                .as_ref()
                .is_ok_and(|v| v.split_whitespace().next() == Some("Xray")),
            "Existing Xray path is not a recognized Xray executable; refusing replacement"
        );
    }
    if !installed.is_ok_and(|v| v.split_whitespace().any(|v| v == version)) {
        artifacts::download_xray(Path::new(&c.runtime.xray_binary))?;
    }
    for user in [&c.runtime.nginx_user, &c.runtime.xray_user] {
        if host::command("id", &[user]).is_err() {
            host::command(
                "useradd",
                &[
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    user,
                ],
            )?;
        }
    }
    host::command("getent", &["group", &c.runtime.nginx_user])?;
    host::command(
        "install",
        &[
            "-d",
            "-m",
            "0750",
            "-o",
            &c.runtime.xray_user,
            "-g",
            &c.runtime.nginx_user,
            &format!("{}/xray", c.runtime.log_root),
        ],
    )?;
    for path in [
        &c.website.root,
        &format!("{}/nginx", c.runtime.log_root),
        "/var/www/acme",
    ] {
        if !Path::new(path).exists() {
            host::command("install", &["-d", "-m", "0755", path])?;
        }
    }
    if (c.warp.enabled || c.routes_cn()) && !Path::new(&c.runtime.usque_binary).exists() {
        let go = ensure_go(work)?;
        let source = work.join("usque-source");
        locked_source("usque", &source)?;
        long_command(&go, &["-C", source.to_str().unwrap(), "mod", "verify"], &[])?;
        long_command(
            &go,
            &[
                "-C",
                source.to_str().unwrap(),
                "build",
                "-trimpath",
                "-ldflags=-s -w",
                "-o",
                &c.runtime.usque_binary,
                ".",
            ],
            &[("CGO_ENABLED", "0")],
        )?;
        host::command("chmod", &["0755", &c.runtime.usque_binary])?;
    }
    if c.routes_cn() {
        let cn = c.cn_warp.as_ref().unwrap();
        store::private_dir(Path::new(&cn.geodata_dir))?;
        let locks: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
        for name in ["geoip", "geosite"] {
            let target = Path::new(&cn.geodata_dir).join(format!("{name}.dat"));
            if target.exists() {
                store::check_private(&target, false)?;
                ensure!(
                    Some(store::file_digest(&target)?.as_str())
                        == locks["geodata"][format!("{name}_sha256")].as_str(),
                    "Installed geodata differs from the pinned version; retain it and inspect before replacement"
                );
            } else {
                store::atomic_write(&target, &artifacts::locked_asset("geodata", name)?)?;
            }
        }
    }
    if c.serves_web() {
        for (component, binary) in [
            ("librespeed", "/usr/local/bin/speedtest-backend"),
            ("openlist", "/usr/local/bin/openlist"),
        ] {
            artifacts::install_component(component, Path::new(binary))?;
        }
    }
    Ok(installed_default)
}

fn ensure_go(work: &Path) -> Result<String> {
    let lock: toml::Value = toml::from_str(include_str!("../versions.lock.toml"))?;
    let version = format!(
        "go{}",
        lock["go"]["version"].as_str().context("Go version lock")?
    );
    let numbers = |value: &str| {
        value
            .strip_prefix("go")
            .unwrap_or(value)
            .split('.')
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    let minimum = numbers(&version)?;
    for binary in ["/usr/local/go/bin/go", "/usr/bin/go"] {
        if let Ok(actual) = host::command(binary, &["version"])
            && actual.starts_with("go version go")
            && actual
                .split_whitespace()
                .filter_map(|v| numbers(v).ok())
                .any(|v| v >= minimum)
        {
            return Ok(binary.into());
        }
    }
    if Path::new("/usr/local/go").exists() {
        ensure!(
            host::command("/usr/local/go/bin/go", &["version"])
                .is_ok_and(|v| v.starts_with("go version go")),
            "Existing /usr/local/go is not a recognized Go installation; refusing replacement"
        );
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("Unsupported Go architecture"),
    };
    let data = host::command(
        "curl",
        &[
            "--disable",
            "--proto",
            "=https",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "https://go.dev/dl/?mode=json&include=all",
        ],
    )?;
    let metadata: Vec<Value> = serde_json::from_str(&data)?;
    let release = metadata
        .iter()
        .find(|v| v["version"] == version)
        .context("Pinned Go release absent from official metadata")?;
    let artifact = release["files"]
        .as_array()
        .context("Go files")?
        .iter()
        .find(|v| v["os"] == "linux" && v["arch"] == arch && v["kind"] == "archive")
        .context("Pinned Go archive")?;
    let filename = artifact["filename"].as_str().context("Go filename")?;
    ensure!(
        filename == format!("{version}.linux-{arch}.tar.gz"),
        "Unexpected Go archive name"
    );
    let archive = work.join(filename);
    long_command(
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
            "--max-time",
            "600",
            "-o",
            archive.to_str().unwrap(),
            &format!("https://go.dev/dl/{filename}"),
        ],
        &[],
    )?;
    ensure!(
        store::file_digest(&archive)? == artifact["sha256"].as_str().context("Go SHA256")?,
        "Go archive digest mismatch"
    );
    if Path::new("/usr/local/go").exists() {
        fs::remove_dir_all("/usr/local/go")?;
    }
    long_command(
        "tar",
        &["-xzf", archive.to_str().unwrap(), "-C", "/usr/local"],
        &[],
    )?;
    Ok("/usr/local/go/bin/go".into())
}

struct Bootstrap {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for Bootstrap {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
fn challenge(mut socket: TcpStream, root: &Path) -> Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = vec![];
    let start = Instant::now();
    while request.len() < 8192 && !request.ends_with(b"\r\n\r\n") {
        ensure!(
            start.elapsed() < Duration::from_secs(3),
            "HTTP challenge header timed out"
        );
        let mut chunk = [0; 512];
        let size = socket.read(&mut chunk)?;
        ensure!(size > 0, "Incomplete HTTP challenge header");
        request.extend_from_slice(&chunk[..size]);
    }
    ensure!(
        request.ends_with(b"\r\n\r\n"),
        "HTTP challenge header too large"
    );
    let request = std::str::from_utf8(&request)?;
    let line = request.lines().next().context("HTTP request")?;
    let mut parts = line.split_whitespace();
    ensure!(parts.next() == Some("GET"), "Only ACME GET supported");
    let path = parts.next().context("HTTP path")?;
    let token = path
        .strip_prefix("/.well-known/acme-challenge/")
        .context("Not ACME path")?;
    ensure!(
        !token.is_empty()
            && token.len() <= 256
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "Invalid challenge path"
    );
    let file = root.join(".well-known/acme-challenge").join(token);
    ensure!(
        fs::canonicalize(&file)?
            .starts_with(fs::canonicalize(root.join(".well-known/acme-challenge"))?),
        "Challenge file escapes webroot"
    );
    let metadata = fs::symlink_metadata(&file)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() < 16384,
        "Invalid challenge file"
    );
    let data = fs::read(file)?;
    socket.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            data.len()
        )
        .as_bytes(),
    )?;
    socket.write_all(&data)?;
    let _ = socket.flush();
    let _ = socket.shutdown(std::net::Shutdown::Both);
    Ok(())
}
fn bootstrap(c: &Config) -> Result<Option<Bootstrap>> {
    match TcpListener::bind("0.0.0.0:80") {
        Ok(listener) => {
            listener.set_nonblocking(true)?;
            let listener6 = if c.node.ipv6.is_empty() {
                None
            } else {
                let l = ipv6_listener(80)?;
                l.set_nonblocking(true)?;
                Some(l)
            };
            let stop = Arc::new(AtomicBool::new(false));
            let signal = stop.clone();
            let task = thread::spawn(move || {
                while !signal.load(Ordering::SeqCst) {
                    for listener in std::iter::once(&listener).chain(listener6.iter()) {
                        if let Ok((socket, _)) = listener.accept() {
                            let _ = challenge(socket, Path::new("/var/www/acme"));
                        }
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });
            Ok(Some(Bootstrap {
                stop,
                thread: Some(task),
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
        Err(e) => Err(e.into()),
    }
}
#[cfg(unix)]
fn ipv6_listener(port: u16) -> Result<TcpListener> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    ensure!(fd >= 0, "Cannot create IPv6 ACME socket");
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let enabled: libc::c_int = 1;
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } == 0,
        "Cannot set SO_REUSEADDR on IPv6 ACME socket"
    );
    #[cfg(target_os = "linux")]
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
    }
    ensure!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } == 0,
        "Cannot isolate IPv6 ACME socket"
    );
    let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    address.sin6_family = libc::AF_INET6 as _;
    address.sin6_port = port.to_be();
    ensure!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        } == 0,
        "Cannot bind IPv6 ACME socket"
    );
    ensure!(
        unsafe { libc::listen(fd.as_raw_fd(), 64) } == 0,
        "Cannot listen for IPv6 ACME"
    );
    Ok(TcpListener::from(fd))
}
#[cfg(not(unix))]
fn ipv6_listener(port: u16) -> Result<TcpListener> {
    Ok(TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, port))?)
}
pub fn certificates(
    c: &Config,
    args: &Deploy,
    work: &Path,
    token: Option<&str>,
    superseded: Option<&str>,
) -> Result<()> {
    let operations = crate::render::operations(c);
    #[cfg(feature = "integration-test")]
    if let Some(source) = std::env::var_os("NODECTL_TEST_CERTIFICATE_DIR") {
        let source = PathBuf::from(source);
        store::check_private(&source, true)?;
        for name in ["fullchain.pem", "privkey.pem"] {
            store::check_private(&source.join(name), false)?;
            store::atomic_write(
                &Path::new(&c.tls.domain_cert_dir).join(name),
                &fs::read(source.join(name))?,
            )?;
        }
        // Only the CA acquisition is a fixture; real SAN, trust, key matching,
        // receipt validation and all service/protocol checks stay enabled.
        return host::certificates(c);
    }
    if host::certificates(c).is_ok() {
        return Ok(());
    }
    ensure!(
        !args.manual_certificates,
        "Certificates invalid; provision manually or enable automatic issuance"
    );
    ensure!(
        args.accept_ca_terms || existing_acme_account(),
        "New ACME registration requires --accept-ca-terms after reviewing Let's Encrypt terms"
    );
    let email = args.acme_email.as_deref();
    if let Some(email) = email {
        ensure!(
            email.contains('@')
                && !email.chars().any(char::is_whitespace)
                && !email.starts_with('-'),
            "Invalid ACME email"
        );
    }
    ensure!(
        email.is_some() || existing_acme_account(),
        "New ACME account requires --acme-email; no existing Let's Encrypt account was found"
    );
    store::private_dir(Path::new("/root/.acme.sh"))?;
    let acme = PathBuf::from("/root/.acme.sh/acme.sh");
    if !acme.exists() {
        let source = work.join("acme-source");
        locked_source("acme", &source)?;
        long_command_in(
            "/bin/sh",
            &[
                "./acme.sh",
                "--install",
                "--home",
                "/root/.acme.sh",
                "--accountemail",
                email.context("New ACME install requires --acme-email")?,
                "--nocron",
                "--noprofile",
            ],
            &[],
            Some(&source),
            &[0],
        )?;
    }
    for (is_ip, dir) in [(false, &c.tls.domain_cert_dir), (true, &c.tls.ip_cert_dir)] {
        if host::certificates_part(c, Some(is_ip)).is_err() {
            store::private_dir(Path::new(dir))?;
        }
    }
    let mut env = vec![];
    if host::certificates_part(c, Some(false)).is_err() {
        env.push((
            "CF_Token",
            token.context("Automatic domain DNS-01 requires Cloudflare token")?,
        ));
        if !args.acme_discover_zones {
            env.push((
                "CF_Zone_ID",
                args.dns_zone.as_deref().context("Missing DNS zone")?,
            ));
        }
    }
    if let Some(email) = email {
        long_command(
            acme.to_str().unwrap(),
            &["--register-account", "--server", "letsencrypt", "-m", email],
            &env,
        )?;
    }
    // Use the exact operations generated by the existing DMIT render model.
    let needs_ip = host::certificates_part(c, Some(true)).is_err();
    ensure!(
        !needs_ip || c.ports.http == 80,
        "Automatic IP HTTP-01 renewal requires HTTP port 80; use manual certificates with an explicitly managed public challenge mapping for custom ports"
    );
    let mut bootstrap_server = if needs_ip { bootstrap(c)? } else { None };
    if needs_ip {
        let webroot = Path::new("/var/www/acme/.well-known/acme-challenge");
        fs::create_dir_all(webroot)?;
        let name = format!("nodectl-{}", uuid::Uuid::new_v4().simple());
        let probe = webroot.join(&name);
        fs::write(&probe, b"nodectl-acme-ready")?;
        let check = (|| -> Result<()> {
            for ip in c.ips() {
                let ip = if ip.contains(':') {
                    format!("[{ip}]")
                } else {
                    ip
                };
                let data = host::command(
                    "curl",
                    &[
                        "--disable",
                        "--noproxy",
                        "*",
                        "--fail",
                        "--silent",
                        "--max-time",
                        "10",
                        &format!("http://{ip}/.well-known/acme-challenge/{name}"),
                    ],
                )?;
                ensure!(
                    data == "nodectl-acme-ready",
                    "Existing HTTP server does not serve /var/www/acme"
                );
            }
            Ok(())
        })();
        fs::remove_file(probe)?;
        check?;
    }
    for kind in ["domain", "ip"] {
        if host::certificates_part(c, Some(kind == "ip")).is_ok() {
            continue;
        }
        let (main, dir, length) = if kind == "domain" {
            (&c.node.domain, &c.tls.domain_cert_dir, "ec-384")
        } else {
            (&c.node.ipv4, &c.tls.ip_cert_dir, "ec-256")
        };
        for file in ["fullchain.pem", "privkey.pem"] {
            let file = Path::new(dir).join(file);
            if file.exists() {
                ensure!(
                    fs::symlink_metadata(file)?.is_file(),
                    "Automatic certificate installation requires regular files; retain a symlink-based certificate under manual management"
                );
            }
        }
        let keylength =
            preserve_acme_key(Path::new("/root/.acme.sh"), main, Path::new(dir), length)?;
        if kind == "domain" && args.acme_discover_zones {
            clear_cf_hints(Path::new("/root/.acme.sh/account.conf"))?;
            clear_cf_hints(&Path::new("/root/.acme.sh").join(format!("{main}_ecc/{main}.conf")))?;
        }
        let mut issue = operations["certificates"][kind]["acme_issue_args"]
            .as_array()
            .context("ACME issue args")?
            .iter()
            .map(|v| v.as_str().context("ACME argument"))
            .collect::<Result<Vec<_>>>()?;
        for arg in &mut issue {
            if *arg == "DNS_PROVIDER" {
                *arg = "dns_cf";
            }
            if ["ec-384", "ec-256"].contains(arg) {
                *arg = keylength.as_str();
            }
        }
        long_command_in(acme.to_str().unwrap(), &issue, &env, None, &[0, 2])?;
        if kind == "domain"
            && let Some(old) = superseded
        {
            retire_acme(old)?;
        }
        let install = operations["certificates"][kind]["acme_install_args"]
            .as_array()
            .context("ACME install args")?
            .iter()
            .map(|v| v.as_str().context("ACME argument"))
            .collect::<Result<Vec<_>>>()?;
        // Preparation cannot reload an unapplied release, nor inherit a cached
        // hook that validates the retired SANs or waits for our held lock.
        let reload = install
            .iter()
            .position(|v| *v == "--reloadcmd")
            .context("ACME reload argument")?;
        let mut prepare_install = install[..reload].to_vec();
        prepare_install.extend(["--reloadcmd", "true"]);
        long_command(acme.to_str().unwrap(), &prepare_install, &env)?;
        if kind == "ip" {
            drop(bootstrap_server.take());
        }
    }
    drop(bootstrap_server.take());
    host::certificates(c)?;
    Ok(())
}
pub(crate) fn existing_acme_account() -> bool {
    Path::new("/root/.acme.sh/ca/acme-v02.api.letsencrypt.org/directory/account.json").is_file()
}
pub(crate) fn acme_scope(known: &[String]) -> Result<()> {
    let home = Path::new("/root/.acme.sh");
    if !home.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(home)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let folder = entry.file_name().to_string_lossy().into_owned();
        let primary = folder.strip_suffix("_ecc").unwrap_or(&folder);
        if entry.path().join(format!("{primary}.conf")).is_file() {
            ensure!(
                known.iter().any(|name| name == primary),
                "ACME home contains unrelated certificates; preserve shared automation with --manual-certificates"
            );
        }
    }
    Ok(())
}
fn clear_cf_hints(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    store::check_private(path, false)?;
    let input = fs::read_to_string(path)?;
    let mut output = String::new();
    for line in input.lines() {
        let name = line
            .trim_start()
            .split_once('=')
            .map(|(name, _)| name.trim_start_matches("export "));
        if name.is_some_and(|name| {
            [
                "CF_Zone_ID",
                "SAVED_CF_Zone_ID",
                "CF_Account_ID",
                "SAVED_CF_Account_ID",
            ]
            .contains(&name)
        }) {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    if output != input {
        store::atomic_write(path, output.as_bytes())?;
    }
    Ok(())
}
fn preserve_acme_key(home: &Path, main: &str, dir: &Path, length: &str) -> Result<String> {
    let installed = dir.join("privkey.pem");
    if !installed.exists() {
        return Ok(length.into());
    }
    store::check_private(&installed, false)?;
    let key = host::command(
        "openssl",
        &[
            "pkey",
            "-in",
            installed.to_str().context("Key path")?,
            "-text",
            "-noout",
        ],
    )?;
    let actual = if key.contains("ASN1 OID: secp384r1") {
        "ec-384"
    } else if key.contains("ASN1 OID: prime256v1") {
        "ec-256"
    } else {
        bail!(
            "Existing certificate key has an unsupported curve; reconcile manually rather than rotate silently"
        );
    };
    ensure!(
        length != "ec-384" || actual == "ec-384",
        "Existing certificate key has incompatible curve; reconcile manually rather than rotate silently"
    );
    let cache = home.join(format!("{main}_ecc"));
    store::private_dir(&cache)?;
    let cached = cache.join(format!("{main}.key"));
    if cached.exists() {
        store::check_private(&cached, false)?;
        ensure!(
            store::file_digest(&cached)? == store::file_digest(&installed)?,
            "ACME key cache differs from installed key; reconcile manually"
        );
    } else {
        store::atomic_write(&cached, &fs::read(&installed)?)?;
    }
    let conf = cache.join(format!("{main}.conf"));
    if !conf.exists() {
        store::atomic_write(&conf, format!("Le_Keylength='{actual}'\n").as_bytes())?;
    }
    Ok(actual.into())
}
pub fn warp(c: &Config, args: &Deploy) -> Result<()> {
    if !c.warp.enabled && !c.routes_cn() {
        return Ok(());
    }
    ensure!(
        Path::new("/dev/net/tun").exists(),
        "WARP requires /dev/net/tun"
    );
    let configs = c
        .warp
        .enabled
        .then_some(c.warp.config_file.as_str())
        .into_iter()
        .chain(
            c.cn_warp
                .as_ref()
                .filter(|cn| cn.enabled)
                .map(|cn| cn.config_file.as_str()),
        );
    for config in configs {
        let path = Path::new(config);
        if path.exists() {
            store::check_private(path, false)?;
            let _: Value =
                serde_json::from_slice(&fs::read(path)?).context("Invalid WARP credentials")?;
            continue;
        }
        ensure!(
            args.accept_warp_terms,
            "New WARP registration requires --accept-warp-terms"
        );
        store::private_dir(path.parent().context("WARP config parent")?)?;
        long_command(
            &c.runtime.usque_binary,
            &["-c", config, "register", "--accept-tos"],
            &[],
        )?;
        host::command("chmod", &["0600", config])?;
        store::check_private(path, false)?;
    }
    crate::cn_warp::credentials(c)?;
    Ok(())
}
pub fn warp_probe(c: &Config) -> Result<()> {
    if !c.warp.enabled {
        return Ok(());
    }
    let active = host::command(
        "systemctl",
        &["show", "usque-warp", "-p", "ActiveState", "--value"],
    )?
    .trim()
        == "active";
    let routes = (host::default_routes(false)?, host::default_routes(true)?);
    if active {
        host::command("systemctl", &["stop", "usque-warp"])?;
    }
    let result = (|| -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port().to_string();
        drop(listener);
        let output = tempfile::tempfile()?;
        let mut command = Command::new(&c.runtime.usque_binary);
        command
            .args([
                "-c",
                &c.warp.config_file,
                "socks",
                "-b",
                "127.0.0.1",
                "-p",
                &port,
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(output);
        inherit_lease(&mut command);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let parent = std::process::id() as libc::pid_t;
            unsafe {
                command.pre_exec(move || {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent {
                        return Err(std::io::Error::other("Provisioning parent exited"));
                    }
                    Ok(())
                });
            }
        }
        struct Socks(std::process::Child);
        impl Drop for Socks {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Socks(
            command
                .spawn()
                .context("Cannot start loopback-only WARP probe")?,
        );
        let start = Instant::now();
        loop {
            ensure!(
                child.0.try_wait()?.is_none(),
                "WARP probe process exited; private output withheld"
            );
            if let Ok(trace) = host::command(
                "curl",
                &[
                    "--disable",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--max-time",
                    "10",
                    "--noproxy",
                    "",
                    "--socks5-hostname",
                    &format!("127.0.0.1:{port}"),
                    "https://www.cloudflare.com/cdn-cgi/trace",
                ],
            ) {
                ensure!(
                    trace
                        .lines()
                        .any(|l| ["warp=on", "warp=plus"].contains(&l.trim())),
                    "WARP trace did not confirm a WARP exit"
                );
                break;
            }
            ensure!(
                start.elapsed() < Duration::from_secs(45),
                "WARP SOCKS handshake timed out"
            );
            thread::sleep(Duration::from_secs(1));
        }
        Ok(())
    })();
    // Restore the existing independent TUN even if the probe failed.
    if active {
        host::command("systemctl", &["start", "usque-warp"])?;
        host::command("systemctl", &["is-active", "--quiet", "usque-warp"])?;
    }
    ensure!(
        routes == (host::default_routes(false)?, host::default_routes(true)?),
        "WARP probe changed DMIT default routes"
    );
    result
}
fn retire_acme(old: &str) -> Result<()> {
    let conf = Path::new("/root/.acme.sh").join(format!("{old}_ecc/{old}.conf"));
    if conf.exists() {
        store::check_private(&conf, false)?;
        long_command(
            "/root/.acme.sh/acme.sh",
            &["--remove", "--ecc", "-d", old],
            &[],
        )?;
    }
    Ok(())
}
pub fn renewal(c: &Config, store: &store::Store, superseded: Option<&str>) -> Result<()> {
    if !Path::new("/root/.acme.sh/acme.sh").exists() {
        return Ok(());
    }
    let binary = std::env::current_exe()?;
    ensure!(
        crate::config::abs_path(binary.to_str().context("nodectl path")?)
            && crate::config::abs_path(store.config_dir.to_str().context("Config path")?)
            && crate::config::abs_path(store.state_dir.to_str().context("State path")?),
        "Renewal paths must be shell-safe absolute paths"
    );
    let hook = format!(
        "[ \"${{NODECTL_DEPLOY_RENEW_SETUP:-}}\" = 1 ] || {} --config-dir {} --state-dir {} renew-hook",
        binary.display(),
        store.config_dir.display(),
        store.state_dir.display()
    );
    let mut managed = false;
    for (domain, dir) in [
        (&c.node.domain, &c.tls.domain_cert_dir),
        (&c.node.ipv4, &c.tls.ip_cert_dir),
    ] {
        if fs::symlink_metadata(dir)?.file_type().is_symlink()
            || fs::symlink_metadata(Path::new(dir).join("fullchain.pem"))?
                .file_type()
                .is_symlink()
        {
            println!(
                "Existing certificate renewal remains operator-managed for {domain}; symlink targets were retained"
            );
            continue;
        }
        let cached = Path::new("/root/.acme.sh").join(format!("{domain}_ecc/fullchain.cer"));
        if !cached.is_file() {
            println!(
                "Existing certificate renewal remains operator-managed for {domain}; no ACME cache was adopted"
            );
            continue;
        }
        ensure!(
            store::file_digest(&cached)?
                == store::file_digest(&Path::new(dir).join("fullchain.pem"))?,
            "ACME cache differs from installed valid certificate; refusing replacement during renewal setup"
        );
        managed = true;
        if domain == &c.node.domain
            && let Some(old) = superseded
        {
            retire_acme(old)?;
        }
        long_command(
            "/root/.acme.sh/acme.sh",
            &[
                "--install-cert",
                "--ecc",
                "-d",
                domain,
                "--key-file",
                &format!("{dir}/privkey.pem"),
                "--fullchain-file",
                &format!("{dir}/fullchain.pem"),
                "--reloadcmd",
                &hook,
            ],
            &[("NODECTL_DEPLOY_RENEW_SETUP", "1")],
        )?;
    }
    if !managed {
        return Ok(());
    }
    long_command("/root/.acme.sh/acme.sh", &["--install-cronjob"], &[])?;
    host::command("systemctl", &["enable", "--now", "cron"])?;
    // The parent owns the deployment lock; validate/reload directly here.
    // Later cron invocations have no setup flag and call the normal locked CLI.
    host::renew(store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(unix, feature = "integration-test"))]
    #[test]
    #[ignore = "Requires the explicitly enabled disposable systemd/CA fixture"]
    fn isolated_acme_preparation_preserves_key_and_defers_reload() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::env::var("NODECTL_ISOLATED_ACME").as_deref(), Ok("yes"));
        assert!(Path::new("/.dockerenv").is_file());
        let fixture = Path::new("/root/nodectl-test/two-name-cert");
        assert!(fixture.join("fullchain.pem").is_file());
        let home = Path::new("/root/.acme.sh");
        assert!(!home.exists(), "Refusing to replace an existing ACME home");
        store::private_dir(home).unwrap();
        struct Home;
        impl Drop for Home {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all("/root/.acme.sh");
            }
        }
        let _home = Home;
        let account = home.join("ca/acme-v02.api.letsencrypt.org/directory");
        store::private_dir(&account).unwrap();
        store::atomic_write(&account.join("account.json"), b"{}").unwrap();
        let script = r#"#!/bin/sh
set -eu
action=$1; shift
main=; key=; chain=; reload=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -d) [ -n "$main" ] || main=$2; shift 2;;
    --key-file) key=$2; shift 2;;
    --fullchain-file) chain=$2; shift 2;;
    --reloadcmd) reload=$2; shift 2;;
    *) shift;;
  esac
done
case "$action" in
  --issue)
    mkdir -p "/root/.acme.sh/${main}_ecc"
    cp /root/nodectl-test/two-name-cert/fullchain.pem "/root/.acme.sh/${main}_ecc/fullchain.cer"
    printf 'issue\n' >> /root/.acme.sh/calls;;
  --install-cert)
    test "$reload" = true
    cp /root/nodectl-test/two-name-cert/fullchain.pem "$chain"
    cp /root/nodectl-test/two-name-cert/privkey.pem "$key"
    printf 'install-without-reload\n' >> /root/.acme.sh/calls;;
  *) exit 2;;
esac
"#;
        fs::write(home.join("acme.sh"), script).unwrap();
        fs::set_permissions(home.join("acme.sh"), fs::Permissions::from_mode(0o700)).unwrap();
        let (mut c, _) = crate::config::load(Path::new("/etc/dmit-node")).unwrap();
        c.node.domain = "speedtest.integration.test".into();
        c.node.reality_domain = "files.integration.test".into();
        c.node.aliases.clear();
        c.vless = Some(crate::config::Vless { encryption: true });
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("domain");
        store::private_dir(&dir).unwrap();
        c.tls.domain_cert_dir = dir.to_str().unwrap().into();
        store::atomic_write(
            &dir.join("privkey.pem"),
            &fs::read(fixture.join("privkey.pem")).unwrap(),
        )
        .unwrap();
        #[derive(clap::Parser)]
        struct TestArgs {
            #[command(flatten)]
            args: Deploy,
        }
        use clap::Parser;
        let args =
            TestArgs::parse_from(["test", "--accept-ca-terms", "--dns-zone", &"a".repeat(32)]).args;
        certificates(&c, &args, tmp.path(), Some("fixture"), None).unwrap();
        assert_eq!(
            fs::read(home.join("calls")).unwrap(),
            b"issue\ninstall-without-reload\n"
        );
        assert_eq!(
            store::file_digest(&dir.join("privkey.pem")).unwrap(),
            store::file_digest(&fixture.join("privkey.pem")).unwrap()
        );
        assert_eq!(
            store::file_digest(
                &home.join("speedtest.integration.test_ecc/speedtest.integration.test.key")
            )
            .unwrap(),
            store::file_digest(&fixture.join("privkey.pem")).unwrap()
        );
        println!("ACME_STAGED_INSTALL_NO_RELOAD_AND_KEY_REUSE_PASS");
    }
    #[test]
    fn only_missing_or_exact_vendor_placeholder_homepage_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c: Config = toml::from_str(crate::config::EXAMPLE).unwrap();
        c.website.root = tmp.path().to_str().unwrap().into();
        assert!(website_change(&c).unwrap());
        let path = tmp.path().join("index.html");
        fs::write(&path,"<!doctype html><html><meta charset=\"utf-8\"><title>DMIT</title><h1>DMIT node</h1></html>\n").unwrap();
        assert!(website_change(&c).unwrap());
        fs::write(&path, "<title>Operator content</title>").unwrap();
        assert!(!website_change(&c).unwrap());
        fs::write(&path, NEUTRAL_PAGE).unwrap();
        assert!(!website_change(&c).unwrap());
        #[cfg(unix)]
        {
            fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(tmp.path().join("missing"), &path).unwrap();
            assert!(!website_change(&c).unwrap());
        }
    }
    #[test]
    fn zone_discovery_clears_stale_hints_without_discarding_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.conf");
        store::atomic_write(
            &path,
            b"SAVED_CF_Token='private-fixture'\nSAVED_CF_Zone_ID='old-zone'\nCF_Account_ID='old-account'\nexport CF_Zone_ID='old-zone'\nSAVED_CF_Account_ID='old-account'\nACCOUNT_EMAIL='operator@example.com'\n",
        )
        .unwrap();
        clear_cf_hints(&path).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "SAVED_CF_Token='private-fixture'\nACCOUNT_EMAIL='operator@example.com'\n"
        );
        clear_cf_hints(&path).unwrap();
    }
    #[test]
    #[cfg(unix)]
    fn changed_sans_reuse_installed_p384_key_and_reject_conflicting_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let installed = tmp.path().join("installed");
        let home = tmp.path().join("acme");
        store::private_dir(&installed).unwrap();
        store::private_dir(&home).unwrap();
        let key = installed.join("privkey.pem");
        host::command(
            "openssl",
            &[
                "ecparam",
                "-name",
                "secp384r1",
                "-genkey",
                "-noout",
                "-out",
                key.to_str().unwrap(),
            ],
        )
        .unwrap();
        host::command("chmod", &["0600", key.to_str().unwrap()]).unwrap();
        preserve_acme_key(&home, "new.example.com", &installed, "ec-384").unwrap();
        let cached = home.join("new.example.com_ecc/new.example.com.key");
        assert_eq!(
            store::file_digest(&key).unwrap(),
            store::file_digest(&cached).unwrap()
        );
        store::atomic_write(&cached, b"conflicting-fixture").unwrap();
        assert!(preserve_acme_key(&home, "new.example.com", &installed, "ec-384").is_err());
    }
    #[test]
    fn challenge_server_only_reads_tokens_inside_webroot() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("web");
        fs::create_dir_all(root.join(".well-known/acme-challenge")).unwrap();
        fs::write(
            root.join(".well-known/acme-challenge/token_ok"),
            b"challenge-fixture",
        )
        .unwrap();
        let request = |path: &str| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let root = root.clone();
            let task = thread::spawn(move || challenge(listener.accept().unwrap().0, &root));
            let mut stream = TcpStream::connect(address).unwrap();
            write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut data = String::new();
            stream.read_to_string(&mut data).unwrap();
            (task.join().unwrap(), data)
        };
        let (result, data) = request("/.well-known/acme-challenge/token_ok");
        assert!(result.is_ok());
        assert!(data.ends_with("challenge-fixture"));
        assert!(request("/.well-known/acme-challenge/../outside").0.is_err());
        #[cfg(unix)]
        {
            fs::write(tmp.path().join("outside"), b"private-fixture").unwrap();
            std::os::unix::fs::symlink(
                tmp.path().join("outside"),
                root.join(".well-known/acme-challenge/escape"),
            )
            .unwrap();
            let (result, data) = request("/.well-known/acme-challenge/escape");
            assert!(result.is_err());
            assert!(!data.contains("private-fixture"));
        }
    }
}
