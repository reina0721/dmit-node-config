#!/bin/sh
# Default: verified nodectl installation followed by the Rust deployment wizard.
set -eu
umask 077
VERSION= PREFIX=/usr/local EXECUTE=no MODE=wizard BUNDLE_DIR= CONFIG_DIR=/etc/dmit-node STATE_DIR=/var/lib/dmit-node TOKEN_FILE= WITH_ADMIN=no
REPOSITORY=reina0721/dmit-node-config
LEGACY_REPOSITORY=i0721/dmit-node-config
LEGACY_MAX=v0.6.0
usage() { printf '%s\n' 'Usage: bash install.sh [--version vX.Y.Z] [--install-only --execute | --dry-run] [--with-admin] [--prefix /usr/local] [--bundle-dir PATH] [--config-dir PATH] [--state-dir PATH]' 'No action flag: install a verified stable release and run the complete interactive deployment wizard.' 'Legacy --execute/--dry-run explicitly select tool-only installation.' '--with-admin installs the signed static WebUI with separate HTTPS on 9443 after a valid node deployment (v0.6.0+).'; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --version|--prefix|--bundle-dir|--config-dir|--state-dir|--token-file)
      [ "$#" -ge 2 ] || die "Missing value for $1"
      case "$1" in --version) VERSION=$2;; --prefix) PREFIX=$2;; --bundle-dir) BUNDLE_DIR=$2;; --config-dir) CONFIG_DIR=$2;; --state-dir) STATE_DIR=$2;; --token-file) TOKEN_FILE=$2;; esac
      shift 2;;
    --install-only) MODE=install; shift;;
    --execute) MODE=install; EXECUTE=yes; shift;;
    --dry-run) MODE=install; EXECUTE=no; shift;;
    --with-admin) WITH_ADMIN=yes; shift;;
    --help|-h) usage; exit 0;;
    *) die "Unknown option: $1";;
  esac
done
if [ "$MODE" = wizard ]; then
  [ -t 0 ] || die 'Interactive installation requires a terminal; use --install-only and explicit non-interactive nodectl approval'
  if [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || die 'Run this installer as root, or install sudo'
    [ -f "$0" ] && [ ! -L "$0" ] || die 'Download the installer to a regular file before elevation'
    if [ "$WITH_ADMIN" = yes ]; then set -- --with-admin; else set --; fi
    exec sudo --preserve-env=http_proxy,https_proxy,all_proxy,no_proxy,HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,CURL_CA_BUNDLE,SSL_CERT_FILE /bin/sh "$0" --version "$VERSION" --prefix "$PREFIX" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" --bundle-dir "$BUNDLE_DIR" --token-file "$TOKEN_FILE" "$@"
  fi
  case "$(cat /etc/os-release)" in *'ID=debian'*|*'ID=ubuntu'*|*'ID="debian"'*|*'ID="ubuntu"'*) :;; *) die 'Automatic deployment requires Debian or Ubuntu';; esac
  [ -d /run/systemd/system ] || die 'A running systemd system is required'
  missing=no
  for tool in curl tar gzip sha256sum flock ip openssl; do command -v "$tool" >/dev/null 2>&1 || missing=yes; done
  if [ "$missing" = yes ] || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
    printf '%s\n' 'Preparing missing download/verification tools; services and DNS are not changed at this stage.'
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl tar gzip coreutils util-linux iproute2 openssl
  fi
  EXECUTE=yes
fi
if [ -z "$VERSION" ]; then
  [ -z "$BUNDLE_DIR" ] || die 'Offline installation requires --version'
  effective=$(curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 20 --max-time 1800 -o /dev/null -w '%{url_effective}' "https://github.com/$REPOSITORY/releases/latest")
  # GitHub redirects the pre-rename owner to the current one; both point at this repository.
  case "$effective" in
    "https://github.com/$REPOSITORY/releases/tag/"*|"https://github.com/$LEGACY_REPOSITORY/releases/tag/"*) VERSION=${effective##*/};;
    *) die 'Unexpected latest-release redirect';;
  esac
fi
printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || die 'Specify an exact stable version: --version vX.Y.Z'
if [ "$WITH_ADMIN" = yes ]; then
  printf '%s\n' "$VERSION" | awk -F '[v.]' '{exit !(($2+0)>0 || ($3+0)>=6)}' || die 'Static admin requires v0.6.0 or newer'
fi
if [ "$MODE" = wizard ]; then
  printf '%s\n' "$VERSION" | awk -F '[v.]' '{exit !(($2+0)>0 || ($3+0)>3 || (($3+0)==3 && ($4+0)>=1))}' || die 'The complete wizard requires v0.3.1 or newer; no suitable stable release is available'
fi
[ "$(uname -s)" = Linux ] || die 'Linux is required'
case "$(uname -m)" in x86_64|amd64) ARCH=x86_64;; aarch64|arm64) ARCH=aarch64;; *) die 'Unsupported CPU architecture';; esac
for value in "$PREFIX" "$CONFIG_DIR" "$STATE_DIR"; do
  case "$value" in /*) :;; *) die 'Paths must be absolute';; esac
  case "$value" in *'/../'*|*/..|*'/./'*|*/.|/|*'
'*) die 'Unsafe path';; esac
done
ASSET="nodectl-${VERSION}-${ARCH}-unknown-linux-gnu.tar.gz"
IDENTITY="https://github.com/$REPOSITORY/.github/workflows/release.yml@refs/tags/$VERSION"
# Releases up to LEGACY_MAX were signed before the owner rename, so their OIDC
# certificate identity still names the legacy owner. Accept that identity only
# for those tags; every newer tag must match the current repository identity.
version_le() { printf '%s\n%s\n' "${1#v}" "${2#v}" | awk -F. 'NR==1{a=$1*1000000+$2*1000+$3} NR==2{exit !(a <= $1*1000000+$2*1000+$3)}'; }
IDENTITIES=$IDENTITY
if version_le "$VERSION" "$LEGACY_MAX"; then
  LEGACY_IDENTITY="https://github.com/$LEGACY_REPOSITORY/.github/workflows/release.yml@refs/tags/$VERSION"
  IDENTITIES="$IDENTITY $LEGACY_IDENTITY"
fi
printf 'Version: %s\nArchitecture: %s\nAsset: %s\nInstall: %s/bin/nodectl\nTrust: %s (GitHub OIDC)\n' "$VERSION" "$ARCH" "$ASSET" "$PREFIX" "$IDENTITY"
[ -z "${LEGACY_IDENTITY:-}" ] || printf 'Pre-rename signer also accepted for this tag: %s\n' "$LEGACY_IDENTITY"
[ "$EXECUTE" = yes ] || { printf '%s\n' 'Preview only; rerun with --execute. No files or downloads changed.'; exit 0; }
for tool in curl sha256sum tar mktemp install flock sync od tr; do command -v "$tool" >/dev/null 2>&1 || die "Missing $tool; see docs/installation.md"; done
[ ! -e "$STATE_DIR/deployment.json" ] && [ ! -e "$STATE_DIR/transaction.json" ] && [ ! -e "$STATE_DIR/uninstall.json" ] || die 'Recover the interrupted lifecycle transaction before installing/upgrading'
[ ! -e "$STATE_DIR/admin-input.json" ] || die 'Recover the interrupted admin configuration transaction before installing/upgrading'
check_dir() {
  [ ! -L "$1" ] || die 'Refusing symbolic-link destination'
  if [ -e "$1" ]; then
    [ -d "$1" ] || die 'Destination parent must be a directory'
    [ "$(stat -c %u "$1")" = "$(id -u)" ] || die 'Destination is not owned by current user'
    [ -z "$(find "$1" -maxdepth 0 -perm /022 -print)" ] || die 'Destination writable by other users'
  fi
}
# Validate every existing path component before creating directories.
check_tree() { p=$1; while [ "$p" != / ]; do check_dir "$p"; p=$(dirname "$p"); done; }
check_tree "$PREFIX"
check_tree "$PREFIX/bin"
check_tree "$PREFIX/lib/nodectl/versions"
mkdir -p "$PREFIX/bin" "$PREFIX/lib/nodectl/versions"
exec 9>"$PREFIX/lib/nodectl/install.lock"
flock -n 9 || die 'Another installation is running'
work=$(mktemp -d)
stage=
cleanup() { rm -f "${stage:-$work/unused}"; rm -rf "$work"; }
trap cleanup EXIT HUP INT TERM
case "$ARCH" in
  x86_64) cosign_arch=amd64; cosign_hash=4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71;;
  aarch64) cosign_arch=arm64; cosign_hash=c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a;;
esac
COSIGN=$(command -v cosign || true)
if [ -z "$COSIGN" ] || [ "$(sha256sum "$COSIGN" | cut -d ' ' -f 1)" != "$cosign_hash" ]; then
  COSIGN="$work/cosign"
  if [ -n "$BUNDLE_DIR" ]; then
    [ -f "$BUNDLE_DIR/cosign-linux-$cosign_arch" ] && [ ! -L "$BUNDLE_DIR/cosign-linux-$cosign_arch" ] || die 'Offline mode needs the pinned official cosign binary in PATH or bundle directory'
    cp "$BUNDLE_DIR/cosign-linux-$cosign_arch" "$COSIGN"
  else
    curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 20 --max-time 1800 --retry 2 --retry-all-errors "https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-$cosign_arch" -o "$COSIGN"
  fi
  [ "$(sha256sum "$COSIGN" | cut -d ' ' -f 1)" = "$cosign_hash" ] || die 'Official cosign digest mismatch'
  chmod 0700 "$COSIGN"
fi
get_asset() {
  if [ -n "$BUNDLE_DIR" ]; then
    [ -f "$BUNDLE_DIR/$1" ] && [ ! -L "$BUNDLE_DIR/$1" ] || die 'Missing regular offline asset'
    cp "$BUNDLE_DIR/$1" "$work/$1"
  else
    curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --silent --show-error --connect-timeout 20 --max-time 1800 --retry 2 --retry-all-errors "https://github.com/$REPOSITORY/releases/download/$VERSION/$1" -o "$work/$1"
  fi
}
get_asset SHA256SUMS
get_asset SHA256SUMS.sigstore.json
verified=no
for identity in $IDENTITIES; do
  if "$COSIGN" verify-blob --bundle "$work/SHA256SUMS.sigstore.json" --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$work/SHA256SUMS" >/dev/null 2>&1; then verified=yes; break; fi
done
[ "$verified" = yes ] || die 'Release signature or workflow identity verification failed'
get_asset "$ASSET"
expected=$(awk -v name="$ASSET" '$2 == name { print $1 }' "$work/SHA256SUMS")
[ "${#expected}" = 64 ] || die 'Missing or ambiguous asset digest'
printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || die 'Invalid asset digest'
actual=$(sha256sum "$work/$ASSET" | cut -d ' ' -f 1)
[ "$expected" = "$actual" ] || die 'Archive digest mismatch'
# Extract only the executable; never expand archive paths as root.
[ "$(tar -tzf "$work/$ASSET" nodectl | wc -l)" -eq 1 ] || die 'Archive must contain one nodectl'
tar -xOzf "$work/$ASSET" nodectl > "$work/nodectl"
[ "$(od -An -tx1 -N6 "$work/nodectl" | tr -d ' \n')" = 7f454c460201 ] || die 'Expected a little-endian 64-bit ELF executable'
case "$ARCH" in x86_64) machine=3e00;; aarch64) machine=b700;; esac
[ "$(od -An -tx1 -j18 -N2 "$work/nodectl" | tr -d ' \n')" = "$machine" ] || die 'Binary CPU architecture mismatch'
chmod 0700 "$work/nodectl"
[ "$("$work/nodectl" --version)" = "nodectl ${VERSION#v}" ] || die 'Binary version mismatch'
"$work/nodectl" --help >/dev/null
"$work/nodectl" schema > "$work/schema.json"
if [ -d "$CONFIG_DIR" ]; then "$work/nodectl" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" validate >/dev/null || die 'Existing configuration incompatible; original binary preserved'; fi
dest="$PREFIX/bin/nodectl"
old_hash=
baseline=$(readlink "$STATE_DIR/current" 2>/dev/null || true)
if [ -e "$dest" ] || [ -L "$dest" ]; then
  [ -f "$dest" ] && [ ! -L "$dest" ] || die 'Installed binary must be a regular file'
  [ "$(stat -c %u "$dest")" = "$(id -u)" ] || die 'Installed binary ownership mismatch'
  [ -z "$(find "$dest" -maxdepth 0 -perm /022 -print)" ] || die 'Installed binary is writable by other users'
  old_hash=$(sha256sum "$dest" | cut -d ' ' -f 1)
  backup="$PREFIX/lib/nodectl/versions/$old_hash"
  if [ -e "$backup" ]; then [ "$(sha256sum "$backup" | cut -d ' ' -f 1)" = "$old_hash" ] || die 'Previous binary backup corrupted';
  else install -m 0755 "$dest" "$backup"; sync -f "$backup"; fi
  printf 'Previous binary retained: %s\n' "$backup"
fi
stage=$(mktemp "$PREFIX/bin/.nodectl-XXXXXXXX")
install -m 0755 "$work/nodectl" "$stage"
sync -f "$stage"
mv -f "$stage" "$dest"
sync -f "$PREFIX/bin"
stage=
printf 'Installed %s at %s\n' "$VERSION" "$dest"
if [ "$MODE" = wizard ]; then
  new_hash=$(sha256sum "$dest" | cut -d ' ' -f 1)
  run_wizard() {
    if [ -n "$TOKEN_FILE" ]; then
      "$dest" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" deploy --wizard --token-file "$TOKEN_FILE"
    else
      "$dest" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" deploy --wizard
    fi
  }
  if run_wizard; then
    printf '%s\n' 'Installation and deployment completed. Client file locations are shown above.'
  else
    result=$?
    if [ -e "$STATE_DIR/deployment.json" ] || [ -e "$STATE_DIR/transaction.json" ]; then
      if [ -f "$CONFIG_DIR/credentials/cloudflare-token" ]; then
        "$dest" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" recover --token-file "$CONFIG_DIR/credentials/cloudflare-token" || die 'Recovery incomplete; keep the new program and protected journals'
      else
        "$dest" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" recover || die 'Recovery incomplete; keep the new program and protected journals'
      fi
    fi
    [ "$(readlink "$STATE_DIR/current" 2>/dev/null || true)" = "$baseline" ] || die 'Deployment state changed; keep the compatible installed program and inspect recovery records'
    [ "$(sha256sum "$dest" | cut -d ' ' -f 1)" = "$new_hash" ] || die 'Installed program changed; refusing automatic replacement'
    if [ -n "$old_hash" ]; then
      [ "$(sha256sum "$PREFIX/lib/nodectl/versions/$old_hash" | cut -d ' ' -f 1)" = "$old_hash" ] || die 'Previous program backup changed; recovery stopped'
      stage=$(mktemp "$PREFIX/bin/.nodectl-restore-XXXXXXXX")
      install -m 0755 "$PREFIX/lib/nodectl/versions/$old_hash" "$stage"
      sync -f "$stage"
      mv -f "$stage" "$dest"
      stage=
    else
      rm -f "$dest"
    fi
    sync -f "$PREFIX/bin"
    printf '%s\n' 'Deployment cancelled or failed; original program and deployment preserved. Bootstrap packages may remain.' >&2
    exit "$result"
  fi
fi
if [ "$WITH_ADMIN" = yes ]; then
  "$dest" --config-dir "$CONFIG_DIR" --state-dir "$STATE_DIR" admin install --archive "$work/$ASSET" --execute
fi
