# 高级参考：手动分层部署

首次部署和保留配置更新，请直接使用 [README 的一键安装命令](../README.md#linux-一键安装与部署)。本页供需要逐层控制和排错的运维人员参考，无需按本页逐条执行才能完成一键部署。

核对日期：2026-10-16。本文对应仓库当前 `nodectl`、[全局配置示例](../config/node.example.toml) 和 [版本锁定清单](../versions.lock.toml)。默认环境为一台全新的 Debian 12/13、Linux amd64、systemd 主机；Ubuntu 用户使用对应的软件源。已有服务的主机先按第 1 节盘点，不能直接当新机器覆盖。

配套资源：[通用图解](visual-guide.md) · [部署记录模板](resources/deployment-record.template.md)。图解为工程示意，实际服务器必须执行验收。首次使用优先阅读 [快速开始](getting-started.md)，本页保留完整参考步骤。

Cloudflare 字段与 A/AAAA 灰云设置见 [脱敏配置图解](cloudflare-screenshots.md)，示例截图不代表真实解析已生效。自动编排入口见 [交互部署与升级](automated-deployment.md)。

## 目录与执行顺序

1. [命名、现状与准备](#1-命名现状与准备)
2. [Cloudflare DNS 与域名接入](#2-cloudflare-dns-与域名接入)
3. [Cloudflare API Token](#3-cloudflare-api-token)
4. [服务器、软件与防火墙](#4-服务器软件与防火墙)
5. [初始化全局配置](#5-初始化全局配置)
6. [acme.sh 与域名证书](#6-acmesh-与域名证书)
7. [首次 IP 证书与 HTTP 验证入口](#7-首次-ip-证书与-http-验证入口)
8. [Cloudflare WARP 与 usque](#8-cloudflare-warp-与-usque)
9. [候选检查与首次应用](#9-候选检查与首次应用)
10. [外部验收与客户端](#10-外部验收与客户端)
11. [无人值守续期与监控](#11-无人值守续期与监控)
12. [变更、回滚与恢复](#12-变更回滚与恢复)
13. [故障排查](#13-故障排查)
14. [部署记录与最终验收](#14-部署记录与最终验收)

首次安装的顺序是 **DNS → 软件 → node.toml → 域名证书 → 临时 HTTP 服务 → IP 证书 → WARP 注册/调试 → check → 停止临时服务 → apply → 启用续期**。Nginx 的最终配置依赖两套证书，不能先启动最终配置再等它签发自身所需的证书。

![两套证书首次签发、临时 HTTP 验证、首次应用和长期自动续期的顺序示意图](assets/deployment/certificate-lifecycle.svg)

图示说明见 [图 6](visual-guide.md#图-6两套证书的首次签发与续期)。它表示操作顺序，不表示证书已签发或服务已上线。

## 1. 命名、现状与准备

### 1.1 本教程统一命名

| 用途 | 完整域名 | Cloudflare「名称」字段 | 对应参数 |
| --- | --- | --- | --- |
| TLS 主入口、网站、默认客户端地址 | `speedtest.example.com` | `speedtest` | `node.domain` |
| REALITY 默认 SNI | `files.example.com` | `files` | `node.reality_domain` |

以上均为 `example.com` 下的 `speedtest`、`files` 子域。这里不使用根域 `@`、已有 `www` 或通配域接管其他业务。两个域名都指向同一台 DMIT；REALITY 的客户端 SNI 与 TLS 主 SNI 分开，但服务端本地 target 始终从 HTTPS 端口派生为 `127.0.0.1:443`。

本教程仅使用 example.com 等通用示例，不记录实际账户、已有 DNS 状态或服务器信息。部署时必须根据自己的控制台与网卡核对地址、归属及已有业务。

### 1.2 三种 Cloudflare 能力分别配置

| 能力 | 本项目用途 | 需要做的事 |
| --- | --- | --- |
| 权威 DNS | 将两个子域解析到 DMIT | A/可选 AAAA，全为灰云「仅 DNS」 |
| DNS API | acme.sh 自动创建并清理 DNS-01 TXT | 单独创建仅限该 zone 的 Token |
| WARP/MASQUE | usque 独立 TUN 调试 | 注册 usque 凭据，检查隧道，不接管默认路由 |

WARP 不要求把节点域名加入 Zero Trust，也不需要为上述子域创建 Cloudflare Tunnel、Access 应用、Gateway 策略或 Workers 路由。浏览器登录 Cloudflare 不会自动把服务器加入 WARP。普通 usque 注册与 DNS API Token 是两套不同凭据。

![Cloudflare 灰云 DNS、Nginx 和 Xray 入口、DMIT 原出口以及独立 usque WARP 支路示意图](assets/deployment/network.svg)

### 1.3 主机盘点

先保留 DMIT 网页控制台入口和第二个 SSH 会话。确认系统时间、架构、IP、DNS 解析和现有监听；记录 SSH 的真实端口，不假定总是 22：

```bash
sudo -i
bash
umask 077
set -euo pipefail
uname -m
cat /etc/os-release
timedatectl status
ip -br address
ip -4 route show default
ip -6 route show default
ss -lntup
systemctl status nginx xray usque-warp --no-pager || true
```

下文命令在服务器的同一个 root Bash 会话中按顺序运行；遇到未处理的错误会退出这层 Bash，应先解决错误，不继续粘贴后面的命令。变量会被后续步骤复用。重新登录/进入 Bash 后，重新设置普通变量，Token 用隐藏输入再次读取。真实 IP、邮箱、Zone ID 留在主机的私密记录中，不提交仓库。

```bash
export DMIT_DOMAIN='speedtest.example.com'
export DMIT_REALITY='files.example.com'
read -r -p 'DMIT 实际公网 IPv4: ' DMIT_IPV4
read -r -p 'DMIT 实际公网 IPv6，无则直接回车: ' DMIT_IPV6
read -r -p 'ACME 联系邮箱: ' ACME_EMAIL
export DMIT_IPV4 DMIT_IPV6 ACME_EMAIL
```

`203.0.113.10`、`2001:db8::10` 只是仓库中的保留文档地址。不能把它们写入真实 DNS 或用来申请证书。没有可从公网直达的 IPv6，就保持 `DMIT_IPV6` 为空，并省略 AAAA、IPv6 SAN 和 IPv6 监听。

## 2. Cloudflare DNS 与域名接入

### 2.1 先确认权威 DNS

在 Cloudflare 选择 `example.com`，进入 DNS → 记录。若 zone 尚未完成接入，在注册商处使用 Cloudflare 分配给这个 zone 的名称服务器；不要照抄其他账户的 NS。检查：

```bash
dig +short NS example.com
dig +trace NS example.com
```

DNS 记录表中手工添加的根域 NS 不等同于注册商的权威委派；以注册商设置、zone 状态和公开查询结果共同核实。迁移涉及原有 DNSSEC/DS 时，按 Cloudflare 的 [名称服务器接入说明](https://developers.cloudflare.com/dns/zone-setups/full-setup/setup/) 完成衔接，避免出现验证失败。已正常接入的 zone 不要为了本教程重新修改整域 NS、DNSSEC 或邮箱记录。

### 2.2 建立节点记录

点击「添加记录」，类型选 A，名称只填表中短名称，内容填自己 DMIT 的 IPv4，代理状态切换为 **仅 DNS（灰云）**，TTL 可用自动，保存。已有 `speedtest` 应核对并编辑原记录，不重复添加相同记录。[官方记录操作说明](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/)

| 类型 | 名称 | 内容 | 代理状态 | 条件 |
| --- | --- | --- | --- | --- |
| A | `speedtest` | `$DMIT_IPV4` 的实际值 | 仅 DNS | 必需 |
| A | `files` | 同一 IPv4 | 仅 DNS | 必需 |
| AAAA | `speedtest` | `$DMIT_IPV6` 的实际值 | 仅 DNS | 有公网 IPv6 才添加 |
| AAAA | `files` | 同一 IPv6 | 仅 DNS | 同上 |

网页内容字段不展开 `$DMIT_IPV4`，要填地址本身。两个名称不要再有指向旧机器的 A/AAAA、冲突 CNAME 或覆盖它们的 Worker 自定义域。

旧版截图中的名称仅用于说明表单操作；新部署按本表的两个中性名称填写自己的地址，确认灰云 **仅 DNS** 后保存。

[通用操作图解](visual-guide.md)

IPv6 对应的 AAAA 表单见 [图 2](visual-guide.md#图-2可选-ipv6-aaaa-记录)。没有公网 IPv6 就不创建该记录。

本方案需要客户端直达 DMIT 的 Nginx/Xray；橙云会把解析与连接路径换成 Cloudflare 代理。尤其 REALITY 不能按普通 HTTPS CDN 回源理解。灰云时 Cloudflare 的 WAF、缓存、边缘 HTTP/3、Always Use HTTPS 及边缘 SSL 模式不会替代本机配置，也无需为了这些子域修改整域设置。[代理状态原理](https://developers.cloudflare.com/dns/proxy-status/)

### 2.3 确认解析与 CAA

```bash
for name in "$DMIT_DOMAIN" "$DMIT_REALITY"; do
  printf '\n%s\n' "$name"
  dig +short A "$name" @1.1.1.1
  dig +short AAAA "$name" @1.1.1.1
  dig +short CAA "$name" @1.1.1.1
done
dig +short CAA example.com @1.1.1.1
```

A 必须返回自己的 DMIT IPv4；配置 IPv6 时 AAAA 也必须正确。没有 IPv6 时不要遗留旧 AAAA。DNS 缓存未过期时，同时向权威服务器查询确认，不要用反复修改记录来“刷新”。若已有 CAA 限制签发机构，确认对两个子域生效的策略允许 `letsencrypt.org`；不存在 CAA 时无须专门新增。不要删除其他业务的 CAA 或邮件 TXT。[CAA 字段说明](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#caa)

## 3. Cloudflare API Token

### 3.1 创建仅用于 DNS-01 的用户 Token

Cloudflare 右上角用户菜单 → My Profile/我的个人资料 → API Tokens/API 令牌 → Create Token。可从 Edit zone DNS 模板开始，并将最终权限限制为：

模板选择入口见 [图 3](visual-guide.md#图-3dns-token-模板入口)。以下权限草稿仅演示设置，拍摄后已退出，没有生成实际 Token。

[通用操作图解](visual-guide.md)

| 配置项 | 值 |
| --- | --- |
| 名称 | `dmit-acme-example` |
| 权限 | Zone → DNS → Edit；Zone → Zone → Read |
| Zone Resources | Include → Specific zone → `example.com` |
| 其他账户/zone 权限 | 不授予 |
| Client IP 过滤 | 可选；启用时需覆盖服务器实际访问 Cloudflare API 的出口 IPv4/IPv6 |
| 到期时间 | 结合续期安排设置，到期前更新服务器凭据 |

确认摘要后创建，由操作者保管只显示一次的 Token。这里的 DNS Edit 权限限定到 zone，仍可修改该 zone 的 DNS，并不是仅限 `_acme-challenge` 的单条记录权限。不要使用 Global API Key 或 WARP 的配置密钥来代替它。[官方 Token 创建说明](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)

在 zone 概述页面的 API 区域获取 Zone ID、Account ID。以下值在服务器输入，文档不保存账户标识或 Token 真值：

```bash
read -r -s -p 'Cloudflare DNS API Token: ' CF_Token
printf '\n'
read -r -p 'example.com 的 Zone ID: ' CF_Zone_ID
read -r -p '该 zone 所属 Account ID: ' CF_Account_ID
export CF_Token CF_Zone_ID CF_Account_ID
```

不要开启 `set -x`。若为 API Token 配置了出口 IP 限制，这里填的是 DMIT 调用 API 的出口，不是客户端 IP；本方案不会把该调用切到 WARP。

### 3.2 验证 Token 与 zone 权限

在安装第 4 节的 curl/jq 后执行。头部通过标准输入传给 curl，避免将 Token 写入命令历史或参数列表：

```bash
printf 'Authorization: Bearer %s\n' "$CF_Token" |
  curl --fail --silent --show-error --header @- \
    https://api.cloudflare.com/client/v4/user/tokens/verify |
  jq -e '.success == true and .result.status == "active"'

printf 'Authorization: Bearer %s\n' "$CF_Token" |
  curl --fail --silent --show-error --header @- \
    "https://api.cloudflare.com/client/v4/zones/$CF_Zone_ID" |
  jq -e '.success == true and .result.name == "example.com"'
```

第一项只说明 Token 有效；第二项检查是否能读取正确 zone。DNS Edit 权限最终由 DNS-01 申请过程中创建/清理 TXT 验证。acme.sh 的 `dns_cf` 使用 `CF_Token`、`CF_Zone_ID`、`CF_Account_ID`，并会保存供续期使用；这些参数不写入 `node.toml` 或 `secrets.json`。[dns_cf 实现](https://github.com/acmesh-official/acme.sh/blob/3.1.6/dnsapi/dns_cf.sh)

## 4. 服务器、软件与防火墙

### 4.1 系统依赖及用户

```bash
apt-get update
apt-get install -y ca-certificates curl wget git jq openssl unzip tar \
  build-essential pkg-config libssl-dev libpcre2-dev zlib1g-dev \
  iproute2 dnsutils util-linux cron gnupg lsb-release debian-archive-keyring
getent group www-data >/dev/null || groupadd --system www-data
id www-data >/dev/null 2>&1 || useradd --system --gid www-data --no-create-home --shell /usr/sbin/nologin www-data
id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray
install -d -m 0750 -o xray -g www-data /var/log/xray
install -d -m 0755 /var/log/nginx /var/www /var/www/html /var/www/acme
install -d -m 0700 /etc/ssl/dmit/domain /etc/ssl/dmit/ip /etc/usque
install -d -m 0700 /root/dmit-install-records
systemctl enable --now cron
```

不要重复创建已存在用户，也不要更改已有业务目录的所有者。Nginx master 读取私钥时以 root 运行；Xray 用 `LoadCredential` 读取配置，其主组是 `www-data`，以便两个 UDS 由 Nginx worker 访问。

### 4.2 Nginx：必须具备 H2/H3

若系统已安装满足要求的 Nginx，先检查版本和模块，不必换源。Debian 默认源的旧版本可能缺少 H3 或 `http2 on`；本教程使用 [Nginx 官方 Debian 软件源](https://nginx.org/en/linux_packages.html#Debian)：

```bash
curl -fsSLo /root/dmit-install-records/nginx_signing.key https://nginx.org/keys/nginx_signing.key
gpg --show-keys --with-fingerprint /root/dmit-install-records/nginx_signing.key
```

核对官网公布的完整主指纹；本次核对为 `573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62`。若不同，先核实官方轮换公告，不跳过验证。核实后：

```bash
gpg --dearmor --output /usr/share/keyrings/nginx-archive-keyring.gpg /root/dmit-install-records/nginx_signing.key
printf 'deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/debian %s nginx\n' \
  "$(lsb_release -cs)" > /etc/apt/sources.list.d/nginx.list
apt-get update
apt-get install -y nginx
nginx -V 2>&1
```

检查输出含 `--with-http_ssl_module`、`--with-http_v2_module`、`--with-http_v3_module`，且支持 `http2 on`（1.25.1 及以上）。没有 H3 模块就先按官网安装/构建适配版本，不能只在配置中写 `quic`。[HTTP/3 模块要求](https://nginx.org/en/docs/http/ngx_http_v3_module.html)

全新主机上安装包可能已启动默认 Nginx，此时停止它，为后续临时验证服务腾出端口：

```bash
systemctl stop nginx
nginx -V > /root/dmit-install-records/nginx-version.txt 2>&1
dpkg-query -W nginx > /root/dmit-install-records/nginx-package.txt
```

已有网站的主机应安排维护窗口和接管，不能直接照抄此停止步骤。Ubuntu 使用官方页面中的 Ubuntu 分支及 keyring 包，不能使用 Debian 仓库地址。

### 4.3 Go 与原始 Xray Core

安装 Go 1.27.2 或满足所选源码要求的官方工具链。若已有 Go，先用 `go version` 检查。全新 amd64 主机可从官方元数据取得归档摘要，再下载和解包到尚不存在的 `/usr/local/go`：

```bash
GO_VERSION='1.27.2'
curl -fsSL 'https://go.dev/dl/?mode=json&include=all' -o /root/dmit-install-records/go-downloads.json
GO_ARCHIVE="go${GO_VERSION}.linux-amd64.tar.gz"
GO_SHA=$(jq -er --arg version "go$GO_VERSION" --arg file "$GO_ARCHIVE" \
  '.[] | select(.version == $version) | .files[] | select(.filename == $file) | .sha256' \
  /root/dmit-install-records/go-downloads.json)
curl -fL "https://go.dev/dl/$GO_ARCHIVE" -o "/root/dmit-install-records/$GO_ARCHIVE"
printf '%s  %s\n' "$GO_SHA" "/root/dmit-install-records/$GO_ARCHIVE" | sha256sum -c -
test ! -e /usr/local/go
tar -C /usr/local -xzf "/root/dmit-install-records/$GO_ARCHIVE"
export PATH="/usr/local/go/bin:$PATH"
go version
```

ARM64 要选择对应归档并重新核对摘要，不能执行 amd64 的下载块。安装说明参见 [Go 官方安装文档](https://go.dev/doc/install)。

按项目锁定版本现场构建 Xray：

```bash
install -d -m 0755 /usr/local/src
git clone --depth 1 --branch v26.10.10 https://github.com/XTLS/Xray-core.git /usr/local/src/Xray-core-v26.10.10
cd /usr/local/src/Xray-core-v26.10.10
go mod verify
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /usr/local/bin/xray ./main
chown root:root /usr/local/bin/xray
chmod 0755 /usr/local/bin/xray
/usr/local/bin/xray version
git rev-parse HEAD > /root/dmit-install-records/xray-source-commit.txt
```

输出版本必须为 `26.10.10`。如改用官方预编译版本，Linux amd64 ZIP 的 URL/SHA256 已列在 `versions.lock.toml`；先验证归档再解包。源码构建产生的二进制摘要可能与官方构建不同，后续记录自己的受信任构建摘要即可。

### 4.4 usque 固定源码构建

教程采用官方 `v4.2.1`，本次核对 commit 为 `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`，其 go.mod 要求 Go 1.26.3 或更高。未来升级单独评估，不在配置应用时自动拉取 main。[固定版本源码](https://github.com/Diniboy1123/usque/tree/v4.2.1)

```bash
git clone --depth 1 --branch v4.2.1 https://github.com/Diniboy1123/usque.git /usr/local/src/usque-v4.2.1
cd /usr/local/src/usque-v4.2.1
test "$(git rev-parse HEAD)" = '6aa03fc97d12848dce34eedbd187fb1077b5d1ea'
go mod verify
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/usque .
chown root:root /usr/local/bin/usque
chmod 0755 /usr/local/bin/usque
/usr/local/bin/usque version
```

### 4.5 构建项目

在服务器准备当前仓库的完整代码，可以从已发布的仓库拉取，也可以通过 SSH 安全复制本地目录。若本地改动还未推送，远端 clone 不会包含它们。以下假设代码已经放在 `/opt/dmit-node-config`：

```bash
cd /opt/dmit-node-config
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git rev-parse HEAD > /root/dmit-install-records/nodectl-source-commit.txt
  git status --short
else
  printf '受控文件复制部署，另存来源与文件摘要\n' > /root/dmit-install-records/nodectl-source-commit.txt
fi
```

Rust 尚未安装时，按 [Rust 官方 rustup 安装说明](https://rust-lang.org/tools/install/) 安装 stable。例如从官方地址下载安装脚本后运行（已有 Rust 时跳过安装部分）：

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
  -o /root/dmit-install-records/rustup-init.sh
sh /root/dmit-install-records/rustup-init.sh -y --profile minimal --no-modify-path
```

在当前代码目录构建：

```bash
export PATH="/root/.cargo/bin:$PATH"
cargo test --locked
cargo build --release --locked
install -m 0755 -o root -g root target/release/nodectl /usr/local/bin/nodectl
nodectl --version
sha256sum /usr/local/bin/nodectl /usr/local/bin/xray /usr/sbin/nginx /usr/local/bin/usque \
  > /root/dmit-install-records/binaries.sha256
find src templates config schemas -type f -print0 | sort -z | xargs -0 sha256sum \
  > /root/dmit-install-records/nodectl-source-files.sha256
```

仓库地址为 [reina0721/dmit-node-config](https://github.com/reina0721/dmit-node-config)。归档当前版本的源代码/补丁和 `nodectl` 二进制；恢复旧快照要求生成它的工具版本。

### 4.6 防火墙和网络方向

DMIT 控制台规则和主机防火墙都要检查；不要清空现有规则。先保留当前 SSH 端口及已有业务，随后允许：

| 方向 | 端口/协议 | 用途 |
| --- | --- | --- |
| 入站 | 实际 SSH TCP 端口 | 运维 |
| 入站 | 80/TCP | IP 证书 HTTP-01、ACME webroot、HTTPS 跳转 |
| 入站 | 443/TCP | 网站、TLS XHTTP/WS |
| 入站 | 443/UDP | Nginx QUIC/H3 |
| 入站 | 8443/TCP | XHTTP + REALITY |
| 出站 | DNS 及 HTTPS | 系统解析、软件获取、Cloudflare API、ACME、健康探测 |
| 出站 | usque 配置中的 Cloudflare endpoint，默认 UDP 443 | WARP MASQUE；不需要新增 WARP 入站端口 |

若已使用 UFW，可在保留 SSH 允许规则后添加 `ufw allow 80/tcp`、`443/tcp`、`443/udp`、`8443/tcp`，并用 `ufw status verbose` 检查；不要在未核实 SSH 和 IPv6 策略时启用或重置防火墙。HTTPS 端口改变时同步开放新端口的 TCP/UDP，REALITY 端口改变时同步开放对应 TCP。

## 5. 初始化全局配置

```bash
nodectl init
chmod 0700 /etc/dmit-node
chmod 0600 /etc/dmit-node/node.toml /etc/dmit-node/secrets.json
```

`init` 已采用本教程两个域名，仍需编辑 `/etc/dmit-node/node.toml` 的真实 IP。只修改普通参数，不用 `cp` 整份示例覆盖初始化结果，以免丢失已随机化的路径。node 段最终应为：

```toml
[node]
domain = "speedtest.example.com"
aliases = []
reality_domain = "files.example.com"
ipv4 = "203.0.113.10" # 必须替换成自己的实际公网 IPv4
ipv6 = ""           # 有可达 IPv6 时填写实际地址
```

上面 IPv4 故意使用文档地址；实际值以第 1 节输入为准。其余参数完整字段见 [node.example.toml](../config/node.example.toml)，上线前逐项核对：

| 参数组 | 本教程采用值/行为 |
| --- | --- |
| `schema_version` | `1` |
| `ports` | HTTP 80、HTTPS 443、REALITY 8443；端口必须不同 |
| `transport.xhttp` | 初始化随机多级路径，以 `/` 结尾；`stream-one`；`/tmp/vless-xhttp.socket` |
| `transport.ws` | 独立随机多级路径，精确匹配；`/tmp/vless-ws.socket` |
| `transport.reality` | 第三个独立随机路径；`stream-one`；不添加到 Nginx location |
| `tls` | 仅 TLSv1.3，H2/H3 开启，Alt-Svc 86400；证书目录 `/etc/ssl/dmit/domain`、`/etc/ssl/dmit/ip` |
| `website` | `/var/www/html`，保留 `/.well-known/`；已有业务路径加入 `reserved_paths` |
| `runtime` | `/usr/local/bin/xray`、`/usr/sbin/nginx`、`/usr/local/bin/usque`；用户 xray/www-data；日志根 `/var/log` |
| `clients` | XHTTP/WS/REALITY 为 80/15/5；指纹 chrome/ios/firefox/qq 为 5/2/3/1 |
| `warp` | `enabled = true`，`config_file = "/etc/usque/config.json"`，`take_over_default_route = false` |

生成一个简单静态首页，让网站根可读；已有站点应保留原内容：

```bash
test -e /var/www/html/index.html || printf '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><h1>Welcome</h1><p>This site is available.</p></html>\n' > /var/www/html/index.html
chmod 0644 /var/www/html/index.html
nodectl validate
```

不要把 UUID、REALITY 私钥或 WARP 注册结果写进文档、工单或 Git。三个 UUID 与私钥由 init 保存，REALITY 公钥由私钥派生，普通 render 不再随机生成。

## 6. acme.sh 与域名证书

### 6.1 安装固定版 acme.sh

本教程采用官方 `3.1.6`，核对 commit 为 `807da6498377ee5e0cf43a78091f46f12dc59a89`：

```bash
git clone --depth 1 --branch 3.1.6 https://github.com/acmesh-official/acme.sh.git /usr/local/src/acme.sh-3.1.6
cd /usr/local/src/acme.sh-3.1.6
test "$(git rev-parse HEAD)" = '807da6498377ee5e0cf43a78091f46f12dc59a89'
./acme.sh --install --home /root/.acme.sh --accountemail "$ACME_EMAIL" --nocron
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
chmod 0700 /root/.acme.sh
```

这里暂不安装 cron，等首次应用完成且续期入口切换好后再安装。acme.sh 是独立证书客户端，其账户私钥、DNS Token 和证书材料位于 `/root/.acme.sh`，需要与项目配置同等级保护。安装及证书部署机制见 [acme.sh 官方说明](https://github.com/acmesh-official/acme.sh/tree/3.1.6)。

### 6.2 用 Cloudflare DNS-01 申请三域名 SAN 证书

第 3 节输入的 `CF_*` 变量必须还在当前会话中。首个 `-d` 固定为主域，后续安装和续期以该主域作为证书标识：

```bash
/root/.acme.sh/acme.sh --issue --server letsencrypt --dns dns_cf \
  -d "$DMIT_DOMAIN" -d "$DMIT_REALITY" \
  --keylength ec-384
```

DNS-01 不依赖此时 Nginx 运行，也不要求为验证开放 80。acme.sh 会为两个名称写入 `_acme-challenge` TXT，并在验证后清理；不要手工永久保留验证码。检查传播问题时只查询对应名称：

```bash
dig +short TXT "_acme-challenge.$DMIT_DOMAIN" @1.1.1.1
```

Token 保存后可从当前 shell 清除，自动续期使用 acme.sh 保存的配置：

```bash
unset CF_Token CF_Zone_ID CF_Account_ID
find /root/.acme.sh -type d -exec chmod 0700 {} +
find /root/.acme.sh -type f -name '*.conf' -exec chmod 0600 {} +
```

不要把 `/root/.acme.sh` 复制进仓库，也不要将它整体打印到日志。DNS 插件调用失败时先检查权限、zone 和出口 IP 限制，不要重复申请新证书碰撞 CA 频率限制。

### 6.3 安装证书到运行目录

首次不设置 reload hook，因为还没有 current、IP 证书或运行中的最终 Nginx。只在新目录预创建目标文件以固定权限；已有非空文件不要清空：

```bash
touch /etc/ssl/dmit/domain/fullchain.pem /etc/ssl/dmit/domain/privkey.pem
chown root:root /etc/ssl/dmit/domain/*.pem
chmod 0644 /etc/ssl/dmit/domain/fullchain.pem
chmod 0600 /etc/ssl/dmit/domain/privkey.pem
/root/.acme.sh/acme.sh --install-cert --ecc -d "$DMIT_DOMAIN" \
  --key-file /etc/ssl/dmit/domain/privkey.pem \
  --fullchain-file /etc/ssl/dmit/domain/fullchain.pem
openssl x509 -in /etc/ssl/dmit/domain/fullchain.pem -noout -dates -ext subjectAltName
```

SAN 必须精确包含三个教程域名。不能用 Cloudflare Origin CA 替代这张公开受信任证书：本项目灰云直连，客户端不经过 Cloudflare 边缘；Origin CA 的信任范围与此不同。[Origin CA 适用范围](https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/)

## 7. 首次 IP 证书与 HTTP 验证入口

域名 DNS-01 证书不能验证一个公网 IP。IP 证书单独申请，SAN 只放自己的实际 IPv4/可选 IPv6，用于 Nginx default_server 的 IP/未匹配 SNI 场景。Let's Encrypt 当前 IP 证书使用 `shortlived` profile，约 160 小时有效；不能按普通长周期证书的节奏维护。[CA 官方说明](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/)

### 7.1 启动只处理 HTTP-01 的临时 Nginx

先用 `ss -ltnp 'sport = :80'` 确认端口空闲；不要终止不认识的进程。如下配置不读证书，不使用项目最终 nginx.conf：

```bash
nginx_v6_listen=''
if [ -n "$DMIT_IPV6" ]; then nginx_v6_listen='listen [::]:80 default_server;'; fi
cat > /etc/nginx/dmit-bootstrap.conf <<NGINX
user www-data;
worker_processes 1;
pid /run/nginx-dmit-bootstrap.pid;
error_log /var/log/nginx/dmit-bootstrap-error.log;
events { worker_connections 256; }
http {
    server {
        listen 80 default_server;
        $nginx_v6_listen
        server_name _;
        location ^~ /.well-known/acme-challenge/ { root /var/www/acme; }
        location / { return 404; }
    }
}
NGINX
nginx -t -c /etc/nginx/dmit-bootstrap.conf
nginx -c /etc/nginx/dmit-bootstrap.conf
install -d -m 0755 /var/www/acme/.well-known /var/www/acme/.well-known/acme-challenge
printf 'dmit-acme-ready\n' > /var/www/acme/.well-known/acme-challenge/probe
chmod 0644 /var/www/acme/.well-known/acme-challenge/probe
curl --fail http://127.0.0.1/.well-known/acme-challenge/probe
```

还必须从另一条公网网络访问 `http://实际IPv4/.well-known/acme-challenge/probe`。若申请 IPv6 SAN，也检查 `http://[实际IPv6]/.well-known/acme-challenge/probe`。本地成功并不能证明 DMIT 防火墙已开放。证书 HTTP-01 对公网 80 端口验证；本教程保留该端口，修改 ports.http 时必须另行保证公网 80 能转发到验证入口。

### 7.2 使用 webroot 申请，避免后续停机续期

首次就使用同一个 webroot，以后最终 Nginx 的 80 server 也提供它，续期不需要抢占端口。`--days 3` 表示在约三天时尝试更新，调度器每天运行检查；实际以签发证书的 notAfter 为准。[acme.sh profile 选项](https://github.com/acmesh-official/acme.sh/wiki/Profile-selection)

```bash
ip_cert_args=(-d "$DMIT_IPV4")
if [ -n "$DMIT_IPV6" ]; then ip_cert_args+=(-d "$DMIT_IPV6"); fi
/root/.acme.sh/acme.sh --issue --server letsencrypt \
  --webroot /var/www/acme --certificate-profile shortlived --days 3 \
  --keylength ec-256 "${ip_cert_args[@]}"

touch /etc/ssl/dmit/ip/fullchain.pem /etc/ssl/dmit/ip/privkey.pem
chown root:root /etc/ssl/dmit/ip/*.pem
chmod 0644 /etc/ssl/dmit/ip/fullchain.pem
chmod 0600 /etc/ssl/dmit/ip/privkey.pem
/root/.acme.sh/acme.sh --install-cert --ecc -d "$DMIT_IPV4" \
  --key-file /etc/ssl/dmit/ip/privkey.pem \
  --fullchain-file /etc/ssl/dmit/ip/fullchain.pem
openssl x509 -in /etc/ssl/dmit/ip/fullchain.pem -noout -dates -ext subjectAltName
```

IP SAN 必须覆盖 node.toml 中所有启用的 IP。若 IPv6 不可达，修好网络或从配置、DNS 和证书申请三处一致移除它，不能只隐藏一个失败检查。申请失败时保留临时 HTTP 服务排查；不改用第三方地址或关闭客户端证书验证。

## 8. Cloudflare WARP 与 usque

### 8.1 注册与凭据保护

usque 是社区开源的 WARP MASQUE 客户端，独立于 Cloudflare DNS 托管。普通注册无需 DNS Token，也无需付费套餐或 Zero Trust organization。本教程不涉及加入企业组织；如果将来使用 Zero Trust，按组织策略单独做 enrollment，而不是复用 DNS Token。[usque 注册说明](https://github.com/Diniboy1123/usque/tree/v4.2.1#registration)

```bash
modprobe tun
test -c /dev/net/tun
if [ ! -s /etc/usque/config.json ]; then
  (cd /etc/usque && /usr/local/bin/usque -c /etc/usque/config.json register)
fi
test -s /etc/usque/config.json
chown root:root /etc/usque/config.json
chmod 0600 /etc/usque/config.json
jq -e 'type == "object"' /etc/usque/config.json >/dev/null
```

已有配置不要再次 register；复用原设备注册结果。注册可能受服务端限制，失败时按错误和官方说明处理，不持续循环注册。不要在项目 secrets.json 中复制 WARP 内容。TUN 内部地址、MASQUE endpoint 来自注册结果，不手工填写猜测的 Cloudflare IP。

### 8.2 应用前前台调试 TUN

先记录路由和接口：

```bash
ip -4 route show table all default > /root/dmit-install-records/default-v4-before.txt
ip -6 route show table all default > /root/dmit-install-records/default-v6-before.txt
ip -br address
/usr/local/bin/usque -c /etc/usque/config.json nativetun
```

这条命令在前台持续运行。在第二个 SSH 会话观察新 TUN 的真实名称，不假定总是 tun0，并检查地址、链路和连接日志。`nativetun` 默认可设置接口地址，但不自动设置路由；`--no-iproute2` 连地址/UP 都不设置，本教程不需要它。[固定版本 nativetun 实现](https://github.com/Diniboy1123/usque/blob/v4.2.1/cmd/nativetun.go)

```bash
ip tuntap show
ip -br address
ip -4 route show default
ip -6 route show default
read -r -p '刚创建的 TUN 名称: ' WARP_IFACE
curl --fail --max-time 20 --interface "$WARP_IFACE" https://www.cloudflare.com/cdn-cgi/trace
```

若成功，查看 `warp=on` 或相应 WARP 状态、出口 IP、colo。若 `--interface` 在本机无路由模式下失败，不能据此认定注册无效；接口绑定仍受系统路由选择影响。先确认隧道握手与地址，再按下一节用用户态代理排除路由因素。保留默认路由；不添加 on-connect 路由脚本、不修改 `/etc/resolv.conf`，也不启用官方 WARP 客户端来替换系统出口。

### 8.3 可选：只在回环地址测试用户态 WARP 出口

在前台 nativetun 窗口按 Ctrl+C，确认它结束；若是上线后调试，先记下服务状态并临时停止 `usque-warp`，结束测试后恢复。避免相同设备凭据同时运行多个模式。然后前台运行：

```bash
/usr/local/bin/usque -c /etc/usque/config.json socks -b 127.0.0.1 -p 1080
```

另一会话执行：

```bash
curl --fail --max-time 20 --noproxy '' --socks5-hostname 127.0.0.1:1080 \
  https://www.cloudflare.com/cdn-cgi/trace
ss -ltnp 'sport = :1080'
```

仅这个 curl 走 WARP，不添加系统路由或 Xray 出站。测试后 Ctrl+C 停止 SOCKS；正式配置仍由 nodectl 启动 `nativetun`。必须显式指定 `-b 127.0.0.1`，因为上游 socks 默认监听所有地址且无认证。[SOCKS 模式说明](https://github.com/Diniboy1123/usque/tree/v4.2.1#socks5-proxy-mode-easy-cross-platform)

## 9. 候选检查与首次应用

前台 usque 调试进程应已退出。两套证书已安装，临时 HTTP 服务仍可运行。不要手写或直接复制 plan.md 的最终 Nginx/Xray 配置覆盖线上入口：

```bash
nodectl validate
release_id=$(nodectl render)
printf '候选版本: %s\n' "$release_id"
nodectl diff "$release_id"
jq '.dns, .certificates, .listeners, .reality_target' \
  "/var/lib/dmit-node/releases/$release_id/operations.json"
sha256sum -c /root/dmit-install-records/binaries.sha256
XRAY_SHA256=$(sha256sum /usr/local/bin/xray | cut -d ' ' -f 1)
nodectl check "$release_id" \
  --client /usr/local/bin/xray --client-version 26.10.10 \
  --client-sha256 "$XRAY_SHA256" \
  --probe-url https://www.cloudflare.com/cdn-cgi/trace
```

摘要必须来自第 4 节已验证的安装记录；不能用一个来路未知程序现场计算的摘要证明其可信。check 是预检查，尚未进行三类线上握手。证书、程序或 WARP 文件改变后要重新 check。

软件包通常已有 `/etc/nginx/nginx.conf` 和 systemd 服务，属于非本项目入口。第一次部署需要显式备份接管：

```bash
nodectl takeover "$release_id"
cat "/var/lib/dmit-node/takeover/$release_id/diff.txt"
```

若提示记录已存在，保留已有备份并审阅，不要删除它来绕过源内容变化检查。接管仅授权当前候选和当前入口内容，不会立即覆盖。

结束 bootstrap 进程，确认它的独立 PID 退出及端口释放，再应用：

```bash
nginx -s quit -c /etc/nginx/dmit-bootstrap.conf
ss -ltnp 'sport = :80'
nodectl apply "$release_id"
```

若 bootstrap 尚在优雅退出，等其退出后再 apply。apply 的强制健康检查包含服务、TCP/UDP、UDS、参考客户端的 XHTTP/WS/REALITY 三类握手与默认路由保持。缺能力或有失败会触发恢复，不更新成功指针。首次失败后的恢复不会重新启动手工 bootstrap 进程；排查/重试签发前可再次用其独立配置启动。

REALITY 到本地 Nginx target 保留方案中的实验性质。不能因为 TLS 网站正常就当 REALITY 已通过，也不能把握手失败改为跳过检查。

## 10. 外部验收与客户端

### 10.1 主机内检查

```bash
readlink /var/lib/dmit-node/current
systemctl status xray nginx usque-warp --no-pager
ss -lntup
stat -c '%A %U:%G %n' /tmp/vless-xhttp.socket /tmp/vless-ws.socket
ip tuntap show
ip -br address
ip -4 route show default
ip -6 route show default
```

两个 socket 应为 `srw-rw---- xray:www-data`；默认路由仍指向 DMIT 原出口。usque 服务 active 不等于 WARP 出口已验证，需结合第 8 节的握手、TUN 与实际 trace 检查。

### 10.2 另一网络检查网站、证书和 H3

以下命令在外部客户端执行，先将 `$DMIT_IPV4` 设置成自己的实际地址；IPv6 测试只在启用 IPv6 时进行：

```bash
curl --fail --head https://speedtest.example.com/
curl --fail --head https://files.example.com/
curl --fail --head --resolve "speedtest.example.com:443:$DMIT_IPV4" \
  https://speedtest.example.com/
openssl s_client -connect "$DMIT_IPV4:443" \
  -servername speedtest.example.com \
  -verify_hostname speedtest.example.com -verify_return_error </dev/null
curl --fail --head "https://$DMIT_IPV4/"
curl -V
```

域名返回域名证书，IP 直接访问返回 IP SAN 证书；HTTPS 响应应有 `Alt-Svc: h3=":443"; ma=86400`。这只是 H3 广告，不能证明 UDP 可达。若 curl 的 features 支持 HTTP3，再执行 `curl --http3-only --head https://speedtest.example.com/`；否则用支持 H3 的客户端测试，不把普通 H2 请求当 H3 结果。不要添加 `-k` 来掩盖证书错误。

验证 HTTP-01 的长期入口仍然可达：

```bash
curl --fail http://speedtest.example.com/.well-known/acme-challenge/probe
```

同时用裸 IP 请求该路径，确保后续 IP 证书续期不依赖 DNS 域名或 HTTPS 重定向。

### 10.3 导出与使用客户端配置

```bash
nodectl export-clients --output /root/exports
chmod 0700 /root/exports
chmod 0600 /root/exports/profiles.json
```

通过已信任的 SSH/SFTP 传输到客户端，客户端副本同样按凭据保护，不用在线订阅转换网站接收这些文件。`profiles.json` 是原生 Xray outbound 对象和分配元数据，不是任意客户端都能直接导入的完整配置。

| Profile | 地址/端口 | SNI | 传输 | ALPN |
| --- | --- | --- | --- | --- |
| XHTTP TLS | `speedtest.example.com:443` | `speedtest.example.com` | XHTTP stream-one，生成路径 | H2 |
| WS TLS | 同上 | 同上 | WS，生成的精确路径 | HTTP/1.1 |
| REALITY | `speedtest.example.com:8443` | `files.example.com` | XHTTP stream-one，第三条路径 | 由参考客户端配置处理 |

REALITY address 使用主域是当前生成器的行为；它与 reality 域都应解析到同一 DMIT，SNI 仍是独立的 `files`。公钥/Short ID/UUID 从导出读取，不复制服务端私钥。80/15/5 是客户端分配权重，服务端不随机分流；四种 XHTTP 指纹内部比例为 5/2/3/1。

## 11. 无人值守续期与监控

### 11.1 首次成功后配置两套证书 reload hook

现在 current 已存在，两套运行证书齐备。重新执行 install-cert，记录目标文件与 hook；不会重新签发：

```bash
/root/.acme.sh/acme.sh --install-cert --ecc -d "$DMIT_DOMAIN" \
  --key-file /etc/ssl/dmit/domain/privkey.pem \
  --fullchain-file /etc/ssl/dmit/domain/fullchain.pem \
  --reloadcmd '/usr/local/bin/nodectl renew-hook'
/root/.acme.sh/acme.sh --install-cert --ecc -d "$DMIT_IPV4" \
  --key-file /etc/ssl/dmit/ip/privkey.pem \
  --fullchain-file /etc/ssl/dmit/ip/fullchain.pem \
  --reloadcmd '/usr/local/bin/nodectl renew-hook'
/root/.acme.sh/acme.sh --install-cronjob
crontab -l
nodectl renew-hook
```

保持 root 只有一条有效的 acme.sh 调度项，并确保每天至少运行一次；本次核对的安装脚本生成每 6 小时检查的 cron 表达式，以主机实际 `crontab -l` 为准。acme.sh 根据每张证书的记录决定是否续期，不能把 IP 证书设为每月才检查。`renew-hook` 核对两套证书、执行 Nginx 配置检查并 reload，不重启 Xray/usque、不重新注册 WARP。安装证书时若 hook 失败，先检查实际部署文件是否已更新，再重新执行 hook；不要盲目 `--force` 重新签发。

首次使用的是 webroot，因此续期时 Nginx 继续占用 80 没有冲突。如果以前按旧教程使用 standalone 申请，先在维护窗口改为 webroot 验证并确认 acme.sh 保存的新验证方式，不能仅改 reloadcmd 就认为端口冲突已解决。

### 11.2 检查续期记录与到期余量

```bash
/root/.acme.sh/acme.sh --list
/root/.acme.sh/acme.sh --cron --home /root/.acme.sh
for cert in /etc/ssl/dmit/domain/fullchain.pem /etc/ssl/dmit/ip/fullchain.pem; do
  openssl x509 -in "$cert" -noout -dates
  openssl x509 -in "$cert" -noout -checkend 172800
done
systemctl status cron nginx --no-pager
journalctl -u nginx --since '1 day ago' --no-pager
```

不加 `--force` 的 cron 检查可能显示“尚未到期，无须更新”，这不等于已做过一次 CA 重签。至少在首个 IP 证书更新周期后，核对运行证书 notAfter/serial 已变化、外部 TLS 检查正常、hook 成功。使用现有监控记录每日 cron 结果、48 小时到期余量、HTTP-01 可达性、服务失败和备份；`nodectl` 的上线门槛是至少剩余 24 小时，不应等到这个门槛才告警。

DNS Token 到期/被撤销、出口 IP 变更、CAA 改动、80 端口关闭、主机时钟错误都会影响续期。不要在控制台更换 Token 后忘记 acme.sh 保存的旧值。

### 11.3 轮换 DNS Token

先创建相同最小权限的新 Token，保留旧 Token 暂时有效。在服务器重新执行第 3 节隐藏输入及 API 验证。新环境变量不会因一次“尚未到期、跳过”的 cron 检查就自动写回 acme.sh。可以等正常到期时在带新 CF_* 环境的会话中完成定向续期；需要立即确认并保存新凭据时，在确认 CA 频率限制后，只对域名证书安排一次有意的强制续期：

```bash
/root/.acme.sh/acme.sh --renew --ecc -d "$DMIT_DOMAIN" --force
nodectl renew-hook
unset CF_Token CF_Zone_ID CF_Account_ID
```

确认 TXT 创建/清理、证书安装及 hook 均成功后，再撤销旧 Token。失败时先定位原因，不循环强制申请。IP 证书使用 HTTP-01，无须为 DNS Token 轮换重签它。

## 12. 变更、回滚与恢复

| 要改的内容 | 正确操作 |
| --- | --- |
| 入口路径、客户端权重、普通运行参数 | 只编辑 node.toml，再 validate/render/diff/check/apply |
| 增加 alias 或更换域名 | 先准备 DNS 和覆盖新 SAN 的证书，再渲染/检查/应用；旧证书和旧 DNS 保留到回滚窗口结束 |
| 新增 IPv6 | 先验证网络和防火墙，再加 AAAA，重签 IP SAN，再改 node.toml 并应用 |
| 更换 IP | 新 IP 先可达；修改 DNS、IP 证书与 node.toml，确认旧版本不再能通过原 IP SAN 检查时的恢复方案 |
| 改端口 | 先开放新 TCP/所需 UDP，渲染后确认 Alt-Svc、target、客户端联动；确认后再关闭旧端口 |
| 轮换一个凭据 | `nodectl init --rotate ws_uuid` 等显式命令，再渲染/应用并重导出 |
| 软件升级 | 独立维护窗口更新固定版本和受信任摘要，再 check；普通 apply 不自动下载升级 |
| WARP 注册/设备凭据更新 | 停止独立 usque，备份凭据后按上游操作，保护权限，再重新 check/apply |

失败时先读明确报错，不改快照、不手工重指 current：

```bash
nodectl rollback
# 若提示未完成事务/恢复失败，则改用：
nodectl recover
```

两条命令是按现场选择，不是无条件连着执行。rollback 应用上一成功版本，也要求旧版所需证书、程序和真实握手能通过。recover 使用 transaction.json 及 backups 恢复中断前的入口、单元、服务状态。恢复仍失败会保留日志并阻止写入；查看 `/var/lib/dmit-node/recovery-required.txt`，先恢复缺失的外部证书、程序、网络或 WARP 文件，再 recover。不要删除事务日志“解锁”。

私密备份至少包含 `/etc/dmit-node`、`/etc/usque/config.json`、两套证书目录、`/root/.acme.sh`、当前/上一快照、事务备份、工具二进制及版本/摘要记录。备份加密、访问受控并演练恢复，不能上传到 Git。current/previous 以外的旧成功快照会按保留策略清理，接管和故障备份不自动清空。

## 13. 故障排查

| 现象 | 优先核查 | 下一步 |
| --- | --- | --- |
| DNS 返回 Cloudflare IP 或其他机器 | 灰云、重复 A/AAAA、CNAME/Worker、缓存 | 对比权威和公共解析；仅修正这两个子域 |
| DNS-01 无法写 TXT | Token DNS Edit/Zone Read、zone 限制、ID、Token TTL/IP 过滤 | 验证 API 与 acme.sh 保存凭据，检查 CAA；不暴露 Token 日志 |
| 域名证书只有一个 SAN | 首次签发参数是否完整 | 以主域为首个 -d，包含 alias/reality，重装证书 |
| IP HTTP-01 失败 | 公网 80、防火墙、IPv6 可达性、bootstrap/webroot | 从外部裸 IP 请求 probe，检查是否被重定向/错误服务接收 |
| Nginx 报未知 http2/quic | 版本/模块不足 | 检查 nginx -V，安装满足 H2/H3 的构建 |
| nginx -t 报证书不存在 | 两套证书是否均已安装 | 先完成第 6/7 节，不提前启动最终模板 |
| cert/private key mismatch | fullchain 与 key 是否来自同一次安装 | 恢复匹配文件，再 renew-hook/check |
| check 拒绝证书权限 | root 所有、私钥 0600、路径和目录 | 修复文件，不把私钥开放给所有用户 |
| UDS permission denied | xray 主组、Nginx 用户、父目录和 0660 | 检查 systemd 生效单元；不改成 0666 |
| apply 报 unmanaged entrypoint | 默认包配置或旧业务入口 | 审阅 takeover 备份与差异，再显式接管 |
| TLS 成功但 WS 失败 | WS 精确路径、UUID、HTTP/1.1 ALPN | 使用成功快照导出，排除旧客户端配置 |
| REALITY 握手失败 | 公钥/Short ID、SNI、第三条路径、端口、本地 target 兼容性 | 保留实验限制，读 Xray 日志，不能跳过健康门槛 |
| H3 无法连接但 H2 正常 | UDP 443 和客户端 HTTP3 能力 | 用 --http3-only/真实 H3 客户端外测；Alt-Svc 不是连通证据 |
| WARP TUN 存在但无流量 | MASQUE 会话、出口 UDP、地址、MTU、路由选择 | 前台调试，回环 SOCKS 分离验证；保持默认路由 |
| usque active 但反复断开 | endpoint 可达性、服务器限制、注册结果 | 检查独立服务日志，不循环 register，不用 --insecure |
| check 后 apply 摘要不符 | 期间换过二进制、证书或 WARP 文件 | 核对变更来源后重新 check |
| 自动续期后仍是旧证书 | 安装目标、reload hook、cron、证书标识 | 检查运行文件和外部 serial，重跑 renew-hook |
| recover 仍失败 | 事务备份、旧版 SAN/二进制/网络不再可用 | 按 recovery-required.txt 修复外部条件，保留现场 |

本机受控诊断命令：

```bash
journalctl -u xray -u nginx -u usque-warp -n 100 --no-pager
systemctl cat xray nginx usque-warp
namei -l /etc/ssl/dmit/domain/privkey.pem
stat -c '%a %U:%G %n' /etc/dmit-node /etc/dmit-node/secrets.json /etc/usque/config.json
```

nodectl 为防泄露会隐藏外部工具的原始输出。必要时在主机上直接运行其提示的 `xray run -test -config <候选>`、`nginx -t -c <候选>` 或 `systemd-analyze verify <候选单元>` 定位；候选和日志可能含凭据，不把完整输出粘贴到公共 issue。

## 14. 部署记录与最终验收

在 `/root/dmit-install-records` 记录这次实际结果；仓库里只保留下面的字段定义，不填真实秘密。

可复制 [部署记录模板](resources/deployment-record.template.md)，填写 DNS、证书、WARP、上线和恢复证据。模板有“待验收”状态，避免把尚未执行的步骤写成成功。以下命令在目标文件不存在时才创建副本：

```bash
deploy_record='/root/dmit-install-records/deployment-record.md'
if [ ! -e "$deploy_record" ]; then
  install -m 0600 /opt/dmit-node-config/docs/resources/deployment-record.template.md "$deploy_record"
fi
```

| 记录项 | 应记录的内容 |
| --- | --- |
| 主机 | 部署日期/时区、系统/架构、DMIT 实际 IP、SSH 端口 |
| DNS | 三个 FQDN、A/AAAA、灰云、权威查询结果、修改时间 |
| DNS Token | 名称、zone 范围、权限、到期/IP 过滤；不记 Token 真值 |
| 证书 | 两套 SAN、算法、issuer、notAfter、运行路径、标识首个 -d、续期方式 |
| 软件 | 源码 commit、构建工具链、包版本、归档/二进制 SHA256、旧版恢复位置 |
| WARP | usque 版本、配置路径、TUN 名、默认路由对比、受控 trace 结果 |
| 项目 | nodectl 版本、源代码补丁、候选 ID、check/apply 时间及结果、current/previous |
| 续期/恢复 | cron、reload hook、首次实际续期结果、告警、备份位置与恢复演练 |

交付前逐项检查：

- [ ] 两个中性子域的真实解析正确，未变更根域/邮件/其他业务。
- [ ] Token 仅限 example.com、凭据和导出未入 Git，文件权限正确。
- [ ] 域名证书精确覆盖三名且为 P-384；IP 证书覆盖全部启用地址，信任链和有效期合格。
- [ ] bootstrap 已退出，最终 HTTP-01 webroot 可从公网裸 IP 访问。
- [ ] check 通过；apply 后三类客户端真实握手通过，current 指向本次成功版本。
- [ ] 外部网站、域名/IP 证书、启用的 IPv6、UDP/H3 分别验收。
- [ ] WARP 会话/TUN/受控出口验证完成，DMIT 默认路由未被接管。
- [ ] 客户端使用成功版本导出，未包含服务端私钥或 WARP 凭据。
- [ ] cron 每天运行、两套 install-cert hook 均配置；首个 IP 证书更新周期已追踪确认。
- [ ] 证书到期监控、私密备份、旧工具与恢复路径已记录。

这些是部署时需要取得的证据，本教程的存在不代表这台服务器已完成上述操作。当前项目已具备生成与强制检查流程，真实 DNS 修改、证书签发、WARP 注册和公网验收以操作者的部署记录为准。
