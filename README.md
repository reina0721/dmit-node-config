# dmit-node-config

一条命令，在 Debian / Ubuntu 上交互部署 Nginx、Xray Core 和可选 WARP。已有部署也使用同一入口更新，优先保留配置和密钥。服务原生运行，由 systemd 管理。

当前版本：[v0.6.1](https://github.com/reina0721/dmit-node-config/releases/tag/v0.6.1)。

v0.6.1 修复仓库所有者更名（`i0721` → `reina0721`）后安装器解析最新版本失败、一键安装直接退出的问题；签名验证仍锚定精确标签，更名前的 `i0721` 签名者只对 v0.6.0 及更早归档有效。功能与 v0.6.0 相同。

v0.6.0 新增 DMIT 单机 Web 管理后台：复用 console-web 设计系统与插件架构，静态前端 + Rust API + 独立 Nginx HTTPS，默认保护现有 DMIT 配置。详见 [后台架构与安装](docs/web-admin-design.md)、[实施验收记录](docs/defect/13-web-admin-acceptance.md)。

## Linux 一键安装与部署

**推荐方式：在 VPS 的 SSH 终端复制执行。** 支持 Debian / Ubuntu + systemd，提供 amd64、arm64 安装包。

```bash
curl -fL --proto '=https' --proto-redir '=https' \
  --connect-timeout 20 --max-time 1800 \
  -o dmitserverconfig-setup.sh \
  https://raw.githubusercontent.com/reina0721/dmit-node-config/main/install.sh &&
bash dmitserverconfig-setup.sh
```

运行后按终端提示填写域名、IP、端口和可选 WARP，选择自动或手动 DNS / 证书，审阅变更并输入 `yes`。脚本会下载并验签正式版，完成部署、服务握手验证及客户端导出。

**更新也运行上面同一条命令。** 安装完成后使用 `nodectl` 管理；客户端文件的私密保存位置会在终端显示。[查看向导填写说明 →](docs/getting-started.md)

### 开始前准备

- 可公网访问的 VPS、域名，以及 root 或可 sudo 的账号；SSH 终端需有 bash、curl。
- 使用 Cloudflare 自动 DNS 时，准备目标域名区域的 **DNS Edit + Zone Read** API Token，终端无回显输入；也可选择手动 DNS。
- 默认需开放 TCP 80、TCP/UDP 443、TCP 8443，并保留自己的 SSH 端口。目标机无需 Rust、Python 或 Docker。

默认主名称为 `speedtest`、REALITY 名称为 `files`，允许修改前缀、域名、端口、双栈及 WARP。新配置启用独立 VLESS Encryption/Vision 参数，提供 Xray 与 Mihomo 节点；已有有效身份、密钥、路径、证书和权重优先保留。公开首页使用中性 Welcome 内容，自定义网站不自动覆盖。

0.5 的向导可另外启用独立 CN WARP，以及 Landing Page、官方 LibreSpeed 测速和 OpenList 文件站。CN 出口使用额外实例，其余流量保持原生直连；网站服务原生运行，后端仅监听 loopback。旧配置缺省不启用这两项功能，已有配置和文件优先保留。[使用与恢复说明 →](docs/cn-warp-web-services.md)

更新时重新执行同一命令。向导显示本次变更，只有确认后才操作 DNS、证书和服务；必要的新 CA/WARP 条款需要明确同意。取消或失败会按保存的事实恢复；系统包和已签发 CA 资源有明确恢复边界。保留手动 DNS、证书与高级运维路径。

## 系统与验收

发行资产为 Linux amd64、arm64，使用 Debian 12 glibc 基线原生构建。手动系统矩阵包含 amd64 Debian 12/13、Ubuntu 24.04/26.04，以及 arm64 Debian 12；本次实际执行、取消及未覆盖的范围见 [交付验收](docs/defect/08-one-command-delivery.md)。

版本锁定、TLS/H2/H3、双域名与 IP 证书、独立 WARP 路由和原事务校验继续保留。WARP 不接管默认出口，用户客户端无需安装 WARP。修改客户端兼容字段时必须更新客户端。0.5 的本地真实双 WARP、网站与协议回归及未覆盖范围见 [本次验收记录](docs/defect/12-cn-warp-web-services-acceptance.md)；发行不表示生产 VPS 已升级。

## 文档

| 任务 | 入口 |
| --- | --- |
| 首次部署、向导输入与完成标准 | [首次部署](docs/getting-started.md) |
| 固定版本、工具安装、离线资产和验签 | [安装与发行](docs/installation.md) |
| DNS、证书、接管与自动恢复细节 | [交互部署](docs/automated-deployment.md) |
| 客户端、续期、备份与恢复 | [日常运维](docs/operations.md) |
| 节点页面、订阅与 Token | [安全节点分发](docs/node-access.md) |
| 手动分层操作与字段 | [高级部署参考](docs/deployment.md)、[配置说明](docs/configuration.md) |
| 图解与故障定位 | [脱敏 DNS 图解](docs/cloudflare-screenshots.md)、[排错](docs/troubleshooting.md) |
| 实现与贡献 | [架构](docs/architecture.md)、[安全](docs/security.md)、[贡献](CONTRIBUTING.md) |
| 0.5 可选功能（发行状态见顶部） | [独立 CN WARP 与网站服务](docs/cn-warp-web-services.md)、[阶段验收](docs/defect/12-cn-warp-web-services-acceptance.md) |

公开教程使用 example.com 和保留地址；脱敏图片不是生产验收证据。凭据与原始环境记录不随仓库发布。

## 开发

全量 GitHub 测试按需手动触发，正式发行仅打包、检查归档并签名，不重复系统矩阵。固定 Rust 1.99.1、Cargo.lock，执行 `bash scripts/check-all.sh`；服务事务变更还需运行隔离集成与恢复测试。项目自身开发、构建、测试、发布和运行不依赖 Python。依赖及许可见 [THIRD_PARTY](THIRD_PARTY.md)，问题与漏洞见 [SECURITY](SECURITY.md)。
