# DMIT 单机后台：审计、需求与实施契约

审计日期：2026-10-19。权威：当前仓库 Config/schema、renderer、host/deploy 事务和 DMIT 默认参数。前端来源：rin721/console-web，固定提交 `60189fd7ccbc1c034034ed0ca5ae30d61a448026`。

## 现有能力与缺口

nodectl 是单 Rust binary；Config 严格拒绝未知字段，Secrets 独立保存。Store 有 owner-only 文件、排他锁、内容寻址发布、完整性验证和脱敏 diff。host 提供真实工具 preflight、固定 reference client、握手检查、事务 journal、失败恢复；deploy 在其外协调 DNS、ACME、依赖安装和配置备份。share 是独立订阅凭据与私有 socket 服务；不能用订阅 Token 认证后台。diagnostics 现有 CLI 输出可复用，不能把 stdout 当进程内数据协议。

缺口：管理身份和会话、配置字段权限、批准和并发绑定、Web API、可查询后台任务、审计、静态后台与独立 HTTPS 入口。不能通过修改原始模板接入，否则历史 release verify 和回滚会受影响。

console-web 是 React 19 / Next 16 / Tailwind 4 / HeroUI 3 monorepo；design-system 提供语义 token，ui-adapter 是 vendor 边界，surface-foundation 提供 Page/Section/Settings/Operation pattern，plugin-framework 提供静态 catalog/registry/route target。原演示、identity 多用户模型和本地示例数据不能进入 DMIT 业务。保留上述基础包的固定来源副本，以独立静态 Next Host 和 DMIT 插件装配，不运行生产 Node。Web Host 负责网络、浏览器、会话与路由，插件只表达业务。

## 配置权限

* 环境资产白名单：`node.domain`、`node.reality_domain`、`node.aliases`、`node.ipv4`、`node.ipv6`。名称以完整 FQDN 编辑，因此兼容自定义前缀。Cloudflare zone/token 为单独 owner-only 凭据，不进入 Config 或回读 API。
* 平台保护：其余全部字段，包括 schema、ports、transport、tls、website、runtime、clients、warp、vless、distribution、cn_warp、web_services。缺省字段保持缺省。新 schema 字段自动受保护。
* 高级模式：重新验证管理员 Token，短时单次 unlock，绑定会话；必须预览原值、新值、字段差异、render diff 和风险，apply 再输入计划 ID 确认。审批绑定原始配置字节摘要、Secrets 摘要、current 指针、候选内容、会话与有效期；过期、重启、并发 CLI 修改都要求重新预览。
* 不变量：继续调用完整 Config::validate；始终禁止 WARP 默认路由接管；runtime 可执行路径/用户、UDS、证书及数据路径不能经 Web 改写（防止 root 执行/任意文件访问）；保留 TLS1.3、H2/H3 和两套证书；端口不得碰 SSH/管理端口。高级模式也不能豁免。

## API 与职责

API `/admin/api/*`，同源 HTTPS，Rust 仅 loopback。JSON 所有写请求要求 Origin 精确匹配及 session CSRF header；login 同样限制 Origin。Token 256 位随机、只存 SHA256，CLI 首次生成/重置显示一次；独立 cookie HttpOnly/Secure/SameSite=Strict，绝对和空闲超时，重置后所有会话失效。全局登录限流限制内存和伪造 IP 绕过；不允许 query token，不记录请求体。

GET：session、overview、config、nodes、network、dns、services、operations、jobs。POST：login/logout、unlock、config/preview、config/check、config/apply、credentials、operations。长操作返回 job ID，GET 查询阶段/完成/失败；错误保留可操作 code 和安全说明，不返回外部 stderr。只允许固定命令和服务白名单，不提供终端、文件浏览、任意 URL 或 shell。

补充契约：`POST config/deploy-preview {plan, options}` 通过原 CLI 生成完整部署计划、验证其配置和摘要，审批包含 DNS、证书与依赖变更；实际 host check 在依赖准备完成后、apply 前执行。`POST backups/preview {backup, token}` 重新认证并验证快照摘要，生成包含节点身份恢复的高级计划，继续复用 check/apply；快照不会还原管理员或订阅 Token。`GET clients/xray|mihomo` 仅按需导出当前成功发布的客户端。精确 DTO 由 `src/admin.rs` 与 `webui/surfaces/src/node-model.ts` 维护。

操作固定为 doctor、DNS/网络诊断、证书 hook、快照、回滚、恢复、订阅轮换/撤销、日志、托管服务重载/重启、签名 CLI 升级与受控 API 重启。任务持久记录只保留摘要；含新订阅 Token 的结果只允许显式消费一次。

配置流：锁定输入 → validate → 隔离配置 render → 脱敏 diff → 用户审阅 → 真实 host::check → 第二次确认 → 写持久恢复日志与原始输入快照 → host::apply → 原子提交 node.toml。失败保留原始输入并调用原事务恢复；崩溃恢复检查 current 和原事务后决定恢复输入。无检查凭据不得 apply。域名/IP 变更涉及 DNS/SAN 时必须先完成依赖，检查失败不降级绕过。DNS 协调、部署升级继续使用现有 deploy/upgrade，不新造事务引擎。

## 页面信息架构与交互

1. 总览：实测 CPU interval、内存/磁盘、网卡计数和速率、版本/事务/服务异常；不可用显示原因，绝不补零。
2. 节点与订阅：当前成功 release 的三协议和客户端导出，订阅状态、独立轮换/撤销与影响提示。
3. 配置中心：环境表单、保护基线、重新认证解锁、字段/render diff、检查结果、明确二次确认；编辑后清除旧计划。
4. 网络：原生出口配置、双 usque 状态、接口/路由、CN 策略、固定目标连通性诊断。
5. DNS 与证书：预期 DNS 记录和验证、write-only Cloudflare 凭据、两套证书 SAN/到期与真实续期 hook。
6. 服务：固定服务状态，check/restart/reload 允许列表，禁用不支持操作并说明。
7. 运维：部署/升级进度、doctor、备份、回滚/恢复、固定来源安全日志、操作审计。无部署显示首次使用指引。

所有页面有 loading/error/empty/pending 和刷新路径；敏感导出明确按需，不放本地 storage；移动端导航可用。前端无权限 authority；Rust 才能执行白名单/不变量/审批。

## 顺序与验收

- [x] 双项目审计与权限/API/IA 设计。
- [x] Rust 管理模块：身份、会话、真实读 API、单任务操作与审计。
- [x] 配置审批：默认保护、约束、check/apply、输入恢复日志。
- [x] console-web 基础包、静态 Host 与七业务插件。
- [x] CLI 初始化/重置、独立 systemd/Nginx 安装与保留已有部署。
- [x] 单元/HTTP 安全测试、前端 typecheck/build、浏览器联调与视觉、Linux 集成/回滚、原 CLI 全回归。

测试必须区分本地隔离环境证据和未执行生产验收。禁止读取或更改 `.local-deploy` 中的生产凭据来完成测试；测试临时配置和 isolated container，不修改生产 VPS。

## 构建与安装

开发环境需要 Node 与 pnpm，VPS 生产环境只需原有 Rust CLI、Nginx/systemd。构建静态目录：

```bash
cd webui
pnpm install --frozen-lockfile
pnpm build
pnpm performance:check
cd ..
nodectl admin install --assets /absolute/project/webui/apps/web/dist
nodectl admin install --assets /absolute/project/webui/apps/web/dist --execute
```

安装需要已有有效节点配置和域名证书；首次节点部署继续运行原 `nodectl deploy` 向导，不会套用示例配置。默认管理地址 `https://节点域名:9443/admin/`；`--port` 可显式选择独立端口，不能占用节点或 API 监听端口。按原 VPS 端口策略允许此端口后访问。

CI 在构建阶段生成静态文件、版本摘要清单和前端第三方声明，随原 Sigstore/OIDC 签名归档分发。版本发布后，`install.sh --with-admin` 在原安装/向导成功后安装后台。已有节点可用 `install.sh --version v0.6.1 --install-only --execute --with-admin`。v0.6.0 与 v0.6.1 已正式发行，这些命令可直接使用。

已验证签名的本地发行归档也可执行 `nodectl admin install --archive /absolute/nodectl-v0.6.0-ARCH-unknown-linux-gnu.tar.gz --execute`。Rust 只把经过摘要、路径与大小检查的选定静态成员复制进新版本目录，不以 root 展开任意归档路径；UI 与当前 CLI 的版本不一致会拒绝。手动 `--archive` 不替代官方签名验证。

`nodectl admin init` 仅首次生成管理员 Token，存在时保留。`nodectl admin reset-token` 随时撤销全部会话并显示新 Token，包括节点事务锁定时；它与 `nodectl share` 凭据完全独立。后台管理员 Token 仅摘要保存，遗失后无法读取原值。

后台 CLI 升级使用原签名安装器，随后在运维中心受控重启 API。静态 UI 更新使用同版本已验证归档再次安装；失败时恢复独立管理服务、静态指针和启用状态。节点配置和原 Nginx 实例不参与后台安装。域名变更必须保留当前管理域名为别名，以免失去证书 SAN；要切换管理域名，可在新的有效节点证书就绪后重新执行 admin install。

## 证据维护

console-web 的 000–111 变更是固定提交的历史记录；被移除演示产品的测试源码以 `.txt` 归档。`webui/tooling/upstream-evidence.json` 固定其摘要，文档审计先验证不可变性，再交还历史链接的上游语境。112 及后续记录、当前主题与 DMIT 文档完整参与链接检查。旧演示测试不会被当成当前 DMIT 浏览器验收。

Linux/Docker 上的完整后台验收入口为 `bash scripts/test-admin.sh`。它仅创建带隔离标签的临时 systemd 容器，构建静态前端、准备真实 Nginx/Xray 与测试 CA、验证独立安装和失败恢复，随后执行 `pnpm check` 的全部门禁；退出时删除容器。需要 pnpm/Node 和已安装的 Playwright Chromium/系统依赖。可通过 `NODECTL_ADMIN_TEST_PORT` 选择空闲测试端口；不得传生产 URL 或生产容器。原 CLI/自动部署全流程入口继续是 `scripts/test-integration.sh`。
