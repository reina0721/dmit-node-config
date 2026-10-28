# 安装与正式发行

完整部署使用 [README 的一键入口](../README.md#linux-一键安装与部署)。本页说明版本选择、工具安装及发行验证，供高级运维和自动化使用。

## 版本与信任

无操作参数时，脚本解析一次最新稳定版并冻结本次版本，自动准备固定摘要的官方 cosign 3.1.3。验证 SHA256SUMS 的 Sigstore bundle，绑定 GitHub OIDC issuer 和本仓库 release.yml 的精确标签身份，再检查归档摘要、ELF 架构、程序版本及旧配置兼容性。

资产缺失、版本过旧或验证失败即停止，不回退到未签名资产、源码编译或手动上传。不提供跳过验签参数。新程序原子安装，原程序按摘要保存在 `/usr/local/lib/nodectl/versions/`；未恢复事务会阻止替换。

在已下载的同一脚本后添加 `--version v0.6.1` 可固定版本；`--token-file /root/cf-token` 把受保护凭据文件交给 Rust 向导，不把 Token 真值放入 argv。

## 只安装或升级 nodectl

此模式不调用部署、不操作服务，适合已有自动化链路：

```sh
sh dmitserverconfig-setup.sh --install-only --version v0.6.1 --dry-run
sudo sh dmitserverconfig-setup.sh --install-only --version v0.6.1 --execute
```

原有明确指定 `--execute/--dry-run` 的命令保留工具安装语义。`nodectl upgrade` 也调用工具安装模式，避免递归进入向导。固定版本的 dry-run 不下载或创建文件；未固定版本时只会查询最新版本元数据。

完整向导需要终端。无终端时不会隐式执行，使用工具安装模式及现有 `nodectl deploy --non-interactive` 的预览和 `--approve` 接口。

## 网络与离线资产

默认直接使用 GitHub HTTPS，支持标准 `http_proxy/https_proxy/ALL_PROXY/NO_PROXY` 及自定义 CA 环境变量；不会自动选用第三方镜像，也不输出含认证信息的代理值。

`--bundle-dir /root/offline --version v0.6.1` 从本地目录读取对应架构归档、SHA256SUMS 和 Sigstore bundle；仍然验签。需在 PATH 或该目录提供固定摘要的官方 `cosign-linux-amd64` / `cosign-linux-arm64`。该选项仅让程序资产离线；系统软件、DNS、CA 和 WARP 的网络需求仍需另行满足，不能宣称整套部署离线。

## 发布与源码

两个架构均以 Debian 12 glibc 基线原生构建。归档包括程序、许可、依赖许可、CycloneDX SBOM 和构建信息；Release 包含清单、Sigstore bundle、安装器及发行说明。可额外使用 `gh attestation verify <archive> --repo reina0721/dmit-node-config` 检查构建证明。

正式版本来自 [GitHub Releases](https://github.com/reina0721/dmit-node-config/releases)。源码开发构建见 [贡献指南](../CONTRIBUTING.md)，本地候选不能冒充正式发行资产。系统矩阵与交付证据见 [验收记录](defect/08-one-command-delivery.md)。

全量质量及系统集成工作流只在手动触发时运行；标签触发的 Release 工作流仅原生构建、检查实际归档、生成 SBOM、签名及验证上传来源证明。不会为打包安装节点运行依赖；生产服务仍在目标主机原生运行。
