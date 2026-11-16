<div align="center">

<img src="apps/desktop/src/assets/logo.png" width="128" alt="MelonARC 标志" />

# MelonARC

**Adaptive Routing Core（自适应路由核心）**

一款开源、跨平台的规则分流代理客户端：按用户定义的规则把流量分发到不同的出站协议，核心守护进程与界面严格分离。

[![CI](https://github.com/Melon-tgj/MelonARC/actions/workflows/ci.yml/badge.svg)](https://github.com/Melon-tgj/MelonARC/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Go 1.27](https://img.shields.io/badge/Go-1.27-00ADD8.svg?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)](#平台与构建产物)
[![Preview](https://img.shields.io/badge/preview-0.1.0--preview.1-orange.svg)](docs/release-notes-0.1.0-preview.1.md)

[English](README.md) · **简体中文** · [日本語](README.ja.md) · [한국어](README.ko.md)

</div>

---

**状态：0.x 源码预览，不是稳定版。** Go 核心、本地 API、CLI 与桌面端前端均已实现；原生安装包、编译好的桌面端外壳、以及在发布目标平台上的端到端验证都还没有。下方的支持矩阵是"到底验证过什么"的唯一事实来源，不要把功能列表读成可用组合的承诺。

## 支持矩阵

### 术语含义

- **已验证（Verified）** — 一个独立的出站客户端把载荷经锁定版本的参考服务端送达独立的回显端点，并对返回字节做过比对。所在行会注明环境与参考版本。
- **项目记录（Project record）** — 在本项目自己的测试框架里通过，并以锁定参考版本记入 `DEVLOG.md`；未由外部评审独立复跑。
- **仅单元测试（Unit-tested only）** — 已知答案、负例与进程内测试通过，但从未有流量到达参考服务端。
- **不可用（Unusable）** — 外部评审发现的缺陷已修复，但此后没有流量经过参考服务端。修复落地不等于可用：它被排除在任何稳定版主张之外，不得进入稳定安装包。
- **未验证（Unverified）** — 在两个环境中都没有该组合的证据。

"TCP 业务"与"UDP 业务"指代理承载的载荷，不是其下层传输。对 QUIC 出站来说，TCP 业务走的是 QUIC 流。

### 出站协议

| 出站 | TCP 业务 | UDP 业务 | 证据与边界 |
|---|---|---|---|
| Shadowsocks 传统 AEAD（`aes-256-gcm`）与 2022 套件（`blake3-aes-128-gcm`、`blake3-aes-256-gcm`、`blake3-chacha20-poly1305`） | **已验证** 4/4 | **已验证** 4/4 | 外部评审，2026-11-15，macOS arm64，shadowsocks-rust 1.25.0，使用仓库原始互通用例。其余两套传统 AEAD 套件仍需各自用例。 |
| VMess (AEAD)、Trojan、VLESS + TLS | **已验证** 3/3 | **已验证** 3/3 | 同一次评审，Xray-core 26.11.9，仓库原始互通用例。范围恰好就是这三个配置过的用例。 |
| VLESS + REALITY | **项目记录**（阶段 16 TCP，16 KiB 往返） | **未验证** | 阶段 16 把手写的 TLS 1.3 握手换成锁定的 uTLS 客户端（`v1.8.3-0.20261108164504-a13c59ffe98b`，即 Xray-core 26.11.9 锁定的版本），外加一层只做 REALITY 凭据工作的适配层。脚本化对端证明：服务端认证段不能被跳过、复制或重排；错误签名、错误凭据、可信站点证书或错误 Finished 都会在写出任何 VLESS 字节之前关闭连接。已对 Xray-core 26.11.9 复跑互通（二进制 SHA-256 `e87bce58…6a66d`）：TCP 16 KiB 往返通过。UDP 尚无证据。 |
| Snell v4 / v5 | **已验证**（CI，2026-11-16） | **已验证**（CI，2026-11-16） | 阶段 11 先在锁定的 Snell 参考服务端上跑通两个版本的 TCP。随后完整互通门禁在 CI（GitHub Actions，ubuntu，2026-11-16）对 snell-server 5.0.0 的两种版本配置运行：每个 Snell 用例都通过，TCP 与 UDP 业务皆然。该系列中有一次运行只失败了两个 UDP 子用例（代码树未变），下一次运行即通过，故记为瞬时失败（清单 B6）；门禁若再遇到会打印完整测试输出。 |
| SOCKS5 (+TLS)、HTTP / HTTPS 出站 | **仅单元测试** | **未验证** | 由本项目测试覆盖；不在外部参考服务端矩阵内。 |
| Hysteria2 | **已验证** | **已验证** | 外部评审（2026-11-15）：三轮回显尝试对锁定的 Hysteria 2.13.0 全部失败；HTTP/3 阶段报 QPACK 字段段解码失败（错误 512）。阶段 15 修复了 HTTP/3 头块并增加了已知答案测试。在 CI（GitHub Actions，ubuntu，2026-11-16）七个参考槽位全部就位后复跑：Hysteria2 互通用例通过，TCP 与 UDP 业务皆然。 |
| TUIC v5 | **已验证** | **已验证** | 外部评审（2026-11-15）：三轮回显尝试对锁定的 tuic-server 1.0.0 全部失败；服务端日志显示认证失败，原因是 exporter 标签用了 UUID 的文本形式。阶段 15 修复了该标签并增加了已知答案测试。在 CI（GitHub Actions，ubuntu，2026-11-16）七个参考槽位全部就位后复跑：TUIC 互通用例通过，TCP 与 UDP 业务皆然。 |

阶段 15 修复了 QUIC 测试夹具、TUIC exporter 标签与 HTTP/3 QPACK 头块，并为每项增加了已知答案测试。本机沙箱拒绝在未连接的数据报套接字上 `sendto`，QUIC 第一程无法离开本机；因此复跑放在 CI（GitHub Actions，2026-11-16）进行，两个协议都对锁定的参考服务端通过，如上两行所记。互通已无未决项：同一次 CI 系列也跑完了每个 Snell 用例（沿途那次瞬时失败见 Snell 行与 `docs/pre-release-checklist.md` 的 B6 条目）。

VLESS 的 `xtls-rprx-vision` 流会在配置期被拒绝，不支持。

### 平台与构建产物

| 目标 | 状态 | 证据与边界 |
|---|---|---|
| Linux x86_64 | 在本工作区源码构建与测试通过 | `go build ./...`、`go vet ./...`、`go test ./...`、`gofmt` 与前端离线套件都在这里跑。没有安装包、没有打包发布、没有长时间浸泡测试。 |
| Windows x86_64 | **仅交叉编译** | `GOOS=windows go build ./cmd/... ./internal/...` 成功；外部评审也为两个目标做过 `CGO_ENABLED=0` 构建。从未原生执行：没有安装包、运行时测试、设备会话。Windows TUN 设备入口仍返回"session not implemented"。 |
| macOS arm64 | 仅外部评审主机 | 2026-11-15 的评审在 macOS arm64 上运行，Go 1.27.4、Node 24.20.0。它不是声明的发布目标。 |
| 桌面应用 | 前端已测试，原生外壳**未构建** | 前端离线与连真实核心的套件通过。Rust 外壳从未在此编译（没有 `rustc`/`cargo`/WebKitGTK），`Cargo.lock` 缺失，没有原生窗口截图或原生 IPC 测试。它最新的职责——启动、监护与停止核心进程——只有源码：进程托管、单实例锁与外壳设置文件都**未被执行过**。 |

开发文档承诺的"双平台可安装构建、常驻托盘、可用的系统代理与 TUN、全部协议连通、全部性能数字实测"**尚未达成**。请把它当作未来的验收标准，而不是对这棵树的描述。

### 组件

| 组件 | 状态 | 边界 |
|---|---|---|
| HTTP / SOCKS5 入站、本地 DNS、索引化规则引擎、策略组、重载、本地 API、CLI | 已实现，在本工作区有单元/集成测试 | 在干净目标安装上的完整入站到出站转发尚未记录。 |
| TUN 入站 | Linux：源码已实现，仅 IPv4 用户态 TCP；Windows：设备会话未实现 | 零窗口、重传、乱序、半关闭与长连接行为未验证。 |
| 系统代理 | 接管并恢复落盘快照 | 恢复只还原仍等于本程序所写值的字段，并删除接管前不存在的值。没有验证向已运行的 Windows 应用广播设置刷新；Linux 后端只覆盖 gsettings 桌面环境。 |
| 观测历史 | SQLite 中的有界本地表，经纯 Go 驱动（`modernc.org/sqlite` v1.62.0） | 三张表每次刷盘整表重写。schema 未知或无法读取的文件会被原样保留并暂停写入，因此本构建不理解的历史永远不会被替换。 |
| 桌面端前端 | 六个已注册面板、两种语言，离线与连真实核心的测试通过 | 只能对着开发预览桥运行；该桥仅供开发，绝不能进入生产包。报告核心进程状态的面板从外壳读状态，因此在浏览器里它显示的要么是桥自己的子进程（用 `--core` 时），要么是对别人已启动核心的真实探测——绝不是桥编造的 pid。 |

### 性能

开发文档中的五项性能目标**尚未在真实硬件上测量**。已公布的规则匹配数字是来自不同机器、不同阶段的固定规则集微基准；不能外推为吞吐、尾延迟、内存占用或跨平台达标。每个发布数字都需要专门的有线测试台、锁定构建与配置哈希、直连/代理交错运行，并把原始样本随发布记录保存。

### 其他已知缺口

- 两个发布目标都没有原生安装包、托盘、自启或签名产物。
- 没有从打包安装经入站监听到出站协议的端到端证据。
- 没有长时运行、公网、多进程或崩溃恢复结果。
- 桌面外壳的数据目录与 API 地址仍需重启 GUI 才生效；核心二进制路径与核心配置在下次核心启动时生效（设置面板可以重启核心）。
- 配置解析器、分享链接、订阅正文与 DNS 响应有 fuzz 目标及种子语料。各自只在本地跑过限时会话；还没有 CI 任务跑它们。
- 带独立互通 job 的 CI 工作流在 Actions 上运行：截至 2026-11-16 三个 job（Go、Frontend、Interop）全绿，互通 job 已对锁定的参考服务端复验 Hysteria2、TUIC v5 与 Snell。尚无任何发布 tag 背后有机器报告。

## 源码级范围

以下是源码树里存在的东西。其验证状态见上方矩阵。

### 入站
- HTTP / SOCKS5 代理服务（本地监听，可选认证）
- 系统代理设置，跟随核心的启动与停止
- TUN 模式（Linux：tun 设备加路由配置；Windows：仅设备绑定）

### 出站协议
- Shadowsocks（含 2022 加密套件）
- VMess (AEAD)
- VLESS（含 REALITY；不接受 XTLS-Vision 流）
- Trojan
- Snell v4 / v5
- Hysteria2、TUIC v5 —— 已在 CI 对锁定的参考服务端验证（2026-11-16）
- SOCKS5（含 TLS 变体）
- HTTP / HTTPS

### 规则引擎
- 规则类型：DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-SET、IP-CIDR、IP-CIDR6、GEOIP、IP-ASN、RULE-SET、DEST-PORT、PROTOCOL、FINAL
- 外部规则集（RULE-SET / DOMAIN-SET）：定时更新、本地索引、循环引用检测
- 保存前整体校验：规则集引用存在、策略引用存在、FINAL 存在；无效配置永不生效
- 规则匹配解释：给定域名或 IP，打印命中的规则与决策路径（CLI 优先）

### 策略组
- Select（手动选择）
- URL-Test（周期性延迟探测，选最快）
- Fallback（按序故障转移）

### 配置与导入
- 原生配置：INI 风格分节纯文本（`[General]` / `[Proxy]` / `[Proxy Group]` / `[Rule]` / `[Host]`），可手工编辑、对版本管理友好
- 分享链接导入：`vmess://`、`vless://`、`ss://`、`trojan://`、`hysteria2://`、`tuic://` 等
- 订阅导入，支持定时更新
- GeoIP / ASN 数据库：兼容 mmdb 格式

### 界面与可观测性
- 主窗口：配置切换、出站与策略组列表及切换、连接列表、流量序列、日志查看
- 连接日志与流量统计本地持久化（有界表）

各阶段细节、参考版本与剩余工作记录在 `DEVLOG.md`。

## 仓库布局

```
cmd/melonarc-core   核心守护进程入口
cmd/melonarc-cli    命令行客户端入口
apps/desktop        桌面端前端与（尚未编译的）原生外壳
internal/           核心包（config、rules、policy、outbound、inbound、dns、api、cli、datadir、store、sysproxy）
spikes/             技术验证原型及其结果
docs/               设计与开发文档
```

## 构建

需要 Go 1.27 或更新版本。

```
go build ./...
GOOS=windows go build ./cmd/... ./internal/...
```

第二条命令只是交叉编译检查；它不产生经过验证的 Windows 构建。

## 许可证

MelonARC 以 GNU 通用公共许可证第 3 版授权。许可证全文见 [LICENSE](LICENSE)。

第三方组件只有在许可证与 GPLv3 兼容时才可加入，且每个都要在 `DEVLOG.md` 中登记其版本、许可证与用途。[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) 列出会进入发布二进制的内容（许可证读自每个组件自己的副本），并点名唯一尚未审计的部分（Rust 外壳）。它会随发布包一起提供。
