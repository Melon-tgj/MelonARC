# 互通测试：装置、口径与复现步骤

- 状态：阶段 20 新增
- 适用对象：`internal/outbound` 的 `TestInterop*` 用例、`scripts/check-interop.sh`、
  CI 的互通 job
- 相关记录：`DEVLOG.md` 阶段 11（装置建立）、阶段 15/16（REALITY 与 QUIC 的修复）、
  阶段 20（本文件、判定脚本、CI）

## 1. 这份文档解决什么问题

互通装置的**代码**在 `internal/outbound/interop_*.go`，自己的注释写得比较全；但"参考实现
从哪来、怎么校验、放在哪、跑出什么算过"只散落在 `DEVLOG.md` 的阶段记录里。DEVLOG 是流水账，
不适合当操作手册：想复现互通的人得先读上千行才知道槽位叫什么名字。

这里把**可复现的那部分**固定下来：五个参考实现的版本、各自的发布渠道与校验办法、槽位布局、
运行命令、环境前提，以及判定口径。

一条不变的原则（阶段 11 决策 2）：**参考实现的名字只出现在开发文档与 DEVLOG 里**。产品代码、
代码注释、提交信息、用户可见文案中一个都不出现——装置按**协议**取二进制
（`$MELONARC_INTEROP_DIR/<协议>/server`），"哪个实现"是机器的属性，不是代码的属性。本文件
属于开发文档，因此可以写名字。

## 2. 参考实现与版本

| 协议 | 槽位 | 参考实现 | 版本 | 发布渠道 | 校验办法 |
|---|---|---|---|---|---|
| Shadowsocks（含 2022 套件） | `shadowsocks/` | shadowsocks-rust | 1.25.0 | GitHub Releases，tag `v1.25.0` | 资产旁的 `.sha256` 文件 |
| VMess | `vmess/` | Xray-core | 26.11.9 | GitHub Releases，tag `v26.11.9` | `Xray-linux-64.zip.dgst` 里的 `SHA2-256:` 行 |
| Trojan | `trojan/` | Xray-core | 26.11.9 | 同上 | 同上 |
| VLESS（含 REALITY） | `vless/` | Xray-core | 26.11.9 | 同上 | 同上 |
| Snell v4 / v5 | `snell/` | snell-server | 5.0.0 | 项目的下载页 | 发布页给出的 zip 哈希（**没有**独立清单文件） |
| Hysteria2 | `hysteria2/` | hysteria | v2.13.0 | GitHub Releases | 资产里的 `hashes.txt` |
| TUIC v5 | `tuic/` | tuic-server | 1.0.0 | GitHub Releases，tag `v1.0.0` | 资产旁的 `.sha256sum` |

读这张表要注意两点：

1. **一行协议不等于一份下载。** 一个 Xray 二进制会说 VMess、Trojan、VLESS 三种协议，所以
   `vmess/`、`trojan/`、`vless/` 三个槽位可以是指向同一个文件的链接或副本；`shadowsocks/`、
   `snell/`、`hysteria2/`、`tuic/` 各要自己的二进制。共 **5 份下载、7 个槽位**。
2. **本文件不写 URL，只写渠道与资产名模式。** 发布页由项目主页指向，写死链接只会随仓库迁移
   过期；能长期成立的是"哪个 tag、哪个资产、拿哪一行哈希"，以及下面的校验命令。资产名里的
   版本号与目标三元组随发布变化，升级版本时按同一模式替换。

## 3. 槽位布局

```
$MELONARC_INTEROP_DIR/
  shadowsocks/server      # shadowsocks-rust 的可执行文件
  vmess/server            # Xray 可执行文件（或指向它的链接）
  trojan/server           # 同上
  vless/server            # 同上
  snell/server            # snell-server 可执行文件
  hysteria2/server        # hysteria 可执行文件
  tuic/server             # tuic-server 可执行文件
```

- 目录按**协议**命名，不按实现命名；槽位里的文件必须叫 `server`，且必须可执行
  （`chmod +x`，解压出来的二进制通常已经是）。
- 缺某个槽位时，对应用例**跳过**并说明缺的是哪个协议——这是"没有参考实现"的诚实表现，
  不是通过。
- 这些二进制**永远不放进仓库**（`.gitignore` 之外，物理上也放在仓库目录之外，例如
  `~/interop-bin`）。它们是第三方产物，许可与体积都不适合随仓库分发。

## 4. 运行

```sh
# 整套互通用例，直接看用例级的通过/跳过
MELONARC_INTEROP_DIR=$HOME/interop-bin go test ./internal/outbound/ -run TestInterop -count=1 -v

# 判定脚本：把"有没有真的全过"变成一个退出码
MELONARC_INTEROP_DIR=$HOME/interop-bin scripts/check-interop.sh
```

`scripts/check-interop.sh` 是 CI 与本地共用的一道门，行为见第 6 节。它不下载、不解压、
不校验——那些属于布置槽位的一次性动作。

## 5. 环境前提

1. **Linux**。互通用例带 `//go:build !windows`：参考服务端以本机进程方式启动、用 `exec`
   拉起、靠信号回收，Windows 上另说。
2. **允许对未连接套接字 `sendto`**。这是硬前提，也是本机唯一缺的一条：开发沙箱的 seccomp
   拒绝它（`EPERM`），于是
   - 所有 UDP 子用例（Shadowsocks / VMess / Trojan / VLESS / Snell）必然跳过；
   - Hysteria2 与 TUIC 整条必然跳过（QUIC 服务端的第一程就走它）。

   换句话说：**在受限沙箱里，UDP 与 QUIC 一律没有互通证据**。这不是代码问题，改不了，
   只能换环境。

   2026-11-16 已在 GitHub Actions（ubuntu）以七个槽位跑过一次：除 Snell 的 v4/v5 UDP
   子用例外全部通过（含 Hysteria2、TUIC 的 TCP 与 UDP）；Snell UDP 的失败定位见公开前
   清单 B6。
3. **回环端口可用**。用例自己挑空闲端口（`freePort`），不需要预先分配，但需要 127.0.0.1
   上能绑临时端口。
4. **不联网**。所有各方都在 `127.0.0.1` 上：下载是一次性动作，跑用例时不需要外网。
5. **不需要 root**。TUN 那条（`TestTUNLinuxLoopback`）不在互通范围内。

## 6. 判定口径

脚本有两种模式，退出码区分它们：

| 情形 | 行为 | 退出码 |
|---|---|---|
| `MELONARC_INTEROP_DIR` 未设或为空 | 打印说明：互通需要一个存放参考实现的目录，并给出本文档的位置 | `2` |
| 设了，但有 `TestInterop*` 用例（父或子）SKIP 或 FAIL | 列出每一个 SKIP / FAIL 的名字，并说明"跳过不等于通过" | `1` |
| 设了，全部 `TestInterop*` 用例通过 | 打印通过数 | `0` |

三条细节：

1. **父与子都算。** `TestInteropVMess` 通过、`TestInteropVMess/udp` 跳过，仍然是非零：
   跳过的是 UDP 这一半协议。
2. **一个用例都没跑也算失败。** 如果过滤条件失效（用例改名、包路径写错），解析出来的
   通过数是 0，脚本按失败处理，而不是"没有失败所以成功"。
3. **不去猜跳过的原因。** 脚本不区分"缺二进制"与"环境缺能力"：这两种都是"这次没验证"，
   而门要回答的问题只有一个——**这次跑，七个协议是不是都真的被验证过了**。

### 本机的预期输出

`$HOME/interop-bin` 只布置了 Xray 的三个槽位（`vmess`、`trojan`、`vless`，都是同一个
二进制的链接）。因此在本机：

- Xray 系的 **TCP** 子用例通过（VMess / Trojan / VLESS / VLESS+REALITY）；
- Xray 系的 **UDP** 子用例跳过（seccomp 拒绝 `sendto`）；
- `shadowsocks`、`snell`、`hysteria2`、`tuic` 四个槽位缺失，整条跳过。

结论是**退出码 1**。这是脚本的正确行为，不是缺陷：本机确实没有验证完七个协议。**不要**为了
让本机变绿而放宽判定——那样 CI 上"全绿"就不再意味着"全测过"。

## 7. 复现步骤

```sh
# 1. 取五个实现（版本见第 2 节），校验哈希后解压
work=$(mktemp -d); cd "$work"

# Xray：.dgst 是文本，取 SHA2-256 那一行
curl -fLO .../Xray-linux-64.zip
curl -fLO .../Xray-linux-64.zip.dgst
want=$(sed -n 's/^SHA2-256:[[:space:]]*//p' Xray-linux-64.zip.dgst | tr -d '\r')
echo "$want  Xray-linux-64.zip" | sha256sum -c -

# shadowsocks-rust / tuic-server：清单本身就是 sha256sum 的输入格式
curl -fLO .../shadowsocks-v1.25.0.x86_64-unknown-linux-gnu.tar.xz{,.sha256}
sha256sum -c shadowsocks-v1.25.0.x86_64-unknown-linux-gnu.tar.xz.sha256

# hysteria：hashes.txt 里按资产名取那一行
curl -fLO .../hashes.txt
grep 'hysteria-linux-amd64$' hashes.txt | sha256sum -c -

# snell：没有清单文件，与发布页给出的哈希逐字符比对
sha256sum snell-server-v5.0.0-linux-amd64.zip

# 2. 布置槽位（共 5 份下载、7 个槽位）
export MELONARC_INTEROP_DIR=$HOME/interop-bin
install -Dm755 xray          "$MELONARC_INTEROP_DIR/vless/server"
ln -sf vless/server          "$MELONARC_INTEROP_DIR/vmess/server"
ln -sf vless/server          "$MELONARC_INTEROP_DIR/trojan/server"
install -Dm755 ss-local      "$MELONARC_INTEROP_DIR/shadowsocks/server"
install -Dm755 snell-server  "$MELONARC_INTEROP_DIR/snell/server"
install -Dm755 hysteria      "$MELONARC_INTEROP_DIR/hysteria2/server"
install -Dm755 tuic-server   "$MELONARC_INTEROP_DIR/tuic/server"

# 3. 跑门
scripts/check-interop.sh
```

哈希对不上就**停**：那说明拿到的不是发布方发布的那个文件，攒一个"能跑但来源不明"的
二进制只会让后面的失败无法归因。

## 8. 已知限制

1. **Snell 没有机器可读的校验清单。** 只有下载页给出的一个哈希，所以 CI 里这一步的期望值
   由仓库变量 `SNELL_ZIP_SHA256` 承载；变量为空时那一步**明确失败**而不是跳过——宁可红，
   也不要一个"看起来校验过了"的分支。
2. **两条只验夹具接线的用例不在互通门里。** `TestQUICFixtureInjectsTrustAtConstruction`
   与 `TestQUICFixtureReachesSendtoBoundary` 不需要参考实现：前者证明本地签发的根证书在构建期
   进了 TLS 配置，后者证明生产拨号路径走到了 `sendto` 边界。后者在允许未连接套接字 `sendto`
   的机器上会 `t.Skip`——它断言的性质在那里根本不存在。阶段 22 把这两条从 `TestInterop*`
   前缀里移出，保留在常规 `go test ./...` 中：第 6 节的判定只统计 `TestInterop*`，所以宽松
   runner 上的这个跳过不再让互通 job 判红，而真正与参考实现通信的用例仍严格执行"设置参考
   目录后 Skip 即失败"。`scripts/check-interop.sh` 与判定口径都未改动。
3. **本机没有 QUIC 与 UDP 的互通证据**（第 5 节第 2 条），到本文档为止仍然成立。
4. **`$MELONARC_INTEROP_DIR` 只接受一个目录**：多套实现并存要自己换软链接，没有"优先级列表"。
