# DEVLOG

> **协议（固定，勿删改）**
>
> 1. 任何新任务开始前，必须先完整阅读本文件与 `docs/development-doc-v1.md`，再动手写代码。
> 2. 每阶段结束必须更新本文件：在文末追加该阶段记录，不覆盖既有内容。
> 3. 每条记录必须写明：完成了什么、关键决策及理由、当前状态（构建/测试结果）、遗留问题、下一步计划。

## 阶段索引

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 技术验证（TUN、QUIC、10 万条规则索引），结果见 `spikes/RESULTS.md` | 通过 |
| 1 | 核心基础层：config / rules / policy / api + 守护进程装配 | 完成 |
| 2 | 出站协议层：DIRECT / SOCKS5 / HTTP(S) CONNECT + 真实探针 | 完成 |
| 3 | 入站层：HTTP / SOCKS5 本地监听 + 规则匹配管线 + 半关闭转发 | 完成 |
| 4 | DNS 层：`[Host]` 映射、TTL 缓存、请求合并、`no-resolve` 语义 | 完成 |
| 5 | 入站运维可见性：连接/关联计数、成员健康明细、最近失败记录、解析器统计进 API | 完成 |
| 6 | API 写端点（策略组切换、配置重载、审计记录）、令牌文件分发、CLI 落地 | 完成 |
| 7 | 明文 DNS 上游、按应答 TTL 的缓存、mmdb 数据源 | 完成 |
| 8 | TUN 入站：平台设备边界、用户态 TCP 栈、按目的地池化的 UDP 关联 | 完成 |
| 9 | TLS 基座与 TCP 类加密出站：Shadowsocks（含 2022）、VMess、Trojan、Snell | 完成 |
| 10 | VLESS（含 REALITY）、自研 TLS 1.3、Hysteria2、TUIC v5 | 完成 |
| 11 | 第三方参考实现互通验证、分享链接解析、订阅导入与定时更新 | 完成 |
| 12 | 收尾件：SQLite 观测层、系统代理接入、重载继承选择 | 完成 |
| 13 | GUI 第一步：Tauri 骨架与架构 | 完成（Rust 壳未编译） |
| 14 | GUI 第二步：规则 / 日志 / 设置 | 完成（Rust 壳未编译） |
| 15 | 按外部评审修订的修复批（9 项） | 完成（QUIC 真实互通待环境复验） |
| 16 | REALITY 握手改用锁版 uTLS + 薄适配 | 完成（Go 1147 / 1126 / 21 / 0） |
| 17 | GUI 第三步：桌面壳托管核心进程 | 完成（Rust 壳仍未编译） |
| 18 | 核心加固批 A：fake-IP 租约保留、重载统一提交点、TUN resolver 随重载 | 完成（Go 1155 / 1134 / 21 / 0） |
| 19 | 换库批：BLAKE3 与 SQLite 换成熟第三方库 | 完成（Go 1166 / 1145 / 21 / 0，二进制 +6.39 MiB） |
| 20 | 测试加固：规则 oracle 对照、四个 fuzz 入口、互通文档与 CI | 完成（Go 1251 / 1230 / 21 / 0，纯测试批 + 一处解析缺陷修复） |
| 21 | 0.x 预览发版准备：支持矩阵统一、发布工程、公开前检查 | 完成（Go 1266 / 1245 / 21 / 0，前端 77 / 75 / 2 / 0，发布 tar 已产出） |
| 22 | GPT 决策收尾批：`/v1/inbound` 枯竭计数出口、夹具用例改名、解析期静态校验 | 完成（Go 1292 / 1271 / 21 / 0，前端离线 79 / 77 / 2 / 0、实时 79 / 79 / 0 / 0） |

---

## 阶段 1 — 核心基础层（2026-11-13）

范围：`internal/config`、`internal/rules`、`internal/policy`、`internal/api` 四个包及其单元测试，
加上 `cmd/melonarc-core` 的装配。不含协议出站、入站、TUN、UI。

### 完成了什么

**internal/config** — INI 分节配置的解析与整体校验

- 五个分节：`[General]` / `[Proxy]` / `[Proxy Group]` / `[Rule]` / `[Host]`；分节名大小写不敏感。
- `Parse` 只做语法，`Validate` 做语义，`Load` 串起两者并记录绝对路径与基准目录（规则集相对路径以它为准）。
- 错误聚合：一次返回全部问题，每条带分节与行号（`Errors` / `Issue`），不是只报第一条。
- 校验项：规则集引用存在性、策略/出站引用存在性（含 `DIRECT` / `REJECT` 内建目标）、FINAL 必须收尾且唯一、
  代理与组的重名、组内成员存在性与自引用、组间循环引用、`url-test`/`fallback` 必须有 `url=`、
  时长参数为正、`api-listen` 必须是回环地址、`[Host]` 地址必须可解析。
- `[Proxy]` 的类型后参数整体保留为 `Args`，不在配置层解释协议细节。

**internal/rules** — 索引化规则引擎（把 `spikes/ruleindex` 产品化）

- 12 类规则全部实现：DOMAIN、DOMAIN-SUFFIX、DOMAIN-KEYWORD、DOMAIN-SET、IP-CIDR、IP-CIDR6、GEOIP、
  IP-ASN、RULE-SET、DEST-PORT、PROTOCOL、FINAL。
- 索引结构：精确名哈希表、后缀标签树、按首字节分桶的关键字表、IPv4/IPv6/端口的「有序不相交区间表」
  （二进制搜索）、协议哈希表；GEOIP / IP-ASN 按规则逐条查数据集。
- 语义是严格的 first-match-wins：每种索引各自返回「命中规则的最小下标」，全局取最小值，
  因此规则顺序而不是模式长度决定优先级（嵌套网段、父子后缀都按此处理）。
- 外部规则集：`RULE-SET` 递归展开（可嵌套），`DOMAIN-SET` 展开进后缀/精确索引但只占一个优先级槽位；
  循环引用检测给出完整链路（`a -> b -> c -> a`），并有嵌套深度与规则总量上限。
- 匹配解释：`Explain` 返回逐步的 `Steps`（每个维度是命中还是跳过、命中了哪条规则、为什么），
  外加文本报告；`Match` 走同一份逻辑但不构造任何解释字符串。
- GEOIP / IP-ASN 提供 `GeoIPLookup` / `ASNLookup` 接口与内存实现 `MemGeoIP` / `MemASN`，不引入 mmdb 依赖。

**internal/policy** — 三种策略组

- Select：手动选择，切换即时生效（下一次 `Active()` 即可见）；不因成员故障改变选择。
- URL-Test：并发探测全部成员，按间隔定时跑，选最快的健康成员；用 `tolerance` 抑制抖动；
  成员在使用中失败时（`NotifyFailure`）立刻用已知延迟重选，不等下一轮。
- Fallback：按声明顺序取第一个健康成员，故障即下移，恢复后回到最高优先级。
- 探测通过 `Prober` 接口注入，单测不碰网络；`Registry` 负责名字到叶子目标的解析，带环路保护。

**internal/api** — 本地回环 API 骨架

- 只监听回环地址（`0.0.0.0`、空 host、局域网地址、域名一律拒绝），启动时生成 32 字节随机令牌，
  所有端点经鉴权中间件，`Authorization: Bearer`，常数时间比较。
- 端点：`GET /healthz`、`/v1/status`、`/v1/config`、`/v1/rules?limit=`、`/v1/rules/explain`、`/v1/policies`。
- 统一 JSON 错误体（`error.code` / `error.message`），未知路径 404、方法不符 405 且带 `Allow`，
  响应带 `Cache-Control: no-store`。
- 传输层与守护进程内部解耦：只依赖 `Provider` 接口与自己的 wire 类型，
  `[Proxy]` 的凭据不会出现在 `/v1/config` 里。

**cmd/melonarc-core** — 装配

- `-config` 加载校验 → 编译规则 → 建策略注册表 → 起 API；`-check` 只校验并打印摘要后退出。
- 退出走信号（SIGINT/SIGTERM），先停策略组轮询再关 API。

### 关键决策及理由

1. **配置里规则集用 `rule-set <name> = <path>` 声明，放在 `[Rule]` 内。**
   开发文档限定只有五个分节，不能新开一节；声明放在规则所在的分节，既守住分节约定，
   又和 `KIND,payload,target` 的规则行在形状上明显区分。引用（`RULE-SET,ads,REJECT`）与声明分离，
   所以同一份规则集可以被多条规则复用，校验也能直接检查「引用是否已声明」。

2. **`[Proxy]` 类型后的参数原样保留，不在配置层解释。**
   密码常含 `=`（base64），若在配置层把 `key=value` 当选项解析会把密码吃掉。
   协议参数的解释留给后续阶段的出站实现，配置层只保证 server/port 可用。

3. **DOMAIN-SET 只占一个优先级槽位，RULE-SET 展开。**
   DOMAIN-SET 是「一批域名的集合」，语义上就是一条规则；如果展开成上千条规则，会把后续规则的下标整体推后，
   解释里的行号也会失真。RULE-SET 里是异构规则，必须逐条参与优先级，所以展开。

4. **优先级用「最小规则下标」实现，不用「最长匹配」。**
   first-match-wins 是这类规则表的语义：`IP-CIDR,10.0.0.0/8` 写在 `10.1.2.0/24` 前面时，
   即便后者更具体也不该命中。实现上让每个索引返回「自己命中的最早规则」，再取全局最小，
   与线性扫描等价但保持了索引的复杂度。区间表的构建用扫描线 + 最小堆，任意重叠也能得到最小下标。

5. **解释信息惰性构造。**
   第一版把解释文本在 `Match` 里一并 `Sprintf`，基准从 330ns 掉到 1.1µs、每次 3 次分配。
   改为只有 `Explain` 才构造 `Step`，`Match` 路径零格式化零分配，回到 489ns/op、0 allocs。

6. **GEOIP / IP-ASN 缺数据集时拒绝编译，而不是静默不命中。**
   「校验不过不得生效」同样适用于引擎：一条 GEOIP 规则没有数据库时无法执行，
   静默放行会让流量走错策略。因此 `Compile` 直接报错，等 mmdb 加载器接上后自然可用。

7. **策略组的探测函数注入，组自身不做网络 I/O。**
   三类组的正确性（选择、选快、故障转移）都能在没有网络的情况下用表驱动测试覆盖；
   真实探测（HTTP 探针）属于出站阶段。

8. **API 只做传输层。**
   `internal/api` 不 import config/rules/policy，只认 `Provider` 接口和自己的 JSON 类型。
   好处是 wire 契约与内部结构解耦、凭据不会误泄漏，后续加写端点不用改传输层。

9. **只用标准库，没有新增依赖。**
   本阶段需要的哈希表、树、区间表、JSON、HTTP 都在标准库里；新增依赖要过 GPLv3 兼容审查，
   没有必要就不引入。`go.mod` 未改动。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...    通过
go vet ./...      通过
go test ./...     全部通过（internal 四个包共 207 个测试用例，含子测试）
gofmt -l .        无输出
```

`go test -race` 对 config / rules / policy 三个包通过（并发路径：策略组轮询）。
api 包在本开发沙箱内无法以 `-race` 构建——race 运行时需要读取工具链里的标准库文件，被沙箱策略拦截，
与代码无关；该包的并发路径由 `go test ./internal/api/` 与实际起服务的手工验证覆盖。

性能（10 万条规则：5 万条 DOMAIN-SUFFIX + 5 万条 IP-CIDR，`go test -bench -benchmem`）：

```
BenchmarkMatchMixed-4   3029020   488.9 ns/op   0 B/op   0 allocs/op
BenchmarkCompile-4            6   171 ms/op     37.5 MB  366234 allocs/op
```

单次匹配 489ns，对 1ms 的目标有两个数量级余量；编译 10 万条约 171ms，可在配置重载时接受。

端到端手工验证：用一份含 `[Proxy]`、两种策略组、外部规则集、`[Host]` 的配置启动守护进程，
`-check` 打印索引摘要；API 在无令牌时返回 401，带令牌时 `/v1/status`、`/v1/policies`、
`/v1/rules`、`/v1/rules/explain` 均返回预期数据；含 `GEOIP` 规则而缺数据集的配置被拒绝启动并给出明确原因。

### 遗留问题

- **mmdb 接入**：`GeoIPLookup` / `ASNLookup` 只有内存实现，`GEOIP` / `IP-ASN` 规则目前必须有外部注入的数据集才能编译。
- **探针是占位实现**：守护进程用 `unavailableProber`，所有成员探测都失败，`url-test` 组永远停在首个成员。
  这是诚实行为（不假装健康），但要等出站层落地才有意义。
- **Select 组不感知健康**：手动选择语义如此，但成员全挂时没有提示；UI 阶段需要呈现。
- **`no-resolve` 只解析并保存，未参与匹配**：它依赖 DNS 层，本阶段没有解析动作。
- **`PROTOCOL` 只支持 tcp/udp**：够 MVP 用，应用层协议识别留给后续。
- **令牌只打印到 stdout**：还没有令牌文件/命名管道，UI 与 CLI 取令牌的方式待定。
- **API 只读**：无切换策略组的写端点；`Group.Select` 已经就位，加端点即可。
- **规则集无定时更新**：只支持本地文件，订阅与更新属于后续阶段。
- **`cmd/melonarc-cli` 仍是占位**：未接入 API。
- **编译内存**：10 万条规则编译期累计分配 37.5MB，与 80MB 空闲目标不冲突，但接入真实数据集后需复测。

### 下一步计划

1. 出站协议层：先做 SOCKS5 / HTTP 出站与真实探针，让 URL-Test / Fallback 具备实际意义。
2. 入站层：HTTP / SOCKS5 本地监听，把规则引擎接到真实连接上。
3. DNS 层：`[Host]` 映射、缓存与 `no-resolve` 语义落地。
4. mmdb 加载器：把 `MemGeoIP` / `MemASN` 换成按需加载的 mmdb 实现，接口不变。
5. API 写端点与 CLI：策略组切换、配置重载，令牌分发方式（文件/管道）一并定稿。

---

## 阶段 2 — 出站协议层（2026-11-13）

范围：`internal/outbound`（拨号抽象、DIRECT、SOCKS5、HTTP/HTTPS CONNECT、真实探针）与
`cmd/melonarc-core` 的装配替换（删除 `unavailableProber`）。不含加密类出站、入站、TUN、DNS。

### 完成了什么

**internal/outbound — 共享拨号抽象**

- `Dialer`：`DialContext(ctx, address)` 开流、`DialPacket(ctx, address)` 开数据报关联。
  `PacketConn` 是「单目的地的数据报连接」，语义等同 `net.Conn`（读只来自该目的地，写只发往它），
  底层由各协议决定是否需要封装；`*net.UDPConn` 直接满足它。
- `Target`：host 与 port 分开保存，域名原样保留、不再二次切分；`ParseTarget` 校验端口与控制字符，
  并实现 `net.Addr`，便于数据报 API 报告来源。
- 超时与取消：每个拨号器有 `DefaultTimeout`（10s），上下文带 deadline 时以上下文为准；
  握手期间用 `context.AfterFunc` 在取消时关闭连接，取消能立即返回而不是等超时。
- `Set`：名字到拨号器的映射，`DIRECT` / `REJECT` 由装配层注册。
- `Spec` + `New`：`[Proxy]` 行「类型之后的原始参数尾」在这一层解释。`key=value` 在第一个 `=` 处切分
  （密码本身含 `=` 也安全），未知键、重复键、半对凭据、长度超限都是错误；本阶段未实现的协议
  返回 `Unsupported` 拨号器。目前 SOCKS5 与 HTTP 共用的键只有 `username` 与 `password`：

  ```
  socks5, 127.0.0.1, 1080, username=alice, password=...
  https, proxy.example, 443, username=alice, password=...
  ```

  加密与否由类型决定（`http` / `https`），不额外接受 `tls=` 之类的键：一个键只有一种含义，
  拼错或猜错时立即报错。仍然没有新增依赖，`go.mod` 未改动。

**DIRECT 与 REJECT**

- DIRECT：TCP 用 `net.Dialer` 直连；UDP 用已连接的 UDP 套接字（`*net.UDPConn` 即 `PacketConn`）。
- REJECT：任何拨号都返回 `ErrRejected`，对应规则的拦截语义。

**SOCKS5**

- 方法协商（无认证、用户名密码，两者都提供时由服务器选，选中无认证也接受）、RFC 1929 认证、
  CONNECT、UDP ASSOCIATE 全部实现。
- 地址编码覆盖 IPv4 / IPv6 / 域名三种 ATYP；域名交给服务器解析，不在本地解析。
- 失败路径按回复码给出具体原因（连接被拒、主机不可达、命令不支持等），而不是笼统的 "failed"。
- `UDPRelay` 是可供后续入站/TUN 复用的中继抽象：一条关联服务任意目的地，按 SOCKS5 UDP 头封装/解封装，
  提供 `WriteTo` / `ReadFrom` / 期限设置与 `Close`；`SOCKS5.DialUDP` 建立关联，`DialPacket` 在其上
  给出单目的地视图。
- UDP 头里 FRAG 非 0 的报文直接丢弃（不支持分片重组，不能把分片当完整载荷交给调用方），
  畸形报文同样丢弃；连续丢弃 32 个后返回错误，避免在一个坏套接字上空转。
- 服务器回复的 BND.ADDR 是未指定地址（`0.0.0.0` / `::`）时，回退到实际连上的服务器地址。

**HTTP / HTTPS**

- 自行构造 CONNECT 请求（请求行 + `Host` + 可选 `Proxy-Authorization: Basic`），自行解析状态行与头部，
  头部总量上限 32 KiB。
- 代理可能把隧道首字节和 200 响应写在同一个 TCP 段里：读取响应后如果缓冲区仍有数据，返回一个
  先读缓冲区的包装连接，不丢字节。
- `https` 类型即先与代理做 TLS 握手再发 CONNECT；ServerName 取代理主机（主机是 IP 时按 IP SAN 校验），
  `TLSConfig` 可注入，测试用自签证书验证这条路径。
- HTTP CONNECT 只承载流，`DialPacket` 明确返回 `ErrUnsupported`。

**真实探针**

- `Prober` 实现第一阶段的 `policy.Prober`，接口一字未改。
- 每个 url-test / fallback 组在装配时各自绑定本组的 `url=`，因此 `Probe(ctx, member)` 不需要额外参数。
- 探测路径就是成员自己的出站：`Resolver` 把成员名经 `policy.Registry.Resolve` 解析到叶子，再取该叶子的
  `Dialer`。DIRECT 成员直连、代理成员经该代理、嵌套组跟随当前成员、REJECT 与未实现协议判失败。
- 延迟取「请求发出 → 响应头到达」；拿到响应头后再读至多 8 KiB 正文，确认隧道真的能传数据；
  2xx / 3xx 视为健康（3xx 本身已证明通路，不跟随重定向，避免额外延迟与环）。
- 上下文没有 deadline 时用 5s 兜底，保证一次探测一定会结束。

**cmd/melonarc-core**

- 新增 `buildDialers`：注册 `DIRECT` / `REJECT` 与全部 `[Proxy]`；未实现协议记为 `Unsupported` 并打 warn，
  配置可以带着后续阶段的协议启动，该成员只是永远不健康。
- `buildRegistry` 为每个探测组建立绑定 URL 的 prober，`unavailableProber` 删除；Select 组依然不探测。
- 新增 `cmd/melonarc-core/main_test.go`：用真实配置文本走 `Parse → Validate → buildDialers → buildRegistry`，
  再跑一轮 `Check`，断言 DIRECT 健康且有延迟、不可达代理与未实现协议都不健康、URL-Test 选中 DIRECT；
  另有一条断言「只有 username 没有 password」在启动期就报错。

### 关键决策及理由

1. **`policy.Prober` 不改，改成「一组一个绑定 URL 的 prober」。**
   第一阶段的方法只有 `Probe(ctx, member)`，没有 URL 参数；而 URL 是每个组的配置项，共享一个 prober
   无法知道该探哪个地址。改接口会牵动 policy 的既有测试与语义，收益却只是省一个对象。绑定 URL 后
   prober 仍然无状态，每组一个实例的成本可以忽略，接口和组行为都不动。

2. **`DialPacket` 每次建独立关联，`DialUDP` 另外暴露共享中继。**
   独立关联意味着回来的每个数据报都属于这条连接，不需要按来源地址猜归属。共享关联做不到这一点：
   客户端发的是域名时，服务器回包里的地址可能是它解析出的 IP，严格按目标地址过滤会把回包全丢掉。
   入站/TUN 需要一条关联服务多目的地时，直接用 `DialUDP` 拿 `UDPRelay` 自己做分流。

3. **未实现的协议给「一定失败」的拨号器，不在装配期报错。**
   一份订阅里同时有本阶段和后续阶段的协议是常态。启动即失败会让配置无法使用，而静默跳过又会让
   规则指向一个不存在的目标。`Unsupported` 让成员诚实地保持不健康，策略组按故障转移处理。

4. **CONNECT 的响应自己解析，不用 `http.ReadResponse`。**
   隧道建立后同一个缓冲区里可能已经有业务字节，需要把它们留给调用方；响应头部也要有明确上限。
   自己解析状态行与头部只有十几行，边界清晰，测试可以直接喂字节。

5. **探针延迟只算到响应头，正文只读一小段。**
   延迟要反映建连与首包，而不是响应体大小；再读至多 8 KiB 是为了确认隧道真能传数据，
   避免「回了个头但隧道不通」被算成健康。

6. **UDP 分片不支持，且丢弃要有上限。**
   MVP 不做重组；把 FRAG 非 0 的报文当完整载荷交付会静默损坏数据，因此丢弃。丢弃不设上限会在
   坏套接字上无限循环，所以连续 32 个后报错。

7. **仍然只用标准库。**
   SOCKS5、HTTP CONNECT、TLS、UDP 都在标准库里，没有必要为这些引入依赖。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...          通过
go vet ./...            通过
go test ./...           通过（全仓 324 个用例含子测试；outbound 包 111 通过、5 跳过，原因见下）
gofmt -l .              无输出
go test -race ./...     全部通过（含 api 包；阶段 1 记录的 race 构建限制本次未再现）
```

跳过的 5 个用例都是「本机起 UDP 回环服务器、由服务器向客户端/远端回包」的转发测试。本开发沙箱的
seccomp 策略禁止对未连接套接字调用 `sendto` / `sendmsg`（EPERM），任何中继服务器都无法回包，
与代码无关；在普通机器上这些用例会正常执行。为此另外补了一条只使用互相 connect 的 UDP 套接字的用例
（`TestUDPRelayFramingOnSockets`），在本沙箱内覆盖了 UDP 头的封装与解封装、分片丢弃、畸形报文跳过。

端到端覆盖（本沙箱内实际执行）：测试内起 SOCKS5 服务器与 HTTP 代理（含带认证的变体、带 TLS 的变体），
验证了经出站的 TCP 批量转发（64 KiB）、SOCKS5 用户名密码认证（成功与失败）、HTTP Basic 认证、
HTTPS 代理先 TLS 再 CONNECT、以及「探针经代理探测本地 HTTP 目标成功、目标不可达时判失败」。
`cmd` 的测试进一步验证了真实配置下的装配：URL-Test 依据真实探测结果选中 DIRECT。

### 遗留问题

- **SOCKS5 的 TLS 变体未实现**（MVP §2.3 有要求）：本阶段只做了 HTTP/HTTPS 的 TLS 变体。
- **TLS 选项缺失**：没有 `sni` / 跳过证书校验之类的配置键，`https` 只能用系统根证书；自签代理暂时不可用。
- **UDP 不做分片重组**：FRAG 非 0 的报文被丢弃。
- **UDP 每目的地一条关联**：TUN 规模下需要「一条共享关联 + 目的地分流 + 空闲回收」，`DialUDP` 已备好底座。
- **探针不保留历史**：只有最近一轮结果；每次探测新建 `http.Transport`，组多时值得复用。
- **探针的域名解析**：DIRECT 成员走系统解析，`[Host]` 映射与缓存要等 DNS 层。
- **`NotifyFailure` 还没有调用方**：需要入站层在拨号失败时上报，策略组才能立刻切换。
- **API 看不到出站实现状态**：哪些 `[Proxy]` 属于未实现协议目前只在启动日志里。
- 阶段 1 的遗留（mmdb、`no-resolve`、令牌分发、API 只读、规则集更新、CLI 占位）仍然成立。

### 下一步计划

1. 入站层：HTTP / SOCKS5 本地监听（含认证），把规则引擎、策略注册表与出站接到真实连接上，
   拨号失败时调用 `NotifyFailure`，UDP 走 `DialUDP`。
2. SOCKS5 的 TLS 变体与 TLS 选项键（SNI、证书校验开关）。
3. DNS 层：`[Host]` 映射、缓存、`no-resolve`。
4. 加密类出站，按开发文档 §2.3 的顺序推进。
5. mmdb 加载器；API 写端点与 CLI。

---

## 阶段 3 — 入站层（2026-11-13）

范围：`internal/inbound`（HTTP 入站、SOCKS5 入站、UDP 关联中继、连接管线、监听生命周期）、
`internal/config` 的入站键、`internal/api` 的配置视图，以及 `cmd/melonarc-core` 的装配与关停顺序。
不含 TUN、DNS、加密类出站、UI。

### 完成了什么

**internal/inbound — 包内分层**

新增 6 个文件（`service.go`、`relay.go`、`http.go`、`socks5.go`、`udp.go`、`pipeline.go`）加上重写的
`doc.go`，按「谁认识谁」分成三层，import 关系是这一层最硬的约束：

- `service.go` + `relay.go`：纯传输，只依赖标准库。监听与连接生命周期、半关闭转发都在这里。
- `http.go` + `socks5.go` + `udp.go`：只依赖 `internal/outbound` 的 wire 类型（`Target`、地址与
  数据报编解码），**不认识 rules / policy**。它们只拿到一个 `Handler` 接口，问一句「给我一条通往
  这个目的地的流」。
- `pipeline.go`：全包唯一 import `rules` 与 `policy` 的文件，负责「目的地 → 规则查询 → 出站」的接线，
  以及失败上报。

这样协议实现可以脱离规则引擎单独测试（假的 `Handler` 就够了），规则语义改动也不会碰到协议代码。

**HTTP 入站（`http.go`）**

- `CONNECT host:port` 走隧道：回 `200 Connection Established` 后进入半关闭转发。
- 普通代理请求（absolute-URI 形式，`GET http://host/path HTTP/1.1`）：用 `http.ReadRequest` 解析，
  拒绝 origin-form 与非 `http` 方案（本阶段不做代理侧的 TLS 终结，`https://` 的 absolute-URI 无意义）；
  逐跳头（`Connection` 及其列举的头、`Proxy-Connection`、`Keep-Alive`、`TE`、`Trailer`、
  `Transfer-Encoding`、`Upgrade`、`Proxy-Authorization`、`Proxy-Authenticate`）在转发前剥掉；
  `Expect: 100-continue` 由入站自己先回 `100 Continue`，避免上游等待；请求与响应都置 `Close`，
  一条连接只承载一次交换（MVP 阶段不做连接复用，语义简单且不会串味）。
- 错误映射：`outbound.ErrRejected` → `403`，其余拨号失败 → `502`，握手期解析失败 → `400`。
- 握手有 30s 读期限（`DefaultHandshakeTimeout`），握手完成后立即清除，不污染隧道期的读写。

**SOCKS5 入站（`socks5.go`）**

- 方法协商（RFC 1928）：无认证、用户名密码（RFC 1929）；配置了凭据时只接受用户名密码，
  未配置时只接受无认证；没有可接受方法回 `0xFF` 并断开。
- 凭据比较用 `crypto/subtle.ConstantTimeCompare`；两个字段都会比较（不因用户名错就跳过密码），
  失败只回同一个 `0x01`，不区分「用户名错」与「密码错」。`ConstantTimeCompare` 在长度不同时直接
  返回不等，泄漏的只是长度，因此配置期就把凭据限制在 255 字节以内。
- CONNECT 成功后回的 BND.ADDR 取**本地出口地址**（`upstream.LocalAddr()`），不用 `0.0.0.0`：
  客户端据此判断连到了谁，回零地址在多重 NAT 下没有信息量。
- 回复码按错误原因细分：不支持的地址类型 `0x08`、命令不支持 `0x07`、被规则拒绝 `0x02`、
  `ECONNREFUSED` → `0x05`、`ENETUNREACH` → `0x03`、`EHOSTUNREACH` / `ETIMEDOUT` → `0x04`，
  其余 `0x01`。错误字符串带上下文，回复码只表达类别。
- 目标地址里的域名原样交给 `outbound.Target`，不在本地解析（代理解析还是本地解析由出站决定）。

**UDP ASSOCIATE 中继（`udp.go`）**

- 关联绑定在客户端连进来的那个本地 IP 上（`listenerIP(client.LocalAddr())`），端口由内核分配，
  回复给客户端。
- 关联锁定**一个**客户端端点：请求里带了具体地址（非 `0.0.0.0:0`）就按它校验，没带就认第一个发来
  数据报的端点。其他端点发来的报文丢弃并计数，连续 32 个后关闭关联并把原因打进日志——
  UDP 无连接，不能让一个本地端口变成开放中继。入站只监听回环，不存在 NAT 改写源地址导致
  严格校验误杀的情况。
- 每个目的地一条 `handler.Packet` 关联（出站侧就是一条 `DialPacket`，SOCKS5 出站时底层是
  `UDPRelay`），一个目的地一个回程 goroutine，回包按 SOCKS5 UDP 头封装后写回客户端。
  目的地表上限 128 条，满了淘汰最久未活动的（LRU），避免长期运行的关联无限增长。
- FRAG 非 0 与畸形报文丢弃，连续丢弃 32 个后关闭关联（沿用阶段 2 的「丢弃要有上限」）。
- 客户端连接关闭即关联结束：`io.Copy(io.Discard, client)` 挂着，读到 EOF 就收尾。
  这是 RFC 1928 的语义——UDP 关联的生命周期绑在 TCP 控制连接上。

**连接管线（`pipeline.go`）**

- `Request{Target, Network}` → `rules.Query{Name, Addr, Port, Network}`：域名进 `Name`，
  IP 字面量进 `Addr`（两者都填会让 `no-resolve` 语义含糊，本阶段只填一个）。
- `Handler.Stream` / `Handler.Packet`：匹配 → 解析到叶子 → 拨号，返回连接与 `Selection`
  （命中规则、目标名、解析路径）。未命中（理论上 FINAL 兜住）、网络不是 tcp/udp 都是错误。
- 失败上报：`failed` 跳过 `outbound.ErrRejected`（拦截是规则的意图，不是故障），其余调用
  `Router.Failed(sel.Path)`；`PolicyRouter.Failed` 沿路径对**每一层**组调 `NotifyFailure`，
  Fallback 立即下移、URL-Test 立即用已知延迟重选，不用等下一轮探测。
  阶段 2 遗留的「`NotifyFailure` 没有调用方」到此关闭。

**半关闭转发（`relay.go`）**

- 两个方向各一个 goroutine，`io.Copy` 返回后对该方向的目标调 `CloseWrite()`
  （`*net.TCPConn` 的真实半关闭），另一方向继续读到 EOF；两个方向都结束才整体关闭。
- 只有 `io.Copy` 返回**真错误**时才整体 abort（两端 `Close`），正常 EOF 不算错误。
- 接口是 `interface{ CloseWrite() error }` 而不是直接断言 `*net.TCPConn`：测试里的包装连接、
  以后的 TLS 连接都能用，退化路径是直接 `Close`（此时对端会看到 EOF，语义仍然正确）。

**监听生命周期（`service.go`）**

- accept 失败按 5ms → 1s 指数退避重试并打 warn，不让一个瞬时错误（EMFILE 之类）打死监听；
  成功一次后退避归零。
- 连接在 `track` 里于同一把锁下登记并 `wg.Add`，`Close` 先冻结集合再关闭，避免「刚 accept 就被关」
  的竞态。`Close` 的顺序是：`cancel()` → 关监听 → 等 accept 循环退出 → 关闭在途连接 → 有限期
  `wg.Wait()`。在途连接关掉后转发 goroutine 会立刻返回，不需要无界等待。

**internal/config**

- `[General]` 新增四个键：`http-listen`、`socks5-listen`、`socks5-username`、`socks5-password`。
- 默认 `127.0.0.1:7890`（HTTP）与 `127.0.0.1:7891`（SOCKS5），要关掉写 `off`。
- 校验沿用 `api-listen` 的风格：必须 `host:port`、端口是数字且非 0、**必须是回环地址**
  （入站只服务本机）、凭据必须成对、各自 ≤255 字节（SOCKS5 用户名的长度上限）、不含控制字符、
  以及「配了凭据但监听是 off」直接报错——静默忽略会让用户以为开了认证。

**internal/api 与 cmd/melonarc-core**

- `ConfigView` 增加 `http_listen` / `socks5_listen`（`omitempty`，关闭的不出现）。凭据不进视图。
- 装配顺序改为：拨号器 → 策略注册表 → 启动组轮询 → 处理器 → 入站。
  关停顺序反过来：先停入站（不再接新连接，在途连接被关闭）→ 再关 API → 最后停组轮询。
- `startInbounds` 在中途失败时把已经起来的监听全部关掉再返回错误，不留半启动状态；
  两个监听都 off 时打 warn 说明进程只剩 API。
- `-check` 摘要多一行 `inbound: http <addr>, socks5 <addr>`（off 显示 `off`，配了凭据显示
  `(authenticated)`），不打印凭据本身。

### 关键决策及理由

1. **协议实现不认识规则与策略，只认 `Handler`。**
   入站协议和路由策略是两条独立的演进线：以后加 TUN 或透明代理，只是又一种「目的地来源」，
   不该重新写一遍匹配逻辑；反之规则引擎改语义也不该改协议代码。代价是 `pipeline.go` 要引入
   rules/policy/outbound 三个包，但这一个文件的依赖换来其余五个文件只依赖标准库和 wire 类型。

2. **SOCKS5 UDP 的封装/解封装复用 `internal/outbound` 的同一份代码，不复制。**
   之前这几个函数是包内私有的（`appendAddress`、`appendUDPDatagram`、`decodeUDPDatagram`）。
   UDP ASSOCIATE 需要同一套帧格式，复制一份意味着两处都要维护 FRAG 处理、ATYP 分支与长度边界，
   迟早漂移。改为导出（`AppendAddress`、`AppendUDPDatagram`、`DecodeUDPDatagram`、
   `MaxUDPHeaderLen`）并在调用点加注释说明入站复用，这是「一份实现」而不是「两个相似实现」。
   导出的是纯函数，没有暴露内部状态。

3. **入站 UDP 按目的地开独立关联，不用一条共享 `UDPRelay`。**
   阶段 2 给 `SOCKS5` 留了 `DialUDP` 拿共享中继的口子。但入站这一侧的语义是「客户端已经用
   SOCKS5 UDP 头告诉我目的地了」，用 `DialPacket` 直接拿到「只属于这个目的地」的视图后，
   数据报不需要再按来源地址二次分流，也就没有「服务器把域名解析成 IP 后回包对不上」的问题。
   共享中继留给 TUN（那里一个连接服务任意目的地，没有上层头）。目的地表用 LRU 上限 128，
   是因为长期运行的关联会积累大量一次性目的地（DNS、QUIC 探测），无上限就是内存泄漏。

4. **UDP 关联锁定单个客户端端点。**
   UDP 没有握手，任何人都能往那个端口发包。不锁定就等于在本机开了个开放中继。
   请求里带地址时按地址严格校验；不带（`0.0.0.0:0`，很常见）时认第一个来源并记住它。
   这条规则只有一处实现（`accepted`），所有收包路径都过它。

5. **半关闭用 `CloseWrite`，只有真错误才 abort。**
   隧道里正常结束是「一方说完了，另一方还要回话」——HTTP/1.0 的响应、SOCKS5 上的交互式协议都
   依赖这个。把 EOF 当错误整体关闭，会截断对方的回包。反过来，真错误（连接重置、写失败）继续
   转发没有意义，只会把错误拖到超时，所以立即两端关闭。

6. **`NotifyFailure` 在管线里统一上报，`REJECT` 豁免。**
   上报点是「拨号失败」这一个地方，而不是散落在两个协议里——协议只负责把错误返回。
   `REJECT` 是规则命中用户的意图，把它算成成员故障会让 Fallback 组在正常拦截时乱跳。
   上报沿 `Selection.Path` 走完全部层级，因为嵌套组时外层组也需要知道「我选的这条路径不通」。

7. **监听关闭用 `off` 关键字，不用空值。**
   INI 里 `http-listen =` 和「这行没写」在解析后无法区分，用空值表示关闭会让默认值永远无法被
   关掉，或者需要额外的哨兵值。`off` 是一个明确的词，大小写不敏感，与同分节的其它键在同一处校验。

8. **入站强制回环，凭据成对且长度受限。**
   MVP 没有 TUN，入站就是本机应用的入口，监听 `0.0.0.0` 等于把代理暴露给整个局域网——
   这是最容易被忽略的安全默认值，因此在配置校验阶段就拒绝，而不是靠文档提醒。
   凭据长度上限 255 来自 RFC 1929 的长度字段（1 字节），超了必须在配置期报错，
   不能等到协商时才发现写不进去。

9. **UDP 路径用 `datagramSocket` 接口而不是直接绑 `net.UDPConn`。**
   本沙箱禁止对未连接套接字 `sendto`（阶段 2 已记录），真实的回环 UDP 中继测不了。
   把套接字收窄成 `ReadFrom` / `WriteTo` / `Close` 三个方法后，测试可以用内存实现驱动整条
   关联逻辑（客户端隔离、目的地淘汰、分片丢弃、关闭释放），**生产代码没有任何为测试而设的分支**。
   这是接口抽象而不是测试开关：真实路径仍然走 `*net.UDPConn`。

10. **关停先入站后 API，最后组轮询。**
    关停期间最不希望发生的是「API 已经没了、入站还在接新连接」。反过来先停入站，新连接立即被拒，
    在途连接被关闭，转发 goroutine 迅速返回，之后再收 API 与轮询才不会有残留的
    「请求正在处理但后端已停」的状态。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...           通过
go vet ./...             通过
go test ./...            全部通过（全仓 392 个用例含子测试通过、6 跳过；inbound 包 26 个顶层用例，25 通过 1 跳过）
gofmt -l .               无输出
go test -race ./...      全部通过（含 inbound / api / cmd；阶段 1 记录的 race 构建限制未再现）
GOOS=windows go build    通过（cmd 与 internal 全部包）
```

跳过的 6 个用例：5 个是阶段 2 的「回环 UDP 服务器回包」用例，1 个是本阶段新增的
`TestSOCKS5UDPRelay`（端到端版本，同样需要服务器向客户端回包）。原因一致：本开发沙箱的 seccomp
策略禁止对未连接套接字调用 `sendto` / `sendmsg`（EPERM），中继服务器无法回包，与代码无关；
在普通机器上这些用例会正常执行。为了不让 UDP 路径失去覆盖，另外用 `fakeSocket` 在内存里驱动了
关联的全部逻辑，并单独覆盖了 `TestSOCKS5UDPAssociateReply`（不依赖服务器回包的那一半）。

端到端覆盖（本沙箱内实际执行，全部是回环上的真实 TCP）：

- **HTTP 入站全链路**：测试内起源站与 HTTP 入站，客户端分别用 `CONNECT` 隧道与 absolute-URI 形式
  取到同一份内容；另有一条用 `net/http` 的 `Proxy` 配置走完整客户端栈（含 `httptest` 的 TLS 源站，
  隧道里跑 TLS），断言正文一致。
- **SOCKS5 入站全链路**：无认证、带认证（6 种凭据组合，含错误密码被拒）两种，按地址与按域名
  （`localhost:port`）拨号，均取到源站正文；协商错误、命令错误、回复码映射各有表驱动用例。
- **规则分流实证**（`TestRuleSplitSendsEachDestinationItsOwnWay`）：同一份配置里两条 DEST-PORT 规则，
  一个端口走 DIRECT、一个端口走本地 SOCKS5 出站（这个出站是个会记录目标的假代理，隧道里回
  `proxied host:port`）。断言：走 DIRECT 的那次拿到源站正文且假代理**没有**记录；走代理的那次拿到
  `proxied host:port`，且记录的 CONNECT 目标**正好**是那个 host:port。HTTP 与 SOCKS5 两种入站
  各跑一遍，证明同一目的地经不同入站结果一致、不同目的地确实分了不同的路。
- **失败上报实证**：假拨号器返回错误 → `stubRouter` 收到 1 次失败；`REJECT` → 0 次且返回
  `ErrRejected`；Fallback 组在收到失败后下移到 DIRECT，下一次请求真的走了 DIRECT；嵌套组时
  两层组都收到失败。
- **半关闭实证**：`TestRelayHalfClose`、`TestHTTPConnectHalfClose`、`TestSOCKS5HalfClose` 三条，
  服务端读到 EOF 后**仍然可以回写**，客户端读到完整回复——这是最容易写错的一条，独立覆盖。

手工演示：`-check` 打印 `inbound: http 127.0.0.1:17890, socks5 127.0.0.1:17891 (authenticated)`；
两个入站都经规则（`DOMAIN-SUFFIX` → url-test 组）取回源站正文；SOCKS5 用错密码被拒
（客户端报 `User was rejected`）；`/v1/config` 如实给出两个监听地址；`/v1/rules/explain` 对同一
目的地给出命中的规则与解析路径（`path="[auto DIRECT]"`）；SIGTERM 后两个监听都打
`inbound stopped` 并正常退出。

演示中还观察到一个真实行为：把 url-test 组的 `url=` 指到一个 404 路径时，所有成员探测都判失败，
该组停在当前成员上，于是两次请求都失败。这是策略组的诚实行为（没有健康成员可切），
但也说明「探测 URL 配错」在运行期表现为全组不健康——运维上需要 `/v1/policies` 能看出这一点。

### 遗留问题

- **HTTP 入站不终结 TLS，也不支持 absolute-URI 的 `https://`**：要靠 `CONNECT` 建隧道。
  代理侧的 TLS 终结不在 MVP 范围内。
- **一条连接一次交换**：HTTP 入站总是 `Connection: close`，不复用连接。正确但比常见实现慢，
  每个请求多一次入站侧连接建立。
- **HTTP 入站无认证**：只有 SOCKS5 有用户名密码。HTTP 的 `Proxy-Authorization` 目前被当作逐跳头
  直接剥掉，不校验。
- **UDP 关联只在 SOCKS5 入站有**：HTTP 入站没有 UDP 语义（本来也没有），TUN 阶段的
  「一关联多目的地 + 空闲回收」仍需另做，`DialUDP` 的共享中继尚未被使用。
- **UDP 每目的地一条关联**：与阶段 2 的遗留一致，目的地上限 128 + LRU 只是兜底，不是优化。
- **无连接数上限**：入站接受任意多个连接，没有并发上限或配额，被动耗尽文件描述符的风险仍在。
- **URL-Test 全成员不健康时停在当前成员**：行为诚实但不理想，切到「最不差」的成员或明确拒绝
  服务可能是更好的选择，需要在 UI 阶段定语义。
- **`/v1/policies` 看不到入站侧的失败计数**：失败已经上报给组，但对外不可见。
- 阶段 1、2 的遗留（mmdb、`no-resolve`、令牌分发、API 只读、规则集更新、CLI 占位、
  SOCKS5 的 TLS 变体、TLS 选项键、探针历史、探针的域名解析）仍然成立。

### 下一步计划

1. DNS 层：`[Host]` 映射、缓存、`no-resolve` 落地——入站现在把域名原样交给出站，
   DIRECT 走系统解析，这一层补上之后 `no-resolve` 与探针的域名解析才有意义。
2. 入站侧的运维可见性：连接数、活跃关联、每组成员健康与最近失败原因进 API，让「全组不健康」
   在 `/v1/policies` 上直接可见。
3. SOCKS5 的 TLS 变体与 TLS 选项键（SNI、证书校验开关），补齐阶段 2 的遗留。
4. 加密类出站，按开发文档 §2.3 的顺序推进。
5. TUN 入站：复用 `DialUDP` 的共享中继做「一关联多目的地」，`internal/inbound` 的
   `Handler` 接口不需要改。
6. 入站的并发上限与 HTTP 入站认证（若 MVP 范围内需要）。

---

## 阶段 4 — DNS 层（2026-11-13）

范围：`internal/dns`（解析器、正/负缓存、请求合并）、`internal/rules` 的 `no-resolve` 语义与
`NeedsResolution`、`internal/outbound` 的 DIRECT 解析注入、`internal/inbound` 的解析接线与
`Explain`、`internal/config` 的 `HostMap`、`internal/api` 的配置视图与解释视图、
`cmd/melonarc-core` 的装配。对应阶段 3「下一步计划」第 1 项。不含明文 DNS 上游、mmdb、TUN、
加密类出站、UI。

### 完成了什么

**internal/dns — 解析器**

- 查询顺序固定为三层：`[Host]` 静态表 → 缓存 → 系统解析器。来源记在 `Result.Source` 上
  （`hosts` / `cache` / `system` / `literal`），这是后面 `Explain` 能说出「这一次到底解析了没有、
  地址从哪来」的依据。
- 正缓存 TTL 默认 5 分钟，负缓存默认 30 秒，都可配置。`Result.Expires` 让 TTL 在接口上可观测。
- 负缓存只记「名字不存在」这一类失败（`*net.DNSError` 的 `IsNotFound`，或 `ErrNotFound` 哨兵）；
  超时、连接被拒这类错误是「此刻的状态」而不是「这个名字的性质」，不缓存，下一次重试。
  解析器返回空地址列表时合成一个 `IsNotFound` 的 `*net.DNSError`，让调用方只需要判断一种错误形状。
- 请求合并（single-flight）：每个名字一个 in-flight `call`（`done` channel + 结果），
  后来者挂在同一个 `call` 上等，**上游只发一次**。等待者可以被自己的 ctx 取消而不影响进行中的查询
  （leader 继续跑，结果照常落缓存）。
- 名字规范化：去空白、转小写、去掉一个末尾点；空名、超长名、含分隔符、空标签、重复的 `[Host]`
  条目都在构造或查询时拒绝。IP 字面量直接返回 `SourceLiteral`，不进缓存也不查表。
- 缓存有上限（默认 1024）：满了先清过期，仍满就淘汰最早过期的那一条。这是容量上限而不是 LRU，
  解析很便宜、缓存很小，多维护一张 recency 表的收益抵不过它带来的一致性成本。
- 返回的地址一律是副本，调用方改不到缓存里的内容。
- `Lookup(ctx, host) ([]net.IP, error)` 是 `Resolve` 的简化形态，形状正好是 `outbound.Direct` 需要的。

**internal/rules — no-resolve 语义**

- `Query` 新增 `Resolved bool`：地址是「客户端给的」还是「查出来的」。这是语义的分界线——
  带 `no-resolve` 的地址规则只接受前者。
- 地址索引做成两套视图：`v4`/`v6` 收全部地址规则，`v4Resolved`/`v6Resolved` 只收不带
  `no-resolve` 的。查询时按 `pre.resolved` 选表，规则本身不需要逐条判断。
  没有任何规则带 `no-resolve` 时两套视图**共用一张表**（指针相同），配置不为没用到的特性付费；
  只有真的出现 `no-resolve` 才构建第二套。
- GEOIP / IP-ASN 是逐条求值的列表，直接在循环里跳过 `pre.resolved && r.NoResolve` 的规则，
  并在 `Steps` 里记一条 "skipped: no-resolve rule does not apply to a resolved address"。
- `Program.NeedsResolution()`：程序里是否存在「能接受解析结果的地址规则」。全为 `no-resolve`
  时返回 false，管线据此一次都不解析——这是「不得为匹配 IP 类规则而触发解析」最省事的保证。
- `Explain` 输出多一行 `resolution:`：`203.0.113.5 (hosts)` / `failed: ...` /
  `not attempted: no address rule can use a resolved address`。查询行里解析来的地址标成
  `addr=203.0.113.5(resolved)`，避免把查出来的地址读成客户端给的。IP-CIDR 维度被 `no-resolve`
  挡下时，说明文字会点名那条规则（`IPv4 prefix 10.0.0.0/8 covers the address, but that rule
  carries no-resolve and the address came from a lookup`）。
- `no-resolve` 通过 RULE-SET 展开时随规则一起复制（`c := *r`），有专门用例守着。

**internal/outbound — DIRECT 复用解析结果**

- `Direct` 新增 `Lookup LookupFunc`（`func(ctx, host) ([]net.IP, error)`）。为 nil 时行为不变，
  仍由 `net.Dialer` 调系统解析器；注入后名字先解析再按地址拨号，多个地址按顺序尝试。
  `DialPacket` 走同一条路径。
- 注入的是函数而不是 `*dns.Resolver`：outbound 不依赖 DNS 包，测试可以塞一个计数函数。
- 这样 `[Host]` 对**真实流量**生效，而不只对规则匹配生效；管线解析过的名字在拨号时命中缓存，
  一次请求只产生一次上游查询。

**internal/inbound — 管线接线**

- `Handler` 新增 `Resolver` 依赖（可为 nil，等于没有 DNS 层：名字保持名字，地址规则不参与）。
- `prepare` 决定「要不要解析」：名字为空、已带地址、没有解析器、`NeedsResolution()` 为 false，
  四种情况都不查；其余情况查一次，把首个地址放进 `Query.Addr` 并置 `Resolved`。
- **解析失败不是请求失败**：记一条 debug 日志后按名字继续匹配。域名规则照常生效，代理解析型出站
  仍可能到达目标，失败最终由拨号的错误映射表达（HTTP 400/403/502、SOCKS5 回复码），
  与阶段 3 的风格一致，不新增错误类别。
- 新增 `Handler.Explain(ctx, Query)`：走与真实请求同一条 `prepare` + `Match` 路径，把
  `rules.Resolution` 填进 `Explanation`。本地 API 的解释端点改为调用它，所以运维看到的报告
  就是连接实际经历的判定。

**internal/config / internal/api / cmd**

- `Config.HostMap()` 把 `[Host]` 转成 `map[string][]net.IP` 交给解析器，名字统一小写。
- `api.ConfigView` 的 `hosts`（完整映射）换成 `host_count`：`[Host]` 往往指向内网服务，
  而本地 API 的令牌任何本机进程都能读到，条数足够说明「这一节被读进来了」，内容不该出去。
  `ExplainView` 新增 `resolution`（`source` / `addrs` / `error` / `note`）。
- 装配：`buildResolver` 建解析器；`buildDialers` 把 `resolver.Lookup` 交给 DIRECT；
  `buildHandler` 注入管线；`daemonState` 持有 handler 供解释端点使用。
- `-check` 摘要多一行 `hosts: N`（只报条数）。

### 关键决策及理由

1. **解析在匹配之前一次决定，不在规则循环里惰性触发。**
   引擎的语义是「每个索引返回自己命中的最小下标，全局取最小」，没有逐条扫描的过程，
   自然也没有「走到第 5 条时再解析」的位置。改成惰性解析就要把索引退化成线性扫描，
   10 万条规则的性能目标立刻作废。所以改成「先问程序需不需要地址，再决定解不解析」：
   `NeedsResolution()` 回答「有没有哪条地址规则能吃到解析结果」，一次查询最多解析一次。

2. **`no-resolve` 用第二套索引视图实现，规则本身不加分支。**
   第一版想法是让区间表给每个区间存两个下标（全部规则的最小、非 no-resolve 规则的最小）。
   那样要改扫描线、`builtRange` 与 `lookup` 三处，且每个区间都要多存 4 字节。
   改成「同一批 block 建两张表」之后，`buildRanges` 与 `rangeTable` 一个字都没改，
   热路径只是按 `pre.resolved` 选一个指针。代价是出现 `no-resolve` 时块列表翻倍；
   没有它时两张表是同一个指针，零成本。

3. **`Query.Resolved` 是数据，不是策略。**
   如果不告诉引擎「这个地址是查出来的」，`no-resolve` 就无法执行：一条为别的规则做的解析，
   会让所有 `no-resolve` 规则凭空获得一个地址。放在 `Query` 里而不是让引擎自己判断，
   是因为只有调用方知道地址的来源；引擎只负责按这个事实选表。

4. **解析失败继续匹配，不提前失败。**
   本地解析失败不等于目标不可达：域名规则仍然有效，代理型出站把名字交给对端解析，
   完全可能成功。把失败提前成 502 会让「只有 IP 规则能匹配」的配置在 DNS 抖动时全盘拒绝服务。
   真正的错误交给拨号，错误映射沿用阶段 3 的那一套。

5. **DIRECT 走同一个解析器（注入 `Lookup`），而不是让管线把 IP 塞给出站。**
   把解析结果塞进 `Target.Host` 会让代理出站也拿到 IP，从而失去「对端解析」的能力（CDN、
   地域调度都会走错）。让 DIRECT 自己查，既保住「代理拿名字」，又让 `[Host]` 对直连生效；
   管线已经查过的名字在缓存里，拨号那一次是缓存命中，不会二次上游查询。
   代价是 DIRECT 多一个可选依赖，用函数注入解决，outbound 仍然不认识 DNS 包。

6. **单地址参与匹配，多地址用于拨号。**
   一次解析可能返回多条 A/AAAA。规则匹配只取第一条：`Query.Addr` 是单值，多地址匹配需要把
   每个地址维度都改成「对所有地址取最小下标」，语义会变成「任一地址命中即算命中」，
   与 first-match-wins 的组合需要另行定义。MVP 取第一条并把完整列表交给拨号，逐条尝试。

7. **正/负 TTL 是固定值，不来自应答。**
   `net.Resolver` 的接口不返回 TTL，拿不到就编不出来。固定 5 分钟 / 30 秒是「够短不至于长期错、
   够长不至于每连接一查」的折中，且可配置；等接上明文上游再按应答里的 TTL 走。

8. **缓存是容量上限而不是 LRU。**
   解析结果小、查询便宜，LRU 需要额外维护一条链并在每次命中时改动它，收益只是淘汰得更聪明一点。
   先清过期、再淘汰最早过期，实现只有十几行且没有隐藏状态。

9. **`/v1/config` 只报 `[Host]` 条数。**
   这不是「顺手删掉一个字段」：映射内容是内网拓扑，而 API 的信任边界是「拿到令牌的本机进程」。
   条数足以让运维确认这一节被读进来了，内容没有必要出去。`-check` 同理。

10. **解释端点走管线，而不是直接问规则引擎。**
    直接 `program.Explain` 得到的是「假如客户端给了这个地址」的判定，而真实请求可能是解析之后
    才有的地址。两者在 `no-resolve` 与 IP 规则同时存在时结论不同，报告必须描述后者。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...           通过
go vet ./...             通过
go test ./...            全部通过（全仓 453 个用例含子测试通过、6 跳过）
gofmt -l .               无输出
go test -race ./internal/rules/ ./internal/dns/ ./internal/inbound/ ./cmd/...   通过
```

6 个跳过仍是阶段 2/3 记录的「回环 UDP 服务器回包」用例（本沙箱 seccomp 禁止对未连接套接字
`sendto`），与本阶段无关。本阶段新增用例分布：dns 18、rules 新增 8（`noresolve_test.go`）、
inbound 新增 7、outbound 新增 6、cmd 新增 2。

端到端覆盖（本沙箱内实际执行，全部是回环上的真实 TCP）：

- **`TestHostMappingDrivesTheIPRules`**：两个 `[Host]` 名字分别映射到 `127.0.0.1` 与 `127.0.0.2`，
  两个源站分别监听这两个地址，规则 `IP-CIDR,127.0.0.2/32,via`。同一份配置只改一个关键字：
  不带 `no-resolve` 时 `proxied.test` 的映射地址命中 IP 规则，请求经 SOCKS5 出站到达假代理
  （代理记录的目标仍是**名字**，证明出站没有被塞 IP）；带 `no-resolve` 时 IP 规则不参与，
  请求直连到 `127.0.0.2` 上的源站。HTTP 入站与 SOCKS5 入站各跑一遍，且全程系统解析器的
  调用次数为 0（两个名字都在 `[Host]` 里）。
- **`TestDirectReusesTheResolvedAnswer`**：名字不在 `[Host]`，注入的系统解析器计数。一次请求
  既要匹配 IP 规则又要直连，计数恰好为 1——管线解析一次，拨号命中缓存，没有第二次查询。
- **`TestNoResolveDoesNotTriggerALookup`**：计数型假解析器断言调用次数为 **0**（验收要求的那条）。
- **`TestResolvedNameMatchesAnAddressRule`**：未带 `no-resolve` 时解析参与 IP 类规则匹配，
  且出站收到的仍是名字。
- **`TestStateExplainShowsTheResolution`**：`/v1/rules/explain` 背后的 `daemonState.Explain`
  给出 `resolution: 203.0.113.7 (hosts)`、`host_count: 1`，报告里没有映射内容。

性能（10 万条规则，`go test -bench -benchmem`）：

```
BenchmarkMatchMixed-4   391.7 ns/op   0 B/op   0 allocs/op     （阶段 1 记录 488.9；同机基线 384.3）
BenchmarkCompile-4      172–233 ms/op  24.4 MB  366209 allocs/op（阶段 1 记录 171ms / 37.5MB）
```

匹配路径与基线同速（差值在本机 ±10% 噪声内），仍是零分配。编译内存反而下降 35%：
本阶段把 `v4Blocks`/`v6Blocks`/`portBlocks` 改成按规则数预分配，去掉了 append 倍增的累计分配；
第一批实现里 `addressHit` 因函数体过大无法内联，把 `lookup` 挤出了内联范围，实测匹配慢了约 10%
（`MatchAddr` 374 → 466 ns），改成在 `evaluate` 里直接选表并调用 `lookup` 后回到基线。

`-check` 摘要（本地演示配置，两条 `[Host]`）：

```
rules: 3 (final: true, rule sets: [])
indexes: 0 suffixes, 0 exact names, 0 keywords, 2 ipv4 ranges, 0 ipv6 ranges, 0 port ranges
proxies: 0
groups: 1
hosts: 2
inbound: http 127.0.0.1:17890, socks5 127.0.0.1:17891
```

### 遗留问题

- **只有系统解析器**：没有明文上游，`[Host]` 之外的名字完全交给系统配置。开发文档 §3 的
  「系统 DNS / 明文上游」只完成了前半。
- **TTL 是固定值**：不从应答读取（系统解析器不给），也没有按名字做长短分级；
  接上明文上游后应当改成按应答 TTL。
- **多地址只取第一条参与匹配**：其余地址只用于拨号。多地址匹配（任一命中）需要先定义语义。
- **负缓存的错误会保留整个 TTL**：一次瞬时 NXDOMAIN 会在 30 秒内被复用，这是负缓存的本意，
  但没有「失败几次后放弃缓存」的机制。
- **DIRECT 逐条串行尝试地址**：没有 Happy Eyeballs 式的并发/延迟竞速，地址多且前面几个不可达时
  会按超时逐个消耗。
- **解析器对 API 不可见**：缓存命中率、条目数、最近失败都没有端点，排障只能看 debug 日志。
- **没有「关闭本地解析」的开关**：是否解析完全由规则集里有没有能用的地址规则决定，
  用户无法强制「一律交给对端解析」。
- **探针的域名解析语义变了**：探测 URL 的主机名现在也走 `[Host]` 与缓存（阶段 2 遗留关闭了一半）。
  这通常是期望行为，但探测结果可能与旧版不同，需要在文档里写清。
- **DNS 规则类型（如域名解析走指定出口）不在 MVP 范围**：TUN 阶段如果要 fake-ip 才需要它。
- 阶段 1–3 的遗留（mmdb、令牌分发、API 只读、规则集更新、CLI 占位、SOCKS5 的 TLS 变体、
  TLS 选项键、UDP 分片、入站并发上限、HTTP 入站认证）仍然成立。

### 下一步计划

1. 入站侧的运维可见性：连接数、活跃关联、每组成员健康与最近失败原因进 API（阶段 3 第 2 项）。
2. 明文 DNS 上游 + 按应答 TTL 调整缓存；顺带把 mmdb 加载器接上，让 `GEOIP` / `IP-ASN`
   不再依赖注入的内存数据集。
3. SOCKS5 的 TLS 变体与 TLS 选项键（SNI、证书校验开关），补齐阶段 2 的遗留。
4. 加密类出站，按开发文档 §2.3 的顺序推进。
5. TUN 入站：复用 `DialUDP` 的共享中继做「一关联多目的地」，`Handler` 接口不需要改；
   直连目的地届时同样走本阶段的解析器。
6. API 写端点与 CLI：策略组切换、配置重载，令牌分发方式一并定稿。

---

## 阶段 5 — 入站运维可见性（2026-11-13）

范围：`internal/inbound` 的运行指标与失败记录、`internal/policy` 的成员健康明细、
`internal/dns` 的解析器统计、`internal/api` 的三个新只读端点与 `/v1/policies` 的扩展、
`cmd/melonarc-core` 的装配。关闭阶段 3 遗留的「`/v1/policies` 看不到失败计数」与阶段 4 遗留的
「解析器对 API 不可见」，对应阶段 4「下一步计划」第 1 项。不含写端点、TUN、UI、明文 DNS 上游。

### 完成了什么

**internal/inbound — 运行指标（新文件 `metrics.go`）**

- `Metrics` 是入站层唯一的观测对象：每个协议（http / socks5）四个原子计数
  （当前连接、累计连接、当前 UDP 关联、累计关联），加上全局的失败/拒绝计数和一份定长失败记录。
  监听、管线、API 三处拿到的是同一个对象，所以「看到连接数」和「看到失败」永远对得上。
- 计数点只有两处：`Service.track`（accept 成功、登记进连接集合时 `open+1`、`accepted+1`）与
  `Service.untrack`（handler 返回时 `open-1`，写在 `defer` 里）。`track` 返回 false（监听已在关闭）
  时不计数，因为那条连接根本不会被服务。
- SOCKS5 的 UDP 关联在 `associate` 里用一对 `defer` 增减：`datagramOpened` 在关联可中继之后，
  `datagramClosed` 在 `assoc.Close()` 之后。HTTP 入站没有 UDP 语义，它的关联计数恒为 0。
- `Snapshot()` 只报告**已绑定**的监听（`newService` 里 `listen(protocol)` 置位），HTTP 在前、
  SOCKS5 在后，顺序固定。关掉的监听不会以「0 个连接」的形式出现，因为那会被读成「在监听但没人用」。
- `Metrics` 的 nil 接收者与零值都安全：不传 metrics 的旧调用点行为一字不变，测试也不必为了路由
  行为去构造指标。

**异常路径的计数回落**

- `Service.serve` 增加 `recover`：单个连接的 handler panic 只终止该连接并打一条带栈的 error 日志，
  监听与进程继续。`defer` 链在 panic 展开时照常执行，`untrack` 因此仍然把计数减回去——
  这是「异常断开也要回落」的最极端情形。不 recover 的话，一个协议实现里的空指针会带走整个守护进程，
  那比计数泄漏严重得多。

**internal/inbound — 失败记录（新文件 `failure.go`）**

- `Failure{Time, Target, Network, Stage, Category, Policy}`。阶段两种：`route`（拨号之前）与
  `dial`（承载失败）。类别九种：`rejected` / `unsupported` / `refused` / `timeout` / `cancelled` /
  `unreachable` / `resolve` / `unroutable` / `unknown`。
- `categorize(stage, err)` 用 `errors.Is` / `errors.As` 归类：`ErrRejected` 与「协议未实现」优先
  （它们的语义与阶段无关）；路由阶段的其余错误一律 `unroutable`——拨号之前出问题只可能是「这个目的地
  没有可用策略」；拨号阶段再看取消、超时、DNS、连接被拒、网络/主机不可达。
- `failureRing` 是定长环形缓冲（默认 `DefaultFailureCapacity = 64`），写满后覆盖最旧的一条；
  `Recent(limit)` 返回**最旧在前**、只取最新 `limit` 条。上限写死，不可配置：它的存在意义就是
  「记录不会随流量增长」。
- 记录点只有两处：`Handler.route` 返回错误（stage=route）与 `Handler.failed`（stage=dial）。
  拒绝也会被记录，但只计入 `rejected`、不计入 `failures`：规则拦截是用户意图，不是故障，
  而排障的人需要看到「是规则挡的」而不是「代理挂了」。
- 只存类别与目标主机名/IP（外加 tcp/udp 与命中的策略名），**不存错误文本、不存任何载荷**。
  错误文本只进日志。

**internal/policy — 成员健康明细**

- `MemberStatus` 增加 `CheckedAt`（最近一次探针或最近一次在役失败的时间）、`Failures`（连续失败数）、
  `Error`（最近一次失败，截断到 160 字节且在 rune 边界切）；`Status` 增加 `AllUnhealthy`。
- `probeRound` 现在带回探针错误；`carryFailures` 在每轮结束后把上一轮的连续失败数并进来：
  健康清零、失败加一。放在 `Check` 里合并而不是让 `probeRound` 去读旧状态，是因为
  `probeRound` 是并发执行的，读共享状态要么加锁要么传快照，两样都比「结果回来之后统一合并」复杂。
- `NotifyFailure` 同样累加 `Failures`：在役失败与探针失败共用一个计数，运维看到的是「这个成员连续
  失败了几次」，不关心是谁发现的。
- Select 仍然不改变选择，但开始记录在役失败。手动组没有探针，「我选的节点一直连不上」在 API 里
  本来完全不可见，这正是阶段 1 遗留的那条。成员仍标记为「未探针」（`Healthy=true`），因为它永远
  不会被探针恢复，标成 down 就再也回不来了。
- `allUnhealthy`：所有成员都被探针过且都失败才为真。未探针的成员算健康，否则一个刚启动的组会在
  第一轮探测之前先报自己全挂。

**internal/dns — 解析器统计**

- `Stats{CacheHits, CacheMisses, Entries, MaxEntries, Succeeded, Failed}` + `Resolver.Stats()`。
- 计数器是原子量：快照不能排在一次上游查询后面。`Resolve` 包住原有的解析序列并记成功/失败
  （字面量与 `[Host]` 也算一次解析）；`fromCache` 命中记 hit，`fetch` 记 miss。
- 合并等待（挂在同一个 in-flight 查询上）既不是 hit 也不是 miss——它没有发起查询，所以
  `CacheHits + CacheMisses` 可能小于 `Succeeded`。这条写进了 `Stats` 的注释，否则读数字的人会以为丢计数。
- 只有数字，没有名字：`[Host]` 的内容依旧不出进程。

**internal/api — 三个只读端点与策略视图扩展**

- `GET /v1/inbound`：`inbounds[]`（`protocol` / `open` / `accepted` / `datagram_associations` /
  `datagram_associations_total`）、汇总的 `open` / `accepted`、`failures` / `rejected`、
  `failure_log_capacity` / `failure_log_count`。
- `GET /v1/failures?limit=`：`capacity` / `count` + 记录数组（`time` / `target` / `network` /
  `stage` / `category` / `policy`）。`limit` 复用 `/v1/rules` 的解析与上限，超限与非法值都是 400。
- `GET /v1/dns`：`cache_hits` / `cache_misses` / `entries` / `max_entries` /
  `resolutions_succeeded` / `resolutions_failed`。
- `/v1/policies`：`PolicyView` 增加 `healthy_members` 与 `all_unhealthy`，`MemberView` 增加
  `checked_at` / `failures` / `error`。原有字段与含义不变，旧客户端不受影响。
- `Provider` 接口加三个方法；三个新端点都走同一套鉴权、405 + `Allow`、`Cache-Control: no-store`，
  空集合返回 `[]` 而不是 `null`。

**cmd/melonarc-core**

- 装配时建一个 `inbound.NewMetrics(inbound.DefaultFailureCapacity)`，同时交给 `buildHandler`
  与 `startInbounds`——监听计数、管线记录、API 读取用的是同一个对象。
- `daemonState` 增加 `metrics` 与 `resolver`，实现 `Inbound` / `Failures` / `DNS`，`Policies`
  填新字段。`Failures` 的 `count` 是「记录里有几条」，`limit` 只裁剪返回的数组。

### 关键决策及理由

1. **一个 `Metrics` 对象贯穿监听、管线与 API，而不是三份独立的统计。**
   连接数与失败数在运维眼里是同一件事的两面：「刚才那几个连接为什么失败」。拆成三个依赖后，
   装配层要保证它们指向同一个事实，任何一处漏传都会让 API 给出互相矛盾的数字。代价是
   `Metrics` 同时认识「连接」和「失败」两种概念，但它的方法都是原子的、无状态的，没有引入耦合。

2. **计数用原子量，减法放在 `defer` 里。**
   锁会把互不相关的连接串起来，而计数器是纯增量语义，原子量正好。减法必须挂在 handler 的
   defer 链上：正常返回、提前 return、panic 三条路径都会执行它，这是「不泄漏」唯一可靠的写法。
   反例是「解析完请求再减」——那样每加一条错误分支就多一个漏点。

3. **handler panic 只影响一个连接。**
   代理守护进程最不能接受的是「一个畸形请求让整个进程退出」。`recover` 之后连接关闭、计数回落、
   监听继续，错误连同栈进日志。这条也顺带保证了计数在 panic 路径上不泄漏。

4. **拒绝被记录，但不计入失败。**
   只记失败会让「规则挡了它」看起来像「代理坏了」；只记拒绝又会让真正的故障淹没在拦截里。
   因此两个计数分开，记录里用 `category=rejected` 标明，语义由类别承担而不是由「记不记」承担。

5. **失败记录只存类别，不存错误文本。**
   需求写的是「类别化原因」；错误文本会随对端的一句回复变长，还会把远端可控的字符串带进一个
   定长缓冲。需要细节时看日志，需要趋势时看 API，两者的职责分开。

6. **环形缓冲用覆盖式，不用「追加 + 裁剪」。**
   覆盖式没有增长、没有 `copy`、没有「先删几条」的分支，淘汰规则就是「写指针追上来了」，
   没有时间戳比较可以写错。`Recent(limit)` 先按最旧在前拷出再截尾，读的人不需要知道环在哪。

7. **连续失败数在轮询结束后合并，而不是让探针去读旧状态。**
   `probeRound` 并发跑所有成员，让它顺带读上一轮结果就要么加锁、要么传快照；而在 `Check` 里
   拿到新结果后统一合并只有一次加锁、一次遍历，语义也更清楚：一轮探测 = 一次状态转移。

8. **Select 记录失败但不改选择。**
   「手动组的成员挂了要不要自动切」是产品语义，阶段 1 已经定成「不切」，这里不改。但「一直失败」
   必须可见，否则用户只能靠猜。把成员标成 down 会让它永远停在 down（没有探针能把它救回来），
   所以只累加计数与时间，健康位保持「未探针」。

9. **DNS 计数放在 `Resolve` 外层。**
   解析序列有五个返回点（非法名、字面量、`[Host]`、缓存、上游），在每个返回点各记一次迟早漏一个。
   包一层之后「一次 `Resolve` 恰好记一次成功或失败」，缓存命中/未命中仍在各自发生的地方记，
   因为它们是「这一次有没有查上游」而不是「这次调用成不成功」。

10. **新端点各自独立，不塞进 `/v1/status`。**
    失败记录有 `limit`、有容量、会滚动，塞进状态里会让一个本来稳定的接口随记录一起变；
    DNS 统计与入站计数也各有各的读者（排障看失败、调优看解析、容量看连接）。分开之后每个端点的
    形状简单，UI 也只取自己要的那一份。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...           通过
go vet ./...             通过
go test ./...            全部通过（全仓 504 个用例含子测试通过、6 跳过）
gofmt -l .               无输出
go test -race ./internal/inbound/ ./internal/api/ ./internal/policy/ ./internal/dns/ ./cmd/...   通过
GOOS=windows go build ./cmd/... ./internal/...                                                  通过
```

6 个跳过仍是阶段 2/3 记录的「回环 UDP 服务器回包」用例（本沙箱 seccomp 禁止对未连接套接字
`sendto`），与本阶段无关；本阶段新增的 UDP 关联计数用例只用到 bind 与 TCP 控制连接，不需要回包，
因此在沙箱内正常执行。本阶段新增顶层用例 31 个：inbound 12、policy 6、dns 5、api 7、cmd 1。

端到端覆盖（本沙箱内实际执行，全部是回环上的真实 TCP）：

- **`TestAPIShowsInboundMetricsAndFailures`**（cmd）：按守护进程的顺序装配 configuration → 规则 →
  拨号器 → 策略组 → 管线 → 入站 → API，然后经 HTTP 入站发四个连接：一个到源站（`DIRECT`，200）、
  一个到没有监听的目的地（`FINAL` 指向 Select 组的 dead 成员，502）、一个命中 `REJECT` 的端口（403）、
  一个用 `[Host]` 映射的名字（200）。断言：`/v1/inbound` 的 `accepted=4`、`open=0`、`failures=1`、
  `rejected=1`、`failure_log_count=2`；`/v1/failures` 两条记录的顺序、目标、类别（`refused` /
  `rejected`）、阶段与策略名；`limit=1` 只裁剪返回数组而 `count` 不变；`/v1/policies` 里 Select 组
  的 `active` 仍是 `dead`、该成员 `failures=1` 且带 `checked_at`、`all_unhealthy=false`；
  `/v1/dns` 的 `resolutions_succeeded≥1` 而 `entries`/`cache_hits`/`cache_misses` 全为 0——
  映射名由 `[Host]` 直接回答，不进缓存。
- **计数回落实证**：`TestServiceCountsConnectionsAndFailures` 用真实连接把 `accepted` 推到 2、
  `open` 回落到 0；`TestAssociationCountersFollowTheControlConnection` 打开一个 SOCKS5 UDP 关联，
  断言 `datagram_associations=1`，关闭控制连接后回落到 0、累计为 1；
  `TestServiceSurvivesAPanickingHandler` 让 handler 直接 panic，两次连接后仍是 `accepted=2`、`open=0`，
  且监听继续接受连接。
- **并发安全**：`TestMetricsCountersAreConcurrencySafe`（16 goroutine × 200 轮增删，最终
  `open=0`、`accepted=3200`）、`TestStatsAreConcurrencySafe`（8 goroutine 并发解析并读快照）、
  整个 inbound/api/policy/dns/cmd 在 `-race` 下通过。
- **记录上限与滚动淘汰**：`TestFailureRingEvictsTheOldest` 写 5 条进容量 3 的环，断言只剩最新的
  3 条且 `failures` 计数仍是 5（淘汰不丢计数）；`TestRecentHonoursTheLimit` 断言 `limit` 是视图
  而不是淘汰。
- **失败归类**：`TestCategorise` 14 个子用例覆盖九种类别与两种阶段的组合；
  `TestRouteFailureIsRecorded` 与 `TestRejectionIsRecordedWithoutBeingAFailure` 分别验证
  「路由阶段失败记成 `unroutable`」与「拒绝记进记录但不计入 failures」。
- **策略健康**：`TestConsecutiveFailuresAccumulateAndReset` 走「失败 → 失败 → 恢复」三轮，
  断言 `failures` 从 1 涨到 2 再清零、`error` 出现又清空、`all_unhealthy` 随之一真一假；
  `TestSelectRecordsFailuresWithoutSwitching` 断言手动组的选择不变但失败计数照涨。

### 遗留问题

- **失败记录没有错误文本**：只有类别，具体原因仍要看日志。要展示细节就得给 `Router.Failed`
  加错误参数，那会动策略组接口，本阶段没做。
- **在役失败没有原因**：`NotifyFailure` 只带成员名，所以成员视图里的 `error` 可能来自上一轮探测
  而不是这次在役失败；两者共用一个计数，但文本只有探针能给。
- **失败记录不含命中的规则**：只有策略名（规则目标的那个名字），没有规则下标/文本。
- **HTTP 入站的 4xx 不记录**：畸形请求、SOCKS5 认证失败这类客户端错误不进记录，否则任何本机进程
  都能把环形缓冲刷满。代价是「客户端配置错了」在 API 上看不到。
- **没有连接级明细**：没有五元组、字节数、时长，也没有持久化；开发文档 §2.7 的连接表与流量曲线
  属于观测层，需要 SQLite。
- **DNS 统计不区分正/负缓存命中**，也没有按名字或按来源（`[Host]` / 缓存 / 系统）的分布。
- **每个失败一次 `time.Now()` 加一次记录**：只在失败路径上分配，正常流量零成本；但大规模失败
  （例如全组不可达）会放大这部分开销，没有池化。
- **`Metrics` 不区分 tcp/udp 失败**：失败计数是按「请求」而不是按「协议」聚合的，因为分类发生在
  管线里，而管线不知道请求来自哪个监听。
- 阶段 1–4 的遗留（mmdb、令牌分发、API 只读、规则集更新、CLI 占位、SOCKS5 的 TLS 变体、
  TLS 选项键、UDP 分片、入站并发上限、HTTP 入站认证、明文 DNS 上游、TUN）仍然成立。

### 下一步计划

1. API 写端点与 CLI：策略组切换、配置重载，令牌分发方式（文件/命名管道）一并定稿；
   写端点直接建在同一个 `Provider` 上，传输层不用改。
2. 明文 DNS 上游 + 按应答 TTL 调整缓存，顺带把 mmdb 加载器接上（`GEOIP` / `IP-ASN` 不再依赖注入）。
3. 观测层的连接表与流量统计（SQLite 持久化），对应开发文档 §2.7；本阶段的计数是它的前身。
4. SOCKS5 的 TLS 变体与 TLS 选项键（SNI、证书校验开关），补齐阶段 2 的遗留。
5. 加密类出站，按开发文档 §2.3 的顺序推进。
6. TUN 入站：复用 `DialUDP` 的共享中继做「一关联多目的地」，`Handler` 接口不需要改。

---

## 阶段 6 — API 写端点、令牌分发与 CLI（2026-11-13）

范围：`internal/api` 的两个写端点与审计记录、`internal/inbound` 的可替换路由状态、
`internal/datadir`（数据目录与令牌文件）、`internal/config` 的 `data-dir`、`internal/cli` 与
`cmd/melonarc-cli`、`cmd/melonarc-core` 的重载装配与令牌分发。对应阶段 5「下一步计划」第 1 项，
关闭阶段 1 起一直挂着的「令牌只打印 stdout」「API 只读」「CLI 占位」三条遗留。
不含 TUN、UI、明文 DNS 上游、加密类出站。

### 完成了什么

**internal/datadir — 数据目录与令牌文件（新包）**

- `Default()`：`os.UserConfigDir()` + `melonarc`。`Resolve(baseDir, explicit)`：显式值优先；相对值按
  `baseDir`（守护进程传配置文件所在目录）解析，与规则集相对路径同一条规则，因此不依赖服务管理器
  用什么工作目录启动进程。
- `WriteToken(dir, token)`：`MkdirAll(dir, 0700)` → 在目录内建临时文件（0600，并显式 `Chmod` 一次，
  不依赖 `CreateTemp` 的默认值抵住 umask）→ 写入并 `Sync` → `Rename` 到 `<dir>/api-token`。
  原子替换意味着读取方要么看到旧令牌要么看到新令牌，不会读到半个文件；失败路径删掉临时文件，
  不会留下「有文件但内容是上一次的」。
- `ReadToken` / `ReadTokenFile` 去掉末尾换行，并对形状做校验（非空、≤512 字节、无空白与控制字符），
  这样被误写成一行说明文字的文件会被拒绝，而不是被当成 `Authorization` 头发出去。
- Windows 上 `0600` 只映射到只读属性位，不等价于 POSIX 权限；这一点写进了注释，ACL 加固留给安装包阶段。

**internal/config — `data-dir`**

- `[General]` 新增 `data-dir`，默认留空（平台目录由运行时决定，不进解析器的默认值）。
- `Validate` 只检查形状（长度 ≤4096、无控制字符）：**校验不碰文件系统**，所以 `-check` 仍然是只读的，
  目录在第一次写令牌时才创建——这与「配置可校验但不得产生副作用」一致。

**internal/inbound — 路由状态可替换**

- `Handler` 从「三个不可变字段」改成「一个 `atomic.Pointer[handlerState]`」，`handlerState` 打包
  matcher / router / resolver。`NewHandler` 内部调用新增的 `Replace`，因此 `cmd` 与测试的构造方式不变。
- `Replace` 只换路由三件套，**metrics 与 logger 不换**：它们描述的是进程，不是配置。返回错误时旧状态照旧。
- 每个请求在入口读一次指针，并把 `*handlerState` 一路传下去（`route`/`prepare`/`failed`）。一个请求
  因此只可能用同一份配置完成匹配与拨号，不会出现「用新规则匹配、向旧策略组报故障」的混合状态。
- 拨号失败的 `Router.Failed` 走**当初路由它的那个** router：路径里的成员名属于旧注册表，
  报给刚加载的新注册表会怪错组。

**internal/api — 两个写端点 + 审计**

- `POST /v1/policies/select`，体 `{"group","member"}`，答 `{"group","previous","active"}`。
  拒绝有明确分类：未知组 404 `unknown_group`、非手动组 409 `not_selectable`（并说明它是哪种组）、
  成员不在组内 400 `unknown_member`（**把成员列表写进消息**，用户不必回去翻配置）。
- `POST /v1/config/reload`，无体，答 `{"ok","path","rule_count","proxy_count","group_count","host_count",
  "restart_required","elapsed_ms"}`。拒绝是 422 `reload_rejected`，消息里带全部配置问题，并显式追加
  「the previous configuration is still in force」。
- `GET /v1/audit?limit=`，答 `{"capacity","count","entries":[...]}`，条目是
  `{"time","action","result","detail","remote"}`。`limit` 复用 `/v1/rules` 的解析与上限。
- 新增 `RequestError{Status,Code,Message}` 与四个构造器（`BadRequest`/`NotFound`/`Conflict`/
  `Unprocessable`）。`Provider` 不 import 任何内部包的老规矩因此没破：它只返回 `*api.RequestError`，
  由传输层映射成状态码，未分类的错误才落到 500 `internal_error`。
- 审计用固定容量环形缓冲（`DefaultAuditCapacity = 64`，覆盖式淘汰，与失败记录同一套写法），
  动作只有 `policy.select` 与 `config.reload`，结果是 `ok` / `failed`，detail 截断到 240 字节（rune 边界）。
  每条同时镜像到进程日志（成功 info、失败 warn），`Options.Logger` 因此新增。
- 请求体走 `MaxBytesReader`（64 KiB）+ `DisallowUnknownFields`：把 `member` 拼成 `members` 会得到 400，
  而不是「成功但什么都没切换」。
- 鉴权、405 + `Allow`、`Cache-Control: no-store`、错误体形状全部沿用只读端点的同一套代码。

**cmd/melonarc-core — 重载与令牌**

- `reloader`：`config.Load` → `compileRules` → `buildResolver` → `buildDialers` → `buildRegistry` →
  `NewPolicyRouter` → `handler.Replace` → `state.install` → 关旧组 → 调日志级别。全程持一把锁，
  两次并发重载不会各自留下一套探测 goroutine。任何一步失败都在**提交点之前**返回，旧配置一字不动；
  已经建好的新组由 `defer` 关掉。
- `daemonState` 的 `cfg/program/registry/resolver` 归一把读写锁管，每个方法先取快照；
  `SelectPolicy` / `ReloadConfig` 两个写方法直接挂在同一个 `Provider` 上，传输层没改。
- 「必须重启才生效」的项在响应里点名：`api-listen`、`http-listen`、`socks5-listen`、
  `socks5-credentials`、`data-dir`。日志级别不在此列——`newLogger` 改为返回 `(*slog.Logger, *slog.LevelVar)`，
  重载直接 `Set`，所以它是唯一免重启的 `[General]` 项。
- 令牌：`api.New`（已绑定端口）之后、`srv.Start()` 之前写文件。先绑定再写，第二个守护进程因端口占用
  失败时不会覆盖正在运行那个的令牌；先写再 Start，客户端在 API 开始应答时一定能读到对应令牌。
  启动日志与 stdout 都给出文件路径，令牌本身仍打印到 stdout（保持阶段 1 的行为，便于人工核对）。
- `-check` 摘要新增两行：`data: <dir>`、`token: <path>`，仅计算路径，不创建任何东西。

**internal/cli 与 cmd/melonarc-cli**

- 逻辑放在 `internal/cli`（`Run(args, stdout, stderr) int`），`cmd/melonarc-cli` 只剩 `os.Exit(cli.Run(...))`。
  这样参数解析、错误文案、表格输出都能单测，命令行本体不需要 exec。
- 命令：`status`（`/healthz` + `/v1/status` + `/v1/inbound` + `/v1/dns` 汇总）、`policies`（组表 + 成员表，
  状态分 `unprobed`/`down`/`active`/`idle`）、`select <group> <member>`、`reload`、`explain <host[:port]>`、
  `audit [limit]`、`version`、`help`。
- 全局旗标在子命令之前：`-api`、`-token`、`-token-file`、`-data-dir`、`-network`、`-timeout`、`-json`。
  令牌来源顺序是 旗标 → `MELONARC_TOKEN` → `<data-dir>/api-token`；`-api` 缺省依次取 `MELONARC_API`、
  `127.0.0.1:7946`，允许只写 `host:port`。
- 错误文案是可执行的：连不上 → 「no core is listening at ...」+ 启动命令；令牌文件缺失 →
  「no API token at <path>」+ 三种解决办法；401 → 指出「每次启动都会生成新令牌，这个文件属于上一次运行」；
  重载被拒 → 原样打印守护进程给出的问题清单与「still in force」。
- 退出码 0 成功、1 失败、2 用法错误；`-json` 输出各端点原始视图（`status` 是四个视图的组合对象）。

### 关键决策及理由

1. **重载是「整份重建 + 一次替换」，不是「就地打补丁」。**
   规则程序、拨号器、策略注册表、解析器是四张互相引用的图，逐项替换必然出现「新规则指向旧组」的
   中间态。整份建好再换，失败的成本是零（什么都不生效），成功的成本是一次指针写。代价是配置里的
   组状态会重置（见遗留问题），但这是可解释的语义：**重载等于一次不重启的重启**。

2. **监听地址不重绑，而是列为「必须重启」。**
   重绑监听意味着关掉旧监听、丢掉在途连接、可能换端口失败后无监听可用——这是一次服务中断，
   不该藏在一次 HTTP 请求里。题面要求的「必须重启才生效的项要在响应中明确标注」正好是这个语义：
   重载负责规则与策略，进程生命周期负责监听。日志级别是唯一例外，用 `slog.LevelVar` 就地改。

3. **`Handler` 用原子指针替换状态，而不是让入站监听持有可替换的 handler。**
   `Service` 在构造时就绑定了 `handle` 函数，换 handler 要么给 `Service` 加写方法（等于把重载逻辑
   漏进入站层），要么关掉监听重建（见上一条）。把「读一次指针」放进管线入口，监听完全不用知道
   重载存在，代价是每个请求多一次原子读（纳秒级，相对一次拨号可忽略）。

4. **一个请求只认一份配置，包括失败上报。**
   状态在入口读一次并向下传，`failed` 用的是当初那个 router。否则「拨号超时 5 秒后正好发生重载」
   会把旧路径里的成员名报给新注册表，可能出现「新组里恰好有同名成员」从而误伤。

5. **令牌分发选文件，轮换选「重启即轮换」，不做显式轮换端点。**
   客户端只有本机的 CLI 与后续 UI，两者都能读同一个目录；文件是它们唯一需要知道的位置。
   显式轮换要处理「旧令牌何时失效」「文件何时替换」「正在读文件的客户端怎么办」三件事，
   而 MVP 的轮换场景只有「怀疑泄漏，立刻作废」——重启已经完成这件事，且不需要任何新语义
   （重启本来就会生成新令牌，旧令牌随之失效）。等有长驻的第三方客户端再谈端点。
   文件的原子替换与「先绑端口后写文件」的顺序见上文，它们保证不会出现「文件里的令牌对不上
   正在运行的进程」。

6. **令牌写不出去就启动失败。**
   代理进程本身能在没有令牌文件的情况下工作，但那样 CLI 与 UI 永远连不上，用户看到的是
   「守护进程在跑，工具说没有令牌」。把失败提前成一句「set data-dir to a writable directory」，
   比留一个半可用的安装状态更省事。

7. **审计沿用阶段 5 的记录风格（有界环形 + 结构化条目），而不是只写日志。**
   日志能看但不好查：`journalctl | grep` 拿不到「最近 5 次写操作的结果」。环形缓冲只有 64 条、
   不随流量增长、字段固定（时间/动作/结果/细节/来源），既能给 CLI 也能给将来的 UI 直接渲染。
   两条都留：记录是事实来源，日志行是「正在看守护进程的人不用轮询」的镜像。
   只记录**通过鉴权的**写请求：401 由中间件拦下，若也入环，任何本机进程都能把 64 条刷成噪声。

8. **写端点用 `RequestError` 表达拒绝，不 import policy。**
   写端点最需要说的是「这个组不是手动组」「这个成员不在组里」。让 `api` 认识 `policy.ErrNotManual`
   会把传输层和策略层绑死，也让错误码散落到两个包。改成 provider 返回带状态码与错误码的类型，
   `api` 只做映射：语义留在守护进程，形状留在传输层。

9. **CLI 逻辑放 `internal/cli`，`cmd` 只做 `os.Exit`。**
   参数解析、令牌解析、错误文案是这一阶段最容易写错也最容易测的部分；放在 `main` 里就只能靠
   exec 子进程测。现在 `Run` 接受 `io.Writer`，40 个用例全部是纯函数级的，集成测试里还能用同一个
   `cli.Run` 驱动真实守护进程（不必起子进程、不必处理信号与僵尸进程）。

10. **CLI 的错误消息以「下一步做什么」结尾。**
    「connection refused」对用户没有信息量。三条最可能的失败（守护进程没起、令牌文件没有、
    令牌过期）各给一句原因 + 一句动作，`-json` 不影响人类可读的错误输出。

11. **`data-dir` 只校验形状，不校验存在性。**
    校验函数一旦 `Stat`/`Mkdir`，`-check` 就不再是只读操作，而 `-check` 的用途恰恰是「在不动任何东西
    的前提下判断这份配置能不能用」。目录在写令牌时按需创建。

12. **仍无新增依赖。**
    HTTP 服务端与客户端、JSON、`atomic.Pointer`、`slog.LevelVar`、文件原子替换都在标准库里。
    `go.mod` 未改动。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...            通过
go vet ./...              通过
go test ./...             全部通过（全仓 596 个用例条目含子测试，590 通过、6 跳过）
gofmt -l .                无输出
go test -race ./internal/api/ ./internal/policy/ ./internal/cli/ ./internal/inbound/ \
             ./internal/datadir/ ./internal/config/ ./cmd/...        通过
GOOS=windows go build ./cmd/... ./internal/...                       通过
```

6 个跳过仍是阶段 2/3 记录的「回环 UDP 服务器回包」用例（本沙箱 seccomp 禁止对未连接套接字
`sendto`），与本阶段无关。本阶段新增用例条目（含子测试）：api 27、cli 42、datadir 14、config 5、
inbound 3、cmd 2。

端到端覆盖（本沙箱内实际执行，全部是回环上的真实 TCP）：

- **`TestCLISwitchesTheGroupAndReloadsTheConfiguration`**（cmd）：按 `main` 的顺序装配完整核心
  （配置 → 规则 → 解析器 → 拨号器 → 策略组 → 管线 → 入站 → API → 令牌文件），两个假 SOCKS5 出站
  各自在隧道里写自己的标签，测试据此判断「这次连接走了谁」。步骤与断言：
  首个连接由 `alpha` 承载 → `melonarc-cli select manual beta` 打印 `manual: alpha -> beta` 且下一个
  连接由 `beta` 承载 → 把 `FINAL,manual` 改成 `FINAL,missing`（外加一条指向 `ghost` 的规则）后
  `reload` 退出码 1、stderr 同时出现 `configuration problem` / `ghost` / `missing` / `still in force`，
  而连接仍由 `beta` 承载、`/v1/policies` 仍显示 `active=beta` → 写回好配置后 `reload` 成功、
  打印 `reloaded <path>`、连接回到 `alpha`（组被重建，回到首个成员）→ 只改 `http-listen` 再重载，
  响应列出 `restart required for: http-listen` 且旧地址继续服务 → `/v1/audit` 恰好 4 条，
  顺序是 ok / failed / ok / ok，成功那条记成 `manual: alpha -> beta`，被拒那条带着原因。
- **`TestDaemonDistributesTheTokenThroughTheDataDirectory`**（cmd）：`data-dir = ./state` 被解析成
  配置文件目录下的 `state`；令牌文件权限 0600、内容等于 API 实际接受的令牌；CLI 只给 `-data-dir`
  就能 `status`（证明「从文件读」这条链路，而不是靠 `-token` 作弊）。
- **写端点单元覆盖**（api）：无令牌 401 且 provider 未被调用、也未入审计；GET 打写端点 405 且
  `Allow: POST`；8 种畸形体（空体、非 JSON、数组、未知字段、两个对象、缺 group/member、空白 group）
  全部 400 且不触达 provider；provider 的四种错误映射到 404/409/400/500；重载被拒时 422 且
  message 逐字保留；审计记录顺序、`limit` 只裁剪视图不裁剪记录、环形淘汰最旧、超长 detail 被截断。
- **令牌文件单元覆盖**（datadir）：相对路径按 base 解析、绝对路径保持、无 base 的相对路径报错；
  写入后目录 0700 / 文件 0600；二次写入替换旧文件且不留临时文件；缺失与空文件被拒；空串/含空格/
  含换行/控制字符/超长令牌在写入前就被拒且不落盘。
- **可替换管线**（inbound）：`Replace` 之后下一个请求走新程序的规则；`Explain` 也读同一份状态；
  缺 matcher/router 的替换被拒且旧配置仍工作；8 个 goroutine 持续拨号 + 1 个 goroutine 反复 `Replace`
  在 `-race` 下通过。
- **CLI 单元覆盖**（cli）：缺命令 / 未知命令 / 11 种参数误用（含 `-network sctp`、端口越界、非正的 `-timeout`）都是
  退出码 2 且文案点明问题；`status` 汇总四个端点并只读一次健康检查；令牌来自数据目录；
  令牌缺失、连不上、令牌过期三种失败文案各自包含路径与下一步动作；`select` 真的发出 POST 且体正确；
  `reload` 打印生效内容与 `restart required`；被拒时逐字打印守护进程的问题清单；`explain` 把
  `Example.COM:443` 拆成 `name`/`port`/`network`；多行 detail 在表格里被压成一行。

手工演示（本沙箱内实际执行）：`-check` 打印 `data: /tmp/.../state` 与
`token: /tmp/.../state/api-token`；守护进程启动后 `state/` 是 0700、`api-token` 是 0600（44 字节）；
`melonarc-cli status` / `policies` / `explain example.com:443` / `explain 10.1.2.3:8443` 输出正确
（后者命中 `DEST-PORT,8443,REJECT`）；`select manual dead` 生效，`select manual ghost` 与
`select nope DIRECT` 分别给出 `unknown_member`（带成员列表）与 `unknown_group`；`audit` 按时间顺序
列出 5 条（1 成功、4 失败）。

演示中的一个环境限制：守护进程一旦作为后台进程留在**上一个** shell 会话里，后续会话再让它
`open` 配置文件会被沙箱拒绝（`function not implemented`），因此手工演示只能看到「重载被拒」这一半；
成功那一半由上面的进程内集成测试用真实临时文件覆盖（同一套装配代码、同一条 `reload` 路径）。

性能：热路径只多一次 `atomic.Pointer` 读，规则匹配与拨号的基准没有变化（未重跑 10 万条基准，
因为匹配代码本阶段未改动）；重载本身复用阶段 1 的编译成本（10 万条约 171–233ms），在
`/v1/config/reload` 的 30s 超时内。

### 遗留问题

- **重载会重置组的运行状态**：URL-Test / Fallback 的探测历史清零（首轮探测前按「未探针=健康」
  处理），Select 组回到首个成员——用户手动选的节点会被重载悄悄改掉。要么在重载时按名字继承选择，
  要么在响应里明确告知，MVP 目前是「重载等于不重启的重启」。
- **「必须重启」只是告知，没有后续约束**：改了 `http-listen` 又不重启，进程会一直用旧监听，
  `/v1/status` 也没有「有待生效的改动」这种字段。下一步应在状态里加 `pending_restart`。
- **端点无法轮换令牌**：轮换只能重启（本文档第 5 条的选择）。若将来有长驻的第三方客户端，
  需要补一个显式轮换端点，并处理「正在读文件的客户端」。
- **审计只在内存里**：重启即清空，容量 64，没有持久化，也没有「谁」——令牌是共享的，
  `remote` 只能区分 `127.0.0.1` 与 `::1`。
- **写端点没有速率限制**：持令牌的本机进程可以循环触发重载，每次都重新编译规则。
  本机进程既然拿得到令牌，威胁模型上并不新增能力，但值得在观测层加一个最小间隔。
- **令牌文件在 Windows 上没有 POSIX 语义**：`0600` 只落到只读属性位，真正的 ACL 收紧属于安装包阶段。
- **CLI 还缺**：`config`（打印生效配置）、`-watch`（跟随状态）、彩色/宽度自适应、shell 补全；
  `policies` 的成员表在组多时较长，没有过滤参数。
- **写端点用 body 传参**，没有 `POST /v1/policies/{group}/select` 这种路径形式；组名有字符集限制，
  用 body 是为了 POST 体形状统一，不是疏忽。
- **重载与关停没有互斥**：关停过程中到达的重载会建一套新组、随即被取消的 ctx 停掉，
  结果正确（不会泄漏 goroutine），但没有明确拒绝，日志里会多几行。
- 阶段 1–5 的遗留（mmdb、明文 DNS 上游、UDP 分片、入站并发上限、HTTP 入站认证、
  SOCKS5 的 TLS 变体、TLS 选项键、规则集更新、观测层 SQLite、TUN、UI）仍然成立。

### 下一步计划

1. 明文 DNS 上游 + 按应答 TTL 调整缓存，顺带接上 mmdb 加载器（阶段 4 第 2 项）。
2. 观测层：连接表与流量统计进 SQLite（开发文档 §2.7），`internal/store` 目前只有包声明。
3. 加密类出站，按开发文档 §2.3 的顺序推进；同时补 SOCKS5 的 TLS 变体与 TLS 选项键。
4. TUN 入站：复用 `DialUDP` 的共享中继，`Handler` 接口不需要改。
5. 桌面 UI：直接消费本阶段的 `/v1/*`（读）与两个写端点，令牌从数据目录读。
6. 补「重载继承选择」与 `pending_restart` 字段，让重载与状态视图把「需要重启」这件事闭环。

---

## 阶段 7 — 明文 DNS 上游、应答 TTL 与 mmdb 数据源（2026-11-13）

范围：`internal/dns`（线格式编解码、明文上游客户端、按应答 TTL 的缓存）、新增 `internal/geoip`
（mmdb 加载器与测试夹具生成器）、`internal/config` 的四个新键与校验、`internal/api` 的配置视图、
`cmd/melonarc-core` 的装配与重载。对应阶段 6「下一步计划」第 1 项，关闭阶段 4 遗留的
「只有系统解析器」「TTL 是固定值」与阶段 1 起一直挂着的「mmdb 接入」三条。
不含 TUN、UI、加密类出站、DoT/DoH、订阅更新。

> 说明：本阶段上一个任务运行约 20 分钟后因宿主机重启中断。接续时先读本文与开发文档、
> 再用 `git status` / `git diff` 对照范围确认已落盘的部分（线格式、上游客户端、TTL 缓存、
> 加载器、配置与装配均已存在），本阶段补完的是：截断路径的定版、超时默认值与回退可达性的
> 修正、两处测试辅助函数的加固、以及本条记录。

### 完成了什么

**internal/dns — 线格式（新文件 `wire.go`）**

- 只实现 stub resolver 需要的那一小块：A / AAAA 两种问题，其它记录按声明长度跳过，
  另外读两个东西——权威段的 SOA（负缓存寿命）与报文头里的 TC 位。
- `buildQuery` 是纯函数（ID 由调用方给），名字编码校验空名、空标签、63 字节标签上限与
  255 字节全长上限。
- `parseResponse` 的每个偏移都对着缓冲区检查；压缩指针只允许**向后**指（`pointer >= off` 直接拒绝），
  再加 32 次跳数上限，因此恶意报文只会变成错误，不会变成循环或越界读。
- 负缓存寿命按 RFC 2308 取 `min(SOA 自身的 TTL, MINIMUM)`，只认第一个 SOA。
- 未知 rcode 折成「服务器答了 N」，因为 stub resolver 对它无能为力；NXDOMAIN 与「答了但没有地址」
  分成两种 `NegativeKind`。

**internal/dns — 明文上游（新文件 `upstream.go`）**

- `Upstream` 按配置顺序逐台询问。每台服务器**同时**问 A 与 AAAA（两个 goroutine），
  所以一台不回话的服务器只花一个超时，而不是两个。
- 传输顺序固定：先 UDP（已连接套接字，读时按随机 ID 过滤杂包与伪造包），
  **被截断或 UDP 整体失败**时对同一台服务器改走 TCP（RFC 1035 的两字节长度前缀）。
- 截断只看报文头（`answerNeedsStream`）：读 TC 标志与 ID 就返回，不解析报文体。
- 每台服务器的地址只接受 IP 字面量或 `host:port`（`ParseNameServer`）；写成域名直接拒绝——
  解析解析器需要一个解析器。去重保序，默认端口 53。
- 负应答是一个类型 `*NegativeError`（`Unwrap` 到 `ErrNotFound`，带 SOA 寿命），
  分 NXDOMAIN 与 NODATA 两种；NXDOMAIN 优先于另一个地址族给出的 NODATA（前者是更强的陈述）。
- 查询 ID 来自 `crypto/rand`：可预测的 ID 允许旁路攻击者在真实服务器之前把应答塞进来。

**internal/dns — 按应答 TTL 的缓存**

- `Source` 新增 `upstream`，`Result.Expires` 原来就有，现在**正缓存的有效期由应答决定**：
  取应答里所有记录 TTL 的**最小值**（两个地址族之间也取最小）。
- 钳制是定版常量，不提供配置：正缓存 `MinAnswerTTL = 10s` / `MaxAnswerTTL = 1h`，
  负缓存 `MinNegativeTTL = 1s` / `MaxNegativeTTL = 5m`。理由写在 `dns.go` 的常量块上：
  过小的 TTL 等于关掉缓存并放大上游查询，过大的 TTL 让换过的地址长期留在缓存里；
  负应答错一次的代价更高（刚建好的名字看不见），所以上下限都更紧。
- 负缓存期限来自上游的否定应答（NXDOMAIN/NODATA + SOA 的 `min(TTL, MINIMUM)`）；
  应答里没有 SOA 时用配置的负缓存默认值 30s。
- **`[Host]` 与系统解析路径的语义一字未改**：`[Host]` 永不进缓存、`Expires` 保持零值；
  系统解析器不报告寿命，仍用固定的正/负默认值（5m / 30s）。同一份缓存里因此有两种寿命来源，
  差异写进了 `doc.go` 的包注释与 `positiveLifetime` 的注释。
- 回退：`Options.FallbackToSystem`（配置 `dns-fallback`）。默认回退，`none` 时上游失败就是失败；
  **负应答永不回退**，因为「这个名字没有地址」是上游的陈述，不是此刻的故障。
- 请求合并、缓存上限、淘汰策略、返回副本等阶段 4 的语义全部不变，上游只是多了一个 `fetch` 来源。

**internal/geoip — mmdb 加载器（新包）**

- `Open(path, kind)`：文件缺失 / 是目录 / 损坏 / 类型不符分别返回 `ErrMissing` / `ErrCorrupt` /
  `ErrWrongKind`，每条都带路径。类型判断是对元数据里类型字符串的启发式（只区分「ASN 库」与
  「国家库」互不通用），因为类型名是发布方自由命名的。
- `Country` / `ASN` 实现 `rules.GeoIPLookup` / `rules.ASNLookup`，接口一字未改；
  `country` 记录没有 `iso_code` 时退到 `registered_country`（地址由另一国宣告的常见情形）。
- `Cache`：按 (path, kind, size, mtime) 复用句柄，配置重载不会重复映射同一个几 MB 的文件；
  文件换过则开新句柄，**旧句柄不关**——重载前开始的请求可能还在用旧规则程序读它。
- `internal/geoip/geoiptest` 是测试用的最小 mmdb **写**器（二分树 + 16 字节分隔 + 数据段 +
  元数据标记 + 元数据）。夹具由被测的读取器自己读回，所以是「读者校验的数据」而不是自说自话的假文件。

**internal/config**

- `[General]` 四个键：`dns-nameserver`（逗号分隔，**保序**）、`dns-fallback`（`system` / `none`）、
  `dns-timeout`、`geoip-db` / `asn-db`。没有新开分节。
- 校验只做形状：服务器地址交给 `dns.ParseNameServer`（与客户端同一份实现，配置能通过就能问）、
  fallback 只认两个词、timeout 必须为正、**配了 `dns-fallback` 却没有服务器是错误**
  （否则用户以为这个开关生效了）、数据文件路径限长且不含控制字符。
- 校验**不碰文件系统**：数据文件是否存在是加载器的问题，`-check` 仍然只读。
- `DataPath` 把相对路径按配置文件所在目录解析，与规则集同一条规则。

**internal/api 与 cmd/melonarc-core**

- `ConfigView` 增加 `dns_nameserver` / `dns_fallback` / `geoip_db` / `asn_db`；后三个 `omitempty`，
  `dns_fallback` 总是拼成 `system` 或 `none`，客户端不必知道默认值。
- `buildResolver` 建上游客户端并交给解析器；`compileRules` 先开数据集再编译规则；
  `reloader` 与启动路径共用同一个 `geoip.Cache`；`datasets.Close()` 排在关闭顺序的最后。
- `-check` 摘要新增 `dns:` 与 `geoip: …, asn: …` 两行（关闭的显示 `off`）。

**测试**

- 单元（`internal/dns`）：假 DNS 服务器（TCP 常开、UDP 可选）驱动 TTL 驱动过期、上下限钳制、
  上游负应答寿命、多服务器顺序、静默服务器超时、上下文优先于配置超时、错误里带服务器地址；
  线格式 8 个恶意/截断报文用例；`answerNeedsStream` 5 个用例，含「被截断且报文体正好断在记录中间」。
- 单元（`internal/geoip`）：与内存实现**逐地址对照**（含两个地址族、库未覆盖的地址、库外的地址）、
  `registered_country` 回退、缺失/目录/损坏/类型不符四种错误、缓存复用与关闭。
- 集成（`cmd`）：`TestPipelineResolvesThroughTheConfiguredUpstream`（只存在于测试服务器的名字 →
  上游解析 → 命中 `IP-CIDR` → 到达源站，第二次请求不再问上游）、
  `TestGeoIPRuleMatchesTheConfiguredDatabase`（同一条规则因数据库内容不同而 403 / 200）、
  `TestCompileRulesReportsAnUnusableDatabase`、`TestConfigViewReportsTheDataSources`。
- 顺手修掉一个测试辅助函数的端口复用竞态：`freePort` 原来用 `:0` 取端口再关闭，内核会把同一个端口
  发给本进程的下一个监听器，于是「拨一个没人听的端口」变成「拨到自己的代理上」，失败类别从
  `refused` 变成 `unknown`（本阶段全量跑测时命中过一次）。改为从临时端口范围以下取号并计数分配，
  断言语义不变。

### 关键决策及理由

1. **mmdb 走现成库，不自研最小读取器（路线定版）。**
   选 `github.com/oschwald/maxminddb-golang v1.13.1`。格式本身包含可变宽度二分树、数据段的类型系统
   与指针压缩、元数据段；自研最小读取器是六百行以上的解析代码，而且**错误是静默的**——读错一个偏移
   不会报错，只会让地址落进错误的网段，于是路由决策安静地走错，这比崩溃难查得多。
   库的许可证是 ISC（首行 `ISC License`，宽松许可，GPLv3 兼容），运行期只额外用到已在依赖里的
   `golang.org/x/sys`，没有新的传递运行时依赖。按开发文档 §1.3 / §7 登记如下：
   **`github.com/oschwald/maxminddb-golang` v1.13.1，ISC，用途：读取 mmdb 数据文件**。
   这也是本项目第一个被 `internal/` 与 `cmd/` 真正用到的第三方库：`go.mod` 里原有的
   `golang.org/x/*` 与 `quic-go` 只被 `spikes/` 使用，产品代码到阶段 6 为止全是标准库。
   选它的理由不是「省事」，而是「解析器写错的代价是静默的错误路由」。

2. **数据文件坏掉时启动直接失败，与阶段 1 的拒绝策略同一条线。**
   `GEOIP` / `IP-ASN` 规则在阶段 1 就定成「缺数据集不得编译」，现在数据集由文件提供，于是
   「文件缺失/损坏」自然落进同一条：`compileRules` 在开库这一步返回错误，进程不启动（`-check` 同样报错），
   重载则被拒且旧配置一字不动。错误里同时给出设置名与文件路径，例如
   `geoip-db: geoip: database file does not exist: /path/country.mmdb`。
   另一条路是「加载失败就跳过该规则、其余照跑」，但那会让一条拦截规则在数据文件丢了之后安静地
   不再拦截——与阶段 1 拒绝的正是同一种失败模式，所以不做。**行为定版：拒绝启动，不降级。**

3. **截断只看报文头，不看报文体。**
   本阶段最后一段工作。被截断的报文很可能正好停在一条记录的中间，如果按「报文体能不能解析成功」
   来决定要不要重试，就会把「服务器要求你改走 TCP」误判成「服务器给了坏报文」，然后把这个错误
   一路报上去。改成先读头部两个字段（ID 与 TC）再决定，报文体只在确定要使用时才解析。
   `answerNeedsStream` 因此是一个只依赖头部的纯函数，可以直接喂字节测——沙箱里 UDP 回环不通，
   这条路径的判定逻辑仍然有完整覆盖。

4. **负应答不回退系统解析。**
   回退的意义是「上游此刻不工作」，而 NXDOMAIN / NODATA 是上游在工作并且给出了结论。
   对负应答回退，等于用一个可能更陈旧、更宽松的解析器覆盖它，还会让「上游说没有」这件事
   在负缓存里变成一次系统查询。所以只有传输失败（超时、拒绝、连接失败）才轮到系统解析器。

5. **TTL 随应答，但钳制不随应答。**
   「服务器给多长就缓存多长」在两端都危险：1 秒的 TTL 让缓存形同虚设并把查询量放大，
   一周的 TTL 让换过的地址长期留在缓存里。所以上限下限是定版常量而不是配置项——用户没有
   信息去调它，而这两个数是「够短不至于长期错、够长不至于每连接一查」的折中。负缓存的上下限
   更紧，因为负应答错一次的代价更高。

6. **per-attempt 超时默认 1 秒，不是 2 秒（本阶段改下来的）。**
   整个查询由解析器的 `Options.Timeout`（默认 5s）兜住，而一台服务器最多花「一次 UDP + 一次 TCP」
   两个 per-attempt。原来的 2s 意味着两台服务器就能吃掉 8s，**系统回退永远拿不到时间**，
   `dns-fallback = system` 就成了一句代码兑现不了的承诺。改成 1s 后最坏情况是 4s，5s 预算里
   还剩 1s 给回退。这条算术现在有测试守着（`TestDefaultUpstreamTimeoutLeavesRoomForTheFallback`），
   改默认值而不改预算会当场失败。服务器数量没有上限，配很多台仍会吃光预算，这条写进遗留问题。

7. **配置键放 `[General]`，不新开 `[DNS]` 分节。**
   开发文档 §2.6 把原生配置的分节钉死在五个（`[General]` / `[Proxy]` / `[Proxy Group]` /
   `[Rule]` / `[Host]`），新增一节就破坏了「可手改、可版本管理」的既有形状与既有解析器。
   题面也允许「以开发文档与现有 config 分节设计为准」。代价是 `[General]` 变长，收益是
   不需要动分节列表、不需要动 `-check` 摘要与 API 视图的结构。

8. **测试夹具自己写 mmdb，不把真实数据集放进仓库。**
   真实库是几 MB 到几十 MB，并带有自己的授权条款（开发文档 §7 要求按其条款分发或提供下载脚本）。
   自己写一个最小写入器（约 300 行）之后，夹具是**被测读取器读得通的文件**，等价性测试才是真的
   「同一份映射，两种实现，逐个地址对照」，而不是拿一个手搓的假结构自证。

9. **数据集句柄进程级缓存，旧句柄不在重载时关闭。**
   重载是「整份重建 + 一次替换」，但替换的瞬间可能有请求还挂在旧规则程序上，而旧程序手里的
   `*Database` 仍指向旧文件。关掉它会让那些请求读到已经解除映射的内存。所以按
   (path, kind, size, mtime) 复用句柄、换文件时开新的、旧的一律留到进程退出。
   代价是频繁换库会累积映射，写进遗留问题。

10. **`-check` 会打开数据文件，但仍然没有副作用。**
    阶段 6 定的规矩是「校验不得产生副作用」（不建目录、不写令牌），读一个文件不属于副作用。
    这样 `-check` 能回答「这份配置能不能用」而不仅是「形状对不对」——数据文件缺失在启动前就被发现。

11. **命名卫生：只用格式名，不出现任何商业数据集名称。**
    代码、注释、文档里出现的是格式名（mmdb / MaxMind DB）与协议名（DNS、RFC 1035、RFC 2308），
    没有任何数据发布方的产品名；测试夹具的文件类型故意叫 `Test-Country` / `Test-ASN`。

### 当前状态

全部验收命令在仓库根目录执行，使用 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...            通过
go vet ./...              通过
go test ./...             704 个用例条目含子测试：696 通过、8 跳过、0 失败
gofmt -l .                无输出
go test -race ./...       全部通过（含 dns / rules / inbound / geoip / config / cmd）
GOOS=windows go build ./cmd/... ./internal/...                通过
GOOS=windows go vet ./cmd/... ./internal/dns/ ./internal/geoip/  通过
go mod verify             all modules verified
```

8 个跳过：6 个是阶段 2/3 记录的「回环 UDP 服务器回包」用例，2 个是本阶段新增的
`TestUpstreamRetriesOverTCPWhenTruncated` 与 `TestUpstreamAnswersOverUDP`——同样需要一台 UDP 服务器
向未连接的地址回包。原因一致：本沙箱的 seccomp 策略禁止对未连接套接字调用 `sendto` / `sendmsg`
（EPERM），与代码无关，普通机器上会正常执行。为此没有放宽任何断言：截断的**判定**由
`TestAnswerNeedsStream`（纯头部，5 个用例含报文体被切断）覆盖，TCP 传输本身由
`TestUpstreamAnswersOverTCP` 覆盖，TTL 过期与钳制走注入的 exchange，回退走真实套接字。

`go.mod` 变化：新增 `github.com/oschwald/maxminddb-golang v1.13.1`（ISC，见决策 1），
`go mod tidy` 把它从间接依赖移到直接依赖；`go.sum` 增加两行，没有其它变动。

端到端覆盖（本沙箱内实际执行，全部是回环上的真实 TCP）：

- **上游解析进管线**（`TestPipelineResolvesThroughTheConfiguredUpstream`）：测试内起一台只监听 TCP 的
  DNS 服务器（UDP 那一半没有监听，所以数据报尝试立刻失败、应答必须走流，顺带覆盖了传输回退），
  `routed.test` 只存在于这台服务器。配置里 `dns-fallback = none`、规则是
  `IP-CIDR,127.0.0.1/32,DIRECT` + `FINAL,REJECT`。请求经 HTTP 入站打到源站拿到正文——
  说明名字确实被解析成了 `127.0.0.1` 并命中了 IP 规则；第二次请求后服务器被问的次数不变，
  说明应答进了缓存。
- **GEOIP 分流从数据文件来**（`TestGeoIPRuleMatchesTheConfiguredDatabase`）：同一份配置只换数据文件，
  `GEOIP,ZZ,REJECT` 在库把 `127.0.0.0/8` 标成 `ZZ` 时返回 403，标成 `YY` 时返回 200。
  一条规则两种结果，证明分流真的读了数据库，而不是恒真或恒假。
- **数据文件不可用**（`TestCompileRulesReportsAnUnusableDatabase`）：缺失与损坏两种，错误里同时出现
  设置名、路径与原因。

`-check` 手工演示（本沙箱内实际执行，配置里两台上游 + 一份生成的夹具）：

```
dns: 127.0.0.53:53, 9.9.9.9:53 (fallback: system)
geoip: /tmp/demo/country.mmdb, asn: off
```

同一个进程日志里打出 `geoip database loaded path=… type=Test-Country ip_version=6`。
把 `geoip-db` 指向不存在的文件：

```
melonarc-core: rule set is not usable:
geoip-db: geoip: database file does not exist: /tmp/demo/absent.mmdb: …
```

指向一个随便写的文件则是 `geoip: database file is not usable: …: error opening database: invalid MaxMind DB file`。
演示脚本里生成夹具用的小程序用完即删，仓库里只有 `geoiptest` 这个写入器。

### 遗留问题

- **上游只有明文 UDP/TCP**：没有 DoT / DoH，也没有 EDNS0——大应答一律靠 TC 位触发 TCP 重试，
  多花一个往返。
- **不做 DNSSEC 校验**：只有随机 ID、已连接套接字与随机源端口这三层，够挡旁路伪造，不够挡
  被篡改的链路。
- **每个查询新建套接字**：UDP 一次一开一关，TCP 更是每次重新握手；查询量大的时候值得做一个
  小连接池（TCP 连接可复用，RFC 7766）。当前没有测量，也没有池化。
- **A 与 AAAA 各发一次查询**：每个名字两条查询、两份上游负载；没有「先 A 后按需 AAAA」的退让策略。
- **服务器数量没有上限**：`dns-nameserver` 配很多台时，按 per-attempt 超时算最坏情况会吃光
  查询预算，回退再次变得不可达。默认值下（≤2 台）有测试守着，但没有校验拦下更长的列表。
- **钳制值是定版常量**：想更长的正缓存只能改代码。这是有意的（用户没有信息去调），但如果
  运维确实需要按站点调，得先有一个「为什么这个数」的说法。
- **系统解析路径的寿命仍是固定值**：拿不到 TTL，与上游路径的语义差异会一直存在；
  `/v1/dns` 也仍然只报计数，看不出「这次是哪条路径答的」。
- **数据集不释放旧版本**：重载换库后会同时持有新旧两份映射，长期运行 + 频繁换库会累积。
  需要引用计数 + 延迟关闭。
- **只读 `country` / `registered_country` / `autonomous_system_number`**：城市、洲、是否匿名代理等
  字段没有暴露，规则类型也只有 `GEOIP` / `IP-ASN`。
- **`dns-fallback` 只有两个词**：没有「先上游后系统再上游」这类顺序编排，也没有按名字后缀选上游。
- **失败回退不可观测**：回退发生了只体现在 `Source=system` 与 debug 日志里，`/v1/dns` 没有
  「上游失败次数」这一项。
- 阶段 1–6 的遗留（TUN、加密类出站、SOCKS5 的 TLS 变体、TLS 选项键、UDP 分片、入站并发上限、
  HTTP 入站认证、规则集更新、观测层 SQLite、UI、重载继承选择、`pending_restart`）仍然成立。

### 下一步计划

1. TUN 入站：复用 `DialUDP` 的共享中继做「一关联多目的地」，`Handler` 接口不需要改；
   直连目的地走本阶段的解析器。
2. DNS 的下一步：DoT/DoH 上游、上游连接池、`/v1/dns` 增加按来源与失败原因的计数。
3. 观测层：连接表与流量统计进 SQLite（开发文档 §2.7），`internal/store` 目前只有包声明。
4. 加密类出站，按开发文档 §2.3 的顺序推进；同时补 SOCKS5 的 TLS 变体与 TLS 选项键。
5. 数据集的引用计数与延迟关闭，让「换库」不再累积映射。
6. 桌面 UI：直接消费 `/v1/*`（读）与两个写端点，令牌从数据目录读。

## 阶段 8 — TUN 入站（2026-11-13）

### 完成了什么

按阶段 7「下一步计划」第 1 项接续：`Handler` 接口本身没有改，TUN 作为第三种「目的地来源」
接进阶段 3 的管线；UDP 复用共享中继做「一关联、多目的地」；直连目的地仍走阶段 7 的解析器。

- **设备与包循环**（`internal/inbound`）：`packet.go` 是纯 IPv4/TCP/UDP 解析与编码（含校验和、
  ICMP echo 应答）；`device_linux.go` 用 `/dev/net/tun` + `TUNSETIFF(IFF_TUN|IFF_NO_PI)`
  开设备，rtnetlink 做地址、Link Up/MTU、路由三项最小设置，非阻塞 fd 用短 poll 读以便关停；
  `tun.go` 是设备无关的 `TUNService`，负责读循环、TCP/UDP/ICMP 分流、DNS 拦截与空闲回收循环。
- **TCP 桥接**（`tuntcp.go`）：小型用户态 TCP 栈，完成 SYN/SYN-ACK/ACK 握手、累积确认、
  MSS 选项、PSH 数据、有界指数退避重传、FIN 半关闭、未知流/拨号失败 RST。`tunTCPConn`
  实现 `net.Conn`，直接复用阶段 3 唯一的 `relay` 半关闭实现，向 `Handler.Stream` 提交
  `Request{Target, Network}`，规则分流逻辑一行未改。
- **UDP 会话**（`tunudp.go`）：按源/目标四元组维护会话，512 上限，注入时钟的空闲超时回收，
  应答按会话还原成 IP/UDP 包写回设备；`outbound/shared.go` 增加 `SharedPacketConn` /
  `SharedDialer`，SOCKS5 复用阶段 2 的 `UDPRelay`（加了一层不改旧签名的适配），
  DIRECT 用「每目的地一条已连接套接字」的共享中继并复用 `Direct.Lookup`；
  `pipeline.go` 的 `Handler.Datagrams` 按（状态代数、策略路径、源端点）池化关联，引用计数释放，
  `Replace` 换掉旧状态代数时关闭空闲关联。
- **DNS 与名字地址**（`tundns.go`、`internal/dns/answer.go`）：设备上的 DNS 查询用
  `ParseQuestion` / `AnswerQuestion` 回答；A 查询分配 `198.18.1.0/24` 的令牌地址并记录
  「地址 → 名字」，命中令牌地址的 TCP/UDP 包在 `TUNService.destination` 映射回域名，
  所以域名规则与 DIRECT 的解析器看到的仍是名字。AAAA 给 NODATA、未知名 NXDOMAIN、
  解析失败 SERVFAIL；令牌 10 分钟不用即回收。
- **平台边界**：`device_windows.go`（`//go:build windows`）、`device_other.go`
  （`//go:build !linux && !windows`）与 `device_linux.go` 共用 `tunDevice` 接口和
  `deviceConfig`。Windows 侧只做驱动 DLL 与导出名的运行时探测，会话未实现时明确报错，
  不假装可用；其它平台返回「仅 Linux/Windows 有实现」。
- **配置与装配**：`[General]` 增加 `tun-enable` / `tun-name` / `tun-address` / `tun-mtu` /
  `tun-route` / `tun-udp-timeout`，默认关；校验沿用现有聚合错误风格（关着却写了 `tun-*`
  直接报错、名字形状、IPv4 CIDR、MTU 576–65535、路由数上限、超时上限）。
  `cmd/melonarc-core` 在 socket 入站之后启 TUN，失败则回滚已起的入站；关停先关 TUN 再关
  其它入站。`ConfigView` 增加只读字段，六个键全部列入 `restart_required`。
  `-check` 只校验形状，绝不建设备、改路由或写文件。
- **测试**：IP/TCP/UDP/ICMP 解析与校验和、会话表增减与超时回收、名字地址池复用与清扫、
  DNS 应答、配置校验、装配与 reload 的单元测试；内存设备上的确定性 TCP/UDP 端到端；
  `tun_linux_test.go` 是真实 `/dev/net/tun` 的回环集成测试，默认跳过并附普通机器的复现命令。

### 关键决策及理由

1. **TCP 桥接选「自研小型用户态 TCP 栈」，不引入第三方网络栈**。开发文档 §4 允许
   「gVisor netstack 或同类开源栈」，但引入一个完整的用户态协议栈会带来新的依赖、许可证
   登记和长期维护面；本阶段只需要承载**本机**客户端经 TUN 进来的流，协议子集可以枚举
   （IPv4、无乱序重组、无窗口缩放、无拥塞控制、固定 65535 窗口）。自研版本只用标准库，
   `go.mod` / `go.sum` 零变化。决定性收益是 `tunTCPConn` 实现 `net.Conn`，
   于是阶段 3 那份唯一的 `relay` 半关闭实现和 `Handler.Stream` 规则管线可以原样复用，
   不必为 TUN 写第二套转发逻辑。代价是功能边界窄，见遗留问题。
2. **用「名字地址」而不是真实解析结果回答 TUN 侧 DNS**。若把解析出的真实 IP 交给内核
   路由进 TUN，进程内再拨这个 IP 会重新落回设备，形成回环；令牌地址只作索引、永不拨号，
   映射回域名后域名规则、负缓存、`Direct.Lookup` 全部照常工作。令牌段与设备段分开，
   `tun-route` 必须显式写才会接管，默认不悄悄改全局路由。
3. **共享 UDP 关联做成 outbound 的能力而不是入站的特例**。`SharedPacketConn` /
   `SharedDialer` 是可选接口：支持者（SOCKS5 的 `UDPRelay`、DIRECT 的新中继）走一条关联，
   不支持者由 `singleDestinationDatagram` 降级成每目的地一条 `PacketConn`。池化键带
   `handlerState` 指针，重载后不会出现「新规则配旧关联」，也不会把故障报给同名新成员。
4. **Windows 只做构建标签隔离与诚实降级**。本阶段 Linux 才是可运行验收平台；Windows 侧
   若伪造可用会在真机上静默丢包，因此运行时明确返回「驱动未安装 / 适配器会话未实现」，
   并把 DLL 名与导出名集中在唯一一个 `windows` 文件里，其余包无平台条件判断。
5. **配置不新增段、默认关、校验无副作用**。与阶段 7「保持五个段」的决定一致；TUN 与
   路由是特权操作，老配置升级后不能凭空得到一个设备。设备/路由无法安全热替换，
   所以六个键全部进 `restart_required`，重载语义仍是「一次不重启的重启」。
6. **校验和必须由接收端独立验证**。伪头的「0 + 协议号」是一个 big-endian 16 位字，
   值就是协议号本身，不是 `protocol << 8`。真实设备集成测试第一次跑出握手超时，
   追下去发现 `transportChecksum` 写成了移位，所有发出的 TCP/UDP 校验和都是错的，
   内核静默丢包；原有单测用生成函数自己校验自己，错误被抵消掉了。已修正并新增
   `verifyTransportChecksum`（按线上格式独立重算，正确的包折叠为 0）覆盖 TCP/UDP/带数据三种情况。
7. **依赖登记**：本阶段**没有新增任何依赖**，`go.mod` / `go.sum` 无变化。生产代码首次使用
   `golang.org/x/sys/unix`：

   | 组件 | 版本 | 许可证 | 用途 | 与 GPLv3 |
   |---|---|---|---|---|
   | `golang.org/x/sys/unix` | v0.50.0（已在 go.mod，spikes 引入） | BSD-3-Clause（Go Authors） | Linux 侧 `/dev/net/tun` ioctl、poll、rtnetlink 常量与结构体 | 兼容 |

   TUN 驱动类依赖单独核查：Windows 侧**没有链接、没有 vendor、没有分发**任何驱动代码或
   二进制，只在运行时按名字探测系统已安装的 `wintun.dll` 及其导出函数。该驱动源码是
   GPLv2（与本项目 GPLv3 不能直接合并源码），官方预编译签名 DLL 另按其发行包内的
   宽松许可分发，条款不同。因此本阶段不构成引入；**将来若随发行包分发该 DLL，必须单独
   登记当时的版本与随包许可，并复核与 GPLv3 的关系**。Linux 侧是内核自带的 TUN 设备，
   无第三方驱动。

### 当前状态

全部命令在仓库根目录执行，工具链为 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...                                      通过
go vet ./...                                        通过
go test ./...                                       757 个用例条目含子测试：746 通过、11 跳过、0 失败
go test -race ./...                                 全部通过（含 inbound / outbound / dns / config / cmd）
gofmt -l .                                          无输出
GOOS=windows go build ./cmd/... ./internal/...       通过
GOOS=windows go vet   ./cmd/... ./internal/...       通过
go mod verify                                       all modules verified
```

11 个跳过：8 个是阶段 2/3/7 记录的「回环 UDP 服务器回包」用例（本沙箱 seccomp 禁止对
未连接套接字 `sendto`/`sendmsg`），2 个是本阶段新增的 `DirectSharedUDP` 真套接字用例，
1 个是 `TestTUNLinuxLoopback`（需要 CAP_NET_ADMIN，默认跳过）。原因均与代码无关，
普通机器上会正常执行。

**特权集成测试在本沙箱内实际跑通**（不是只留了代码）：

```
go test -c -o /tmp/inbound.test ./internal/inbound
unshare -Urn env MELONARC_TUN_LOOPBACK=1 /tmp/inbound.test -test.run TestTUNLinuxLoopback -test.v
--- PASS: TestTUNLinuxLoopback (0.01s)
```

用的是真实 `/dev/net/tun`、真实内核 TCP 客户端、真实已连接 UDP 套接字：SYN 经内核路由进设备，
用户态栈握手后经编译规则与 `Handler` 到本地源站，应答以 IP 包写回并被内核交给套接字；
UDP 数据报经会话表到共享关联，注入的应答也能回到客户端。本沙箱限制 `connect` 到
`127.0.0.0/8` 之外（返回 ENETUNREACH），所以测试沿用 `spikes/tun` 验证过的办法：
把 `127.0.0.9/32` 路由到设备、临时摘掉 local 表的 `127.0.0.0/8`、开启 `route_localnet`，
退出时恢复。**该改动只在私有网络命名空间里做，文档注释已明确要求 `unshare -Urn`**。
`MELONARC_TUN_DEBUG=1` 可打开包级日志。

**验收偏差（需明确记录）**：字面量 `GOOS=windows go build ./...` 仍未通过，失败只来自
`spikes/tun/main.go` 与 `spikes/quic/main.go` 两个历史 Unix-only 原型
（`undefined: unix.Open` / `unix.Connect` 等）。`spikes/` 与 `docs/` 是只读历史材料，
本阶段一个字未改；产品包的 `GOOS=windows go build ./cmd/... ./internal/...` 与对应 vet
全部通过，这也与阶段 7 记录的验收命令一致。要让字面命令全绿，唯一做法是在那两个 spike
文件加 `//go:build linux`，这会触碰禁改目录，需要单独授权。

### 遗留问题

- **Windows 未做实机验证**：只有交叉编译通过。`device_windows.go` 的运行时路径明确返回
  「驱动未安装 / 适配器会话未实现」——适配器创建与销毁、会话收发包循环、驱动安装与分发
  都没写，也没有在任何 Windows 真机上跑过。不得写成已验证。
- **`GOOS=windows go build ./...` 字面命令未全绿**，原因与所需授权见「当前状态」。
- **用户态 TCP 功能边界**：仅 IPv4；无乱序重组、SACK、窗口缩放、拥塞控制；固定 65535
  窗口与有界重传；IP 分片一律丢弃。大流量或高丢包链路上没有实测。
- **DNS 只答 A**：AAAA 给 NODATA；TUN 侧没有 DNS over TCP；名字地址池只有 /24（254 个），
  大量并发名字会互相顶掉，且映射失效后该地址的包被丢弃。
- **没有连接数/关联数上限**：UDP 会话上限 512，DIRECT 共享中继是「每目的地一条已连接
  套接字」，没有独立配额。
- **路由改动没有兜底**：设备地址与路由由进程直接改，进程被强杀不会自动回滚；没有租约
  或退出看门狗。`-check` 也不探测驱动/能力是否真的存在。
- **重载语义**：TUN 六个键全部 `restart_required`，重载会清空会话表与名字地址映射；
  这一点目前只有 `restart_required` 提示，没有更细的运维说明。
- **ICMP 只答 echo request**，IPv6 包全部丢弃（设备起来时内核发出的 IPv6 流量可见于
  debug 日志）；TUN 侧没有 IPv6 目标。
- 阶段 1–7 的遗留（加密类出站、SOCKS5 的 TLS 变体、TLS 选项键、UDP 分片、入站并发上限、
  HTTP 入站认证、规则集更新、观测层 SQLite、UI、重载继承选择、`pending_restart`、
  DoT/DoH 上游与连接池等）仍然成立。

### 下一步计划

1. Windows 实机路线：实现适配器会话与收发包循环、驱动安装/卸载清理，明确 DLL 分发方式并
   按当时的许可单独登记，然后在真机验证。**这一步做完之前 Windows 只能算「可交叉编译」。**
2. 用户态 TCP 补 IPv6、乱序重组、背压与窗口缩放；或先做一轮大流量实测，再决定是否换成
   成熟开源栈（引入时按规则登记名称、版本、许可证、用途）。
3. 名字地址池扩到更大网段并加 LRU；TUN 侧 DNS 支持 TCP 与可配置的 AAAA 策略。
4. 路由/设备改动的进程退出兜底（信号 + 看门狗），并把「TUN 配置必须重启」写成运维文档。
5. 承接阶段 7 的 DoT/DoH 上游与上游连接池、`/v1/dns` 按来源计数；随后推进观测层 SQLite、
   加密类出站与桌面 UI。

---

## 阶段 9 — TLS 基座与 TCP 类加密出站（2026-11-14）

范围：按开发文档 §2.3 的出站协议清单，接续阶段 8 遗留的「加密类出站、SOCKS5 的 TLS 变体、
TLS 选项键」。本阶段只做 TCP 类加密出站与共用的 TLS 拨号配置；QUIC 类出站、分享链接与
订阅导入不在范围内（理由见关键决策 9）。`spikes/` 与 `docs/` 一个字未改。

### 完成了什么

- **统一 TLS 基座**（`internal/outbound/tls.go`、`proxyconn.go`）：所有需要保护这一跳的出站
  共用 `TLSOptions{Enabled, ServerName, SkipVerify, ALPN, Config}` 与 `For(host)` / `Wrap(ctx, conn, host)`。
  四个键全部写在 `[Proxy]` 行上：`sni`（证书名/SNI 覆盖）、`skip-cert-verify`（关闭证书校验）、
  `alpn`（用 `|` 分隔，因为原生配置按逗号切参数）、`tls`（仅协议本身可选 TLS 时用于开关）。
  `tlsModeFor` 是唯一的模式表：`socks5-tls` / `https` / `trojan` 恒为 TLS，`vmess` 可选，
  其余类型不接受任何 TLS 键。`dialProxyHop` 统一拨号、超时与 TLS 包装，`completeHandshake`
  统一取消守卫与握手后清理 deadline。
- **配置层接入**（`internal/config`）：`knownProxyTypes` 增加 `socks5-tls`；`validateProxies`
  调用 `outbound.ValidateTLSOptions`，坏值、重复键、明文类型上误写 TLS 键、恒 TLS 类型上
  误写 `tls=` 都进聚合错误，形状仍是 `[Proxy] line N: ...`。`ValidateTLSOptions` 只读 TLS 键，
  其它协议参数仍由装配期的 `outbound.New` 解释。
- **补齐阶段 2 遗留的 SOCKS5 TLS 变体**：`SOCKS5Options.TLS` 让 `openControl` 在 SOCKS5
  协商之前包裹控制连接（UDP ASSOCIATE 的控制连接同样走这条路）。HTTPS CONNECT 删掉原来
  直接 `tls.Client` 的路径，改走同一个基座；`TLSConfig` 仅作为测试用的信任根替换口。
- **Shadowsocks**（`aead.go`、`shadowsocks.go`、`blake3.go`）：三种传统 AEAD
  （`aes-128-gcm` / `aes-256-gcm` / `chacha20-ietf-poly1305`）与三种 2022 BLAKE3 套件
  （`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`），
  TCP 与 UDP 都实现。传统侧用 `EVP_BytesToKey` + `HKDF-SHA1(ss-subkey)` 与长度/载荷双块分片；
  2022 侧用固定长度 base64 PSK、`blake3DeriveKey("shadowsocks 2022 session subkey", psk||salt)`、
  带类型/时间戳/回显请求 salt 的请求与应答头（校验时间窗与 salt 绑定）、AES 独立头 +
  XChaCha20-Poly1305 的 UDP 封装。BLAKE3 是自研的最小实现，用官方测试向量校验，见决策 3。
- **VMess AEAD**（`vmess.go`）：AuthID（时间戳 + 随机 + CRC32，用 KDF 派生密钥做单块 AES）、
  嵌套 HMAC-SHA256 KDF、认证长度块 + 连接 nonce + 认证头块、带 FNV1a 校验的请求头
  （端口在地址前，使用协议自己的 ATYP 编号）、AEAD 应答头、
  `aes-128-gcm` / `chacha20-poly1305` 双计数 nonce 的分片体。TCP 与 UDP 共用一套头和体，
  UDP 每个分片带自己的目标地址前缀；TLS 由 `tls=true` 打开。
- **Trojan**（`trojan.go`）：TLS 恒开，`hex(SHA224(password)) + CRLF + CMD/ATYP/ADDR/PORT + CRLF`，
  TCP 用 CONNECT，UDP 用 UDP ASSOCIATE 并在同一条 TLS 流上按
  `ATYP/ADDR/PORT/Length/CRLF/Payload` 分帧。
- **Snell v4 / v5**（`snell.go`）：Argon2id(`psk`, `salt`, t=3, m=8KiB, p=1) 派生每方向密钥，
  16 字节方向 salt、7 字节 AEAD 帧头、每帧两次推进的 12 字节小端 nonce、padding 与密文
  偶数位互换；TCP 用 v4 的 `Connect` / v5 的 `ConnectV2`，UDP 用 `UDP` 命令的逐帧封装。
  v5 另实现首帧 0x100–0x1FF 填充块与动态记录尺寸（首帧小、逐帧放大、30 秒空闲复位），
  支持 `aes-128-gcm` 与 `chacha20-ietf-poly1305` 两种套件。
- **注册与装配**：`outbound.New` 的 switch 扩展到 `socks5-tls` / `https` / `ss` / `vmess` /
  `trojan` / `snell`；`cmd/melonarc-core` 的 `buildDialers` 一行未改，所有新协议照旧注册进
  `outbound.Set`，因此可直接作为策略组成员。`vless` / `hysteria2` / `tuic` 仍返回
  `Unsupported`（两处旧测试据此把「未来协议」的样例换成了 `vless`）。
- **测试**：为每种协议写了对端测试服务器，端到端往返覆盖
  Shadowsocks 6 种套件的 TCP echo 与 UDP echo、VMess 的明文/TLS × 两种加密 TCP echo 与 UDP、
  Trojan 的 TCP echo 与 UDP、Snell v4/v5 × 两种套件的 TCP echo 与 UDP，以及 SOCKS5-TLS、
  HTTPS 基座的往返。失败路径覆盖错密码 / 错 PSK / 错 UUID / 错加密套件 / 错版本号 /
  篡改的 2022 应答 salt。BLAKE3 用官方 hash、keyed hash、derive_key 向量校验；VMess 无公开
  数值向量，改为校验 KDF 确定性与域分离、AuthID 校验和、头封装与篡改检测、请求头解析；
  Snell 用裸线读取首帧校验 v4/v5 的填充与命令差异。配置层新增 6 个用例校验 TLS 键的
  分节/行号报错与合法组合。

### 关键决策及理由

1. **TLS 键放在 `[Proxy]` 行，不新增配置段**。开发文档 §2.6 定死五个段，且这些选项是
   「某一个代理这一跳怎么建」而不是全局开关。用一张 `tlsModeFor` 表同时驱动校验器与构造器，
   校验期就能拒绝「明文类型写了 `sni`」「恒 TLS 类型写了 `tls=true`」，避免装配期才炸，
   也避免悄悄退化成明文。`tls=` 只允许 `vmess`，因为其它类型的类型名已经决定了是否用 TLS。
2. **所有加密出站共用一份 TLS 实现**。`For` 生成 `*tls.Config`（最低 TLS 1.2、默认用代理
   主机名做 SNI），`Wrap` 用 `HandshakeContext`  ctx 取消。测试中发现的真实缺陷：
   当测试传入替代信任根的 `Config` 时，早期实现会整个返回它，丢掉 `sni` / `alpn` /
   `skip-cert-verify`；已改成「`Config` 只提供根证书与证书，共享选项继续叠加在上面」，
   并由 `TestTrojanTLSBaseSNIAndALPN` 在服务端核对手协商出的 ALPN 与 SNI。
3. **BLAKE3 自研实现，不引入新模块**。Shadowsocks 2022 必须用 BLAKE3 derive-key，标准库
   没有该算法；尝试拉取 `github.com/zeebo/blake3` 时模块代理返回 Bad Gateway。自研版本
   （chunk chaining、父节点、root output、keyed hash、derive-key）用官方发布的测试向量
   （含 `BLAKE3 2019-12-27 16:29:52 test vectors context`）逐项比对，避免了在本阶段新增
   依赖与许可登记面，也让「零新依赖」这个结论可核。
4. **依赖登记**：本阶段**没有新增任何第三方模块**。`go mod tidy` 只把已在 `go.mod` 的
   `golang.org/x/crypto` 从 indirect 提升为 direct，`go.sum` 无变化：

   | 组件 | 版本 | 许可证 | 用途 | 与 GPLv3 |
   |---|---|---|---|---|
   | `golang.org/x/crypto` | v0.54.0（原已在 go.mod，本阶段转为直接依赖） | BSD-3-Clause（Go Authors） | `chacha20poly1305`：传统/2022 ChaCha 套件、VMess 与 Snell 体加密；`argon2`：Snell 每方向密钥派生 | 兼容 |

   `github.com/quic-go/quic-go`、`github.com/oschwald/maxminddb-golang`、`golang.org/x/sys`
   维持原状。生产代码仍优先只用标准库。
5. **UDP 按协议自身能力落地**。Shadowsocks 的 UDP 是真数据报：每条关联一条已连接 UDP
   套接字，密文独立封装。VMess / Trojan / Snell 的 UDP 能力是「over TCP 的分帧」，因此
   `DialPacket` 返回的是同一条 TCP 流上的 `PacketConn`，每个数据报独占一个分片/帧并自带
   目标地址；这样既符合协议，也不需要第二条 UDP 套接字。VMess 的 UDP 分片采用与请求头
   一致的「端口在前、地址在后」格式。
6. **测试对端复用生产侧的线格式原语**（与阶段 3 复用 `AppendAddress` / `DecodeUDPDatagram`
   同一条原则）：VMess 的 `vmessOpenHeader` / `vmessParseRequestHeader`、Snell 的
   `parseSnellUDPRequest` / `snellUDPResponse` 都放在生产文件里并注明「本地测试对端使用」，
   避免两边各写一份编解码而悄悄漂移。**代价是互操作性证据有限，见「当前状态」。**
7. **沙箱 UDP 的处理方式如实记录**。本沙箱 seccomp 禁止对未连接套接字 `sendto`/`sendmsg`
   （EPERM），所以旧的回环 UDP 服务器用例继续按 `datagramSendAllowed` 跳过。为了让本阶段
   Shadowsocks 的 UDP 往返真的跑起来，新增的测试服务器在收到第一个数据报后把**监听套接字**
   `connect` 到对端（仅 `!windows` 的测试辅助文件用 `syscall.SockaddrInet4`；Windows 侧
   辅助文件直接 `t.Skip`）。两端都是已连接套接字，走的是真实内核数据报，不是内存假通道，
   也不是把跳过包装成通过。此前阶段记录的 11 个环境跳过一个没少、也没有新增跳过。
8. **Snell v4 / v5 的语义边界**。两者共用同一套帧格式，本阶段把差异落在真实存在的三处：
   v4 用 `Connect` 且无首帧填充；v5 用可复用的 `ConnectV2`、首帧填充块、动态记录尺寸。
   v5 的 QUIC/HTTP3 代理模式是**另一个传输族**，留到 QUIC 阶段，未在本阶段假装实现。
9. **不做分享链接与订阅导入**。开发文档 §2.6 把它们列为 MVP 总体能力，但没有把它们划定到
   本阶段；按本阶段任务书的约束，只有明确列入本阶段范围才动，因此本阶段一行未写，留到
   下一步计划的对应阶段。
10. **`go.mod` 的 indirect 标记必须跟着实际导入走**。直接 import `x/crypto` 后若保留
    `// indirect`，`go mod tidy -diff` 会报差异；已执行 `GOPROXY=off go mod tidy`，
    并用 `go mod verify` 复核。这不是新增依赖，但必须写清楚，否则后续阶段会误判依赖来源。

### 当前状态

全部命令在仓库根目录执行，工具链为 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...                                      通过
go vet ./...                                        通过
go test ./... -count=1                              860 个用例条目：849 通过、11 跳过、0 失败
go test -race -count=1 ./internal/outbound/ ./internal/config/ \
                       ./internal/inbound/ ./cmd/melonarc-core/   全部通过
gofmt -l .                                          无输出
GOOS=windows go build ./cmd/... ./internal/...      通过
GOOS=windows go vet   ./cmd/... ./internal/...      通过
go mod tidy -diff（GOPROXY=off）                     无差异
go mod verify                                       all modules verified
```

11 个跳过全部是阶段 2/3/7/8 已有的环境性跳过（10 个回环 UDP 中继用例受未连接
`sendto` 限制，1 个 `TestTUNLinuxLoopback` 需要 CAP_NET_ADMIN），与阶段 9 代码无关；
本阶段新增的 Shadowsocks / VMess / Trojan / Snell UDP 用例**全部实际执行通过**，
没有新增跳过。`GOOS=windows go build ./...` 字面命令仍受 `spikes/tun`、`spikes/quic`
两个只读 Unix-only 历史原型阻断，与阶段 8 记录一致，产品包用上面的分目录命令验收。

**互操作性证据（必须如实说明）**：本阶段所有端到端往返都是「本项目自己写的客户端 +
本项目自己写的测试服务端」，共用同一套线格式原语；**没有与任何第三方参考实现做过
互通验证**，因此不能写成「已验证与参考实现兼容」。VMess、Trojan、Snell 的细节按公开的
协议定义与公开开源实现的源码核对过，AEAD 的 KDF 常量、头布局、分帧与命令编号都按定义
实现；BLAKE3 是唯一有**公开发布的数值测试向量**并已逐项比对通过的密码原语。VMess 与
Snell 没有公开的数值向量，只做了结构性校验（KDF 确定性/域分离、AuthID 校验和与篡改
检测、头封装往返、裸线帧头与版本差异），这不等价于与参考实现的互通证明。

### 遗留问题

- **未做第三方参考实现互通**：见上。上线前需要至少对每种协议接一次独立实现的服务端，
  并用真实握手/真实流量复测，尤其是 VMess 的 KDF 链与 Snell 的 padding 交换。
- **VMess 能力子集**：只实现 `aes-128-gcm` / `chacha20-poly1305` 与
  `ChunkStream` 选项；`none`、`legacy`、chunk masking、global padding、authenticated length、
  mux / connection reuse 都没做。`alterid` 仅为配置兼容而接受，AEAD 头里不使用。
- **Shadowsocks 2022 只做单 PSK**：没有多用户身份（IKB / user token）与服务端主动
  PSK 轮换；UDP 未做重放窗口与包序号去重（只校验时间戳与会话 id）；TCP 请求头 padding
  固定 8 字节、未做流量整形。
- **Trojan 没有「伪装回落」**：密码错误时测试服务端直接断开，真实实现通常会把可疑连接
  引到预设端点，本阶段未实现；也没有 TLS 会话复用与 WebSocket 传输。
- **Snell v5 的 QUIC/HTTP3 代理模式未实现**；`ConnectV2` 只实现了单连接语义，没有做
  跨请求复用连接池；填充只实现首帧的固定区间，没有做比特比例整形。
- **ALPN 只是被动提供**：`alpn=` 会放进 ClientHello，但没有按协议自动设置，也没有校验
  服务端协商结果是否符合预期（Trojan 的 SNI/ALPN 用例在服务端核对了，客户端没有）。
- **UDP 测试的平台差异**：已连接监听套接字这条路径目前只在 `!windows` 的测试辅助里实现，
  Windows 上这些用例跳过；将来需要在 Windows 上补等价做法或改用内存帧级断言。
- **观测层未接入**：新出站的握手失败没有进阶段 5 的 `inbound.Metrics` 分类明细，也没有
  按协议统计；`/v1/policies` 不暴露协议类型或 TLS 设置。
- 阶段 1–8 的其余遗留（Windows 实机验证、用户态 TCP 边界、DoT/DoH 上游与连接池、
  规则集更新、观测层 SQLite、桌面 UI、重载继承选择、`pending_restart`、
  `GOOS=windows go build ./...` 字面命令等）仍然成立。

### 下一步计划

1. **VLESS**：含 REALITY 与 XTLS-Vision flow，作为下一批 TCP 类加密出站的第一项；
   与阶段 9 共用 `TLSOptions` 基座，并补齐 REALITY 所需的证书/客户端指纹处理。
2. **QUIC 类出站**：Hysteria2、TUIC v5，连同阶段 8 已引入的 QUIC 传输能力一起做；
   同时决定 Snell v5 的 QUIC/HTTP3 代理模式是否并入这一阶段。
3. **互通验证**：为 Shadowsocks（传统 + 2022）、VMess AEAD、Trojan、Snell v4/v5 各接一次
   独立实现的真实服务端，补齐上节列出的数值向量或握手证据，再据此修正线格式细节。
4. **分享链接与订阅导入**：`ss://`、`vmess://`、`trojan://`、`vless://`、
   `hysteria2://`、`tuic://` 的解析与定时更新，按开发文档 §2.6 单独成阶段。
5. **补能力子集与观测**：VMess 的 masking / authenticated length / mux、Shadowsocks 2022
   多用户与重放窗口、Trojan 回落与会话复用、Snell v5 连接池；把新握手的失败进
   `inbound.Metrics` 分类，并让 API 能按协议类型查看出站状态。
6. Windows 实机与 DoT/DoH 上游、观测层 SQLite、桌面 UI 按阶段 8 的计划继续推进。

## 阶段 10 — VLESS（含 REALITY）与 QUIC 类出站（2026-11-14）

范围：按开发文档 §2.3 的出站协议清单收尾，做 VLESS（TCP 传输，含 TLS 组合与 REALITY）、
Hysteria2、TUIC v5 三种出站，以及它们需要的 QUIC 传输、HTTP/3 客户端与共用会话管理。
XTLS-Vision 的 `flow` 语义没有公开的线格式定义，按「不猜测线上字节」的原则**拒绝**而不是
假装实现（决策 4）。分享链接与订阅导入仍不在本阶段（决策 10）。`spikes/` 与 `docs/` 一个字未改。

### 完成了什么

- **VLESS**（`vless.go`）：请求头是 `版本(1) + UUID(16) + addons 长度(1) + addons + 命令(1) +
  端口(2) + ATYP + 地址`，端口在地址之前且 ATYP 用协议自己的编号（域名 `2`、IPv4 `1`、
  IPv6 `3`）；应答头是 `版本 + addons 长度 + addons`。TCP 用命令 `1` 直接复用流，UDP 用
  命令 `2`，在同一条流上按 2 字节长度前缀分帧，每个数据报自带目标地址。类型要求
  `tls=true` 或 `reality=` 二者之一，只写地址不给任一者会在装配期报错，避免悄悄退回明文。
- **REALITY**（`reality.go`）：客户端把一段 16 字节明文（3 字节版本 + 1 字节保留 + 4 字节
  unix 时间 + 8 字节 short id）用 AES-256-GCM 封进 TLS 1.3 的 session id 字段。密钥是
  `HKDF-SHA256(X25519 共享密钥, salt = ClientHello random[0:20], info = "REALITY")`，
  随机数是 `random[20:32]`，附加数据是**把 session id 清零后的 ClientHello**（服务端也不知道
  明文，只能这样重建 AAD）。服务端用「Ed25519 证书 + 把 Certificate 的 64 字节签名域替换成
  `HMAC-SHA512(authKey, 服务端公钥)`」证明自己，客户端按同样方式重算并常量时间比较。
  证书链本身照常校验，因此 `sni` 仍然决定证书名。
- **自研 TLS 1.3 客户端**（`tls13.go`）：`crypto/tls` 不提供设置 session id 的接口，而 REALITY
  的认证就藏在那里，所以写了一个只做客户端的 TLS 1.3：单个 X25519 key share、
  `TLS_AES_128_GCM_SHA256`、标准密钥调度（early/handshake/application traffic secret）与
  记录层（握手、应用数据、`close_notify`、握手后消息按应用数据记录读取）。
  它用 `crypto/tls` 的服务端做交叉验证（`TestTLS13AgainstStdlibServer`：握手、密钥调度、
  「握手后的握手消息走应用数据记录」、多记录写入、`CloseWrite`）。
- **Hysteria2**（`hysteria2.go`、`h3client.go`）：QUIC 上的 HTTP/3 认证 —— 向
  `https://hysteria/auth` 发 POST，带 `hysteria-auth`、`hysteria-cc-rx`（客户端下行速率，
  未配置时为 `0`，让服务端用它自己的默认值）与随机长度的 `hysteria-padding`，应答状态
  `233` 为通过。TCP 是 `0x401` 请求帧 + 地址长度 + 地址 + padding 长度 + padding，应答帧回
  状态、消息与 padding；成功后这条流就是隧道。UDP 是数据报：
  `会话 id(4) + 包号(2) + 分片号(1) + 分片总数(1) + 地址长度(varint) + 地址 + 载荷`，
  超过 1100 字节按最多 255 片切开，接收侧按会话与包号重组。混淆用 Salamander：
  8 字节 salt + 载荷与 `BLAKE2b-256(密码||salt)` 逐字节异或。
- **HTTP/3 客户端与 QPACK 编解码**（`h3client.go`）：手写的最小客户端——控制流 + SETTINGS、
  一个请求流、DATA/HEADERS 帧读写、`h3` 的变长整数，以及只用 QPACK 静态表的字段行编解码
  （静态索引行、名字引用行、名字内联行）。不引入 `quic-go/http3`，因为这一阶段只需要
  一个 POST 和四个响应状态，而那个包会带来一整套服务端能力与额外的依赖面（决策 5）。
- **TUIC v5**（`tuic.go`）：版本字节 `0x05`。认证走单向流，命令 `0x00` + UUID(16) +
  32 字节 token；token 由 TLS exporter 派生（label 是 UUID 的规范小写连字符文本，
  context 是密码），所以**密码本身从不上线**，录下的握手也无法拿去重放。TCP 用命令 `0x01`
  加地址开一条双向流，写完即隧道（协议没有应答）；UDP 用命令 `0x02` 的数据报：
  `关联 id(2) + 包号(2) + 分片总数(1) + 分片号(1) + 长度(2) + 地址`，关联 id 由计数器分配
  （随机 id 在 16 位空间里碰撞概率太高），关闭时发命令 `0x03` 让对端释放。
- **共用的 QUIC 会话**（`quicsession.go`）：每个出站一条 QUIC 连接，懒建立、引用计数、
  空闲 60 秒关闭；一个读循环把数据报按协议自己的键分发给对应的关联；`Disown` 只「退租」
  不切断在途流量，供重载使用（决策 7）。
- **共用的数据报重组**（`datagramReassembler`）：两种 QUIC 协议的分片都带「包号 + 序号 +
  总数」，重组逻辑只写一份，放在 `quicsession.go`；映射表有 64 条上限并按最旧淘汰，
  避免丢一片的数据报把内存吃掉。
- **注册、TLS 模式表与重载**：`outbound.New` 的 switch 增加 `vless` / `hysteria2` / `tuic`；
  `tlsModeFor` 把两种 QUIC 类型归入「恒 TLS」，因此 `sni` / `skip-cert-verify` 可用，
  `tls=` 被拒绝且有分节行号；`outbound.Set` 新增 `Disown()`，`daemonState` 的快照带上
  拨号器集合，重载在提交点之后对**被替换的那一份**调用 `Disown`，让旧配置的 QUIC 连接
  在最后一个引用释放时消失，而不是继续对着一台已经不在配置里的服务器保活。
- **测试**：新增 34 个测试函数（65 个用例条目）。VLESS 有 TCP 回显、TLS 组合、SNI 覆盖、
  UDP 回显、逐字节的请求头断言、错 UUID 与错版本号；REALITY 有用例端到端往返、明文证书被拒、
  错公钥、short id 不匹配；TLS 1.3 与标准库服务端交叉验证；Hysteria2 有 TCP 回显、UDP
  回显（含约 3.6 KB 的分片往返）、错密码、Salamander 往返、选项与速率解析、QPACK 单元用例；
  TUIC 有 TCP 回显、UDP 回显（含分片）、错 token、选项；另有 `Disown` 的两种语义
  （空闲即释放、在途不切断）与空闲连接释放用例。

### 关键决策及理由

1. **QUIC 栈选 `quic-go`**。开发文档 §4 已经把它列为 QUIC 族的技术选择；它是 Go 生态里
   唯一成熟、纯 Go、带数据报与迁移支持且持续维护的实现。自研 QUIC 等于重写拥塞控制、
   丢包恢复与 TLS 集成，与本阶段目标（做出出站）不成比例。许可证与登记见决策 9。
2. **只写客户端侧的 TLS 1.3，而不是改 `crypto/tls`**。REALITY 的认证必须落在 ClientHello
   的 session id 字段上，而 `crypto/tls` 明确不暴露该字段（也无意暴露）。自研范围被刻意
   压到最小：单套件、单 key share、单条连接语义，不做会话复用、0-RTT、客户端证书、
   HelloRetryRequest（决策 3 的遗留里如实列出代价）。
3. **REALITY 的 AAD 必须是「session id 清零后的 ClientHello」**。最初用未清零的字节做附加
   数据，服务端永远验不过——它拿到的 session id 是密文，重建不出客户端当时用的 AAD。
   改成两边都先清零再算，并用**副本**清零，避免把密文本身也抹掉（这是实现过程中真实踩到的
   别名 bug，已修）。
4. **XTLS-Vision 明确拒绝，不猜**。`flow=xtls-rprx-vision` 的填充与记录层改写没有公开的
   线格式文档，猜错不会「差一点」，而是直接把字节流写坏。因此 `newVLESSFromSpec` 在配置期
   就以「需要记录级填充，本构建未实现」报错，未知 flow 同样报错。宁可少一个能力，
   不要一个会静默破坏数据的实现。
5. **HTTP/3 手写，不引 `quic-go/http3`**。需要的只是一个带四个自定义头的 POST 和状态码，
   手写约 300 行；引入完整 HTTP/3 会多一个包、多一套服务端语义，也让「只支持静态表」
   这个明确的能力边界变模糊。代价是 QPACK 只实现静态表（动态表引用直接报错），
   而 Hysteria2 的认证应答只用到静态表。
6. **两种 QUIC 协议共用会话与重组，但各自保留分帧**。连接生命周期、引用计数、
   数据报分发与分片重组是同一件事，抽成一份；而 Hysteria2 与 TUIC 的帧头、地址编码与
   命令字完全不同，强行统一会得到一个两边都不像的抽象。因此 `quicsession.go` 只管
   「一条连接怎么被共享」，协议差异留在各自文件里。
7. **`Disown` 而不是 `Close` 用于重载**。重载替换配置时若直接 `Close`，会把还在传输的
   连接切断；若什么都不做，旧 QUIC 连接会对着已经不在配置里的服务器保活到空闲超时。
   `Disown` 把会话标记为退租、停掉空闲计时器、在没有引用时立即关闭，有引用时等最后
   一个引用释放——既不留 socket，也不切流量。
8. **TUIC 的关联 id 用计数器**。16 位空间里随机取 id，在同一连接上开几十条 UDP 流就会
   撞号，而撞号的后果是两条流互相收到对方的数据报。计数器在连接生命周期内单调递增，
   关联关闭即释放，不存在回绕风险。
9. **依赖登记**：本阶段新增一个第三方模块，另一个仅在用途上扩展：

   | 组件 | 版本 | 许可证 | 用途 | 与 GPLv3 |
   |---|---|---|---|---|
   | `github.com/quic-go/quic-go` | v0.65.0（本阶段由间接依赖转为直接依赖） | MIT | QUIC 传输：连接、流、数据报、连接状态；QUIC 变长整数 | 兼容 |
   | `golang.org/x/net` | v0.56.0（quic-go 的间接依赖，先前已在 `go.sum`） | BSD-3-Clause（Go Authors） | `quic-go` 内部依赖；本项目代码不直接 import | 兼容 |
   | `golang.org/x/crypto` | v0.54.0（阶段 9 已转直接依赖） | BSD-3-Clause（Go Authors） | 本阶段新增用途：`blake2b`——Hysteria2 Salamander 混淆的密钥流 | 兼容 |

   `go mod tidy -diff`（`GOPROXY=off`）无差异，`go mod verify` 全部通过。
10. **分享链接与订阅导入仍不做**。开发文档 §2.6 把它们列为 MVP 总体能力，但本阶段任务书
    的范围是三种出站；按「只有明确列入本阶段范围才动」的约束，一行未写，留给下一阶段。
11. **沙箱里的 QUIC 只能走已连接套接字，如实记录而非掩盖**。本沙箱 seccomp 禁止对未连接
    套接字 `sendto`/`sendmsg`，而 `quic.DialAddr` 正是用一条未连接套接字向对端发第一程。
    测试因此通过一个包内钩子 `dialQUICAddr` 换成「先 `connect` 再 `quic.Dial`」的拨号器，
    两端仍是真实内核数据报、真实 QUIC 握手，不是内存假通道。生产路径保留 `quic.DialAddr`
    （它能用 GSO/ECN，且一条套接字可服务多个对端）。**代价是默认拨号路径本身没有被测试
    覆盖**，这条写在「遗留问题」里，不含糊。
12. **实现过程中修掉的真实缺陷**（都来自测试，不是推测）：QPACK 名字内联行的名称长度前缀
    是 3 位而值 7 位、名字引用行的索引前缀是 4 位（原先误用 6 位）、TLS 1.3 握手后的
    握手消息按应用数据记录读取、VLESS 地址是「端口在前」、REALITY 的 AAD 清零与切片别名。

### 当前状态

全部命令在仓库根目录执行，工具链为 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...                                      通过
go vet ./...                                        通过
go test ./... -count=1                              925 个用例条目：914 通过、11 跳过、0 失败
go test -race -count=1 ./internal/outbound/ ./internal/config/ \
                       ./cmd/melonarc-core/          全部通过
gofmt -l .                                          无输出
GOOS=windows go build ./cmd/... ./internal/...      通过
GOOS=windows go vet   ./cmd/... ./internal/...      通过
go mod tidy -diff（GOPROXY=off）                     无差异
go mod verify                                       all modules verified
```

11 个跳过与阶段 2/3/7/8 记录的完全相同（10 个回环 UDP 中继用例受未连接 `sendto` 限制，
1 个 `TestTUNLinuxLoopback` 需要 CAP_NET_ADMIN），**本阶段没有新增跳过**：三种新协议的
TCP/UDP 往返全部实际执行通过。`GOOS=windows go build ./...` 字面命令仍被 `spikes/tun`、
`spikes/quic` 两个只读 Unix-only 原型阻断，产品包用上面的分目录命令验收；Windows 侧的
测试辅助文件（`quic_test_conn_windows_test.go`）给 QUIC 测试服务端提供普通监听套接字。

`knownProxyTypes` 里的 11 个类型到这里全部有实现，`Unsupported` 只再承担「未知类型」的兜底。

**互操作性证据（必须如实说明）**：三种协议的端到端往返都是「本项目自己写的客户端 +
本项目自己写的测试对端」，双方共用同一套线格式原语；**没有与任何第三方参考实现做过
互通验证**，因此不能写成「已验证与参考实现兼容」。可以称得上跨实现验证的只有两处，
且都在协议之外的下层：TLS 1.3 的握手与密钥调度对着 **Go 标准库的 `crypto/tls` 服务端**
跑通（`TestTLS13AgainstStdlibServer`），QUIC 本身是 `quic-go` 的完整实现而非自研。
REALITY 的认证、VLESS 的请求头、Hysteria2 的 HTTP/3 与数据报、TUIC 的命令与分片，
全部只有「本端与本端」的证据，线格式按公开协议定义与公开开源实现的源码核对过，
但这不等价于互通证明。

### 遗留问题

- **未做第三方参考实现互通**：见上。三种协议上线前各接一次独立实现的服务端，用真实握手与
  真实流量复测，重点核对 REALITY 的 AAD 构造与证书签名替换、Hysteria2 的 HTTP/3 应答与
  分片重组、TUIC 的 exporter label/context 顺序。
- **XTLS-Vision 未实现**：`flow=xtls-rprx-vision` 在配置期被明确拒绝（决策 4）。要接这个
  能力，先得有公开的线格式定义，再补记录级填充与 Vision 的 padding 策略。
- **自研 TLS 1.3 的能力边界**：单密码套件（`TLS_AES_128_GCM_SHA256`）、单 X25519 key share、
  不支持 HelloRetryRequest（服务端若坚持 P-256 组会握手失败）、不支持会话复用与 0-RTT、
  不支持客户端证书。对 REALITY 够用，对「伪装成主流客户端」不够——ClientHello 的扩展集合
  与顺序是自研实现的形状，本身就是可识别特征，没有做浏览器指纹模仿。
- **REALITY 只做客户端**：没有服务端实现、没有 short id 轮换与多用户、没有回落目标；
  `spider-x` 之类的探针防护不在范围内。
- **Hysteria2 的能力子集**：没有实现它的拥塞控制（只上报 `hysteria-cc-rx`，未实现带宽探测
  与 Brutal）、没有端口跳跃、没有 masquerade 回落、没有 UDP over stream、没有 0-RTT；
  分片固定按 1100 字节切，不按路径 MTU 自适应；接收侧没有包号去重窗口
  （重传的重复分片会被当成新分片参与重组）。
- **TUIC 的能力子集**：没有 0-RTT、没有发送心跳（命令字已定义但客户端不发，靠 QUIC 自身
  保活）、没有 gzip、没有证书 pinning；拥塞控制用 `quic-go` 默认（CUBIC），没有实现 BBR；
  UDP 只走不可靠的数据报，QUIC 数据报本身不重传，因此丢包直接体现为丢包。
- **每个出站只有一条 QUIC 连接**：没有按对端做连接池，也没有处理连接迁移；一条连接上的
  拥塞控制窗口被所有流共享。
- **默认 QUIC 拨号路径未被测试覆盖**：见决策 11。这条路径在真实机器上才是常态，
  需要在一个允许未连接 `sendto` 的环境里补一条端到端用例（或一个可配置的拨号器）。
- **观测层未接入**：新出站的握手失败没有进阶段 5 的 `inbound.Metrics` 分类明细，
  也没有按协议统计；`/v1/policies` 不暴露协议类型或 TLS 设置（与阶段 9 相同）。
- **Snell v5 的 QUIC/HTTP3 代理模式**：阶段 9 记录为待定，本阶段按其协议语义判断它属于
  「另一种传输」，与 QUIC 出站不是同一件事，仍然未实现。
- 阶段 1–9 的其余遗留（Windows 实机验证、用户态 TCP 边界、DoT/DoH 上游与连接池、
  规则集更新、观测层 SQLite、桌面 UI、重载继承选择、`pending_restart`、
  `GOOS=windows go build ./...` 字面命令等）仍然成立。

### 下一步计划

1. **第三方互通验证**：VLESS（含 REALITY）、Hysteria2、TUIC v5 各接一次独立实现的真实
   服务端，连同阶段 9 的 Shadowsocks / VMess / Trojan / Snell，一起补上互通证据。
2. **分享链接与订阅导入**：`ss://`、`vmess://`、`trojan://`、`vless://`、`hysteria2://`、
   `tuic://` 的解析与定时更新，按开发文档 §2.6 单独成阶段。
3. **补 XTLS-Vision**：等公开线格式；同时评估是否用一个可插拔的 ClientHello 构造器
   替掉自研 TLS 1.3 的固定扩展集合，以便做指纹模仿。
4. **补 QUIC 出站能力**：Hysteria2 的拥塞控制与端口跳跃、TUIC 的 0-RTT 与心跳、
   按对端的连接池，以及分片的路径 MTU 自适应与去重窗口。
5. **观测与 API**：把出站握手失败送进 `inbound.Metrics` 的类别化字段，让 API 能按协议
   类型查看出站状态；这条已经连续两个阶段挂在遗留里。
6. Windows 实机与 DoT/DoH 上游、观测层 SQLite、桌面 UI 按阶段 8 的计划继续推进。

## 阶段 11 — 第三方互通验证、分享链接与订阅导入（2026-11-14）

范围：四件事。一是把阶段 9/10 的八种出站逐协议接到**第三方参考实现**上，给出真实互通证据；
二是分享链接解析（`internal/share`）；三是订阅导入与定时更新（`internal/config` 的
`[Subscription]` 段 + `internal/subscription`）；四是修掉阶段 10 那条抖动用例。开发文档
§2.6 的两种能力到这里补齐，出站协议清单在阶段 10 已经闭合，本阶段**不新增协议**。
`spikes/` 与 `docs/` 一个字未改。

### 完成了什么

- **互通验证的装置**（`interop_test.go`）：所有互通用例都受一个环境变量守卫——
  `MELONARC_INTEROP_DIR` 指向本机存放参考实现可执行文件的目录，未设置时整组跳过。用例用
  `exec.Command` 起真实服务端、等它的监听端口就绪，然后由本项目的客户端拨真实端口、跑真实
  回显流量；服务端 stdout/stderr 全程留档，失败时随测试日志一起打印。仓库里只有我们自己的
  测试代码与配置生成代码，**没有一个第三方二进制**（决策 2）。
- **逐协议互通用例**：Shadowsocks 旧版 AEAD 与三种 2022 套件（`interop_ss_test.go`）、
  VMess / Trojan / VLESS（含 REALITY）（`interop_stream_test.go`）、Snell v4 与 v5
  （`interop_snell_test.go`）、Hysteria2 与 TUIC v5（`interop_quic_test.go`）。另有四条
  反向用例：错密码的 Shadowsocks、错 PSK 的 Snell、错 UUID 的 VMess、错 UUID 的 VLESS，
  断言的是「服务端不隧道」而不是「我们报错」。
- **分享链接解析**（`internal/share`）：`ss://`（SIP002 的 `ss://base64(method:pass)@host:port`、
  旧式整体 base64、以及 `ss://method:pass@host:port` 三种写法）、`vmess://`（base64 的
  JSON）、`trojan://`、`vless://`、`hysteria2://`（含 `hy2://` 别名）、`tuic://`。产出物直接
  是 `config.Proxy`，与手写 `[Proxy]` 行走同一条构建路径，所以导入的节点与手写的节点不可能
  长得不一样。错误携带链接类型与原因（`share.Error{Scheme, Reason}`），**不携带链接本身**
  （决策 6）；`ParseAll` 逐条报告而不是停在第一条。
- **`[Subscription]` 段**（`config/ini.go`、`config/subscription.go`）：`name = url [interval=6h]`，
  区间下限 5 分钟、默认 6 小时。声明一个订阅**同时声明一个同名 `select` 组**，成员在导入时
  填入；因此规则与其它组可以在解析期就指向它，`-check` 不必联网（决策 8）。节点名统一为
  `subscription/<sanitized>`，重名按 `-2`、`-3` 递增，长度受 `maxNameLen` 约束。
- **订阅管理器**（`internal/subscription`）：`Import` 并发抓取所有订阅（`join` 合并错误），
  解码（base64 或明文）后逐行 `share.Parse`，再交给 `cfg.MergeSubscriptions`；`Run` 按
  interval 判断到期（30 秒一跳的检查节拍），更新成功后回调让守护进程走一次重载；`Snapshot`
  与 `Status` 给运维看。抓取上限 4 MiB、默认 HTTP 超时 20 秒。
- **失败语义**：一次失败的刷新不夺走已有节点（上一次的结果继续生效），并按 15 秒起、×2、
  上限 15 分钟退避；最后一次成功的响应体落盘（`<data-dir>/subscriptions/<name>.txt`，0600，
  临时文件 + rename），所以重启时网络不通也仍能产出规则所指向的节点。一个订阅若一条可用
  链接都产不出来，是**错误**（`ErrEmpty`），不是空组。
- **守护进程接入**：启动时先 `subs.Import`（失败即启动失败，不留半套状态），再装配；
  `reloader` 持有一个 `*subscription.Manager`，`reload` 在 `config.Load` 之后重新导入，
  失败在提交点之前返回，旧状态继续服务；后台 `go subs.Run(ctx, onChange)` 在更新成功后触发
  同一条重载路径。`-check` 打印 `subscriptions: N (not fetched by -check)`，不建目录、
  不写文件。
- **REALITY 可用性的前置修复**（`tls13.go`）：自研 TLS 1.3 客户端原先只提供 `x25519`
  （组 29）一个 key share，参考服务端直接把它当「过期/奇怪的 ClientHello」丢弃——它要求
  **X25519MLKEM768（组 4588）必须在前**。现在客户端提供混合 share
  （`ML-KEM-768` 封装公钥 1184 字节 + X25519 公钥 32 字节），并把 `x25519` 作为**第二个**
  share 供服务端退选；REALITY 的认证密钥始终从**经典那一半**导出，所以 `curveShared` 与
  `shared` 分成两条路径。这条是互通的**前提**，不是优化（决策 4）。
- **抖动用例修复**（`quicsession_test.go`）：`TestQUICSessionDisownReleasesAnIdleConnection`
  的 5 秒硬期限在 `-race` 下偶发超时。根因不是「期限太紧」：客户端关得太快时，测试对端的
  `Accept` 才返回，随后**没有任何连接对象**去观察 `Context().Done()`，测试就只能白等自己的
  期限。改成等对端发出 `accepted` 信号之后再 `Disown`，期限放宽到与实现无关的 20 秒。
  `-race` 连跑 20 次全通过（修复前 10 次里能复现 3 次）。

### 关键决策及理由

1. **互通的做法是「真服务端 + 真流量」，不是「对源码」**。每个协议从它的官方发布渠道取
   可执行文件，并核对发布方公布的哈希（Xray 用 `xray.zip.dgst` 里的 SHA2-256，
   shadowsocks-rust 用 `ss.tar.xz.sha256`，hysteria 用仓库的 `hashes.txt`，tuic-server 用
   `.sha256sum`，Snell 用发布页给出的 zip）。二进制只放在 `/tmp` 下，只在测试进程里以
   本机服务端身份运行。这样做的理由是：阶段 9/10 的「本端对端」证据只能证明自洽，
   而线格式的错误恰恰是自洽的天敌。
2. **参考实现不进仓库、不进产品、不随包分发**。装置按**协议**取可执行文件：
   `$MELONARC_INTEROP_DIR/<协议>/server`，找不到就跳过。这个分层是有意的——测试要的是
   「某个会说这个协议的服务端」，具体是哪个实现是**机器的属性、不是代码的属性**；同一个
   二进制会说多个协议时，在几个槽位上各放一个链接即可。这样仓库的测试代码里连一个实现名
   都不出现，命名红线不必靠自觉。参考实现的名称只出现在**本文件的互通记录**里；产品代码、
   注释、用户文档、提交信息里一个都没有。
3. **不能验证的，不写成通过**。本沙箱的 seccomp 禁止对未连接套接字 `sendto`/`sendmsg`，
   QUIC 服务端的第一程与所有 UDP 出口都命中这条规则。因此 Hysteria2 与 TUIC v5 **没有**
   互通证据：用例写好了、守卫写好了、跳过原因写在跳过信息里，等一个允许未连接 `sendto`
   的环境来跑。所有 UDP 子用例（SS / VMess / Trojan / VLESS / Snell）同样如此。
   Snell 这条还多了一份旁证：参考服务端自己被拒绝时在日志里打出
   `UDP socket send error: operation not permitted`。
4. **互通挖出的四个真实缺陷**（这是本阶段最有价值的产出，全部先由测试暴露再修）：
   - **REALITY 根本不接受纯 X25519 的 ClientHello**。这是最先挡住互通的一条：服务端在读完
     ClientHello 后逐个找 key share，找不到 `X25519MLKEM768` 就直接放弃认证、把连接当回落
     流量转给模仿站点，于是客户端拿到的是**真实站点的证书**（自研 TLS 1.3 因此报
     「证书公钥是 *ecdsa.PublicKey，期望 ed25519」——这条报错其实是正确拒绝）。把
     `tls13.go` 改成混合 share 之后握手成立。参考实现里那行判断的注释写得很直白：
     `reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before optional X25519`。
     这一步是「能不能连上」的问题，不是能力增强，所以放在决策里而不是优化清单里。
   - **Snell 的应答是惰性发的**。参考服务端要等客户端发出**第一段数据**才回那个应答字节，
     而原先的实现把应答当成握手的一部分同步读，于是 v4/v5 全部被拒——服务端日志显示它其实
     已经解密了 CONNECT 并拨通了目标，是我们这一侧先把连接关掉了。改成「首次 `Read` 时再读
     应答」（`awaitResponseLocked`），与 SS-2022 / VMess / VLESS 的惰性读法一致；改完两个
     版本都通。
   - **Snell 首帧要把 salt 与 padding 一起带走，v4 也一样**。原先 salt 单独先写、padding
     只在 v5 的首帧加，参考服务端认不出首帧。改成 salt 并入首帧、两个版本都做首帧填充，
     并把 `nextPayloadLimit` 的增长曲线同样应用到 v4。
   - **REALITY 的那 5 秒不是我们的握手慢**。参考服务端在收到客户端 Finished 之后，还要先
     把它回落目标（模仿站点）的「握手后记录长度」剖绘出来，而它**以 5 秒为步长轮询**这个
     剖绘结果；结果没就绪就不置 `isHandshakeComplete`，隧道也就不会开始转发。于是首个认证
     连接要等 1~2 个 5 秒，之后的连接立刻可用。用客户端侧的 socket 轨迹可以把它钉死：
     `write 1377`（ClientHello）→ `read 1860`（服务端 flight）→ `write 58`（Finished）→
     `write 48`（请求记录）全在 5 毫秒内上线，然后服务端沉默 10 秒。因此这是参考服务端的
     启动期行为，不是本项目的性能问题，只在用例里写注释说明，不做「优化」。
5. **分享链接：要么全懂，要么报错**。不支持的传输（ws/grpc/h2/kcp）、SS 插件、未知的 TLS
   变体、缺失的凭据一律在解析期拒绝并给出类型与原因。理由是静默丢字段的后果会推迟到拨号期
   才显现，而且看起来像「服务器有问题」。同理，`vless://` 必须给 `tls=` 或 `reality=`
   之一（与阶段 10 配置期的规则一致），REALITY 必须给 `pbk=`。
6. **错误信息不回显链接**。链接里带密码，而这些字符串会进日志和本地 API。`share.Error`
   只存类型与原因，测试里专门断言错误文本不含凭据（`TestParseRejectsWithTheTypeAndReason`）。
7. **订阅做成「一个声明的组」，而不是一堆动态节点名**。供应商随时改名，规则指向单个节点会
   腐烂；指向订阅本身跨更新有效。节点名带 `subscription/` 前缀，一是让 API 与日志里看得出
   它从哪来，二是让两个供应商的同名节点不撞车。
8. **`-check` 必须离线**。订阅的组在解析期声明，所以 `-check` 不抓取也能校验规则与组的
   引用是否成立；它只打印订阅数量，不建目录、不写文件。这与阶段 6 定下的 `-check` 语义一致。
9. **订阅的刷新走既有的重载路径，不另开一条**。刷新成功后调用与 `POST /v1/config/reload`
   同一条 `reload`：整份重建、一次替换、失败在提交点前返回。多一条独立的「只换节点」路径
   等于多一套状态机，而重载已经把「监听不重绑」的语义定死了（阶段 6 决策）。
10. **失败保留上一次成功结果 + 磁盘缓存 + 退避**。订阅是外部依赖，刷新失败是常态而不是
    异常：夺走节点会让正在工作的配置突然断流，而缓存让「重启 + 网络不通」不至于连启动都
    过不去。
11. **依赖登记：本阶段没有新增第三方模块**。`internal/share` 与 `internal/subscription`
    只用标准库（`net/url`、`encoding/base64`、`encoding/json`、`net/http`）；`go.mod` 与
    `go.sum` 无变化，`go mod tidy -diff`（`GOPROXY=off`）无差异。

### 当前状态

全部命令在仓库根目录执行，工具链为 `~/sdks/go/bin` 的 Go 1.27.4：

```
go build ./...                                      通过
go vet ./...                                        通过
go test ./... -count=1                              999 个用例条目：978 通过、21 跳过、0 失败
go test ./... -race -count=1                        全部通过
gofmt -l .                                          无输出
GOOS=windows go build ./cmd/... ./internal/...      通过
go mod tidy -diff（GOPROXY=off）                     无差异
go mod verify                                       all modules verified
```

用例条目相比阶段 10 的 925 条增加 74 条：10 条是互通占位（未设置 `MELONARC_INTEROP_DIR`
时以「参考实现二进制未下载」跳过，这是**设计使然**，不是环境缺陷），另外 64 条是新通过的
用例。新用例分布在 9 个新测试文件、33 个测试函数里：`internal/share`（3 个函数 / 37 条，
其中 12 条链接构造、22 条拒绝）、`internal/subscription`（11 条）、`internal/config` 的订阅
段（7 条）、`cmd/melonarc-core` 的装配端到端（2 条），以及 `internal/outbound` 的 5 个互通
文件（10 个函数，设置环境变量后展开成 34 条）。跳过总数因此从 11 条变为 21 条，多出来的
正是那 10 条互通占位。

设置 `MELONARC_INTEROP_DIR` 后再跑互通子集：

```
MELONARC_INTEROP_DIR=… go test ./internal/outbound/ -run TestInterop -count=1 -v
                                                    34 个用例条目：23 通过、11 跳过、0 失败
```

11 条跳过 = Hysteria2 与 TUIC v5 两条整例 + 9 条 UDP 子用例，原因统一是未连接 `sendto`
被拒。**逐协议互通结果**（参考实现名称仅出现在此表内）：

| 协议 | 参考实现 | 结果 |
|---|---|---|
| Shadowsocks 旧版 AEAD（`aes-256-gcm`） | shadowsocks-rust 1.25.0 (`ssserver`) | TCP **通过**；UDP 跳过 |
| Shadowsocks 2022（`blake3-aes-128-gcm` / `blake3-aes-256-gcm` / `blake3-chacha20-poly1305`） | 同上 | TCP **通过** ×3；UDP 跳过 |
| VMess（AEAD，TCP 传输） | Xray-core 26.11.9 | TCP **通过**；UDP 跳过 |
| Trojan | Xray-core 26.11.9 | TCP **通过**；UDP 跳过 |
| VLESS + TLS | Xray-core 26.11.9 | TCP **通过**；UDP 跳过 |
| VLESS + REALITY | Xray-core 26.11.9（另起一个 TLS 站点当回落目标） | TCP **通过**（16 KiB 往返） |
| Snell v4 / v5 | snell-server 5.0.0（同一可执行文件按 `version=4` / `version=5` 分别运行） | TCP **通过** ×2；UDP 跳过 |
| Hysteria2 | hysteria v2.13.0 | **无法验证**：QUIC 首程 `sendto` 被拒（EPERM） |
| TUIC v5 | tuic-server 1.0.0 | **无法验证**：同上 |

四条反向用例（错密码的 Shadowsocks、错 PSK 的 Snell、错 UUID 的 VMess、错 UUID 的 VLESS）
都实际执行并通过：参考服务端在凭据不匹配时不建立隧道。

槽位与实现的对应关系（本机布局，根目录由 `MELONARC_INTEROP_DIR` 给出）：
`shadowsocks/server` 指向 shadowsocks-rust 的 `ssserver`；`vmess/server`、`trojan/server`、
`vless/server` 三处指向同一份 Xray-core 可执行文件；`snell/server` 指向 `snell-server`；
`hysteria2/server` 指向 `hysteria`；`tuic/server` 指向 `tuic-server`。

`knownProxyTypes` 的 11 个类型全部有实现（阶段 10 已闭合）；本阶段给其中 5 个类型（Shadowsocks、
VMess、Trojan、VLESS、Snell）的 8 种形态补上了第三方互通证据，剩下 2 个类型（Hysteria2、
TUIC v5）连同所有 UDP 行为如实留白。

### 遗留问题

- **Hysteria2 与 TUIC v5 没有互通证据**：见决策 3。要在允许未连接 `sendto` 的环境里补跑
  `TestInteropHysteria2` / `TestInteropTUIC`，重点核对 REALITY 之后的第二层——Hysteria2 的
  HTTP/3 认证应答与分片重组、TUIC 的 exporter label/context 顺序与关联 id 语义。
- **所有 UDP 互通都未验证**：不是只有 QUIC。SS / VMess / Trojan / VLESS / Snell 的 UDP 子
  用例都因同一原因跳过；其中 SS 走真 UDP 套接字，另外四种是 over-TCP 分帧、本可以用
  「服务端连到一个已连接的 UDP 对端」绕开，但那需要改参考服务端的部署方式，不划算。
- **REALITY 的首连成本**：参考服务端对每个 `(回落目标, SNI, ALPN)` 组合只剖绘一次，首个
  认证连接要等 1~2 个 5 秒轮询。真实部署里这同样是首连成本，本项目无从缓解（除非服务端早已
  剖绘过）。凡是拿本项目的 REALITY 出站做「首包延迟」测量，都必须把这段排除在外。
- **订阅的能力子集**：只支持「链接列表」形态（明文或整体 base64）。没有 `subscription-userinfo`
  的流量/到期信息、没有 ETag / If-Modified-Since 条件请求、没有按订阅做节点过滤或重命名规则、
  没有把拉取本身走代理（拉取是直连）。也没有「只更新不重载」的轻量路径。
- **自研 TLS 1.3 的能力边界（本阶段更新）**：仍是单密码套件
  （`TLS_AES_128_GCM_SHA256`）、不支持 HelloRetryRequest、会话复用、0-RTT 与客户端证书；
  但 key share 已从「单 X25519」变成「X25519MLKEM768 + X25519 退选」。代价与收益都要记：
  ClientHello 从约 300 字节涨到 1377 字节，PQ 成为硬要求（没有它连 REALITY 都连不上），
  而 `crypto/mlkem` 是标准库（Go 1.24 起），没有引入第三方模块。
- **分享链接的能力子集**：不支持 `plugin=`（SS 插件）、ws / grpc / h2 / kcp 传输、
  `flow=xtls-rprx-vision`、Trojan 的 `type=ws`。一律报错而不是忽略，但这也意味着从供应商
  拿到的链接里只要带插件或 ws，就会被拒——这是当前最可能影响实际可用性的缺口。
- **订阅的鉴权与隐私**：订阅 URL 可能带 token，目前只做形状校验，日志里打印的是订阅名而
  不是 URL；缓存文件名用订阅名，不含 URL 片段。没有做「URL 里的凭据」这类静态检查。
- **互通用例不进 CI 的常规路径**：没有参考实现时它们只是跳过，因此「互通是否还成立」不会被
  日常 `go test ./...` 发现。要让它成为常规门禁，得有一个允许未连接 `sendto` 且预置二进制的
  环境。
- 阶段 1–10 的遗留照旧（Windows 实机验证、用户态 TCP 边界、DoT/DoH 上游与连接池、规则集
  更新、观测层 SQLite、桌面 UI、重载继承选择、`pending_restart`、出站握手失败未进
  `inbound.Metrics` 的按协议统计等）。

### 下一步计划

功能面按开发文档收口，接下来是**收尾而非扩张**，顺序如下：

1. **SQLite 观测层**：把连接、失败、解析、策略探测与订阅刷新落成一张可按时间查询的表，
   API 增加历史查询端点。这条在阶段 5 与阶段 10 连续挂账，且订阅刷新又给它添了一类事件。
2. **系统代理接入**：`[General]` 增加系统代理开关（Linux 走环境变量与 GNOME 设置、
   macOS 走 `networksetup`、Windows 走注册表），把「本地监听已经在跑」变成「应用不用配置
   就能用」。这是产品可用性的最后一块短板。
3. **重载继承选择**：`POST /v1/config/reload` 增加「保留当前策略组选择」的选项。现在重载会把
   选择重置为第一个成员，用户手动选过的节点会在每次订阅刷新后被悄悄换掉——订阅一旦定时
   更新，这个问题就从「偶发」变成「每 6 小时一次」，优先级因此上调。
4. **GUI 骨架**：先做只读面板（入站统计、失败、DNS、策略组与订阅状态、审计），再考虑
   写操作。API 已经把只读面收敛得比较干净，接起来不需要新端点。
5. 与上面并行的补课项：Windows 实机验证、DoT/DoH 上游、规则集在线更新、XTLS-Vision
   （等公开线格式）、Hysteria2 的拥塞控制与端口跳跃、TUIC 的 0-RTT 与心跳。

---

## 阶段 12 — 收尾件：SQLite 观测层、系统代理接入、重载继承选择（2026-11-14）

范围：阶段 11「下一步计划」的前三条，按给定优先级做完（重载继承选择实际最先落地，因为它是
订阅定时的直接后果）。三件事各自独立，共同点是都**不加新协议、不动分层**：
`internal/store` 是新的叶子包，`internal/sysproxy` 也是，两者都不被任何既有包 import；
`spikes/` 与 `docs/` 一个字未改。

### 完成了什么

**1. `internal/store` — 观测层落盘（自研 SQLite 文件格式）**

- 三张有界表：`connections`（时间、监听协议、目标、网络、命中规则、策略、叶子出站、
  上下行字节、时长）、`events`（时间、类别、名称、详情、成败）、`samples`（时间、上下行增量）。
  保留上限 `2000 / 500 / 1440`，满则丢最旧；一条记录的所有列都受字节上界约束（最长的是
  host 255），因此一行一定落在单个叶子页里。
- **写整个文件**：`Store.Flush` 把内存表渲染成一份完整 image，`CreateTemp`（同目录）→
  `chmod 0600` → `Sync` → `Rename`。读者只会看到旧文件或新文件，看不到半个数据库；失败时
  旧文件不动、记录仍在内存里，`Status.LastError` 记原因、日志只打一次（同一个错误不会按
  刷新节拍刷屏）。刷新节拍 30 秒，`Close` 时再刷一次。
- **读回来**：`Open` 读已有文件并解析回三张表。文件不存在不是错误（第一次运行）；文件存在
  但读不懂也不是错误——观测历史不该拦住守护进程启动——原因写进 `Status.Notice`，直到被
  下一次写入替换。
- 写入路径全部 nil 安全：`(*Store)(nil)` 上任何方法都可调用，所以「没有观测层」和「有观测层
  但还没写入」在调用点上没有分支。

**2. 观测数据的采集点（`inbound.Observer`）**

- `inbound.Metrics` 增加一个可选观察者接口（`Connection(ConnectionRecord)` /
  `Failure(Failure)`），入站层照旧只维护自己的定长环，**把记录同时告诉观察者**。观察者实现
  是 `cmd/melonarc-core/history.go` 里的 `historyObserver`，只做字段映射与一次 append。
  存储写不出去不影响任何请求：这是「观测是旁路」的落点（决策 2）。
- 字节计数在 `pipeline.go` 新增的 `trackedConn` / `trackedPacketConn` 上：包住出站返回的
  连接，按方向累加，`CloseWrite` 透传给底层（半关闭只有 `relay.go` 一份实现，这里不许
  复制），`sync.Once` 保证一条连接只报一次。`Request` 增加 `Protocol` 字段，标注记录来自
  哪个监听（http / socks5 / tun）。
- `Metrics.Traffic()` 返回累计上下行，采样器取两次读数之差；计数器只增不减，所以跨越采样
  边界的连接不会被漏掉或重复计。

**3. 历史查询面**

- API 四个只读端点：`/v1/history`（摘要：文件、大小、三张表的用量与容量、写入次数、最近
  写入时间、最近错误、notice、进程累计字节）、`/v1/history/connections`、
  `/v1/history/events`、`/v1/history/traffic`。三者共用 `limit`、`since`；events 另有
  `kind`。空集合返回 `[]` 而不是 `null`。
- `since` 接受两种写法：RFC3339 时刻，或 `1h` 这样的时长（「往前看多久」）。时长在
  handler 里换算成时刻，所以 `Provider` 不需要时钟。
- events 的四个类别 `failure` / `reload` / `subscription` / `policy`：拨号失败与策略拒绝
  记成事件而不是连接（那次请求没被承载），REJECT 也算「未承载」，类别留在 detail 里，
  读者能区分「规则拦的」与「代理挂了」；重载成功与**失败**都记（`ok` 字段），订阅刷新
  记节点数与结果，手动切换记 `group: 旧 -> 新`。
- CLI 新增 `history [summary|connections|events|traffic] [limit]` 与 `-since <duration>`。
  summary 描述文件本身，窗口命令打印表格；`-since` 配 summary 是用法错误（那是「整个文件」，
  不是某个窗口），不做静默忽略。字节数按一个人读得懂的写法打印。

**4. 系统代理接入（`internal/sysproxy`）**

- `[General]` 新增两键：`system-proxy = on|off`（默认 off）、`system-proxy-bypass = a, b`
  （回环三项永远在内，不写也在）。校验拦三种错：开了但没有监听、写了 bypass 但开关没开、
  bypass 项里带 `;`（Windows 的分隔符，一项会被拆成两项）。
- 三个后端，逻辑与平台选择分离（后端本身无 build tag，只有 `platform()` 按 GOOS 选）：
  Linux 走 `gsettings`（parent 的 `mode`，http/https/socks 子 schema 的 host 与 port，
  `ignore-hosts`），Windows 走 `reg.exe`（`HKCU\...\Internet Settings` 的 `ProxyEnable` /
  `ProxyServer` / `ProxyOverride`），其它系统返回 `ErrUnsupported`。这样两套后端在任何系统上
  都能被测试覆盖，而交叉编译只需要选对一个 `platform()`（决策 4）。
- **不留半应用**：写之前先把要动的键读出来（快照），任何一步失败就按快照写回，错误里同时
  带原始失败与「已恢复」。读不出来就**不写**——不知道旧值就没有回滚能力（决策 5）。
  Windows 的顺序是「先写地址、最后写 `ProxyEnable=1`」，清除时只写 `ProxyEnable=0`：
  代理永远指向已经写好的地址。
- 守护进程：监听与 TUN 起来之后才写系统代理（写下去一定指向已经在答的端口），失败即启动
  失败并按 TUN 的同一条路径回滚；关停时**第一个**清系统代理（先停止把机器指向即将关闭的
  端口），再停 TUN、入站、API。`system-proxy` 进 `restart_required`（决策 3）。
  `-check` 只打印将要写什么，不碰桌面设置。

**5. 重载继承选择（本阶段优先级最高的一项）**

- `policy.Registry.Selections()`：返回每个 `select` 组当前指向的成员，按组名索引；自决组
  不在其中。
- `buildRegistry` 增加 `carry map[string]string` 参数：重载时把旧 registry 的选择带进新
  组，`carriedMember` 只在该成员仍然存在时采用；成员被订阅删掉就退回第一个成员。
- `droppedSelections` 把「没能保住的 pin」渲染成 `group: 原因` 列表，进 `ReloadView.
  selection_dropped`，CLI 逐条打印 `selection not restored: ...`——一个悄悄消失的节点必须
  有地方说话。
- `pending_restart`：`daemonState` 记住启动时那份 `[General]` 作为基线，重载时与当前文件
  比较，得到**累计**的「还在等重启」集合；`/v1/config` 一直报告它，不会因为下一次重载而
  丢失。改回启动时的值就会从集合里消失（比较的是值与基线，不是尝试历史）。
- 回归用例 `TestSubscriptionRefreshKeepsThePinnedMember`：假订阅服务器 + 可控时钟，先 pin
  `airport/NodeB`，刷新到 `NodeB,NodeC` 后断言组仍在 `NodeB`（`Active()` 与
  `Resolve().Leaf` 两条路径都看），再把 NodeB 删掉，断言 `selection_dropped` 有一条且组落到
  `NodeC`。

### 关键决策及理由

1. **不加第三方 SQLite 驱动，自己写文件格式**。本机模块代理与 github/gitlab 都不可达，
   `go get` 拿不到任何模块；而且这台机器的交叉编译是硬要求（Windows 单文件二进制），
   cgo 驱动直接排除。权衡后选了「只实现用得到的那一小块 SQLite 格式」：100 字节文件头、
   4096 字节页、table b-tree（叶子页 `0x0d`、内部页 `0x05`）、记录头里的 serial type 与
   varint。代价是约 600 行格式代码，收益是**零依赖、零 cgo、GPLv3 干净、Windows 交叉编译
   无感**，而且产物是任何 SQLite 工具都能打开的标准文件（不是私有格式）。
   **不新增任何模块**，`go.mod` 与阶段 11 完全一致（决策 2 一并覆盖）。
   验证方式是独立的：`sqlite3` 命令行（3.45.1）作为**测试预言机**，检查行数、极值、单行
   回读、`sqlite_schema`、空表、`PRAGMA integrity_check` 与 `user_version`；它只在测试里
   通过 PATH 调用，**不链接、不随产品分发、不进仓库**，缺失时该用例跳过。
2. **观测是旁路，写不出去不算故障**。`Observer` 的方法在承载请求的 goroutine 上调用，
   因此实现只做有界内存表的 append；落盘在后台按节拍进行。文件写不出去时记录留在内存、
   下一次刷新再试，`/v1/history` 的 `last_error` 与 `notice` 把状态说清楚。反过来做（写失败
   即请求失败）会让一块满盘的磁盘变成一次断网。
3. **系统代理是启动设置，不是可重载设置**。重载的语义是「换掉路由」，而系统代理的副作用
   落在整台机器上：编辑一条规则就改变所有应用的去向，不符合「重载 = 一次不重启的重启」。
   另外它指向的地址本身就要重绑监听才能变。因此 `system-proxy` 与 `system-proxy-bypass`
   进 `restart_required`，并通过 `pending_restart` 持续可见（这条复用阶段 12 第 5 项）。
4. **后端逻辑与平台选择分离**。两套后端（gsettings / reg.exe）都只依赖「跑一个命令」这个
   能力，所以它们不需要 build tag，能在 Linux 上把 Windows 后端也测一遍（把 `reg.exe` 的
   输出当输入喂进去）。真正平台相关的只有 `platform()` 一个函数、三行。这让「不留半应用」
   这种关键性质在两套后端上都有真实用例，而不是「Windows 上没测」。
5. **读不到旧值就不写**。回滚能力等于快照能力：一个读不出来的设置写下去就是不可撤销的。
   gsettings 后端因此在第一步 `get` 失败时直接返回错误（哪怕只是某个 schema 缺失）；
   Windows 后端相反，`reg query` 报「值不存在」是合法状态（从没配过代理的机器就是这样），
   记成「不存在」，回滚时删掉而不是写回。
6. **失败即启动失败，而不是打一行 warning 继续跑**。`system-proxy = on` 是一个明确的意图，
   悄悄不生效的后果是「用户以为整机在走代理，实际没有」——正是这个包最想避免的那种
   「看起来配好了」的状态。所以写失败时按 TUN 的同一条路径回滚并返回错误。代价是
   没有桌面设置工具的服务器上开了这一项就起不来，需要显式关掉；`-check` 与错误文本都把
   这一点说清楚。
7. **`since` 是时长或时刻，不是「一个页码」**。历史查询的自然问句是「最近一小时」，
   所以 API 直接收 `1h`，在 handler 里换算成时刻；`Provider` 保持无时钟。
8. **空集合永远序列化成 `[]`**。客户端不该为了「什么都没发生过」写一个 null 判断。
9. **采样写 0 而不是跳过空区间**。0 是关于那个区间的**事实**；有洞的序列没法画，也没法和
   总量对齐。代价是空转机器也会有一张 1440 行的表，正好就是容量上限的用途。

### 当前状态

- 验收五连全绿（Go 1.27，Linux/x86_64）：
  - `go build ./...`、`go vet ./...`、`gofmt -l .`（无输出）
  - `go test ./...`：**1085 条目 / 1064 通过 / 21 跳过 / 0 失败**（阶段 11 是 999/978/21/0，
    本阶段净增 86 条）。21 跳过与阶段 11 完全同一批：未连接 `sendto` 被 seccomp 拒绝的
    UDP 用例 + 缺参考实现的互通用例。
  - `go test -race ./...`：全绿（阶段 11 留下的抖动已修，本阶段新用例没有新增不确定性）。
  - `GOOS=windows go build ./cmd/... ./internal/...` 与 `GOOS=windows go vet ./cmd/...
    ./internal/...`：通过（`./...` 仍会被 `spikes/` 下 Unix-only 原型阻断，这是既有约定）。
  - `GOOS=darwin go build ./internal/sysproxy`：通过（`unsupported` 后端）。
- 覆盖率（本阶段直接相关的包）：`internal/store` 85.4%、`internal/sysproxy` 80.7%、
  `internal/api` 94.4%、`internal/cli` 75.8%。
- 观测层的体积与代价（按保留上限塞满后实测）：整份 image **400 KiB**（100 页），
  一次全量重写 **约 22 ms**（其中 fsync 占大头），读回约 5 ms。30 秒一次意味着约 0.07% 的
  占空比；这是「不用日志文件、换取文件永远自洽」的价钱，如实记录。
- 新增文件：`internal/store/{doc,store,sqlite}.go`、`internal/sysproxy/
  {sysproxy,gsettings,registry,platform_linux,platform_windows,platform_other}.go`、
  `cmd/melonarc-core/{history,history_test,sysproxy_test}.go`、`internal/api/history.go` 等；
  `go.mod` 未变。

### 遗留问题

- **观测层是「窗口」不是「档案」**：`2000 / 500 / 1440` 是写死的上限，没有配置项，也没有
  按天分表、导出、清理策略。整份重写意味着刷新期间会短暂占用两倍磁盘（旧文件 + 新临时
  文件），在极小的磁盘上仍可能失败（失败会被记录并重试，不影响转发）。
- **`samples` 的最后一小段不落盘**：关停时不写不完整区间（短区间画成整区间就是一次不存在的
  下跌），因此守护进程停止前后那不到一分钟的字节只进总量、不进序列。
- **进程被 SIGKILL 时最多丢失 30 秒记录**（下一次刷新之前的内容只在内存里）。
- **系统代理的「别人开过怎么办」**：只清除自己开的那一份（`applied` 标志），如果用户在守护
  进程运行期间又手动改过系统代理，关停时不会被还原成第三方值——只按「关掉」处理。
  桌面设置被别的程序同时改写也没有互斥保护。
- **SIGKILL 后系统代理留在开启状态**：机器会指向一个没人听的端口，直到下次启动或被手动关掉。
  没有「守护进程崩溃后自动回滚」的机制（需要外部看护，不属于本阶段）。
- **Linux 只覆盖 GNOME 系（gsettings）**：KDE 的 `kwriteconfig5/6`、环境变量方式（`http_proxy`
  只在登录会话里生效）、以及 Wayland/X11 的差异都没做。没有 gsettings 的机器开这一项会
  启动失败并给出明确原因。
- **Windows 后端只写注册表，不广播 `WM_SETTINGCHANGE` / 不调 `InternetSetOption`**：已经
  运行的浏览器可能要到重启才认新设置。这块要用 `syscall` 调 wininet，本阶段没做；也没有
  Windows 实机验证（与阶段 8/9 的欠账同一批）。
- **`connections` 只记 tcp/udp 承载成功的连接**：被拒绝、拨号失败的在 `events` 里，两张表
  的「一次请求」无法直接 join（没有关联 id）。
- **重载继承只保 `select` 组的 pin**：`url-test` / `fallback` 的历史（探测结果、当前成员）
  在重载时清零，这是既有语义，本阶段没改。
- **CLI 的 `history` 没有分页**：`limit` 是从最新往回截断，没有游标，也没有「按目标/策略
  筛选」。
- **README 的 Status 段仍停在阶段 3 的口径**（说 TUN 与加密出站未实现），已过期；
  本阶段不改文档口径，留待与 GUI 一起更新。
- 阶段 1–11 的遗留照旧（Windows 实机验证、用户态 TCP 边界、DoT/DoH 上游、规则集在线更新、
  Hysteria2/TUIC 互通证据、订阅能力子集、GUI 等）。

### 下一步计划

功能面到此收口，**下一步是 GUI**（开发文档 §2.7 与阶段 11 计划的第 4 条）：

1. **GUI 骨架：先静态样例**。按既定流程做一份**静态前端样例**（入站统计、失败记录、
   DNS 统计、策略组与订阅状态、审计、历史三个窗口的折线/表格），给出可访问的 URL 让用户
   确认版式与信息密度，**用户点头之后**再做 Tauri 外壳。不许跳过样例直接上 Tauri。
   本阶段已经把只读面收敛成 14 个端点（`/healthz`、`/v1/status`、`/v1/config`、`/v1/rules`、
   `/v1/rules/explain`、`/v1/policies`、`/v1/inbound`、`/v1/failures`、`/v1/dns`、`/v1/audit`、
   `/v1/history`、`/v1/history/connections`、`/v1/history/events`、`/v1/history/traffic`），
   样例只需要这些，不需要新端点。
2. 与 GUI 并行：Windows 实机验证（TUN、系统代理、令牌文件、交叉编译产物）、
   `WM_SETTINGCHANGE` 广播、README 口径更新。
3. 之后才是补课项：DoT/DoH 上游、规则集在线更新、XTLS-Vision、Hysteria2 拥塞控制与端口
   跳跃、TUIC 0-RTT 与心跳、`url-test` 重载后的探测历史保留。

---

## 阶段 13 — GUI 第一步：Tauri 骨架与架构（2026-11-14）

范围：把已经定稿的静态版式落成真正的桌面应用骨架，只做三个能读真数据的面板与三个占位页。
**核心 Go 代码一行未改**，`spikes/` 与 `docs/` 一个字未动；`go.mod` / `go.sum` 零改动。
顺带更正阶段 12 的一处旧记录：`sqlite3` 测试预言机的版本是 **3.45.1**，不是 3.50.4。

### 完成了什么

**1. 落盘位置与 Tauri 2 骨架**

- 开发文档 §3 只画了「桌面 UI（Tauri）」这一层，没有给目录；选 `apps/desktop`：
  与单一 Go module 的 `cmd/` / `internal/` 并列，`<app>/src`（前端）与 `<app>/src-tauri`
  （Rust 壳）同属一个应用目录，后续再加第二个前端或安装包脚本不用搬迁。
- `src-tauri/`：`Cargo.toml`、`build.rs`、`tauri.conf.json`、`capabilities/default.json`、
  `main.rs`（一个窗口 + 两个命令）、`settings.rs`（数据目录与 API 地址）、`api.rs`（令牌 +
  回环 HTTP）。窗口 1180×800，`withGlobalTauri`，CSP 只允许自身资源与 IPC。
- 前端产物 `dist/` 由 `scripts/build.mjs` 生成；`package.json` + `package-lock.json`
  入库，依赖图是空的，`npm ci --offline` 即可复现。

**2. 架构三件套**

- 设计令牌：`src/theme/tokens.css` 分两层——原始层（色板、间距刻度、圆角、字阶、
  动效时长）与语义层（表面、墨色、强调色、毛玻璃参数、布局尺寸）。`base.css` 与
  `panels.css` 只消费语义层；组件与面板**不写任何颜色、间距、圆角、模糊值、时长**，
  深色模式与「减少动效」也只是在令牌层覆盖。
- 面板注册表：`src/panels/registry.js` 是唯一扩展点。侧栏、hash 路由、标题、卸载
  全部由注册表生成；新增面板 = 新建一个模块 + 一行注册。六个页面签各自一个模块。
- i18n：`locales/zh-CN.json` 与 `locales/en.json`，本步全部界面文案都在里面，
  含 `meta.self`（语言自称）。启动时预载全部语言包，切换语言只换一次指针并重新挂载
  当前面板，**即时生效**、不重载窗口。新增日/韩/德/西 = 加一个同结构 JSON + 一行
  `LOCALES`。

**3. 三个真数据面板 + 三个占位页**

- 概览：`/v1/status` + `/v1/config` + `/v1/policies` —— 运行状态、版本、运行时长、
  规则/策略/出站点数、三个监听地址、各策略组当前节点、配置文件路径。
- 节点与策略：`/v1/policies` —— 组、成员健康与延迟、当前 pin；`select` 组的成员可点，
  走既有写端点 `POST /v1/policies/select`，成功后用应答里的 `active` 就地更新；
  `url-test` / `fallback` 组不提供点击（核心会拒绝，按钮不该存在）。
- 连接：`/v1/inbound` + `/v1/failures?limit=20` —— 活动/累计/失败/拦截四个计数、
  各监听计数表、最近失败记录表（阶段与类别翻成语言包里的标签，未知类别原样显示）。
- 规则 / 日志 / 设置：只放多语言占位页，明写「后续步骤实现」与各自计划要做的事；
  设置页另有关于区（占位 Logo、版本、许可证）。

**4. API 接入与令牌边界**

- 令牌只在两侧代持：Tauri 侧 `api_request` 读 `<data-dir>/api-token` 后加
  `Authorization` 头发到回环 API；开发预览 `scripts/dev-preview.mjs` 的 `/bridge` 前缀
  做同样的事。前端只有 `fetch('/bridge/...')` 或 `invoke('api_request')`，
  **界面、日志、DOM 里都没有令牌**，界面上最多显示令牌文件的**路径**。
- 数据目录默认规则与 `internal/datadir.Default()` 一致（`os.UserConfigDir()/melonarc`）；
  API 地址默认 `127.0.0.1:7946`（`defaultAPIListen`）。GUI 没有命令行，因此显式覆盖
  走 `MELONARC_DATA_DIR` / `MELONARC_API_ADDR`（预览脚本另有 `--data-dir` / `--api`）。
  Rust 侧**拒绝非回环地址**，避免把明文 bearer 发到别的机器；请求目标还做了
  字符集与长度校验，读应答有 4MiB 上界。
- 核心没起来时不是白屏：错误只带类别码（`token_missing` / `core_unreachable` /
  `unauthorized` / `no_bridge` / `api_error` / `bad_response`），顶部给多语言提示，
  列出启动命令、当前 API 地址、令牌文件路径与一句技术细节，并有重试按钮。
  任何一次成功请求都会把窗口自动恢复成在线。

**5. Logo**

- **Logo 已定稿**：蓝色渐变圆角底 + 加粗白色随手弧线 M（用户最终确认版）。
  已替换 `src/assets/logo.png`，并重新生成 `src-tauri/icons/` 下的 32/128/256/512 PNG
  与 `icon.ico`；简报里那张黑白磨砂版作废，仓库里不再有它。这仍是**位图占位**，
  正式矢量重绘与多尺寸导出留待后续图标资产步骤。

**6. 测试与验证件**

- `test/` 下 36 条 `node --test` 用例：语言包键集/占位符/CJK 硬编码扫描、注册表约束、
  版本四处一致、格式化、错误码映射、数据目录规则、真实核心集成（读五个端点 +
  pin 切换再还原 + 断言应答里不含令牌）、以及无浏览器 DOM 挂载烟测
  （六个页签、中英即时切换、离线提示）。

### 关键决策及理由

1. **用户约束一（组件化 + 设计令牌化）**：视觉参数全部收进 `tokens.css` 的语义层，
   业务组件只带 class 名；`lib/dom.js` 干脆不提供 `style` 入口，从工具上堵住内联样式。
   单测会扫 `src/` 里的 CJK 与远程资源引用，构建会检查语言包键集和页面引用文件是否齐备。
   理由是防止「先写死几个颜色、以后改版要翻二十个文件」——动效与排版后续想改，
   只需动令牌文件。
2. **用户约束二（预留扩展位）**：注册表模块契约固定为
   `{ id, icon, titleKey, order, mount(ctx) }`，注册时校验，挂载返回 `dispose`。
   骨架里没有 `switch (panelId)`，也没有「概览特殊处理」；面板只拿到
   `{ t, locale, api, core, root, navigate }`。传输层同样是注册表式的
   `chooseBridge`（原生壳 → 预览代理 → 无通道），加传输不改面板。
3. **用户约束三（i18n 先行）**：键值语言包在 `locales/<id>.json`，语言自称也进包，
   `LOCALES` 只列 id；这样目录结构直接能加 ja/ko/de/es。全部文案走 `t(key)`，
   唯一的例外是 `main.js` 在启动器本身崩掉时的一行 ASCII 兜底文本——那时语言包
   还没读出来，写什么都得硬编码，所以选了不含界面文案用途的一行。构建与测试都会
   拦「某个键只存在于一个语言」「源码里出现硬编码中文」。
4. **用户约束四（一步一步来）**：只做三个真面板、只用一个写端点（pin），
   规则树/匹配解释/日志/设置/流量曲线/托盘一概不碰，三个页签明确写占位。
   先把骨架、令牌边界与语言架构建稳，后面每加一个功能都是「新增模块并注册」。
5. **前端零依赖、构建手写**。本机 npm registry / crates.io / apt 全不通，拉不到
   Vite、React 或任何 Tauri JS 包；与其把构建建立在一个装不上的依赖上，不如用
   原生 ES module + 一段 100 行的零依赖构建脚本（`npm ci --offline` 已验证）。
   Tauri 命令直接经 `window.__TAURI__`（或内部 IPC 回退）调用，不引入 JS 客户端包。
   后续若引入打包器，只需替换 `scripts/build.mjs` 与 `frontendDist`，面板模块不用改。
6. **Rust 侧手写回环 HTTP 客户端**。目标是本机明文 HTTP/1.1 + JSON，引入完整 HTTP 栈
   会顺带拖进一套用不上的 TLS 配置和依赖树；用 `std::net::TcpStream` 写死
   `Connection: close`、方法白名单、请求目标校验、超时与读上界，反而更容易审。
7. **两个传输、一份错误分类**。原生壳与预览代理都不把令牌交给页面，错误码在
   `src/api/errors.js` 里收敛成六个；只有「连不上」和「令牌不认」会改变全局状态，
   某个端点 500 只是该面板自己显示读失败。这样核心一恢复，界面无需刷新就回来。
8. **预览代理是开发件，不是分发路径**。它让版式和真数据能在浏览器里迭代，
   但正式产物只经 Rust 壳；`README.md` 明确写了这一点。

### 依赖登记（GPLv3 兼容）

| 名称 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| Tauri（`tauri`） | `2`（caret，精确版本由首次 `cargo build` 生成的 `Cargo.lock` 固定） | MIT 或 Apache-2.0 | 窗口、IPC、能力配置 |
| `tauri-build` | `2`（同上） | MIT 或 Apache-2.0 | 构建期嵌入配置与图标 |
| `serde` | `1`（同上） | MIT 或 Apache-2.0 | 命令应答的 `Serialize` 派生 |
| 前端 JS 依赖 | 无 | — | `package-lock.json` 里只有根包 |
| 系统运行库（Linux） | 由发行版提供 | WebKitGTK / GTK 等 LGPL 系 | Tauri 运行时动态链接，**不随仓库分发** |

本机没有 crates.io 索引，无法预生成 `Cargo.lock` 或枚举 `tauri` 的全部传递依赖；
首次联网构建后需要补一次完整许可证清单复核（见遗留问题）。Go 侧无新增依赖。

### 当前状态

- 前端构建链：`npm ci --offline` 通过；`npm run build` 通过（`dist/` 25 文件 / 147.5 KiB）；
  构建会校验语言包键集一致、页面引用的文件都存在、无远程资源。
- 前端测试：无核心时 `npm test` **34 通过 / 2 跳过 / 0 失败**（跳过的是需要真实核心的
  两条，跳过原因写在用例上）；挂真实核心后 **36 通过 / 0 跳过 / 0 失败**。
- 真实核心验证：用 `/tmp/arc/demo.conf` 起了 `melonarc-core`（数据目录
  `/tmp/arc/data`，令牌文件 0600），经本地目标服务制造了真实流量：
  `/v1/status` 报 `0.1.0-dev`、7 条规则、3 个策略组；`/v1/config` 报三个监听地址；
  `/v1/inbound` 报累计接受 3、失败 2、规则拦截 1；`/v1/failures` 有
  `example.invalid:80`（refused）与 `blocked.test:80`（rejected）两条真实记录。
  预览代理 `/bridge/v1/status`、`/bridge/runtime` 及静态资源均 200；集成用例通过
  `POST /v1/policies/select` 把 `manual` 切到另一成员、回读确认、再切回原值。
  无浏览器 DOM 烟测覆盖六个页签、中→英即时切换、以及核心不可达时的中文提示。
- Go 侧验收五连全绿，与阶段 12 完全一致、无回退：
  `go build ./...`、`go vet ./...`、`gofmt -l .`（无输出）、
  `go test -count=1 ./...` **1085 条目 / 1064 通过 / 21 跳过 / 0 失败**
  （21 条仍是既有的 UDP/互通环境跳过，无新增跳过）、
  `GOOS=windows go build ./cmd/... ./internal/...` 通过。
- **未通过的验收项（如实记录）**：Tauri 原生窗口没能在 Xvfb :99 打开。本机既没有
  `rustc` / `cargo`，也没有 `libwebkit2gtk-4.1-dev`，crates.io 与 apt 都不可达，
  `cargo build` 无法执行；Rust 壳只以源码交付，未做本机编译验证。另外本机自带的
  Chromium 在此沙箱里启动即 SIGTRAP，连 `about:blank` 都截不到图，所以**没有界面截图**；
  证据改用上面的真实核心日志、预览代理应答、集成测试与无头挂载烟测。

### 遗留问题

- **Rust 壳未经编译**：`Cargo.lock` 尚未生成，传递依赖清单与许可证复核也还没做；
  拿到有 Rust 工具链 + WebKitGTK 的机器后第一步应跑 `cargo build` 并把锁文件入库。
  `tauri.conf.json`、能力文件、命令签名都只做过静态核对（JSON/TOML 语法已校验）。
- **没有界面视觉留证**：与已定稿静态样板的像素级对齐（毛玻璃、密度、深浅色）
  目前只靠令牌取值一致与 DOM 烟测，尚未用真实窗口截图核对。
- **核心若配置了非默认 `data-dir`，GUI 会对不上**：GUI 不解析核心的 INI 配置文件
  （那会把配置层耦合进界面），只能按同一默认规则找，或由用户设
  `MELONARC_DATA_DIR` / 预览的 `--data-dir`。这是当前最可能踩到的使用缺口。
- **API 地址同理**：核心配置里改了 `api-listen` 而 GUI 没设 `MELONARC_API_ADDR` 时
  会连到默认的 `127.0.0.1:7946`。设置页（后续步骤）应把这两个值做成可见可改。
- 令牌轮换后旧窗口会进入 `unauthorized` 状态，需要点一次重试；没有自动重读的
  后台退避。面板轮询节拍写死 4~5 秒，除离线横幅外没有手动刷新按钮。
- 三个占位页尚未实现；规则树、匹配解释、日志/审计/历史视图、流量曲线、系统托盘、
  配置编辑与托盘启停都留待后续。
- 只有 zh-CN 与 en 两个语言包；日/韩/德/西只是结构可加，内容还没有。
- Windows / macOS 安装包未构建，Windows 实机验证与仓库根 README 的口径更新
  （阶段 12 已挂账）仍未做。
- Logo 仍是位图占位：正式矢量重绘、多尺寸与平台专用格式导出留待图标资产步骤。

### 下一步计划

1. **先补编译验证**：在有 Rust + WebKitGTK 的机器跑 `cargo build` 并在 Xvfb :99
   打开窗口，连真实核心截图三个数据面板；提交 `Cargo.lock`，复核完整依赖许可证。
2. 之后是规则页（`/v1/rules` + `/v1/rules/explain`）与日志页
   （`/v1/history/events` + `/v1/audit`），都按「新增模块并注册」的方式接。
3. 设置页把语言、主题、API 地址与数据目录做成可见可改，顺手消掉上面两条对不上的缺口。
4. 再往后：连接页接 `/v1/history/connections` 与流量曲线、系统托盘、
   Logo 矢量化与图标资产、Windows 构建与 README 口径更新。

## 阶段 14 — GUI 第二步：规则 / 日志 / 设置（2026-11-14）

范围：按阶段 13 的下一步计划，先限时重试 Rust / WebKitGTK 工具链，再把规则、日志、
设置三个占位页补成真实功能。**核心 Go 代码一行未改**，`spikes/` 与 `docs/` 一个字未动，
`go.mod` / `go.sum` 零改动；阶段 13 暂缓的 6 个图标二进制文件本阶段不处理。
开工前已确认工作区干净、HEAD 为 `e4a5f74`。

### 任务 A：Rust 工具链与 Tauri Linux 依赖重试（限时，两次为限）

用户提示本机网络状态可能已变化、凌晨曾从镜像成功取到 `.deb`，故按「一次完整安装尝试
＋一次换源尝试」上限重试，**不无限重试**。两次都失败，确切失败点如下。

**第 1 次：默认源的一次完整安装尝试**

- `apt-get update` 直接失败，代理主机名解析不了，且沙箱不允许写 apt 状态目录：

  ```text
  Temporary failure resolving 'hatch-egress-proxy'
  W: Problem unlinking the file /var/lib/apt/lists/partial/... - IsAccessibleBySandboxUser (1: Operation not permitted)
  E: Unable to read /var/cache/apt/ - opendir (1: Operation not permitted)
  E: The package lists or status file could not be parsed or opened.
  ```

- 安装前探测确认：本机既没有 `rustc` / `cargo`，也没有 `libwebkit2gtk-4.1-dev`；
  因此 Tauri 官方 Linux 依赖清单（`libwebkit2gtk-4.1-dev`、`build-essential`、
  `curl`、`wget`、`file`、`libxdo-dev`、`libssl-dev`、`libayatana-appindicator3-dev`、
  `librsvg2-dev`、`patchelf` 等）连解析包索引这一步都没走到。
- 网络探测结果不一致：通用环境代理对 apt 镜像返回 `403`、对 crates 端点超时；
  `hatch-egress-proxy:3128` 对 Ubuntu 镜像的 HTTP URL 能返回 `200`，但
  `crates.io` 与 cargo 镜像全部 `000`（超时）。即.deb 通道可能可用，Rust 依赖通道不可用。

**第 2 次：换源 + 显式出网代理**

- 改用镜像源并显式指定出网代理后，更新与安装仍全部失败：

  ```text
  UPDATE_RC=100
  INSTALL_RC=100
  Temporary failure resolving 'hatch-egress-proxy'
  E: Unable to locate package rustc
  E: Unable to locate package cargo
  E: Unable to locate package libwebkit2gtk-4.1-dev
  E: The package lists or status file could not be parsed or opened.
  ```

- 该次尝试还被沙箱安全策略拦截（「命令被安全策略拦截，但 Sandbox 未返回具体资源，
  无法安全重试」），并明确要求不得重试等价方案；因此按预定上限停止，不再尝试第三条路径。

**任务 A 结论（如实记录）**：Rust 工具链与 WebKitGTK 开发包**没装上**，
所以下面四件约定产物本阶段都**没有**：

1. `cargo build` 未执行，Rust 壳仍只以源码交付、未做本机编译验证；
2. `Cargo.lock` 未生成、未入库，Rust 依赖版本仍未锁定；
3. Xvfb :99 上**没有原生窗口**（Xvfb 进程本身在跑，但没有可启动的窗口二进制），
   概览 / 节点与策略 / 连接三张截图**没有**；
4. Rust 传递依赖许可证清单**无法枚举**，阶段 13 登记的那张表仍是唯一依据，
   待首次联网 `cargo build` 后补复核。

这不是功能缺陷，是构建环境问题；任务 A 到此封顶，继续任务 B。

### 完成了什么（任务 B）

**1. 先查 API 现状，命中测试不用改核心**

动手前逐个核对 `internal/api/server.go` 的路由表与 `internal/api/views.go` 的线格式，
确认核心**已经有** `GET /v1/rules/explain`（`parseExplainRequest` 接受 `name` / `addr` /
`port` / `network`，自己校验 IP、端口与网络），装配在 `cmd/melonarc-core/state.go` 的
`daemonState.Explain`。因此阶段 13 记的「可能缺 HTTP Explain 端点」不成立，规则页的
命中测试直接接既有能力，**核心 Go 代码零改动**，也不需要把「命中测试」挂成遗留。

- 只读规则列表：`GET /v1/rules?limit=500`，字段严格照 `RuleView`
  （`index` / `type` / `payload` / `target` / `source` / `line` / `no_resolve`）；
  外部规则集来自 `GET /v1/config` 的 `rule_sets`（`name` / `path`）。
  API 只给这两个字段，界面明确写出「没有条目数与刷新时间」，不臆造。
- 命中测试：输入域名或 IP，`isIP` 判定后分别发 `name=` 或 `addr=`（可选 `network`），
  展示 `matched`、命中规则、`steps` 决策路径、`resolution` 与 `report`；
  IP 走 `addr` 而不是 `name`，有单测钉住。全程只读，不改配置。
- 面板 5 秒轮询，读失败只显示类别化错误，成功则 `core.noteSuccess()` 恢复在线状态。

**2. 日志面板：`/v1/audit` + `/v1/failures`**

- 审计走 `GET /v1/audit?limit=64`（`time` / `action` / `result` / `detail` / `remote`），
  失败记录走 `GET /v1/failures?limit=20`
  （`time` / `target` / `network` / `stage` / `category` / `policy`）。
- **过滤按线格式真实字段推导，不新增字段**：级别 = 审计的 `result`
  （`ok` / `failed`）或失败记录的隐式 `failed`；来源 = 审计的 `action`
  （`policy.select` / `config.reload`）或失败记录的 `stage`（`route` / `dial`）。
  未知值原样显示，翻译缺失时回落原文。
- 「暂停滚动」保留当前快照：暂停期间不再拉取、不再自动滚到底部，恢复后继续 4 秒轮询。

**3. 设置面板：可见可改、持久化、重启口径**

- 新增叶子模块 `src/lib/gui-settings.js`：`localStorage` 键 `melonarc.gui` 存
  `MELONARC_DATA_DIR` / `MELONARC_API_ADDR` 两份覆盖值，默认 API 地址
  `127.0.0.1:7946`；提供 read / save / clear / validate / `envLines` / `setLocale`。
  API 地址只接受回环（`localhost`、`::1`、`127.*`）+ 合法端口，与 Rust 侧红线一致；
  数据目录拒绝控制字符；存储不可写不抛异常，只回报失败。
- 面板显示「当前生效值」（来自 bridge 的 runtime 元数据，只含路径/地址不含令牌）、
  可编辑的两个字段、保存/重置，以及**下次启动 GUI 时要设的两行环境变量**。
  重启口径写死在文案里：这两个值由桌面壳**启动时**读取 → 保存后**重启 GUI 生效**；
  只有核心配置里的 `data-dir` / `api-listen` 改了才需要**同时重启核心**（且重启会轮换令牌）。
- 语言切换复用阶段 13 的头部机制：`setLocale()` 写共享键 `melonarc.locale` 后
  向 `#locale-select` 派发 `change`，由既有 `app.js` 完成重挂载，**即时生效**；
  因此 `app.js` / 路由 / 侧栏一字未改。
- 关于区用定稿 Logo `src/assets/logo.png`、`APP_VERSION` 与 `APP_LICENSE`（GPLv3 字样），
  并配一条多语言许可证说明。

**4. 接入层与测试**

- `src/api/client.js` 新增 `rules` / `explain` / `audit` 三个方法与 `withQuery`（只带非空参数），
  `Paths` 补齐四条路径；新增 `runtime()` 读 bridge 元数据（不含令牌）。
- `src/panels/registry.js` 只把三处占位导入换成真模块，注册行仍是唯一扩展点；
  `src/panels/placeholders.js` 删除。样式只在 `tokens.css` 增加布局尺寸、表格列比、
  1px 边框宽度令牌，`panels.css` 新增类全部消费语义令牌。
- 语言包 zh-CN / en 各 **220 键**，键集与 `{占位符}` 集合完全一致；删除废弃的
  `placeholder.*` 键，新增 `common.yes` / `common.no` 等共享键。
- 新增 `test/gui-settings.test.mjs`（缺省/损坏设置、存取往返、存储拒绝、回环校验、
  环境变量行、语言切换通知）与 `test/panels.test.mjs`（三个真面板的无头挂载、
  过滤、暂停、命中测试参数、注册表契约）；扩展 `client.test.mjs`、
  `test/lib/app-smoke-run.mjs`（六页签烟测改为真面板断言）、`test/lib/fake-dom.mjs`
  与 `live-core.test.mjs`（实时断言覆盖新端点，并把新应答加入令牌泄漏检查）。

### 关键决策及理由

1. **不改核心**：Explain 端点已存在，用现成的比在阶段 14 动 `api` / `rules` 边界更安全，
   也正好满足用户「先查 API 现状、缺了才降级」的分支条件。
2. **日志不臆造字段**：审计与失败记录没有 `level` / `source`，用 `result` / `action` /
   `stage` 做映射并在语言包里给出可读标签；宁可少一列，也不给界面喂假数据。
3. **GUI 设置归 GUI**：`MELONARC_*` 是壳的启动期环境，窗口内无法热替换，
   所以设计成「窗口自己持久化 + 明确提示重启 GUI」，并把「核心要不要重启」单独说清，
   避免把两类重启混成一句「重启生效」。
4. **语言切换借道既有头部控件**：派发 `change` 复用 `app.js` 的重载与重挂载逻辑，
   既满足「即时生效」又不动壳/路由/侧栏结构，改动面最小。
5. **只加模块、只改一行注册**：新增 4 个模块、删 1 个占位模块，`registry.js` 的注册行
   是唯一结构改动；面板契约 `mount(ctx) → { dispose }` 保持不变。
6. **视觉值只在令牌层**：新增 3 个布局尺寸、5 组表格列比、1 个 `--border-hairline`；
   新增 CSS 与面板 JS 里没有颜色、间距、圆角、时长、像素字面量。
7. **零新依赖**：前端运行时依赖与 Rust crate 都保持 0 新增，
   `package.json` / `package-lock.json` / `Cargo.toml` 未改；本机无 crates.io 索引，
   强行加依赖只会让构建更不可复现。
8. **实时测试挂真核心**：新增端点全部用真实 `melonarc-core` + 真实令牌文件 +
   真实代理流量验证，并把四份新应答并入「任何应答都不许含令牌」的检查。

### 依赖登记（GPLv3 兼容）

| 名称 | 版本 | 许可证 | 用途 |
|---|---|---|---|
| 前端运行时依赖 | 本阶段新增 0 | — | `package.json` / `package-lock.json` 零改动，依赖图仍只有根包 |
| Rust crate | 本阶段新增 0 | — | `Cargo.toml` 零改动；`Cargo.lock` 仍缺（任务 A 失败） |
| Go module | 本阶段新增 0 | — | `go.mod` / `go.sum` 零改动 |
| 系统运行库（Linux） | 由发行版提供 | WebKitGTK / GTK 等 LGPL 系 | 不随仓库分发，未安装、未链接 |

阶段 13 登记的 Tauri / `tauri-build` / `serde` 表仍是唯一依据；任务 A 没跑成
`cargo build`，因此**没有**可枚举的传递依赖清单，也没有可复核的锁文件版本。

### 当前状态

- 前端构建链：本阶段早前一次 `node scripts/build.mjs` 通过（`dist/`
  **28 文件 / 191.0 KiB**，比阶段 13 的 25 文件多 3 个净新增模块）；构建会校验
  语言包键集一致、页面引用的文件都存在、无远程资源。语言包实测 zh-CN / en
  各 **220 键**、键集与占位符 **0 差异**。
- 前端离线测试（托管 Node 22.22.2）：
  `env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u NODE_USE_ENV_PROXY node --test --test-concurrency=1 "test/*.test.mjs"`
  → **50 条目 / 48 通过 / 2 跳过 / 0 失败**（基线 34/2/0，通过数 +14；
  2 条跳过仍是既有的「需真实核心」用例，**无新增跳过**）。
- 前端实时测试（系统 Node 24.22.1，挂 `/tmp/arc/demo.conf` 起的演示核心、真实令牌文件
  与真实代理流量）：**50 条目 / 50 通过 / 0 跳过 / 0 失败**（基线 36/0/0，通过数 +14）。
  新增实时断言覆盖 `/v1/rules`、`/v1/rules/explain?name=…&network=tcp`、
  `/v1/rules/explain?addr=…`、`/v1/audit?limit=64`，并全部并入令牌泄漏检查。
- Go 侧验收五连全绿、与阶段 12/13 完全一致、无回退：`go build ./...`、`go vet ./...`、
  `gofmt -l .`（无输出）、`go test -count=1 -v ./...`
  **1085 条目 / 1064 通过 / 21 跳过 / 0 失败**（16 个包，21 条仍是既有的 UDP/互通环境跳过）、
  `GOOS=windows go build ./cmd/... ./internal/...` 通过。
- 命名红线：新增/修改的源码、样式、语言包、测试、DEVLOG 新增段落与两处提交信息
  已扫描，无非开源商业产品名称；公开协议名与开源项目名不在此限。
- 提交：任务 A 的失败记录单独一笔（`5d7e320`），任务 B 的代码与本记录随后一笔。

### 遗留问题

- **任务 A 四件产物仍缺**：Rust 壳未编译、`Cargo.lock` 未生成、原生窗口三张截图没有、
  Rust 传递依赖许可证清单无法枚举；沿用阶段 13 的挂账，未因本阶段重试而改善。
- **托管 Node 22 在本沙箱有 undici Wasm 问题**：本机 `vmemory` 硬上限 4 GiB，
  Node 22.22.2 下一次普通 `node:http` 请求会触发 `lazyllhttp` 的
  `WebAssembly.instantiate(): Out of memory`，以 `unhandledRejection` 形式污染
  `node:test` 的第一个用例；HTTP 请求本身成功，属环境瑕疵而非产品缺陷。
  已用最小复现钉住，实时模式改用系统 Node 24.22.1 验证并全绿；
  离线模式仍用托管 Node 22（清理代理环境变量 + 串行并发）全绿。
- **`dist/` 当前是部分陈旧产物**：收尾时重跑构建，脚本的清空步骤被沙箱删除保护拦下，
  且拦截前已删掉部分旧文件（28 → 4）。`dist/` 是 git 忽略的构建输出、不入库，
  源码树、语言包校验与全部测试都不依赖它；在允许清理的环境重跑一次
  `node scripts/build.mjs` 即可复原。安全策略明确要求不得重试等价删除命令，故未强行绕过。
- **GUI 设置还不能「点了就生效」**：值存在窗口里，环境变量仍需在下次启动时由用户或
  启动器注入；本阶段按用户要求明确写成「重启 GUI 生效」，没有改 Rust 侧读取逻辑。
- 规则集 API 只有 `name` / `path`，没有条目数与刷新时间；命中测试也没有批量与历史。
- 日志只有固定 limit 与级别/来源过滤，没有时间范围、搜索、分页、导出或历史视图；
  暂停是「停拉取 + 保快照」，不是服务端流式订阅。
- 沿用阶段 13 的其它挂账：令牌轮换后旧窗口需手动重试、轮询节拍写死、
  连接页尚未接 `/v1/history/connections` 与流量曲线、系统托盘、只有两种语言、
  Logo 位图待矢量化与图标资产、各平台安装包与 README 口径更新。

### 下一步计划

1. 找一台有 `rustc` / `cargo` / `libwebkit2gtk-4.1-dev` 且能连 crates.io 的机器：
   `cargo build` → 提交 `Cargo.lock` → 在 Xvfb :99 打开窗口、连真实核心截三张图 →
   复核完整传递依赖许可证；同时重跑一次 `node scripts/build.mjs` 复原 `dist/`。
2. 把 GUI 设置从「提示环境变量」升级为「壳启动时直接读窗口设置」，做到保存后
   只需重启、无需手工设环境变量（这一步要改 Rust 侧，届时同步登记依赖与权限）。
3. 规则页接规则集内容预览与命中历史；日志页接时间范围、搜索、导出与
   `/v1/history/events`，并评估服务端流式订阅。
4. 之后是连接页历史与流量曲线、系统托盘、Logo 矢量化与图标资产、安装包与 README 更新。

### 阶段 15 开工前依赖说明（第 3 项 QPACK）

- 不引入 QPACK 编解码库；自研 h3 头部块编解码保留。响应侧需要能解 Huffman 编码的
  字符串（成熟 QPACK 编码器会对常见串启用 Huffman），仅把已在模块图内的
  `golang.org/x/net v0.56.0`（BSD-3-Clause，与 GPLv3 兼容，源码已在本机模块缓存）
  从间接依赖升为直接依赖，使用 `http2/hpack` 的 Huffman 解码；不增新模块、不联网。
- 理由：手写 257 项 Huffman 码表易错且无法与成熟实现逐项对照；复用其码表可把
  「与规范一致」固定为已知答案测试。版本与许可证如上，用途仅限字符串编解码。

---

## 阶段 15 — 按外部评审修订的修复批（2026-11-15）

任务来源：仓库外评审文件 `melonarc-review-gpt-20261115.md`（只读参考，未拷入仓库）。
本阶段只做评审点名的 9 项修复，逐项单独实现、单独补测试、尽量少动；不改
`spikes/`、不改 `docs/development-doc-v1.md`、不动六个前端面板的功能。

### 逐项修复内容与证据口径

1. **QUIC 互通夹具信任注入（第 1 项，`31dd276`）**
   - `trustDialer` 原来只认 `*Trojan` / `*VLESS`（这两类保留可变 `TLSOptions`）；
     Hysteria2 / TUIC 在构造期就把 TLS 选项编译进 `*tls.Config`，事后改不到。
   - `Spec` 增加 `TLSConfig *tls.Config` 测试逃生口（配置层绝不设置），
     夹具用 `trustSpec(spec, pool)` 在 `New(spec)` 前注入测试 CA；
     生产 QUIC 拨号器显式命名 `dialQUICDefault`（`quic.DialAddr`），互通测试用
     `useProductQUICDial` 恢复产品路径；进程内 QUIC 单测仍走既有的
     `dialQUICConnected` 钩子，两者不合并。
   - 新测试：`TestInteropQUICFixtureInjectsTrustAtConstruction`（hysteria2/tuic）、
     `TestInteropQUICFixtureReachesSendtoBoundary`（hysteria2/tuic）——后者断言
     拨号推进到 seccomp 的 `sendto` 边界（EPERM）。
   - **证据口径**：本机 seccomp 禁止未连接套接字 `sendto`，QUIC 首程无法真实互通；
     本项验收只到「夹具注入信任 + 拨号到达 `sendto` 边界」。Hysteria2 / TUIC
     **仍按「已知不可用、修复进行中」口径**，不得写成已互通；真实互通待环境复验。

2. **TUIC 认证：导出标签用 UUID 原始字节（第 2 项，`31dd276`）**
   - 参考实现用 `uuid.as_ref()`（16 字节原始值）作 TLS exporter 标签；本实现原来
     用格式化 UUID 文本，导致外部实现认证必败（评审 TUIC 失败根因）。
   - 改为 `string(id[:])`（`tuicExporterLabel`），密码仍是上下文，令牌长度仍 32 字节。
   - 已知答案测试：`TestTUICExporterLabelKnownAnswer`、
     `TestTUICAuthenticationTokenKnownAnswer`；自研测试对端同步改为原始字节。

3. **HTTP/3 QPACK 头部块对齐 RFC 9204（第 3 项，`31dd276`）**
   - 原实现漏了 §4.5.1 的编码字段段前缀（必需插入计数 8 位前缀 + S/Delta Base
     7 位前缀），静态表也不全；外部实现回包解不开，即评审 Hysteria2
     错误码 512 / 字段段解码失败的根因。
   - 补齐：每个头部块带 `0x00 0x00` 前缀（本客户端无动态表，插入计数必须为 0，
     非零即拒）；静态表补全 99 行；字符串支持 Huffman 解码（复用
     `golang.org/x/net/http2/hpack` 的码表，依赖登记见下方「开工前依赖说明」）；
     静态表越界索引由静默丢字段改为报错。
   - 已知答案测试：RFC 9204 附录 B 向量（B.1 字面量、B.2 / B.4 动态表应拒）、
     `TestH3StaticTableIsComplete`（99 行）、Huffman 解码、前缀整数扩展用例；
     自研 QUIC 测试对端的响应块同步加前缀。

4. **启动输出不再泄露 Bearer 令牌（第 4 项，`696755b`）**
   - 原来 `fmt.Printf` 直接把完整令牌打到 stdout。现在 `announceAPI` 只打印
     监听地址与令牌文件路径，结构化日志同样只带 `token_file`。
   - 测试 `TestStartupOutputDoesNotDiscloseToken`：对 stdout 与日志分别断言
     不含令牌本体、且含文件路径。

5. **凭据连接的地址校验三处统一（第 5 项，`f41df25`）**
   - 统一口径：按 IP 类型判断回环（不做字符串前缀匹配）；`localhost` 必须解析并
     逐一验证解析结果全部为回环后才连接已验证的地址；IPv6 用规范括号形式；
     凭据请求禁远端代理（`Proxy = nil` / 裸 `TcpStream`）、禁重定向
     （`http.ErrUseLastResponse`）。
   - Go CLI：`resolveAPITarget` / `loopbackIP`，请求钉死到已验证地址的拨号器。
   - JS 预览桥（`dev-preview.mjs` + 新共享模块 `address.mjs`）：启动即
     `assertDevelopmentOnly()`（`NODE_ENV=production` 拒绝启动）；API 地址走
     `resolveAddress`；`/bridge` 校验 Host 与浏览器 Origin（写请求必须有合法
     Origin）；目标路径走 `validateBridgeTarget`；上游请求头经
     `upstreamRequestOptions` 统一构造（不带令牌，令牌单独注入）。
   - Rust 壳（`settings.rs` / `api.rs`）：`Settings` 改存 `api_addrs: Vec<SocketAddr>`
     （读设置时已验证的回环地址，连接期只拨这些地址并再验回环）+
     规范括号 `api_label`；`connect` 用裸 `TcpStream::connect_timeout`，
     无环境代理、无重定向（3xx 原样返回）。**仅源码交付**：本机无
     `rustc` / `cargo`，未编译，沿用阶段 13/14 挂账。
   - 测试：Go 侧 `TestAPIBaseNormalisation` 扩展（规范 IPv6、https/私网/域名/
     userinfo/路径/查询/缺端口拒绝）、`TestAPIBaseRejectsNonLoopbackByIPType`、
     `TestLocalhostMustResolveOnlyToLoopback`（混入非回环解析结果必须拒）、
     `TestCredentialedRequestRefusesRedirectsAndProxy`（真实 HTTP 服务端 +
     环境代理变量，断言不跟随、不走代理）；JS 侧新增 `address.test.mjs` 与
     `paths.test.mjs` 扩展共 8 条；Rust 侧 `#[cfg(test)]` 单测随源码交付、未编译。

6. **SQLite 历史保全：不再用空表覆盖（第 6 项，`dba1db8`）**
   - 原行为：打不开 / 版本不认识的库文件照常以空表继续，`Flush` 时用
     原子重写把原文件覆盖掉，历史不可逆丢失。
   - 新行为：读不开 / `userVersion` 不认识 / 表读失败 → 进入 `preserve` 态
     （`ErrHistoryPreserved`）：原文件原地保全、字节不动，`Flush` 与
     `Close` 前的最后落盘一律拒绝替换并返回显式包装错误；`Close` 不把
     拒绝视为停机失败；`Notice` 全程说明「原文件已保全、写入挂起」，
     经 `/v1/history` 与 CLI `note:` 透出。选择原地保全而非备份改名：
     谁都不该替用户动它的历史文件，明确报错 + 手动移走是更安全的契约。
   - 测试：`TestStorePreservesACorruptFile`（损坏夹具）、
     `TestStorePreservesAFileFromAnotherVersion`（合法镜像 + `userVersion+1`），
     均断言 `Flush` 返回 `ErrHistoryPreserved`、原文件字节不变、重启后仍保全；
     原 `TestStoreReplacesAFileItCannotRead`（旧语义）删除。
   - modernc 驱动迁移列入后续计划（见遗留问题）。

7. **系统代理释放：恢复接管前快照（第 7 项，`bedf0ca`）**
   - 原行为 `Release` 只是清空代理（gsettings 置 `none` / 注册表置 `0x0`），
     用户接管前的手工代理配置被抹掉。
   - 新行为：`Enable` 前先拍快照（每个后端先读后写），持久化到
     `<data-dir>/system-proxy.json`（临时文件 + Rename，0600）；`Release` 恢复
     快照——只恢复「当前值仍等于本程序写入值」的字段，用户改过的字段不动，
     接管前就不存在的注册表值恢复为不存在（删除）；进程重启后由
     `recoverSnapshot` 从盘上记录恢复，后端不匹配（换机器/换后端）则保留记录
     并显式报错，不盲目写。快照恢复成功后删除盘上记录。
   - `Backend` 接口 `Clear` → `Restore(Snapshot)`；gsettings 逐键读回、列表按
     条目比较（GVariant 重排格式不算用户改动）；注册表 DWORD 读回的 `0x0`
     归一化后与写入值比较。
   - 测试：正常恢复（逐字段回写、快照文件删除）、用户改过的字段不覆盖、
     跨进程重启的快照恢复（模拟：启用 → 释放后重开控制器）、失败回滚、
     后端不匹配保留记录；`cmd/melonarc-core` 侧 `fakeProxy` 同步适配。

8. **REALITY TLS 1.3 服务器 CertificateVerify 验签（第 8 项，`c959c4d`）**
   - 原实现对 `CertificateVerify` 只挂进转录不验签（注释明说赌调用方不依赖
     证书链）；REALITY 的认证恰恰经过这条握手，服务器签名必须验。
   - 新行为：按 RFC 8446 §4.4.3 验证——签名内容是固定上下文串 +
     握手转录哈希，用证书叶子公钥（ECDSA P-256 / Ed25519）验证；消息顺序
     强制 Certificate → CertificateVerify → Finished，任何失败在**任何业务
     数据送达之前**终止握手。`Options.VerifyPeer` 钩子保留，收原始证书链。
   - 不引新 TLS 库、不做指纹仿真、不做会话复用（约束不变）。
   - 测试（`tls13_certverify_test.go`）：正例用独立 `crypto/tls` 服务器
     （ECDSA / Ed25519 两种真实签名）；负例：改签名一个字节、签错转录
     （换 ClientHello 后重签）、错误密钥类型（RSA 公钥）、算法不匹配、
     长度不符、截断，全部断言拨号失败且连接上收不到应用数据。
   - **证据口径**：仅单元/已知答案 + 独立标准库对端验证，上游参考实现
     互通未复跑；换库评估列入后续计划。

9. **README 支持矩阵改为证据口径（第 9 项，`914a418`）**
   - 删除 MVP 时代的过期承诺（如「加密出站未实现」），改为逐协议
     TCP / UDP 验证状态 + 证据环境：明确区分外部评审（macOS arm64、
     2026-11-15）的阶段 11 七组 TCP/UDP 通过、Hysteria2 / TUIC 三轮全败
     （错误码 512 / 认证失败，修复已落码但**未在本机复验真实互通**）、
     本机 seccomp 限制下未验证的 UDP 路径清单；Windows 标注仅交叉编译；
     性能目标标注未在真实硬件实测；REALITY 验签标注「单元已验、互通未复跑」。
   - 命名红线扫描通过（无非开源商业产品名称）。

### 关键决策

- **QUIC 验收口径降级为本机可达边界**：第 1/3 项的验收只到「夹具注入 +
  RFC 向量已知答案 + 拨号到达 `sendto EPERM`」，不在 DEVLOG 里把 QUIC 互通
  写成已修复/已通过；真实互通复验是遗留问题。
- **第 3 项不引 QPACK 编解码库**：仅把模块图内已有的 `golang.org/x/net v0.56.0`
  （BSD-3-Clause，GPLv3 兼容）从间接升为直接依赖，用 `http2/hpack` 的
  Huffman 解码；登记见上方「阶段 15 开工前依赖说明」。除此之外零新依赖，
  `go.sum` 无新模块。
- **第 6 项原地保全而非备份改名**：打不开的历史文件一个字节都不动，
  写入挂起 + 显式报错 + 提示手动移走；避免任何自动改名覆盖用户数据。
- **第 7 项「只恢复仍等于本程序写入值的字段」**：快照恢复不是无条件倒带，
  用户在接管期间的修改保留；注册表「恢复为不存在」用删除实现。
- **第 5 项 Rust 侧只交源码**：无工具链，静态核对 + 单测随源码交付，
  编译验证挂账。
- 令牌输出、地址校验、历史保全、快照恢复的测试都写在各自包内，
  全部不需要外部环境。

### 当前状态

- 提交（本地，未推送）：`31dd276`（第 1–3 项）→ `696755b`（第 4 项）→
  `f41df25`（第 5 项）→ `dba1db8`（第 6 项）→ `bedf0ca`（第 7 项）→
  `c959c4d`（第 8 项）→ `914a418`（第 9 项 README）→ 本记录（docs）。
- Go 验收五连全绿、无回退、通过数上升：
  `go build ./...`、`go vet ./...`、`gofmt -l .`（无输出）、
  `GOOS=windows go build ./cmd/... ./internal/...` 通过；
  `go test ./... -count=1 -v` **1140 条目 / 1119 通过 / 21 跳过 / 0 失败**
  （基线 1085 / 1064 / 21 / 0：条目 +55、通过 +55，全部来自本阶段新测试）。
  **零新增跳过**：21 条跳过与基线完全同一集合（seccomp 环境的 UDP 往返/
  互通二进制缺失类用例）。两个新 QUIC 夹具测试（注入信任、到达 sendto 边界）
  在本机**通过**而非跳过。
- 前端离线测试（托管 Node 22.22.2，清代理 + 串行）：
  **58 条目 / 56 通过 / 2 跳过 / 0 失败**（基线 50 / 48 / 2 / 0，+8 条来自
  第 5 项；2 条跳过仍是既有的「需真实核心」用例，无新增跳过）。
- 前端实时测试（系统 Node 24.22.1，挂重建的 `/tmp/arc/demo.conf` 演示核心、
  真实令牌文件，`MELONARC_TEST_API` / `MELONARC_TEST_DATA_DIR`）：
  **58 条目 / 58 通过 / 0 跳过 / 0 失败**（基线 50 / 50 / 0 / 0，+8 条同样全过；
  含对真实核心的策略切换/回读、规则解释、审计与「任何应答不含令牌」检查）。
  演示核心启动输出实测只有监听地址与令牌文件路径（第 4 项的直接旁证）。
- 前端六面板功能无回退：面板注册、i18n、构建校验相关离线用例全部通过。
- 命名红线：本阶段所有新增/修改源码、测试、README 与各条提交信息已扫描，
  无非开源商业产品名称。

### 遗留问题

- **QUIC 真实互通待环境复验**：Hysteria2 / TUIC 的修复（信任注入、UUID 原始
  字节标签、RFC 9204 头部块）已落码并有已知答案测试，但本机 seccomp 不允许
  QUIC 首程真实收发；需在无此限制的环境对参考实现服务器复验，通过后才可把
  两者从「已知不可用」改为「已验证」。
- **Rust 壳仍未编译**：第 5 项改动沿用阶段 13/14 挂账，`cargo build` /
  `Cargo.lock` / 原生窗口验证全部待有 `rustc` + WebKitGTK 的机器。
- **SQLite 驱动迁移（后续计划）**：自研最小写端保持现状；迁到
  `modernc.org/sqlite`（纯 Go、无 CGO）作为后续独立阶段评估，届时按约定
  登记版本 / 许可证 / 用途并用系统 sqlite3 CLI 做 oracle 对照。
- **REALITY 换库评估（后续计划）**：自研 TLS 1.3 现已含 CertificateVerify
  验签，但仍是不支持会话复用 / 0-RTT / HRR 的受限实现；是否换成熟库
  （以及指纹兼容性取舍）作为后续独立评估，不随本阶段决策。
- **预览桥丢弃 query string（既有缺口，非本阶段回归）**：
  `dev-preview.mjs` 的 `/bridge` 转发只取 `url.pathname`，`?limit=…` 之类
  查询参数到不了上游；阶段 13 起即如此，本阶段保持不动，记为后续修复项。
- 沿用阶段 14 全部挂账：托管 Node 22 的 undici Wasm 环境瑕疵、`dist/` 陈旧
  产物、GUI 设置重启生效、规则集/日志功能缺口等。

### 下一步计划

1. 在可用环境复验 QUIC 真实互通（Hysteria2 / TUIC 对参考实现服务器，
   TCP + UDP），把结论按证据写回 DEVLOG 与 README 支持矩阵。
2. 修复预览桥 query string 透传（小改动 + 一条实时用例）。
3. 评估 SQLite modernc 驱动迁移与 REALITY 换库两项后续计划，先登记
   依赖与许可证再动手。
4. 找有 Rust 工具链的机器补编译验证、`Cargo.lock` 与传递依赖许可证复核。

## 阶段 16 — REALITY 握手改用锁版 uTLS + 薄适配（2026-11-15）

外部评审 7 项修复批（阶段 15）之后，REALITY 的剩余问题不再是某一条校验，而是
「自研 TLS 1.3 手写实现」这个决定本身：它不支持会话复用、0-RTT、HRR，握手消息
顺序与验签全靠自己维护，每加一条规则都要再证明一次没有绕过。本阶段按所有者决策
（方案 B）换掉它：**握手交给锁版 uTLS，本仓库只留 REALITY 自己那一层**。

### 开工前的判断

`DEVLOG` 阶段 10/11 记录的是自研 `tls13.go` 的完整实现与当时对 Xray-core
26.11.9 的互通结果；阶段 15 第 8 项给它补了 CertificateVerify 验签。开工前
`git status` 干净，`HEAD = 575fc24`（阶段 15 收尾），符合任务书基线。

**锁版依据**：uTLS 版本取自 Xray-core v26.11.9 的 `go.mod`，即
`github.com/refraction-networking/utls v1.8.3-0.20261108164504-a13c59ffe98b`
（伪版本，commit `a13c59ffe98b`，2026-11-08T16:45:04Z）。不取最新、不浮动升级：
服务端与客户端用同一份 ClientHello 解析与指纹代码，版本一旦分叉，"我发出的
形状"和"它能接受的形状"就又是两件事。

该提交的公开 API 与 v1.8.2 不同名，照旧版记忆写必然编译失败：

- `PubClientHandshakeState`（不是 `ClientHandshakeState`）、`PubClientHelloMsg`；
- `State13.KeyShareKeys *KeySharePrivateKeys{Ecdhe, Mlkem, MlkemEcdhe}`。

### 完成工作

1. **依赖落位**（`go.mod` / `go.sum`）：`go mod edit -require` 写入上述伪版本后
   `GOPROXY=off go mod tidy`。MVS 连带升版 `golang.org/x/crypto` 0.54.0→0.57.0、
   `golang.org/x/net` 0.56.0→0.59.0（后者由间接转直接，因为 QPACK 码表本来就在用），
   新增两个间接模块 `github.com/klauspost/compress v1.20.1`、
   `github.com/molecule-man/go-brrr v1.2.0`（uTLS 的 `u_handshake_client.go`
   无条件 import `zstd` 与 `brrr`，缺一个就编译不过）。逐项登记见下。
2. **适配层重写**（`internal/outbound/reality.go`）：`RealityOptions.Dial` 现在只做
   REALITY 独有的四件事，其余全部交给 uTLS：
   - 用 `utls.HelloChrome_Auto` 建 ClientHello，取本次握手的密钥材料；
   - 把 16 字节明文（3 版本 + 1 保留 + 4 时间戳 + short id）用
     `HKDF-SHA256(shared, salt=random[0:20], "REALITY")` 派生的密钥封进 legacy
     session id，AAD = session id 清零后的 ClientHello；
   - 从证书回调里验服务端凭据（`HMAC-SHA512(authKey, leaf public key)` 与证书
     签名域逐字节比较），复用原有 `realityVerifyCertificate`；
   - 只有握手完成（含客户端 Finished 已发出）且凭据验过才返回 `net.Conn`。
3. **删除自研握手**：`internal/outbound/tls13.go`（1056 行）与
   `tls13_certverify_test.go`（286 行）同批删除。删除前逐文件核查引用面：生产代码
   只有 `RealityOptions.Dial` 一处调用，测试侧只有上述两个文件与 `reality_test.go`
   的 `TestTLS13AgainstStdlibServer`；`tls13SessionIDOffset` 被本地测试对端使用，已搬
   进适配层并改名 `realitySessionIDOffset`（与 `realitySessionIDLen` 同处声明）。
   没有第二个调用方，因此没有"停下报告"的分支。
4. **本地对端与测试改造**：`reality_test.go` 的本地服务端按 uTLS 产出的形状改写
   （key share 遍历要容忍 GREASE 与未知组；认证用的 X25519 取"独立 share"，
   混合 share 只作兜底；首记录必须是 handshake 而非 CCS），并删掉
   `TestTLS13AgainstStdlibServer`（它测的客户端已不存在）。
5. **新增测试装置**：`tlspeer_test.go` 是一个只存在于测试里的**脚本化 TLS 1.3
   服务端**，自己讲记录层（HKDF 标签、AEAD、transcript、Finished MAC）。理由：
   想验证的失败全在握手的负空间里——缺/重/乱序的 CertificateVerify、签错摘要、
   错凭据、错 Finished——`crypto/tls` 只会发一个正确且有序的 flight，造不出来。
   `reality_handshake_test.go` 在其上落了 14 个用例（含 10 个子用例）。
6. **README 支持矩阵**：REALITY 行更新为阶段 16 口径（TCP 仍是「项目内记录」，
   UDP 仍无证据）。

### 关键决策与理由

1. **回调不返回 nil 就等于成功 —— 这条必须堵死**。`InsecureSkipVerify` 下
   `VerifyPeerCertificate` 是唯一接受对端的入口，所以回调里先查
   `len(verifiedChains) > 0`：链能验通说明握手到的是**被模仿的真实站点**而不是
   服务器，直接拒绝；再用 REALITY 凭据判定，成功才置 `verified`。`Dial` 结束时
   除了 `HandshakeComplete` / `VersionTLS13` / `!DidResume`，还要查 `verified`：
   回调从未被调用（比如对端根本没发证书）时不会留下"空成功"。
   这正是任务书第 2 项要求的「不得把证书回调返回 nil 当作 REALITY 成功」。
2. **关掉会话复用与 0-RTT**：`SessionTicketsDisabled: true`，不设 `ClientSessionCache`。
   复用会跳过携带服务端凭据的 Certificate 消息，而 session id 又必须留给
   客户端那一半证明，两者不能共存。任务书第 5 项也明确不做 PSK 与 early data，
   因此在 VLESS 请求头层面不可能出现"提前写"。
3. **模板与上游的对应关系如实记录，不做指纹承诺**：`HelloChrome_Auto` 在本版本
   就等于 `HelloChrome_155`（Chrome 155 的 parrot），所以客户端形状是"某个
   Chrome 版本的形状"，不是"任意 Chrome 都认"。相对该模板只有两处**故意**偏离，
   都写在 `realityShapeHello` 的注释里：
   - 签名算法补 `ed25519`：凭据是 Ed25519 证书，而该模板的列表里没有它，
     不加就在证书选择阶段就死，REALITY 检查根本轮不到；
   - ALPN 用配置里的列表替换模板自带列表（`h2`/`http/1.1`），因为真正跑在
     上面的是 VLESS 而不是浏览器。
   两处都改在**扩展对象**上再 `MarshalClientHello()`，不是改字节：字段与扩展
   必须同时前进，否则"发出去的列表"和"拿来校验服务端的列表"会不一致。
4. **AAD 必须用真正发出去的那份字节**。`PubClientHelloMsg.Raw` 在本版本就是
   `clientHelloMsg.original`（同名同偏移的结构体视图），而 TLS 1.3 握手写的是
   `hello.original`，即 `Raw` 原样落盘。反过来，"从字段重新 marshal 一遍"会丢掉
   模板里的 GREASE、padding、ECH GREASE 等只存在于扩展对象里的内容，得到的是
   **另一个** ClientHello。第一版就是这么错的，表现为本地对端回
   "the session id was not sealed with this key"：封的时候用的是一份重新 marshal
   出来的字节，对端收到的却是 `Raw` 那一份，两者长度就不相等。现在改为：
   清零 `Raw` 里的 session id 段 → 用它做 AAD 算封文 → 把封文写回 `Raw` 同一段；
   实测发出记录的负载与 `hello.Raw` 逐字节相同（1978 = 1978，某一轮的形状）。
5. **认证密钥取"独立 X25519 share"，不取混合 share 的经典半段**。这条是**真实
   互通打出来的**，本地测试反而会掩盖它：脚本化对端若跟着客户端一起选错，两边
   自洽，永远绿。第一次互通时 Xray 日志是
   `REALITY: processed invalid connection …: failed to read client hello`，
   而客户端收到的是被模仿站点的 ECDSA 证书——即服务端把这次握手当成了未认证
   探测并转给了 `dest`。把密钥来源从 `KeyShareKeys.MlkemEcdhe` 换成
   `KeyShareKeys.Ecdhe` 后互通立刻通过（同一份 hello、同一份模板）。
   现在代码顺序是 `Ecdhe` 优先、`MlkemEcdhe` 兜底，本地对端
   （`peerClassicalShare` 与 `reality_test.go`）同步改成同一规则，避免测试与
   实现对"哪个 share"各执一词。
6. **失败零业务数据的断言放在对端字节预算上，不放在 sleep 上**。脚本化对端在
   发完认证段后开始记录客户端后续字节；拒绝一次握手时，客户端只可能写
   "一个兼容 CCS（6 字节）+ 一个加密 alert（5+2+1+16=24 字节）"共 30 字节，
   而客户端 Finished 光自己就是 5+4+32+16=57 字节、还必须在 VLESS 请求之前，
   因此 30 字节的预算里装不下任何隧道前言。成功路径则用**字节偏移**证明顺序：
   请求所在记录的结束偏移必须严格大于 Finished 记录的结束偏移。
7. **不拷贝上游文件**。适配层是照 REALITY 协议与 uTLS 公开 API 重写的调用代码，
   没有整文件、也没有片段来自 Xray-core 或 uTLS 源码，因此不涉及 MPL-2.0 双许可
   声明（uTLS 本体是 BSD-3-Clause，见登记表）；`unsafe` 只存在于 uTLS 内部，
   适配层没有引入。

### 依赖登记（本阶段）

`go.mod` 变动：新增 1 个直接依赖、1 个直接依赖升版、1 个间接转直接升版、
2 个新增间接依赖。**下表取代此前各阶段对同一模块的版本数字**（旧值已就地更新，
不留两份互相矛盾的记录）：`golang.org/x/crypto` 原记 v0.54.0、`golang.org/x/net`
原记 v0.56.0，本阶段起分别为 v0.57.0 / v0.59.0。

| 组件 | 版本 | 许可证 | 用途 | 与 GPLv3 |
|---|---|---|---|---|
| `github.com/refraction-networking/utls` | v1.8.3-0.20261108164504-a13c59ffe98b（锁版，源自 Xray-core v26.11.9 的 go.mod） | BSD-3-Clause（Go Authors） | 客户端 TLS 1.3 握手：ClientHello 构造与模板、密钥调度、记录层、消息顺序、CertificateVerify 验签、Finished 收发 | 兼容 |
| `golang.org/x/crypto` | v0.57.0（原 v0.54.0，uTLS 的 MVS 要求所致） | BSD-3-Clause（Go Authors） | `chacha20poly1305`/`argon2`（既有用途）＋ uTLS 依赖 | 兼容 |
| `golang.org/x/net` | v0.59.0（原 v0.56.0，uTLS 的 MVS 要求所致；本阶段起为直接依赖） | BSD-3-Clause（Go Authors） | `http2/hpack` 码表（阶段 15 起）＋ uTLS 依赖 | 兼容 |
| `golang.org/x/sys` | v0.50.0（未变；uTLS 也要求它，MVS 取两者较高者，仍是 0.50.0） | BSD-3-Clause（Go Authors） | TUN ioctl / poll / rtnetlink 常量（既有用途） | 兼容 |
| `golang.org/x/text` | v0.42.0（仅 `go.sum` 的 `/go.mod` 摘要，不参与构建） | BSD-3-Clause（Go Authors） | `x/net` 的模块图需求；本仓库没有任何代码路径 import 它 | 兼容 |
| `github.com/klauspost/compress` | v1.20.1（新增，间接） | BSD-3-Clause（Go Authors + Klaus Post） | uTLS 的 `u_handshake_client.go` 无条件 import `zstd`（证书压缩扩展）；本仓库代码不直接 import | 兼容 |
| `github.com/molecule-man/go-brrr` | v1.2.0（新增，间接） | MIT | 同上，uTLS 无条件 import 的 brotli 实现（证书压缩扩展）；本仓库代码不直接 import | 兼容 |
| `github.com/quic-go/quic-go` | v0.65.0（未变） | MIT | QUIC 传输（既有用途） | 兼容 |
| `github.com/oschwald/maxminddb-golang` | v1.13.1（未变） | ISC | mmdb 读取（既有用途） | 兼容 |

说明：`klauspost/compress` 与 `go-brrr` 是 uTLS 的**编译期**硬依赖（不是可选的
构建标签），因此"零依赖"的红线在本阶段被一次性地改写为"新增依赖必须锁版并登记"。
它们不进入本仓库源码，只在构建时链接。

### 验收证据

**（1）消息顺序：缺失、重复、乱序都必须被拒，且证明适配层没有绕过。**
uTLS 自己维护状态机，测试用脚本化对端发出被篡改的认证段，实测拒绝原因逐条如下
（三条都是 uTLS 的 `unexpectedMessageError`，说明判定发生在库内而不是适配层）：

- 缺 CertificateVerify（`ECF`）：`received unexpected handshake message of type
  *tls.finishedMsg when waiting for *tls.certificateVerifyMsg`；
- 重复 CertificateVerify（`ECVVF`）：`… of type *tls.certificateVerifyMsg when
  waiting for *tls.finishedMsg`；
- 乱序（`CEVF` / `EFCV` / `CVEF`）：`… when waiting for *tls.encryptedExtensionsMsg`
  / `… when waiting for *tls.certificateMsgTLS13`。

**（2）三类独立负例，各自至少一个，且都必须被拒**（另覆盖错误签名算法、错误
握手摘要、消息乱序）：

- ① 凭据与 Finished 都对，签名错或 CertificateVerify 缺失：缺失/重复/乱序见上；
  用**另一把私钥**签真实摘要 → `tls: invalid signature by the server certificate:
  Ed25519 verification failure`；对**另一份 transcript** 签名 → 同一错误。
- ② TLS 签名对但凭据错，或对端出示普通可信站点证书：用另一个 authKey 封装证书
  → `reality: the server certificate is not sealed with the authentication key`；
  出示一张**真的能验通**的证书（用例内先用 `crypto/tls` 客户端做对照，证明这条链
  确实可信）→ `reality: the server certificate carries a *ecdsa.PublicKey key,
  want ed25519`。
- ③ 前两者都对但 Finished 错 → `tls: invalid server finished hash`。
- 附：声明一个证书不可能产生的签名算法（`ecdsa_secp256r1_sha256`、
  `rsa_pkcs1_sha256`、`rsa_pss_rsae_sha256` 配 Ed25519 证书）→
  `tls: certificate used with invalid signature algorithm`。

**（3）失败零业务数据**：四个失败场景（普通证书、错凭据、缺 CertificateVerify、
错 Finished）都在对端字节计数器上断言：`afterFlight ≤ 30`（兼容 CCS 6 + 加密
alert 24）、`finished == false`、`appData` 为空。成功路径断言
`appAt > finishedAt`（VLESS 请求所在记录的结束偏移严格大于客户端 Finished 记录的
结束偏移），即"请求在 Finished 之后"是字节序事实，不是时序巧合。

**（4）真实互通复跑（TCP，本机可跑，必须跑）**：

- 服务端：`$HOME/interop-bin/vless/server`，`Xray 26.11.9 (Xray,
  Penetrates Everything.) 676eaf6 (go1.27.3 linux/amd64)`
  （`server version` 实测输出）；
- 二进制 SHA-256（本机复算）：`e87bce586acdb9136aa5b1f1d9c8db9f1ea1d145b6d86368c7f6f662f9f6a66d`；
- 发布 zip 的 SHA-256 为 `b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82`
  （由编排侧在本机之外与官方 `.dgst` 核对；本机无外网，只能复算**二进制**这一层）；
- 客户端：本阶段代码，锁版 uTLS 上述伪版本；
- 命令：`MELONARC_INTEROP_DIR=$HOME/interop-bin go test ./internal/outbound/
  -run TestInteropVLESSReality -count=1 -v`；
- 结果：**PASS，5.2–5.4 s**（其中约 5 s 是参考服务端首次连线时对 `dest` 做画像
  轮询的等待，不是握手耗时），16 KiB TCP 回环一致。

REALITY 是 TCP，不受本机 `sendto` 限制，所以这一项是**真跑出来的**，不是"到达
边界"的替代证据。也正因为如此，README 支持矩阵的 REALITY 行可以从阶段 15 的
"未复跑互通"改为"阶段 16 复跑通过"。

### 当前状态

- 提交（本地，未推送）：`a07c565`（依赖与适配）→ `f1ce97f`（测试）→ 本记录随
  文档提交一并落盘。第一条带上了 `tlspeer_test.go`，因为改写后的 `reality_test.go`
  要用它的线上常量，拆出去会让那一笔编译不过；第二条只剩新增的负例套件。
- Go 验收五连：`go build ./...`、`go vet ./...`、`gofmt -l .`（无输出）、
  `GOOS=windows go build ./cmd/... ./internal/...` 全绿。
- `go test ./... -count=1 -v`：**1147 条目 / 1126 通过 / 21 跳过 / 0 失败**
  （基线 1140 / 1119 / 21 / 0）。逐项对账：
  - 减少 17 条：`tls13_certverify_test.go` 的 3 个函数及其 13 个子用例
    （KnownAnswer 3、RejectsBadForms 8、MismatchedCertificateVerify 2）合计 16 条，
    加 `TestTLS13AgainstStdlibServer` 1 条——全部随自研握手一起删除；
  - 新增 24 条：`reality_handshake_test.go` 14 个函数 + 10 个子用例
    （乱序 3、签名算法 3、零业务数据 4）；
  - 净 +7 条 = 1147。**21 条跳过与基线完全同一集合**（seccomp 环境的 UDP 类
    用例 + 缺互通二进制的 7 个 `TestInterop*`），无新增跳过。本阶段新增的
    `TestInteropVLESSReality` 在设了 `MELONARC_INTEROP_DIR` 时**通过**，
    不设时与其它互通用例一样跳过。
- `-race`：逐包跑（`internal/*` 全部 + `cmd/melonarc-core`）**全部通过**。
  单次 `go test ./... -race` 在本沙箱被内存上限杀掉（退出码 137 / SIGTERM），
  是环境限制而非测试失败，故按包执行。
- 前端无改动，复跑确认无回退：离线（托管 Node 22.22.2，清代理 + 串行）
  **58 条目 / 56 通过 / 2 跳过 / 0 失败**；实时（系统 Node 24.22.1 + 重建的
  `/tmp/arc/demo.conf` 演示核心 + 真实令牌文件）**58 条目 / 58 通过 / 0 跳过 /
  0 失败**。
- 命名红线：本阶段新增/修改的源码、测试、README 与提交信息已扫描，无非开源
  商业产品名称（`Threat`/`clash` 类子串在前几阶段已清理，本阶段没有引入）。

### 遗留问题

- **两处偏离模板的后果要记住**：补 Ed25519 会让签名算法列表比真 Chrome 多一项，
  ALPN 用配置值则可能少于真浏览器。这是"能连上"与"看起来像"之间的取舍，
  本阶段选前者，且不做指纹承诺。若将来要做指纹仿真，得先把凭据换成模板本来
  就支持的曲线（例如 ECDSA P-256）。
- **只有 Chrome 模板经过真实互通**。Firefox 模板在排查过程中临时切过去也通过了
  （它只发一个 X25519 share，正好绕开决策 5 的坑）；Safari/iOS/旧 Chrome 在
  Xray 26.11.9 上会落到"被模仿站点"。当前实现固定用 `HelloChrome_Auto`，
  若将来开放模板选择，必须先按模板逐个复跑互通，不能只跑单测。
- **`go list -m all` 在本机不可用**（`GOPROXY=off` 下缺部分模块图的 `go.mod`），
  传递依赖清单以上表的实测 `go.mod` / `go.sum` 为准。
- **QUIC 真实互通、Rust 壳编译、SQLite modernc 迁移、预览桥 query string**
  四项挂账沿用阶段 15，本阶段未触碰。
- REALITY 的 UDP 业务仍无任何证据（`Unverified`），与是否换库无关：UDP 需要
  能跑参考服务端并允许数据报往返的环境。

### 下一步计划

1. 在允许 UDP 的环境补 REALITY 的 UDP 证据，或明确把该组合标为不支持。
2. 若要开放 uTLS 模板选择，按模板逐个复跑互通并登记对应关系。
3. 沿用阶段 15 计划：QUIC 互通复验、Rust 壳编译、modernc 迁移评估、预览桥修复。

## 阶段 17 — GUI 第三步：桌面壳托管核心进程（2026-11-15）

范围：把桌面壳从「只持有令牌的 API 客户端」变成「核心进程的宿主」。
启动时按壳侧设置拉起核心、监护它、崩溃后退避重启、退出时收尾；前端能看到壳报告的
进程生命周期状态并手动重启核心；设置面板四个值改走壳契约；预览桥在同一契约下给出
等价实现。阶段 15 的安全属性一条不丢：令牌只在壳/桥里，绝不下发前端；API 地址只接受
校验过的回环地址；桥只在开发态、生产构建拒绝启动。

开工前的基线：`HEAD = 422f842`（阶段 16 收尾），`git status` 干净；
Go 1147 / 1126 / 21 / 0；前端离线 58 / 56 / 2 / 0、实时 58 / 58 / 0 / 0。
`DEVLOG` 阶段 13/14/15 关于壳与设置的措辞已逐条对照，本阶段改动必须与之一致
（尤其「令牌不进前端」「地址只回环」「桥是开发态工具」三条）。

### 完成了什么

**1. 壳设置文件（`src-tauri/src/settings.rs` 重写）**

- 位置：`<config_home>/melonarc/shell.json`，即**默认**数据目录，与 `data_dir` 是否被改
  无关。理由写在模块头上：如果文件名着另一个数据目录，再从那个目录读它就成了循环。
- 四个键全部可选（`data_dir` / `api_addr` / `core_path` / `core_config`），空值与缺键等价，
  写入是**稀疏**的——清空的字段从文件里消失，而不是变成 `""`。
- 优先级：环境变量 `MELONARC_DATA_DIR` / `MELONARC_API_ADDR` > 设置文件 > 默认值。
  环境层保留，因为开发与本机测试都靠它把壳指向一个临时目录。
- 写入前逐个校验：`api_addr` 走与启动路径**同一个** `resolve_api_address`（回环判定按
  IP 类型而非字符串前缀，`localhost` 解析一次且每个答案都必须回环），路径拒绝控制字符；
  不合格直接报错、文件不动。写入是「同目录临时文件 + rename」，崩在中间不会留下半个文件。
- 令牌永不写进这个文件；`read_overrides` 对未知键静默忽略（新版本写、旧版本也能启动）。
- 核心二进制查找顺序：① 壳可执行文件同目录（`melonarc-core` / `.exe`）；
  ② 文件里的 `core_path`；③ `PATH`。找不到时 `stopped` 的 detail 会把**找过的每个路径**
  列出来——这是本阶段唯一能自证的排错手段。
- 默认核心配置：`core_config` 未设时取 `<生效数据目录>/melonarc.conf`。
- `data_dir` / `api_addr` 只在壳启动时读一次；`core_path` / `core_config` 在**每次 spawn 前**
  重新解析（`core_targets`），所以「重启核心」能应用新值而不用重启壳。

**2. 核心监护（新增 `src-tauri/src/core.rs`，约 700 行含测试）**

- spawn 参数固定为 `melonarc-core -config <core_config> -api-listen <壳的 api_label>`；
  **每次都传 `-api-listen`**，见决策 2。
- 子进程 stdout 与 stderr 都追加到 `<data_dir>/core.log`：桌面启动没有控制台，丢掉核心
  自己的诊断会让每次失败都不可解释。目前**不轮转**，已记入遗留问题。
- 状态机四个线名：`starting` / `running` / `stopped` / `crashed`。规则：
  - 启动 → 解析二进制与配置；缺任一项 → `stopped` + 说清缺什么、找过哪里；齐全 → spawn → `starting`；
  - `starting`：监护线程每 500 ms 探一次——进程已经退出即失败；进程活着且
    **令牌文件在**且 `GET /v1/status` 返回 200 → `running`（复用 `api` 的连接与
    读令牌，`probe_status` 提升为 `pub(crate)`，没有第二套 HTTP 实现）；
  - 15 s 没到 `running` 算一次失败：杀掉、计数、退避、重来；
  - 意外退出：失败数 +1，退避 1s → 2s → 5s（封顶 5s）自动重启；
  - 连续 5 次失败 → `crashed`，不再自动重启，detail 保留最后一次退出信息；
  - 到达 `running` 清零失败计数。
- `core_restart`：先礼后兵停掉当前子进程、清零失败计数、重新解析二进制与配置、spawn、
  返回最新状态。
- 状态对象 `{ state, pid, started_at_unix_ms, restarts, detail }`；没有子进程时 pid 与启动
  时刻为 null（绝不编造），`restarts` 只数本会话的自动重启，detail 是英文技术文本。
- 已经 `running` 的子进程**不再每 tick 探活**：退出由 `try_wait` 看住，健康度归窗口自己的
  轮询。否则每个 500 ms 都会打一次 `/v1/status`。

**3. 单实例（新增 `src-tauri/src/single.rs`）**

- `File::try_lock`（Rust 1.89 稳定的标准库文件锁）锁 `<生效数据目录>/shell.lock`，
  先 `create_dir_all`。句柄存进 Tauri state 活到进程结束，drop 即释放；进程被杀时内核
  自动丢锁，不会留下需要手工清理的 pid 文件。
- 抢不到（`WouldBlock`）→ 一行 stderr 说明「同一数据目录已有窗口在跑，本次启动到此为止」
  然后退出；**其它**锁错误（权限等）只告警继续启动——那是文件问题，不是第二实例。

**4. 命令面（`main.rs` + 两个新命令文件）**

- 新增 `core_status` / `core_restart` / `get_shell_settings` / `set_shell_settings`，
  与既有 `api_request` / `runtime_info` 一起注册，共六个。
- `get_shell_settings` 返回 `{ settings_path, stored, effective, restart_required }`；
  `stored` 是文件原样（未设为空串），`effective` 是按优先级算出来的、以及**现在**会用的
  核心路径（找不到二进制则是空串）；`set_shell_settings` 校验后原子写文件，返回同一形状。
- `set` 只写文件：不热切换运行中壳的 API 客户端，也不自动重启核心。`core_path` /
  `core_config` 在下次 spawn（含 `core_restart`）生效。
- `runtime_info` 保持兼容，只增补 `settings_path`。
- 退出：`RunEvent::ExitRequested` 与 `RunEvent::Exit` 都挂同一个 `shutdown()`（幂等），
  置 stopping 标志、终止子进程、状态落到 `stopped`。

**5. 前端契约面（`src/api/bridge.js`、`client.js`）**

- 三个桥都长齐 `coreStatus()` / `coreRestart()` / `shellSettings()` / `saveShellSettings()`：
  Tauri 桥转 `invoke`，HTTP 桥走 `GET/POST /bridge/shell/{status,restart,settings}`，
  空桥 `coreStatus` 返回 null（面板整段不渲染），其余与 `runtime()` 一样失败即 null。
- **snake_case 只在桥里出现**：`coreStatusFromWire` / `shellSettingsFromWire` /
  `shellSettingsToWire` 三个函数是唯一转换点，面板只看见 camelCase。
- `client.js` 加四个同名方法，风格与 `runtime()` 一致，走桥不走 HTTP 端点。

**6. 两个面板**

- 概览：状态卡（「核心 API 答不答」）之后加一张**核心进程**卡（「壳眼里的进程」），
  四态文案 + 进程号 + 启动时刻 + 自动重启次数，`stopped` / `crashed` / 重启失败时给出
  detail 正文与一个「重启核心」按钮。它和状态卡并排、文案从不混用；
  `coreStatus()` 返回 null 时整张卡不渲染。取数与 `status/config/policies` 同一个
  `Promise.all` 批次，且是桥的本地调用，不打核心。
- 设置：四个字段（数据目录 / API 地址 / 核心路径 / 核心配置）挂载时从
  `get_shell_settings` 填充、保存走 `saveShellSettings`；显示设置文件路径；
  `restart_required` 时给一条「需重启应用才生效」；核心路径与配置文件注明
  「重启核心后生效」并给可直接点的「重启核心」。语言切换仍归本窗口（local storage），
  旧 `melonarc.gui` 记录**故意不迁移**。
- 样式只用语义 token，没有新增颜色/间距字面量；新增文案全部进两套语言包
  （键集与占位符完全一致，构建与测试双重校验）。

**7. 预览桥等价实现（`scripts/dev-preview.mjs` + `scripts/lib/supervisor.mjs`、
`shell-settings.mjs`）**

- 新增可选 `--core <path>` 与 `--core-config <path>`；**只有给了 `--core` 才托管**。
  托管时用同样的参数（`-config` + `-api-listen <桥的生效地址>`）、同样的状态机与退避
  （1s/2s/5s、连续 5 次 → crashed、15 s 启动预算、running 清零），桥收到 SIGINT/SIGTERM
  先 SIGTERM、超时再 SIGKILL。
- 不给 `--core` 时 `/bridge/shell/status` **真探一次**：被代理的核心 `/v1/status` 可达 →
  `running`（pid 与启动时刻为 null，detail 写明「不是本桥启动的」），不可达 → `stopped`
  并写明地址。绝不编造 pid 或时间。
- `/bridge/shell/settings` 读写同一个 `shell.json`；桥的 `--data-dir` / `--api` 相当于
  壳的环境层，生效值由桥自己的解析算。所有 `/bridge/shell/*` 都先过
  `validateBridgeRequest`（Host/Origin 检查，POST 必须有 Origin），
  `assertDevelopmentOnly` 一字未动。
- 既有 `/bridge/runtime` 与代理行为无回退：`query string` 透传是阶段 13 起的已知缺口，
  本阶段按任务书要求**明确不修**。

### 关键决策及理由

1. **设置在默认数据目录，不在生效数据目录。** 反过来读会自指：文件本身可能正是改
   `data_dir` 的那一份。代价是「用户改了数据目录后，文件还在老地方」，所以设置面板
   必须显示完整路径，而不是只说「设置文件」。
2. **每次 spawn 都传 `-api-listen`。** 核心的配置文件里也有 `api-listen`，不传就会出
   现「令牌发到 A、核心听在 B」的静默错配。命令行覆盖配置文件是核心自己定义的语义，
   壳按「壳说听哪就听哪」使用；这条会出现在 DEVLOG，也会出现在设置面板的提示里。
   附带约束：壳不解析核心 INI（阶段 13 的假设不变），所以非默认 `data_dir` /
   `api_listen` 时仍要靠环境变量把壳指过去。
3. **`core.log` 放生效数据目录**，与 `api-token`、`history.sqlite3` 同处：一个数据目录
   就是一次会话的全部现场，拷走即可复现。不轮转是明确取舍——先有现场，再有整洁；
   长期运行的轮转/大小上限记入遗留问题。
4. **Unix 的 SIGTERM 走外部 `kill`。** 标准库没有信号 API，而本阶段的硬约束是零新增
   crate（`libc` 也算）。`Command::new("kill").arg("-TERM").arg(pid)` 失败不致命：
   三秒后 `Child::kill()` 仍然收尾。Windows 没有 SIGTERM 可发，直接 `Child::kill()`。
5. **`rust-version` 1.77 → 1.89。** 单实例用的是标准库稳定不久的 `File::try_lock`；
   另一条路是加一个锁 crate，与「零新增依赖」冲突。选前者，并把理由写进 `Cargo.toml`
   注释与本记录。这是本阶段 `Cargo.toml` 唯一的改动。
6. **锁文件放生效数据目录，第二实例直接退出。** 两个同样配置的窗口才会抢同一个
   `api-token`，所以判据是数据目录而不是可执行文件。第二实例只打一行 stderr 就退出，
   **不会**把已有窗口提到前台——那需要窗口管理插件，本阶段不加，记入遗留问题。
7. **`restart_required` 比的是「文件现在」与「壳启动时那份文件」**，不是「文件」与
   「生效值」。后者在设了环境变量时会立刻误报（文件没改，但生效值来自环境）。
   两者的语义在无环境变量时等价，节点是「你刚保存的东西，运行中的壳还没用上」。
   前端、Tauri 命令与预览桥三处用同一规则，宁可略保守也不三种说法。
8. **前端地址预检比壳宽松，是故意的。** 面板只挡明显错误（非回环主机、端口不合法），
   权威判定在壳里（`127.example.com` 这类壳会拒）。这样面板不必复刻 IP 解析，
   代价是这类值会以「写入失败」而不是「地址不合法」呈现——记入遗留问题。
9. **监护线程在持锁状态下做就绪探测**（最多一次连接超时 2 s + 读超时 5 s）。
   代价是这段时间内 `core_status` 会等一下；换来的是一条线程、一个互斥量、
   没有「探测结果与状态各说一套」的窗口。到达 `running` 后不再探测，影响只限启动期。
10. **`starting` 也用于「已排期、还没起来」**（失败退避期间）。线名只有四个，
    要么新增第五个状态，要么复用；`starting` + detail 里的「restarting in Ns」信息量足够，
    前端四态文案也不必多一套。

### 当前状态

- **Rust 只交付源码，未编译**：本机没有 `rustc` / `cargo`（`~/.cargo` 不存在），也没有
  WebKitGTK，crates.io 不可达。已做的是：逐个文件括号配平校验、逐条对照
  `tauri` 2 / 标准库签名人工复核、把可能触发借用检查的写法改成明显安全的形态
  （`tick` 里先取出 `try_wait` 结果再改状态）。**这不等于编译通过**，
  沿用阶段 13/14/16 的挂账。
- 前端构建：`npm run build` 通过，`dist/` 28 文件 / 208.3 KiB（语言包键集一致、
  页面引用文件都存在、无远程资源三项校验在内）。
- 前端离线测试（托管 Node 22.22.2，清代理环境变量 + 串行）：
  **75 条目 / 73 通过 / 2 跳过 / 0 失败**（基线 58 / 56 / 2 / 0，+17 条目、+17 通过，
  **零新增跳过**；2 条跳过仍是既有的「需真实核心」用例）。逐项对账：
  - 新增 `bridge-contract.test.mjs` 4 条、`supervisor.test.mjs` 8 条（+12）；
  - `client.test.mjs` 13 → 16（+3，三个桥的四问一致性）；
  - `panels.test.mjs` 5 → 9（+4：四态文案与重启按钮、crashed → 重启 → Running、
    空桥隐藏整段、无壳时的设置提示）；
  - `gui-settings.test.mjs` 7 → 5（−2：环境变量行与本地存储读写两族用例随旧实现删除）。
- 前端实时测试（系统 Node 24.22.1，`/tmp/arc/demo.conf` 重建的演示核心、真实令牌文件，
  `MELONARC_TEST_API` / `MELONARC_TEST_DATA_DIR`）：**75 条目 / 75 通过 / 0 跳过 /
  0 失败**（基线 58 / 58 / 0 / 0，同样全过）。
- 桥契约实测（真跑 `dev-preview.mjs`，不是桩）：托管模式观测到 `starting` → `running`
  （真实 pid 与启动时刻）；`POST /bridge/shell/restart` 后 pid 变化并回到 `running`；
  `kill -9` 子进程后 detail 给出信号名并按 1s 退避拉回、`restarts` 变 1；
  `--core` 指向不存在的路径 → `stopped`，pid/时刻为 null 且 detail 点名该路径；
  设置读写往返一致（稀疏文件、`restart_required` 只在改了数据目录/地址时为真）、
  非回环地址被 400 `bad_settings` 拒绝且文件未动、无 Origin 的 POST 403、错误方法 405；
  无 `--core` 时状态与核心真实可达性一致、`restart` 返回 409 `not_managed`。
- Go 侧零改动（本阶段不需要），验收五连无回退：`go build ./...`、`go vet ./...`、
  `gofmt -l .`（无输出）、`GOOS=windows go build ./cmd/... ./internal/...` 通过；
  `go test ./... -count=1 -v` **1147 条目 / 1126 通过 / 21 跳过 / 0 失败**，
  与阶段 16 完全一致，21 条跳过是同一集合。
- 命名红线：本阶段新增/修改的源码、测试与文档已扫描，无非开源商业产品名称。

### 遗留问题

- **Rust 壳仍未编译**（`cargo build`、`Cargo.lock`、原生窗口截图、真实 IPC 往返四条
  全部待有工具链的机器）。本阶段的监护、单实例、设置文件写入、退出收尾都没有在
  真实进程里跑过；能证明的只有前端契约、预览桥等价实现与纯函数单测。
- **`core.log` 无轮转**，长期运行会无限增长。
- **第二实例不会聚焦已有窗口**，只打印一行 stderr 退出（需要窗口管理插件）。
- **预览桥的 `/bridge` 仍丢 query string**（阶段 13 起的既有缺口，本阶段按要求未碰）。
- **前端地址预检比壳宽松**：`127.example.com:7946` 这类值会在壳侧被拒，界面呈现为
  「写入失败」而不是「地址不合法」。
- **`ExitRequested` 与 `Exit` 共用同一个收尾**：若有插件在 `ExitRequested` 阶段阻止退出，
  核心已经被停掉了。当前没有这种插件，但这是一个已知耦合。
- 沿用：QUIC 真实互通复验、SQLite modernc 迁移评估、REALITY UDP 证据。

### 下一步计划

1. 在有 `rustc` + WebKitGTK 的机器上首次编译，先跑通「壳拉起核心 → 页面看到 running →
   关窗后子进程消失」这一条最短链路，再补单实例与 crashed 两态。
2. 给 `core.log` 加大小上限或按次轮转（同一次运行一个文件即可）。
3. 预览桥 query string 透传（小改动 + 一条实时用例），修完顺手把
   `/bridge/shell/*` 的等价性用例并进同一批。
4. 视需要加窗口管理插件，让第二实例把已有窗口提到前台。

---

## 阶段 18 — 核心加固批 A：fake-IP 租约保留、重载统一提交点、TUN resolver 随重载（2026-11-15）

范围：三项**核心侧**缺陷修复，纯 Go。前端与 Rust 壳（`apps/desktop`）一个字未改，
`/v1` 字段与语义未改，`go.mod` / `go.sum` 未改，`spikes/` 与 `docs/` 未改。
基线 HEAD `3a37ce7`（Go 1147 条目 / 1126 过 / 21 跳 / 0 败）。

### 完成了什么

**1. fake-IP 租约保留与池满的明确失败（`internal/inbound/tundns.go`）**

- `nameAddress` 增加 `refs`，池的回收条件从「过期即回收」收紧为
  **「过期且无会话引用」**。`allocate`、`sweep`、`nameFor` 三条路径遵守同一条规则，
  所以清扫器不可能释放一个分配器会拒绝复用的地址。
- 池满且无可回收地址时 `allocate` 返回 `(ip4{}, false)`，DNS 应答改给 **SERVFAIL**，
  不再挑最早过期的映射改派。计数落在 `inbound.Metrics` 的新字段
  `Snapshot.NameAddressExhausted`，日志按「一次告警、恢复时报一次」处理
  （`dnsResponder.exhausted` 记录当前是否处于枯竭期，避免每个问题一行 Warn）。
- **引用计数的口径**（本项要求写清）：
  - **TCP**：`tcpStack.handle` 在 SYN 建立 flow 时 `claim(目的地址)`，
    `tunTCPConn.Close`（`closeOnce` 内，defer）释放一次。**取在 SYN 而不是握手完成**：
    SYN 已经指明目的地，从这一刻起这条流就属于那个名字；取在握手完成会让
    「已回 SYN-ACK、ACK 还在路上」的几百微秒里地址可被改派，而这一小段恰恰是最难
    用测试覆盖的窗口。代价是只发了 SYN 就消失的半开流会多压住一个 token 直到
    `Close`（`tcpTimeWait` 或 abort），量级是个位数。
  - **UDP**：`udpDispatcher.handle` 在**新建会话**时 `claim`，在
    `removeLocked` / `dropRelay` / `close` 三条会话结束路径上 `release`。
    每条路径都是同一次释放，所以「会话还在表里但没引用」这种状态不存在。
  - 一次 `claim` 同时完成「查名 + 计数」（`dnsResponder.claim`），不是「先 `nameFor`
    再计数」：两步之间清扫器可能刚好删掉一份刚过期的映射，那样会话会拿着一个
    没人认领的地址继续发包。
  - **过期但被引用**的 token 在 `nameFor` / `claim` 里仍然可读，`claim` 还会顺手续租：
    「TTL = 无人使用的时间」比「TTL = 从发答案起的绝对寿命」更贴近这条流的需要，
    否则一条长连接会在第 10 分钟被自己的租约掐死。
- 回归测试（`internal/inbound/tundns_test.go`，全部用注入时钟 `svc.now`，零 sleep）：
  ① `TestTUNFakeIPPoolRefusesToReassignALiveLease`：填满 253 个未过期租约 → 第 254 个
  分配失败、返回零地址、253 个映射逐个核对一个都没变、池大小仍 253、计数器 1→2；
  再经设备 DNS 路径问这个放不下的名字，断言 **rcode = SERVFAIL** 且既有映射仍不变。
  ② `TestTUNFakeIPPoolKeepsALeaseInUse`：先让一个 UDP 会话占住 token，再把时钟推过
  租约（其余 252 个租约仍新鲜）→ 清扫不回收、`nameFor` 仍可读、新名字分配失败；
  会话结束（走 dispatcher 的移除路径，与写失败/关闭同一条）→ 引用归零且映射立即消失，
  下一个名字**恰好**拿到这个被释放的地址（此时它是唯一的空位，所以断言是确定的）。
  ③ `TestTUNFakeIPTCPStreamHoldsItsLease`：真实握手 → 流占住 token → 租约过期仍可解析、
  拨号出去的是 `stream.test:443` 而不是 token → FIN + 上游关闭 → 引用与映射一起消失。
  ④ 既有 `TestTUNFakeIPPoolReusesAndSweeps` 只改了 `allocate` 的两返回值签名，断言未变。

**2. 重载统一提交点（`cmd/melonarc-core/reload.go`、`state.go`）**

- `daemonState` 增加 `commitMu`：**重载的提交**与 **`SelectPolicy`** 共用这一把锁，
  `mu`（RWMutex，供所有读视图）内嵌其下。`SelectPolicy` 现在整段
  （取 registry → 读当前成员 → `Select` → 记审计）都在 `commitMu` 内。
- `reloader.commit` 是唯一的换入点：读「提交那一刻仍在生效的 registry」的 pin →
  `applySelections` 应用到新 registry → `droppedSelections` 当场算 → `handler.Replace`
  → `state.install`（顺带更新 TUN 的 resolver 持有者，见第 3 项）。
  `handler` 与 `state` 在同一个临界区内换入，顺序与旧实现一致（数据面先、状态后）。
- `buildRegistry` **不再接受 `carry` 参数**，`carriedMember` 删除：pin 继承从
  「构建期」整体搬到「提交期」，生产路径上只有一个地方应用 pin。
  `ReloadView.SelectionDropped` 的语义与排序完全不变（仍是 `group: 原因` 的字典序列表）。
- `reloader.beforeCommit` 是**测试同步点**（生产恒为 nil）：在「重建完成、换入未开始」
  这一瞬间会合，测试据此把一次 pin 精确放进那个窗口。
- 回归测试（`cmd/melonarc-core/reload_commit_test.go`）：
  - `TestReloadKeepsAPinMadeWhileTheRebuildRuns`：重建完成 → 停住 → `SelectPolicy(beta)`
    成功且**在旧 registry 上可见**（证明 pin 真的落在窗口内）→ 放行 → 新 registry 仍是
    beta、`selection_dropped` 为空、规则数是新文件的 2 条、随后一条真实连接由 beta 承载。
  - `TestReloadDropsAPinWhoseMemberIsGone`：同一个交错，但新文件已删掉 beta →
    `selection_dropped` 恰好一条且说清「组 / 成员 / 退回到谁」、组落到 alpha、
    再 pin beta 被 API 拒绝。
  - **非 flaky 的口径**：交错由一对 channel 会合（`arrived` / `proceed` / `done`），
    断言发生在「会合点已到达」之后，不依赖任何时延；`10s` 只作死锁保护，触发即
    `t.Fatal` 而不是重试。`-count=10` 与 `-race -count=10` 各跑两轮全绿；
    另有 `-run` 过滤下的 `-count=10 -race` 结果记在「当前状态」。

**3. TUN DNS resolver 随重载更新（`internal/inbound/resolver.go`、`tun.go`、`tundns.go`、
`cmd/melonarc-core/main.go`、`state.go`）**

- 新增 `inbound.ResolverHolder`：`atomic.Pointer[Resolver]` 的极薄持有者，nil 接收者安全。
  `TUNService` 不再保存 `resolver` 字段，只保存 `resolvers *ResolverHolder`，
  `dispatch` 的 53 端口判断与 `tundns.handle` 的解析都改成**每次查询 `Load()` 一次**。
- `TUNOptions.Resolvers` 是新的装配入口；`Resolver` 字段保留，`Resolvers == nil` 时
  `NewTUN` 用它自建一个 holder（既有测试与「没有重载的进程」不受影响）。
- `daemonState.resolvers` 持有同一个对象，`install` 在 `mu` 临界区内
  `s.resolvers.Store(next.resolver)`：**API 快照与设备 DNS 的 resolver 同时换代**。
  重载提交点因此不需要再多一步，也不会出现「API 说新的、设备还在用旧的」。
- 回归测试：`internal/inbound/tunresolver_test.go`
  `TestTUNDNSFollowsTheResolverHolder`（换 holder 前同名 NXDOMAIN、换后一条 A 记录，
  且旧 resolver 不再被问）与 `TestTUNDNSQueryInFlightKeepsItsResolver`
  （查询停在 resolver 里 → 换 holder → 放行：这条查询仍算旧 resolver 的，
  下一条才走新的）；`cmd/melonarc-core/reload_commit_test.go`
  `TestReloadRepointsTheDeviceResolver`（改 `[Host]` → 重载 → holder 给出新地址，
  且与 `snapshot().resolver` 是同一个对象）。**能测到的层**：inbound 侧证明
  「responder 用当前 holder」，cmd 侧证明「重载提交更新 holder」；
  真实设备上「改配置 → 重载 → 内核客户端拿到新答案」这一条仍属真机验证项（见遗留）。

### 关键决策及理由

1. **租约三态而不是两态**。旧实现的隐含假设是「映射是缓存，随时可以换人」，
   但 token 同时是**在途流的身份**：换人之后 `destination()` 会把旧流的包按新名字转发，
   错得悄无声息。加上「有没有会话在用」这一维之后，缓存语义只对**没人用**的条目成立，
   这正是可以安全回收的集合。
2. **引用计数挂在会话上，不挂在包上**。按包计数会在两个包之间的空隙回到 0，
   而地址恰恰是在那段空隙里被改派最危险；挂在会话上，计数区间与「这条流可能还会发包」
   的区间完全重合。
3. **池满就 SERVFAIL，不踢最旧**。三条路（踢最旧 / 拒绝新名字 / 扩池）里，
   踢最旧是唯一会**在别人不知情的情况下改变语义**的一条：客户端拿到的地址还是那个，
   但含义变了。拒绝新名字把代价放在「新名字暂时解析不了」，是唯一诚实的失败模式，
   而且客户端会按 60s 的应答 TTL 自然重试。扩池不解决根因（只是把阈值推远），
   留作下一步。
4. **枯竭计数不进 `failure` 环、也不进 `/v1`**。failure 环的语义是「一次没能承载的请求」，
   而这是一次 DNS 应答；把它混进去会让 `/v1/failures` 的读者以为有连接失败了。
   进 `/v1/inbound` 需要给 `InboundStatsView` 加字段，那会改动本阶段明令冻结的契约，
   因此计数只落在 `inbound.Metrics` 与日志里，**是否需要暴露单列为待决策**（见遗留）。
5. **pin 继承搬到提交点，而不是给 `SelectPolicy` 加重试**。「提交后进行、发现被覆盖就再
   pin 一次」能修表象，但会留下「用户看到的 ok 对应哪一代 registry」说不清的问题；
   把唯一的写者（pin）与唯一的换代者（commit）放到同一把锁下，才让两种顺序成为**仅有的**
   两种顺序。
6. **提交锁挂在 `daemonState` 上，不新开一个协调器**。换代与 pin 都已经是 state 的操作，
   多一个协调器只会多一个「谁先拿锁」的问题；`commitMu` 在 `mu` 之上、且没有任何路径反向
   获取，锁序是单层的。
7. **`handler` 与 `state` 同临界区换入，但不合并成一个指针**。合并需要把规则、registry、
   resolver 全部塞进一个跨层对象，`inbound` 就得认识 `config`/`policy` 的全部字段，
   与「api 不 import 内部包」同类的分层约束相悖。当前形态把窗口压到两次相邻的原子写，
   而每个请求各自只读一次（`handler.load()` / `snapshot()`），所以**单个请求内部**
   仍然只会看到一代；剩下的是「一个 API 请求与一个 TUN DNS 查询在相邻纳秒内读到相邻代」，
   已记入遗留。
8. **TUN 用持有者而不是重建 service**。设备、路由、用户态栈都是启动期资源，
   重建等于一次重启；而 resolver 只被「问一个问题」这一瞬间需要。持有者把
   「设备寿命」与「配置寿命」解耦，代价是每次查询一次原子读。
9. **`beforeCommit` 钩子只存在于测试**，不进任何生产分支（生产恒 nil）。用 Sleep 制造
   窗口的测试会在慢机器上假绿、在快机器上假红；channel 会合让「重建完成」与「换入开始」
   成为两个可观测事件。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                       通过
go vet ./...                                         通过
gofmt -l .                                           无输出
go test ./... -count=1 -v                            1155 条目 / 1134 通过 / 21 跳过 / 0 失败
go test -race ./internal/inbound/ ./cmd/melonarc-core/  通过
go test ./internal/inbound/ -run 'TestTUNFakeIP|TestTUNDNSFollows|TestTUNDNSQueryInFlight' -count=10 通过
go test ./cmd/melonarc-core/ -run 'TestReloadKeepsAPin|TestReloadDropsAPin|TestReloadRepoints' -count=10 通过
（上一行两组再加 -race -count=10 亦通过）
GOOS=windows go build ./cmd/... ./internal/...       通过
```

- 逐项对基线（`3a37ce7`，1147/1126/21/0）：**条目 +8、通过 +8、跳过 ±0、失败 0**。
  新增的 8 条：`internal/inbound` 5 条（池 3 + resolver 2）、`cmd/melonarc-core` 3 条。
  21 条跳过与阶段 8/9/11 起的那一批**完全同一集合**：缺参考实现的互通 10 条、
  未连接 `sendto` 被 seccomp 拒绝的 UDP 用例 9 条（`Direct` 3 + `SOCKS5` 4 + 回环中继 1 +
  上游 UDP 1）、上游「UDP 被截断后改走 TCP」1 条（同一根因）、`TestTUNLinuxLoopback` 1 条
  （需 CAP_NET_ADMIN）；无新增跳过。
- 本阶段两笔本地提交（未推送）：`c4079a6`（租约保留 + SERVFAIL + resolver 持有者，`internal/inbound`）→
  `66d2dd9`（重载提交点 + 设备 resolver 重指 + 三组回归用例，`cmd/melonarc-core`）。
- `go.mod` / `go.sum` 零改动；本阶段没有新增依赖。
- 前端与 Rust 壳零改动：`git status` 在 `apps/` 下无任何条目；前端测试基线
  （离线 75/73/2/0、实时 75/75/0/0）本阶段未复跑，因为代码一字未动。
- 行为对照（可复核）：
  - 旧实现：第 254 个名字拿到「最早过期」的地址，旧名字后续包被按新名字转发；
    新实现：第 254 个名字得到 SERVFAIL，253 个映射逐字节不变。
  - 旧实现：重建期内的 pin 被重建开始时读到的值覆盖且无人报告；新实现：pin 生效或被
    明确列入 `selection_dropped`。
  - 旧实现：`[Host]` 改动后 TUN 侧仍用启动时的 resolver；新实现：提交后新查询走新的。

### 遗留问题

- **枯竭计数没有对外出口**：`NameAddressExhausted` 只在 `inbound.Metrics.Snapshot()` 与日志里。
  要进 `/v1/inbound` 必须给 `InboundStatsView` 加字段，属于契约变更，本阶段按约束未做。
  **建议单列为决策项**：是给 `/v1` 加可选字段（向后兼容但是契约变更），还是留待
  「契约 v2」一次性处理。
- **名字地址池仍是 /24（253 个）**，没有 LRU、没有按名分桶，也没有更大网段或 IPv6 侧方案。
  池满时的正确行为现在有了，但「更容易池满」这件事没变（阶段 8 起的既有边界）。
- **提交点是「两次相邻原子写」**：`handler.Replace` 与 `state.install` 在同一把锁内，
  但不是一个指针。单个请求各自只读一次，因此不会看到跨代半状态；一个 API 请求与一个
  TUN DNS 查询在相邻纳秒内仍可能读到相邻代。真要消灭这一点需要把「代数」提升为
  跨层对象，属于架构级改动。
- **提交锁假设进程内只有一个写入者**：`SelectPolicy` 与 `reload` 是仅有的两处。若将来
  出现第三个写者（例如按连接自动 pin），必须同样经过 `commitMu`。
- **TUN 重载只做到「内存设备 + holder」层**：真实 `/dev/net/tun` 上「改 `[Host]` →
  `POST /v1/config/reload` → 内核里 `getaddrinfo` 拿到新答案」没有跑过（沙箱无
  CAP_NET_ADMIN；`TestTUNLinuxLoopback` 仍需 `unshare -Urn`）。
- **过期但被引用的 token 会续租**：一条长期空闲但没关闭的流可以让一个 token 一直不回收。
  上界是该会话的空闲超时（`tun-udp-timeout` / TCP timewait），没有额外上限。
- 阶段 8–17 的既有挂账照旧：Windows 实机（TUN / 系统代理 / 令牌文件）、Rust 壳编译、
  QUIC 真实互通、REALITY UDP 证据、预览桥 query string、SQLite modernc 迁移评估、
  `core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放。

### 下一步计划

1. **决策项先行**：枯竭计数是否进 `/v1`（`InboundStatsView` 加可选字段 vs 留待契约 v2）；
   决定后若加，补一条 `internal/api` 的序列化用例即可，不动语义。
2. 名字地址池扩容与 LRU：网段可配置（默认仍 /24）、按名字哈希分桶，并给池加
   `容量 / 已用 / 枯竭次数` 的只读观测；扩容后应有一条「池满仍失败」的用例保留。
3. 真机验证：Linux 有 CAP_NET_ADMIN 的机器上跑一遍「改 `[Host]` → 重载 → TUN 侧 DNS 生效」，
   顺带补 Windows 侧（阶段 8 起一直挂着）。
4. 若继续加固批：把「提交点」的两次写收敛成跨层代数对象（需先设计分层的边界，
   不属小改）；以及为 `commitMu` 增加一个「第三个写者必须走提交点」的编译期或测试约束。

## 阶段 19 — 换库批：BLAKE3 与 SQLite 驱动（2026-11-15）

范围：两处**自研实现换成成熟第三方库**，纯核心侧。前端与 Rust 壳（`apps/desktop`）一个字未改，
`/v1` 的字段与语义未改，`spikes/` 与 `docs/` 未改。基线 HEAD `d566fcc`
（Go 1155 条目 / 1134 通过 / 21 跳过 / 0 失败）。

上一轮任务被机器刷新打断，本阶段在**已落地的那部分**上继续：BLAKE3 与 SQLite 两处换库的代码
上一轮已经写完、`go build ./...` 已通过，缺的是 store 包的测试、迁移读用例、语义核对、
体积与依赖台账。本条目记录的是**收尾后的完整状态**，两项换库一并登记。

### 完成了什么

**1. BLAKE3 换成 `lukechampine.com/blake3` v1.4.1（`internal/outbound/blake3.go`）**

- 三个包内函数 `blake3Hash` / `blake3Keyed` / `blake3DeriveKey` 的名字与签名不变，函数体改成对
  模块的一行转调（`Sum256`、`New(32, key)`、`DeriveKey`）；调用点（`aead.go` 一处、
  `shadowsocks.go` 两处 `derive-key`）一个字未动，差异锁在一个文件里。
- **换之前做过差分**：derive-key / hash / keyed 三种模式在 0/1/32/64/100/1024/5000/102400/102401
  等长度上与旧实现逐字节比对，全部相等；换库后这些期望值进测试成为常量，不是「跑通了就算」。
- `blake3_test.go` 重写为三层：① 官方 `test_vectors.json` 的 8 个长度（0/1/1023/1024/1025/2048/
  31744/100000）三列各取前 32 字节；② 上一实现产出、且已与模块互验的 5000 与 102400 两组值，
  钉住官方向量没覆盖到的多块与 100 块路径；③ 2022 家族真正在用的那条路径——
  `derive_key("shadowsocks 2022 session subkey", …)` 的 8 个值作为常量，另加一条上下文域分离断言。
  outbound 包的测试条目 20 → 30。
- 旧的 ~230 行压缩函数、chunk 链接与父节点折叠整份删除。保留这三个函数而不把调用点改成直接
  import 模块，是为了让「BLAKE3 从哪来」成为**一个文件里的一个决定**（决策 3）。

**2. SQLite 换成 `database/sql` + `modernc.org/sqlite` v1.62.0（`internal/store/db.go`，删除 `sqlite.go`）**

- 自研的 763 行格式代码（100 字节文件头、4096 页、table b-tree 叶子/内部页、record 头与
  serial type、varint、overflow 判定、镜像自读）整份删除；新增 `db.go`：三张表的定义与 `CREATE`
  语句、建库、只读校验、整表重写、三张表的读回。
- **契约不变**：同三张表、同列名/列序/类型/可空性、同 `user_version = 1`、同文件名
  `history.sqlite3`。旧构建写的文件能被新构建读，新构建能往旧文件里追加（下面有两条用例）。
- **打开顺序是契约的一部分**：先用 `mode=ro&_query_only=1` 的 DSN 只读连上去 →
  `PRAGMA user_version` → `PRAGMA table_info` 三张表逐列比 → 三张表读一遍并统计行数 →
  `Close` 之后才 `openWritable`。校验阶段任何一条不满足就走 `preserve`，**从不以可写方式打开**，
  所以「保全」不再依赖「我们没写」这种自觉，而是依赖 SQLite 的 `SQLITE_READONLY`。
- 写路径：`_journal_mode=delete`（单文件，不留 WAL 对）、`_synchronous=full`（提交即落盘，
  等价于旧实现的 `Sync` + `Rename`）、`_txlock=immediate`（事务开始就拿写锁，两个写者排队而不是
  一方在升级时失败）。一次 `BEGIN IMMEDIATE` 里三张表 `DELETE` + 重插，读者看到上一份或这一份。
- 建库时用 `O_RDWR|O_CREATE|O_EXCL` 自己按 0600 创建文件再交给驱动：驱动会按进程 umask 建
  （通常 0644），而历史文件不该有一瞬间是别人可读的；`O_EXCL` 顺带让两个同时启动不会都去初始化
  schema（`ErrExist` 视为「已经是别人的文件」，走接管）。

**3. 测试：删掉测已消失格式的用例，补迁移读、接管写与四条语义**

- **删除 6 条**（随实现一起消失）：`TestVarintRoundTrip`、`TestRecordRoundTrip`、
  `TestImageIsReadBySQLite`、`TestImageRejectsWhatItCannotRead`、`TestBuildImageRefusesAnOversizedRow`、
  `TestVarintWidthsMatchTheFormat`。它们断言的是 `putVarint`/`readVarint` 的宽度、
  `encodeRecord`/`decodeRecord` 的头长度、页内 payload 上界与镜像自读，这些函数已经不存在。
  其中「读不懂的文件被拒」这一**意图**没有丢：文件不是数据库、头对正文短、schema 版本超前、
  列类型对不上，四条都各有用例（见下），比原来的三条更全。
- **保留意图并改写 1 条**：`TestImageIsReadBySQLiteTool` → `TestHistoryFileIsReadBySQLiteTool`。
  不再是「手搭镜像再交给 sqlite3」，而是**建真 Store → 写 500 行（跨页）→ Flush → 交给系统
  `sqlite3`** 查行数与极值、单行回读、`sqlite_schema` 的三个表名、空表计数、`PRAGMA integrity_check`、
  `PRAGMA user_version`。缺 `sqlite3` 时 `t.Skip`，口径与旧一致；它只在测试里通过 PATH 调用，
  不链接、不随产品分发、不进仓库。
- **新增 7 条**：
  - `TestLegacyHistoryFileIsReadByThisBuild`：把 `testdata/legacy-history.sqlite3.base64` 解码成
    旧实现写的文件，逐列核对三张表全部 10 行（4 连接 / 3 事件 / 3 采样）。夹具故意挑难：252 字节
    主机名、`2^40`/`2^41` 的计数、空字符串列（不能变成 NULL）、punycode 主机名。
  - `TestLegacyHistoryFileTakesNewWrites`：**接管写**——打开旧文件 → 追加 1 连接 / 1 事件 / 1 采样
    → `Flush` → 再打开断言 5/4/4，且旧行字段不变、新行在末尾（顺序不乱）。
  - `TestStorePreservesATruncatedFile`：合法 100 字节头 + 半页正文 → 拒绝、字节不变、无 `-journal/-wal/-shm`。
  - `TestStorePreservesAFileWithAColumnItCannotRead`：schema 全对、行列数全对，但某列是错类型
    （把 INTEGER 列写成文本，SQLite 的动态类型允许）→ 同样拒绝。旧实现的读端对解不开的行是
    `continue`，**下一次 Flush 就会把那一行从文件里抹掉**；新实现的 `Scan` 出错直接让整次接管失败。
  - `TestStoreDefaultsBoundTheTables`：默认 2000/500/1440 的容量与「丢最旧」在**默认值**上验一遍
    （原来只在自定的 {2,1,2} 上验），顺带把三个常量钉住。
  - `TestStoreFlushesWithoutBeingTold`：只靠节拍（测试里 5ms，生产 30s）落盘，全程没有显式
    `Flush`，重开后记录在。
  - `TestStoreRetriesAFailedWrite`：写失败后记录仍在内存、`last_error` 有值、下一次 Flush 把
    它们写进去（用「句柄被关掉」制造可确定的写失败，因为满盘与权限在测试里不可控）。
- **改 fixture 不改断言 1 条**：`TestStorePreservesAFileFromAnotherVersion` 不再自己拼镜像，改成
  「用本构建建库 → 只改头部第 60 字节的 `user_version` 再 +1」；`another version` + `preserved`
  的 notice、`ErrHistoryPreserved`、字节不变、重启后仍保全，四条断言逐条保留。
- 新增 `assertNoSidecars`：preserve 路径结束后，文件旁边不得出现 `-journal` / `-wal` / `-shm`
  ——「没写」要能被测出来，而不是靠 review 相信。
- 另加 `internal/store/benchmark_test.go`（`BenchmarkFlushFullHistory`），把「一次 Flush 多久」
  变成可复现的数字（见「当前状态」与「遗留」）。
- 包内测试条目：store 包 16 → 17（删 6、改写 1、增 7）。

### 关键决策及理由

1. **手写格式换成驱动：维护成本已经超过收益**。阶段 12 选自研，是因为当时模块代理不可达、
   cgo 驱动会毁掉「单文件 + 交叉编译」这两条硬要求。现在 `modernc.org/sqlite` 是纯 Go、无 cgo、
   Windows 交叉编译已实测通过，而那份 763 行代码的每一行都要我们自己对 SQLite 文件格式负责
   （页分裂、空闲表、溢出页、崩溃恢复都是我们自己没实现的部分）。观测层是**旁路**，它不值得
   继续占用这种级别的注意力。
2. **先只读校验、再可写打开，顺序是契约的一部分**。`preserve` 的全部价值在于「原文件一个字节
   都没动」；只要在校验前以可写方式打开过一次，`-journal`、头部 change counter、乃至
   `journal_mode` 的持久化都可能落盘，那就不再是「保全」而是「碰过但没改内容」。所以校验走
   `mode=ro&_query_only=1`，通过之后才拿可写句柄，并且测试额外断言旁边没有 sidecar 文件。
3. **BLAKE3 保留三个函数名，不把调用点改成直接 import**。2022 家族的会话子密钥是安全关键路径：
   换实现时最怕的是「某处调用忘了换」或「换了一半」；把差异收在一个 40 行的文件里，配合
   「旧值 vs 新值逐字节相同」的常量测试，才能保证这次替换是**可审的**。
4. **迁移用旧实现的产物当夹具，不按新代码重新生成**。「新代码能读自己写的文件」是同义反复；
   真问题是「新代码能不能读**别人**写的文件」。夹具是从旧构建的真实产物里拿的（base64 存文本，
   二进制 blob 在 diff 里没法 review），并且在用例里被逐列核对，包括那 252 字节的主机名与
   超过 32 位的计数——这两处正是格式实现最容易出错的地方。
5. **删测试，不删意图**。六条被删的用例测的是已经不存在的函数，留着只会变成编译错误；
   但它们覆盖的风险（产物别人能读、读不懂的文件不被覆盖）全部在新用例里以更高一层的形态存在。
   `DEVLOG` 逐条记录了删了什么、为什么，避免「测试变少了」被读成「覆盖变差了」。
6. **不允许「读不懂的行被跳过，然后被 Flush 抹掉」**。旧读端对解不开的行是 `continue`：文件能
   打开、行数少一行、下一次 Flush 把少的那行永久删掉，全程没有一句日志。新实现的 `Scan` 出错
   直接让接管失败，文件进入保全。这条是阶段 12「不静默丢历史」原则的补齐，而不是新原则。
7. **`_journal_mode=delete` 而不是 WAL**。WAL 会带出 `-wal`/`-shm` 两个伴生文件：运维拷贝或删除
   「那份历史」时得记着三件套，备份也容易只备主文件。历史是旁路，读少、写更少（30 秒一次），
   WAL 的并发收益用不上，单文件的可搬运性更重要。
8. **别让驱动按 umask 建文件**。`0600` 是契约里的一条（历史里有访问过的主机名），而
   `sql.Open` 会以 0644 建文件。所以先 `O_EXCL` 按 0600 建，再把路径交给驱动；`O_EXCL` 还顺带
   解决了「两个进程同时首次启动都去初始化 schema」。
9. **go.sum 补齐到 `go mod tidy` 幂等**。上一轮留下的 go.sum 缺 28 行传递依赖条目（模块图层面
   的哈希，构建其实不需要），导致任何人跑一次 `go mod tidy` 都会得到一个无关 diff。这次补齐，
   并验证第二次运行无差异。

### 依赖登记（GPLv3 兼容）

许可证逐项从**模块缓存里该版本自带的 LICENSE 原文**核对（不是从文档或印象），`go mod verify` 通过。

| 组件 | 版本 | 许可证 | 用途 | 与 GPLv3 |
|---|---|---|---|---|
| `lukechampine.com/blake3` | v1.4.1 | MIT（Luke Champine） | 2022 家族的子密钥派生、hash、keyed hash | 兼容 |
| `modernc.org/sqlite` | v1.62.0 | BSD-3-Clause（The Sqlite Authors） | `database/sql` 驱动：历史文件的读写 | 兼容 |
| `modernc.org/libc` | v1.80.1 | BSD-3-Clause（The Libc Authors） | 驱动依赖：被转译的 C 运行时 | 兼容 |
| `modernc.org/memory` | v1.12.1 | BSD-3-Clause（The Memory Authors） | 驱动依赖：分配器 | 兼容 |
| `modernc.org/mathutil` | v1.7.1 | BSD-3-Clause（The mathutil Authors） | 驱动依赖：大整数/位运算 | 兼容 |
| `github.com/remyoudompheng/bigfft` | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause（The Go Authors） | `mathutil` 依赖：FFT 乘法 | 兼容 |
| `github.com/dustin/go-humanize` | v1.1.0 | MIT（Dustin Sallings） | `libc` 依赖：数字/时间格式化 | 兼容 |
| `github.com/mattn/go-isatty` | v0.0.24 | MIT / Expat（Yasuhiro MATSUMOTO） | `libc` 依赖：TTY 判定 | 兼容 |
| `github.com/ncruces/go-strftime` | v1.1.0 | MIT（Nuno Cruces） | `libc` 依赖：`strftime` | 兼容 |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause（Google Inc.） | `libc` 依赖：UUID 类型 | 兼容 |
| `github.com/klauspost/cpuid/v2` | v2.0.9 | MIT（Klaus Post） | `blake3` 依赖：运行期 CPU 特性探测（选用 AVX2/AVX512 实现） | 兼容 |
| `golang.org/x/sys` | v0.50.0（阶段 9 已登记的直接依赖） | BSD-3-Clause（Go Authors） | 本阶段新增用途：`modernc.org/libc` 的 syscall 面 | 兼容 |

驱动**随源码带进来的 C 代码**（同一份 `LICENSE-3RD-PARTY.md` 逐条核对，与本项目二进制的关系写明）：

| 组件 | 版本 | 许可证 | 是否进本项目的二进制 | 与 GPLv3 |
|---|---|---|---|---|
| SQLite | 3.54.1（转译进 `modernc.org/sqlite/lib`） | 公有领域（`LICENSE-SQLITE`） | 是 | 兼容（无限制） |
| musl libc | —（经 `modernc.org/libc`） | MIT | 是 | 兼容 |
| Go 运行时 / `go-netdb` | —（经 `modernc.org/libc`） | BSD-3-Clause / MIT | 是 | 兼容 |
| `sqlite-vec` | v0.1.9（`LICENSE-SQLITE_VEC`） | MIT | **否**：只有 import `modernc.org/sqlite/vec` 才链接，本项目没有 | 兼容 |
| SQLite `test_demovfs.c` | — | 公有领域 | **否**：只有 import `modernc.org/sqlite/vfs` 才链接 | 兼容 |

其它：`go.mod` 新增 2 个直接依赖、9 个传递依赖（其中 `klauspost/cpuid/v2` 归 BLAKE3，
其余归驱动）；`github.com/molecule-man/go-brrr` 等既有传递依赖未变。`go.sum` 补 28 行，
`go mod tidy` 两次运行无差异。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                            通过
go vet ./...                                              通过
gofmt -l .                                                无输出
go test ./... -count=1 -v                                 1166 条目 / 1145 通过 / 21 跳过 / 0 失败
go test -race ./internal/store/ ./internal/outbound/       通过
go test ./internal/store/ -run XXX -bench BenchmarkFlushFullHistory -benchtime 20x   39–42 ms/op
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
```

- 逐项对基线（`d566fcc`，1155/1134/21/0）：**条目 +11、通过 +11、跳过 ±0、失败 0**。
  增量 = outbound +10（BLAKE3 向量分列成 hash / keyed / derive 三组，另加两组常量与一条域分离）
  + store +1（删 6、改写 1、增 7 的结果）。21 条跳过与阶段 8/9/11 起的那一批**逐名核对完全同一集合**：
  缺参考实现的互通 10、未连接 `sendto` 被 seccomp 拒绝的 UDP 9、上游「UDP 截断改 TCP」1、
  `TestTUNLinuxLoopback` 1。无新增跳过。
- `GOOS=windows GOARCH=amd64 go build ./...` 仍是 `./cmd/... ./internal/...`：`./...` 会被
  `spikes/tun` 的 Unix-only 原型挡住（阶段 8 起如此），与本次换库无关；驱动本身交叉编译通过，
  `GOOS=windows go vet ./internal/store/` 也通过。
- **二进制体积**（同机同工具链，`go build -o` 默认参数，均未 strip）：

  | 树 | 大小 | 相对 HEAD |
  |---|---|---|
  | HEAD `d566fcc` | 17,588,294 B（16.77 MiB） | — |
  | HEAD + 只换 BLAKE3 | 17,733,376 B（16.91 MiB） | +145,082 B（+141.7 KiB） |
  | HEAD + 两项都换（当前树） | 24,287,933 B（23.16 MiB） | +6,699,639 B（+6.39 MiB，+38.1%） |

  即：BLAKE3 换库几乎不改变体积（+142 KiB，模块带 AVX2/AVX512 实现，换掉的是 230 行纯 Go），
  **体积增量基本全部来自驱动**（+6.25 MiB，被转译的 SQLite + libc）。
- `go.mod` / `go.sum`：`go mod verify` 通过，`go mod tidy` 幂等。
- **包外零改动**：`git status` 在 `internal/store`、`internal/outbound`、`go.mod`、`go.sum` 之外
  没有任何条目；`internal/api` / `internal/cli` / `cmd/` 一个字未改，`/v1/history*` 的字段与
  CLI 输出形状因此不变（相关用例在 1166 条里原样通过）。
- 两笔本地提交（未推送）：`795898e`（BLAKE3 → 模块，含 `go.mod` / `go.sum`）→
  `f0c5586`（store → 驱动 + 测试 + 迁移夹具 + 基准）。本条目单独一笔，不推送。

### 遗留问题

- **体积 +6.39 MiB（+38%）**，单文件二进制 23.16 MiB，且未 strip。这是换驱动的主要代价：换来自研
  写端（约 600 行）为一份被转译的 SQLite + libc。若要压，`-ldflags "-s -w"` 与 `-trimpath` 是
  下一步；驱动侧能裁的只有我们本来就没链接的 `vec`/`vfs`。
- **一次满载 Flush 约 40ms，是旧实现的约 3 倍**（旧 10–14ms，新 39–42ms；见
  `BenchmarkFlushFullHistory`）。里面至少有一次 fsync（`_synchronous=full` 买的是「提交即落盘」），
  其余是约 3900 行插入走转译引擎；**没有拆分测量**，所以「fsync 占多少」目前是推测。
  30 秒一次、0.13% 占空比，可以接受；但保留量若上调，这条要重新评估。
- **整表重写没有变**：仍然每次把三张表删光重插。驱动本身能做增量（`INSERT`/`UPDATE`/`DELETE`
  逐行），只是「内存表是唯一真相」这条设计没变，改成增量会让「内存与文件不一致」变成可能。
  要改的话是一次独立设计，不属换库批次。
- **掉电与并发没有真机证据**：`_synchronous=full` 只保证提交落盘，`kill -9` 后重开、
  两个进程同时打开同一个 history 文件（`_txlock=immediate` 下应排队）都没有用例。沙箱里能做的
  只有「句柄被关掉」这种可确定的失败（已覆盖）。WAL 模式、热日志回滚同理未验。
- **迁移只在 Linux/x86_64 上跑过**：Windows 侧交叉编译通过，但没有在真机上对旧文件（夹具）跑
  一遍迁移，与阶段 8 起的 Windows 挂账同类。
- **启动期行为有一处可观测变化**：路径不可创建时，旧实现是「静默在内存里跑，第一次 Flush 才
  报错」，现在是启动就 `preserve`，`/v1/history` 的 `notice` 立刻有值、`last_error` 也有值。
  行为更诚实（运维在启动后就能看见），但确实与旧版不同，记在这里。
- **保留的 `blake3Hash` / `blake3Keyed` 目前没有生产调用点**（生产只走 derive-key），留着是为了
  签名稳定与测试可读；若确认长期不用，可连同测试一起收掉，但那会让「换库前后逐字节一致」的
  证据链少一环。
- 阶段 8–18 的既有挂账照旧：Windows 实机（TUN / 系统代理 / 令牌文件）、Rust 壳编译、QUIC 真实
  互通、REALITY UDP 证据、预览桥 query string、`core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、
  名字地址池枯竭计数的对外出口。

### 下一步计划

1. **二进制体积**：`-s -w` + `-trimpath` 实测（预计 -25%~-30%），并把「是否 strip」写进构建脚本与
   发布说明；顺手确认三个平台的产物大小都可接受。
2. **Flush 成本**：把「fsync 占多少」拆出来测（`_synchronous=off` 的对照跑，只作测量不作默认），
   再决定是否需要「只在有变化时重写」或按保留量自适应的节拍。
3. **掉电与并发**：两个进程同时打开同一个 history 文件跑一遍；`kill -9` 后重开的一致性；
   若要，再把 WAL 作为可选模式评估（收益是 Flush 更快，代价是三个文件）。
4. **真机迁移**：Windows 上用 base64 夹具跑一遍「旧文件 → 新构建 → 追加 → 重开」，与阶段 8 起的
   Windows 挂账一起清。
5. 回到核心侧：阶段 18 留下的两个决策项（枯竭计数是否进 `/v1`、名字地址池扩容与 LRU）。

---

## 阶段 20 — 测试加固：规则 oracle 对照、四个 fuzz 入口、互通与 CI 规范化（2026-11-15）

范围：**测试、判定脚本、文档、CI 定义**，四件事。生产代码只动一处，是 fuzz 抓到的真缺陷
（第 2 节末段，单独一笔提交）。基线 HEAD `6192b2d`（Go 1166 条目 / 1145 通过 / 21 跳过 /
0 失败），收尾 **1251 / 1230 / 21 / 0**。`spikes/`、前端与 Rust 壳一个字未改；
`docs/` 只新增一个文件，`development-doc-v1.md` 未动。

### 完成了什么

**1. 规则引擎的对照实现（`internal/rules/oracle_test.go`，包内 136 → 151 条目）**

- **oracle 是什么**：把引擎的语义用最直白的方式再写一遍——拿 `Program.Rules()`（`Compile`
  展开后的规则列表），从下标 0 开始逐条判断是否命中，第一条命中即决策。它**不碰任何索引**：
  DOMAIN 用字符串相等，DOMAIN-SUFFIX 用 `name == suffix || HasSuffix(name, "."+suffix)`，
  DOMAIN-KEYWORD 用 `strings.Contains`，IP-CIDR/IP-CIDR6 用 `net.ParseCIDR` + `Contains`，
  DEST-PORT 自己 `strings.Cut` + `Atoi`，PROTOCOL 字符串相等，GEOIP/IP-ASN 调**同一份**
  `Lookup`，FINAL 恒命中，`no-resolve` 规则在地址来自解析时不命中。
  引擎侧的 `cidrBlock`、`parsePortSpec`、`parseRulePayload` 一个都没复用，只共用规则列表
  （那是配置，不是计算）与两个数据集（那是被注入的依赖）。
- **生成器**：固定种子 `math/rand`（1..6），每个种子一份规则集 + 一份请求集。
  - 规则集：先放**一条不落的 12 类**骨架，再随机追加 12 条，然后**整体打乱**，让优先级只
    来自顺序。载荷刻意重叠：`example` / `alpha.example` / `sub.alpha.example` 三级后缀，
    `10.0.0.0/8` / `/16` / `/24` / `/25` 四级嵌套网段，`443` / `8080` / `9000-9100` /
    `8000-8100` 重叠端口；`no-resolve` 以 35% 概率落在地址类规则上（触发第二套地址表）。
    DOMAIN-SET 三份（其一为空文件）、RULE-SET 两份（`set-b` 嵌套引用 `set-a`，且含一条
    `no-resolve`，验证标志能穿过展开），都由 `Options.ReadFile` 注入内存文件。
  - 请求集：名字取精确值 / 子域（一层与两层）/ 共享尾标签但越界（`notalpha.example`、
    `alpha.example.evil`）/ 含关键字 / 无关名；地址取每个网段的首、尾、首+3、首-1、尾+1，
    两个族共 55 个；端口取区间内、边界、边界外、0、65536、-1；协议取 `tcp`/`udp`/空/`TCP`/
    `sctp`；**名字与地址的四种组合 × `Resolved` 两值**全取，每个种子 1904 条请求。
- **规模与结论**：6 份规则集（26~38 条），**11424 次对照，0 处分歧**（11397 条由某条规则
  决定，27 条什么都没命中——后者来自唯一一份没有 FINAL 的规则集）。
- **不算白跑的证明**：断言"赢的规则种类"覆盖了能赢的 11 类（RULE-SET 不可能赢，`Compile`
  已把它换成了文件里的规则），实测分布
  `IP-CIDR 2171 / PROTOCOL 2132 / FINAL 2108 / IP-CIDR6 929 / IP-ASN 888 / GEOIP 731 /
  DOMAIN-KEYWORD 723 / DEST-PORT 720 / DOMAIN-SUFFIX 610 / DOMAIN 270 / DOMAIN-SET 115`。
  一条"语料退化成 FINAL 通吃"的断言守着它：以后谁把生成器改坏，这条会红。
- **oracle 看不到的那一半**：`Program.Rules()` 已经是展开后的列表，所以展开顺序、目标传递、
  "DOMAIN-SET 只占一个槽位"这些它验证不了。另加一份 `expectedFlatten`，按生成器的意图把
  展开结果拼出来，与 `Rule.String()` 逐条比对（含嵌套引用与 `no-resolve` 的顺序）。
- **边界**：`Compile` 零规则报 `no rules`；只含一个空 RULE-SET 的列表同样报 `no rules`
  （展开在空检查之前）；空 RULE-SET **不占**优先级槽位、空 DOMAIN-SET **占**一个槽位；
  无 FINAL 且全不命中返回 `(Decision{}, false)`；FINAL 写在第一行时通吃（这条顺序单列，
  因为生成器会把落到第一行的 FINAL 挪走，否则整份规则集只剩一种比较）。
- **换数据源的用例**：用 `internal/geoip/geoiptest` 写一个小 mmdb、经 `internal/geoip`
  真实加载，再走一遍对照，证明 oracle 不绑在 `MemGeoIP` 上。`internal/geoip` 不 import
  `internal/rules`（只有它的测试 import），所以包内测试引用它没有环。
- **注入错误验证 oracle 有效**（临时改引擎、跑完即还原，不提交）：① 后缀树改成"最长匹配"
  → 抓到（`DOMAIN-SUFFIX,test` 与更深的 `sub.alpha.example` 谁赢）；② 去掉编译期
  `no-resolve` 的 `continue`，让受限规则漏进"解析来的地址"那张表 → 抓到（`2001:db8::/32`
  的 `no-resolve` 规则抢答了 `Resolved` 查询）；③ DOMAIN 精确表改成"后者覆盖前者" →
  抓到（同名两条规则取了大的下标）。三次都是第一条分歧就带着完整规则集打印出来。

**2. 四个 fuzz 目标（+83 条目，见「当前状态」的加总）**

| 目标 | 入口 | 种子 | 不变量 |
|---|---|---|---|
| `config.FuzzParse` | `Parse([]byte)` | `sampleConfig` + 15 条（BOM/CRLF、引号与尾注释、以及 `TestParseSyntaxErrors` 那批非法形状） | 有错或有配置，绝不同时为空 |
| `share.FuzzParse` | `Parse(string)` | 六种链接 + 拒绝样本 + 2 条回归种子（21 条） | 成功即意味着 type/server/port 可拨号、参数非空 |
| `subscription.FuzzParseBody` | `parseBody([]byte)`（白盒） | 明文、base64、76 列折行的 base64、BOM+注释、空、注释-only、base64 的非法体（8 条） | 成功即意味着至少一个可拨号条目 |
| `dns.FuzzParseResponse` | `parseResponse([]byte)`（白盒） | 9 条报文（A/AAAA 带压缩指针、NXDOMAIN+SOA、只有头、查询、自指指针、两处截断、rdata 越界） | 有错或应答；id 等于前两字节，rcode 四位，记录长度 4/16 |

- `parseBody` 内部就调 `decodeSubscription`，所以明文与 base64 两条路都在同一个目标里。
- dns 的语料写成**报文常量**而不是用 `buildTestResponse` 生成（那个助手要 `*testing.T`，
  fuzz 目标只有 `*testing.F`），另配 `TestFuzzParseResponseSeedsReachTheParser` 逐条断言
  每个种子落在哪儿——A 记录真的走到 `readName` 的指针路径、负应答真的走到 SOA、三处截断
  真的报错。语料不会悄悄退化成"一堆早退错误"。
- **本机有界短跑各 75 秒**（`go test -run xxx -fuzz '^FuzzX$' -fuzztime=75s`）：

  | 目标 | execs | 结论 |
  |---|---|---|
  | `config.FuzzParse` | 638,580 | 干净 |
  | `share.FuzzParse` | 第 8 秒停在第 99 字节输入 | **发现缺陷**，见下 |
  | `share.FuzzParse`（修复后重跑） | 639,497 | 干净 |
  | `subscription.FuzzParseBody` | 294,207 | 干净 |
  | `dns.FuzzParseResponse` | 1,549,848 | 干净 |

- **fuzz 抓到的真缺陷（`1ee0b43`，与测试分开提交）**：输入 `ss://0006001A0C0j0006M0`。
  `ss` 的旧式写法把整个 `method:password@host:port` 做 base64，解析器直接对**解码出来的
  字节**切 `@` 与 `:`，中间没有任何 URL 解析——那份载荷解码成 `ÓM:ÓM@Ð-#ÓM:3`，于是
  "主机"是 `\xd0-#\xd3M`（含 `#`）、端口 3、密码是两字节任意值，**解析成功**。
  包自己在 `TestParseBuildsEveryLink` 上写着契约："每一条能解析的链接都必须能构建成 dialer"，
  而 `outbound.New` 拒绝了这个条目——解析产出了一个永远连不上的节点。修法是在**所有协议
  共用的** `splitHostPort` 后加一道 `validateHost`：拒绝空白、URL 分隔符（`: / \ ? # @ [ ]`）
  与控制字符，地址字面量原样放行（冒号本来就该在里面），非 ASCII 名字也原样放行（拒绝的是
  "不可能是主机"的形状，不是"不眼熟"的名字）。回归证据三条：`TestParseRejects…` 表里新增
  两行、fuzz 种子表里两条可读样本、以及 `testdata/fuzz/FuzzParse/931897f2ffd8da69`
  ——fuzzer 自己写的那个文件原样保留。
- **短跑后 `git status`**：`testdata/fuzz` 下只有上面那一个文件，没有别的未解释语料；
  其余"interesting"输入留在构建缓存里，不进仓库。

**3. 互通文档、判定脚本与 CI（工作三）**

- **`docs/interop-testing.md`**：把阶段的装置从 DEVLOG 里抽出来做成手册——五个参考实现
  （Xray-core 26.11.9、shadowsocks-rust 1.25.0、snell-server 5.0.0、hysteria v2.13.0、
  tuic-server 1.0.0）的版本表、各自的发布渠道与校验办法（`.dgst` 里的 `SHA2-256`、
  `.sha256`、`hashes.txt`、`.sha256sum`、Snell 的发布页哈希）、槽位布局（5 份下载 /
  7 个槽位，Xray 一个二进制挂三个槽）、复现命令、环境前提（**允许未连接 `sendto`**，
  否则 UDP 与 QUIC 必然跳过）、以及判定口径。**不写 URL**：发布页由项目主页指向，写死链接
  只会随仓库迁移过期；能长期成立的是"哪个 tag、哪个资产、拿哪一行哈希"与校验命令。
- **`scripts/check-interop.sh`（POSIX sh）**：三种退出码——未设 `MELONARC_INTEROP_DIR` 打印
  说明并退 **2**；跑 `go test ./internal/outbound/ -run TestInterop -count=1 -v`，任一
  `TestInterop*`（父或子）SKIP 或 FAIL 就列出名字并退 **1**；全过退 **0**。另加一条：
  **一个用例都没跑也算失败**，否则过滤条件写错就会"因为没失败而成功"。
  本机实测（`$HOME/interop-bin`，只有 Xray 三槽）：

  ```
  check-interop: SKIPPED (a skip means this protocol was not verified)
    SKIP TestInteropHysteria2
    SKIP TestInteropShadowsocks
    SKIP TestInteropShadowsocksRejectsAWrongPassword
    SKIP TestInteropSnell
    SKIP TestInteropSnellRejectsAWrongPSK
    SKIP TestInteropTUIC
    SKIP TestInteropTrojan/udp
    SKIP TestInteropVLESS/udp
    SKIP TestInteropVMess/udp
  exit 1
  ```
  Xray 系的 **TCP** 子用例（VMess / Trojan / VLESS / VLESS+REALITY）全过，跳过的 9 条是
  "缺四个槽位 + 三个 UDP 子用例"。**退出码 1 是正确行为**，没有为了变绿放宽判定。
  脚本其余分支用一个桩 `go` 验过：全过 → 0、什么都没跑 → 1、有 FAIL → 1 并列出名字。
- **`.github/workflows/ci.yml`（三个 job，`push` / `pull_request` 触发）**：
  - **Go**：`setup-go` 用 `go-version-file: go.mod`；`go build ./...`、`gofmt` 检查
    （有输出即失败）、`go vet ./...`、`go test ./... -count=1`、
    `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...`（不用 `./...`：`spikes/`
    的 Unix-only 原型挡着，阶段 8 起如此）。
  - **Frontend**：`setup-node` 22（`apps/desktop` 要求 `>=20`，且它**零依赖**，`npm ci`
    不需要网络）；`npm ci` → `npm run build` → `npm test`（两条需要真实核心的用例跳过）；
    然后 `go build` 出核心、写一份 `/tmp/arc/demo.conf` 演示配置（`data-dir`、一个代理两条、
    select/url-test/fallback 各一、8 条规则 + 一条外部规则集、`[Host]` 一条）、`-check`
    通过后后台起核心、轮询 `/healthz` 到应答，再带 `MELONARC_TEST_API` /
    `MELONARC_TEST_DATA_DIR` 跑 `npm test`。**全部是仓库既有的脚本，没有新造命令。**
  - **Interop**：按 `docs/interop-testing.md` 下载五个实现（`gh release download` 按资产名
    glob 取，tag 与版本写在 `env` 里）、逐个校验哈希、布置 7 个槽位、跑
    `scripts/check-interop.sh`。Snell 没有机器可读清单，因此 zip 的 URL 与 SHA-256 由仓库
    变量 `SNELL_ZIP_URL` / `SNELL_ZIP_SHA256` 承载，**留空即整步失败**（宁可红，不要一个
    看起来校验过了的分支）。
  - **未在 Actions 上实跑**：本阶段不推送。做过的静态检查只有：YAML 缩进结构自检
    （无制表符、每级 2 空格、块标量内的内容都更深）、`sh -n` 语法检查、以及把每个
    `run:` 里的 shell 片段按行读一遍。资产名与 tag 形式**没有**逐个核对过 404
    （本机无外网）。

### 关键决策及理由

1. **oracle 只吃 `Program.Rules()`，不碰索引。** 引擎的价值全在"每个索引返回自己命中的
   最小下标，再取全局最小"这一步；让 oracle 也走索引就只是把同一份代码抄一遍。测试的独立性
   来自**换一种实现方式**：线性扫描 + 最直白的判断。代价是它验证不了展开与索引构建，所以
   `expectedFlatten` 单独补上那一半。
2. **oracle 自己解析载荷。** `net.ParseCIDR` 与 `strings.Cut` + `Atoi` 都是重写的，没有调
   `cidrBlock` / `parsePortSpec`。如果复用，载荷解析的错误会在两侧同时错，测试永远是绿的。
3. **生成器保证覆盖，随机只用来制造顺序。** 12 类各一条是**构造**出来的，不是掷骰子掷出来的；
   随机只决定载荷细节、追加规则与整体顺序。这样"某个类型一个用例都没覆盖"这类沉默失效不会
   发生。
4. **打乱顺序，并且专门照顾 FINAL 的位置。** first-match-wins 的正确性只在"顺序会改变结果"
   时才被测到；一条写在末尾的 FINAL 会让整份规则集退化成一种比较。所以骨架含 FINAL、整体
   打乱，但**落到第一行时挪走**，另用一条专门的用例覆盖"FINAL 在第一行"这个真实语义。
5. **覆盖度写成断言，不写成注释。** 只比较结果的话，"FINAL 回答了一切"也是 0 分歧。
   断言赢的规则种类覆盖 11 类，把"测试本身退化了"变成一次红灯。
6. **fuzz 的不变量取"最弱但确实成立"的那条。** 解析器对任意输入的正确行为就是"有错或
   有结果"，所以四个目标的主断言都是"不 panic、不返回半成品"。在此之上各加一条便宜的结构
   检查（可拨号的 server/port、id 与 rcode）；`share` 那条正是抓到缺陷的那条。曾考虑在
   fuzz 里顺手 `outbound.New` 一遍（更强的契约），放弃：每次执行都要生成密钥，execs 会掉
   一到两个数量级，而那条契约已经由 `TestParseBuildsEveryLink` 在固定夹具上守着。
7. **dns 语料用字面量，并配一条"种子落在哪儿"的测试。** 随机字节进不了 `parseResponse` 的
   深处（多数在头部就被拒），所以语料必须是人挑的报文；而人挑的报文最容易悄悄写错，于是
   用一条普通测试把每条种子的预期解析结果钉住——这条同时证明了"压缩指针路径被覆盖"。
8. **判定脚本严格，且不猜跳过原因。** 不区分"缺二进制"与"环境缺能力"：两者都是"这次没
   验证"，而门要回答的只有一个问题。另外把"一个都没跑"当成失败，堵住"过滤条件失效 → 没有
   失败 → 通过"这条静默路径。
9. **修 `share` 而不是放宽断言。** 分歧的三条出路里（改 oracle、改引擎、删用例），
   删用例被明确排除；结论是引擎错，依据是包自己写在 `TestParseBuildsEveryLink` 上的契约与
   `outbound.New` 的实际拒绝。修的落点选在 `splitHostPort` 之后——六个协议共用这一处，
   所以不存在"某个协议漏了校验"。
10. **阶段 11「实现名只出现在 DEVLOG」这条，本阶段有意放宽到 `docs/interop-testing.md`。**
    阶段 11 的原文是"产品代码、注释、用户文档、提交信息里一个都没有"。互通手册不是用户文档，
    是开发文档；不写名字它就不可复现。**产品代码与注释仍然一个名字都没有**（装置按协议取
    二进制），这条没变。
11. **CI 里 Snell 用仓库变量承载哈希。** 它没有 `.dgst`/`.sha256`/`hashes.txt` 这类机器可读
    的清单，只有一个网页上的值。把猜来的哈希写进工作流会让第一次真跑就红在一个无法解释的
    常量上；写成"变量为空即失败"，至少把不确定性放在明面上。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                              通过
go vet ./...                                                通过
gofmt -l .                                                  无输出
go test ./... -count=1 -v                                   1251 条目 / 1230 通过 / 21 跳过 / 0 失败
go test -race ./internal/rules/ ./internal/config/ ./internal/share/ ./internal/subscription/ ./internal/dns/
                                                            五包全通过
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
scripts/check-interop.sh（未设变量）                          退出 2
MELONARC_INTEROP_DIR=$HOME/interop-bin scripts/check-interop.sh
                                                            退出 1，列出 9 条跳过（预期行为）
```

- **逐项对基线**（`6192b2d`，1166/1145/21/0）：**条目 +85、通过 +85、跳过 ±0、失败 0**。
  增量拆解（逐包核对）：rules +15、config +16、share +25（fuzz 23 + 拒绝表 2 行）、
  subscription +9、dns +20（fuzz 10 + 种子断言 10），合计 85。
- **21 条跳过与基线逐名 `diff` 完全一致**：缺参考实现的互通 10、未连接 `sendto` 被 seccomp
  拒绝的 UDP 9、上游「UDP 截断改 TCP」1、`TestTUNLinuxLoopback` 1。无新增跳过。
- 包内条目：rules 136 → 151、config 122 → 138、share 37 → 62、subscription 11 → 20、
  dns 94 → 114。
- **fuzz 数字**：见第 2 节的表（638,580 / 639,497 / 294,207 / 1,549,848 execs，四次各 75 秒）。
  一次失败（share，第 8 秒，99 字节），修完后重跑到干净。
- **命名红线**：新增/修改的源码、文档、脚本、工作流与提交信息已按已知清单扫描
  （`clash|surge|quantumult|shadowrocket|stash|loon|kitsunebi|mellow|surfboard|nekobox|
  v2ray|…`），零命中。文档里出现的五个参考实现名是本阶段任务明确允许的开源项目名。
- 三笔代码/文档提交 + 一笔本条记录（均未推送）：
  `802c3a0`（规则 oracle）→ `1ee0b43`（share 主机校验修复）→ `5902129`（四个 fuzz 目标 +
  回归语料）→ `b94992d`（互通手册 + 判定脚本 + CI）→ 本条目单独一笔。
  顺序说明：**修复排在 fuzz 目标之前**，这样每一笔单独 checkout 都是绿的（fuzz 目标那一笔
  已经带着修复后的语料跑通）；代价是修复那一笔的回归证据只有表里的两行，fuzzer 的原始输入
  与种子随下一笔落地。

### 遗留问题

- **CI 没有实跑过。** 三个 job 都只做了静态检查；资产名（尤其 `tuic-server` 与
  `snell-server` 的 zip 命名）、`gh release download` 的 glob、hysteria 的 `app/v2.13.0`
  这类带斜杠的 tag，**都没有核对过**。首次真跑时最可能在这里 404。
- **`TestInteropQUICFixtureReachesSendtoBoundary` 与严格判定冲突（需决策）。** 它断言的是
  "沙箱把 `sendto` 挡住了"；一台**允许** `sendto` 的机器上这条性质不存在，所以它 `t.Skip`。
  名字以 `TestInterop` 开头，于是被判定脚本记成"这次没验证"。后果：在允许 `sendto` 的
  runner 上（CI 就是），互通 job 会因为这两条跳过而红，**即使七个协议全部通过**。
  本阶段**没有**用改名或放宽判定绕开它。两条候选出路：(a) 把它改名出 `TestInterop*` 家族
  （它测的是夹具接线，不是互通）；(b) 判定脚本区分"环境比沙箱更宽松"与"环境缺东西"。
  建议 (a)：改的是名字，不是断言，而且名字本来就名不副实。
- **`share` 的密码套件仍未在解析期校验。** 修掉主机那条之后，`ss://aes-999:pass@h.example.com:1`
  仍然能解析、要到 `outbound.New` 才被拒——同一份契约的另一条缝。修复方向是让 `share` 拿到
  `outbound` 支持的套件清单（新增一条 share → outbound 的依赖，需评估），或接受"解析只保证
  形状、构建才保证可用"。本阶段没动，因为 fuzz 抓到的是主机那一条。
- **oracle 的输入有三处刻意收窄**：查询名只用 ASCII（引擎的大小写归并是"有 ASCII 大写字节
  时走 `strings.ToLower`、否则逐字节"，混合脚本名的语义文档没定，不在对照范围）；GEOIP/
  IP-ASN 用同一份 `Lookup`（任务如此规定，测的是引擎的分派不是数据集）；DOMAIN-SET 的条目
  取自生成器的意图而非解析器的输出（这是有意的独立性，但也就测不到 `parseDomainSetFile`）。
- **fuzz 只各跑了 75 秒**，不是持续 fuzz；也没有进 CI 的定时任务。`config` 那个目标 76 秒
  内只覆盖到 638,580 次执行、语料 224 条，离饱和还很远。
- **`share` 的 fuzz 不变量仍只覆盖主机与端口**，没有覆盖"参数键集合"（未知键要到构建期
  才报错）。想覆盖它就得在 fuzz 里构建 dialer，代价见决策 6。
- 阶段 8–19 的既有挂账照旧：Windows 实机（TUN / 系统代理 / 令牌文件 / 迁移）、Rust 壳编译、
  QUIC 与 UDP 的真实互通（本机 seccomp 不允许）、REALITY UDP 证据、预览桥 query string、
  `core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、名字地址池枯竭计数的对外出口、
  二进制体积与 Flush 成本。

### 下一步计划

1. **CI 首跑**：找一台能出网的机器推一次分支，逐个修资产名/glob 的 404，并把 Snell 的两个
   仓库变量补上；跑绿之后再谈"这三条 job 是门"。
2. **决定并落地 `TestInterop` 的冲突**（见遗留第 2 条）；在此之前互通 job 在宽松 runner 上
   会红，不能当作回归信号。
3. **把 fuzz 放进 CI 的定时任务**：`schedule` 触发，四个目标各 60~120 秒，发现即开 issue；
   顺带把 `-race` 也挂到定时任务上（本机 5 包已过，全量 `-race` 尚未跑过）。
4. **`share` 的套件校验**：先决定契约到底是"解析保证形状"还是"解析保证可构建"，再动代码；
   若选后者，`outbound` 需要导出一个套件清单。
5. 回到核心侧的两条既有决策项：阶段 18 的枯竭计数是否进 `/v1`、名字地址池扩容与 LRU；
   阶段 19 的 `-s -w` + `-trimpath` 与 Flush 成本拆分。

## 阶段 21 — 0.x 预览发版准备：支持矩阵统一、发布工程、公开前检查（2026-11-15）

范围：四件事——让 README 的支持矩阵与代码事实对齐、把版本/构建/声明做成一条可复现的发布
链路、把公开前该挂账的东西逐项列清、把许可证口径的差异汇总（**只汇总不改**）。产品行为只
动一处（配置含已知不可用协议时打 warn），其余是文档、脚本与构建参数。`spikes/` 未动；
`docs/development-doc-v1.md` 按任务书要求在开头加了一段状态说明，其余一字未改。

开工前：`HEAD = 96238a1`，工作区干净，协调者复跑基线 **1251 条目 / 1230 过 / 21 跳 / 0 败**，
前端离线 **75 / 73 / 2 / 0**。开工前重跑一遍确认基线一致（条目 1251、通过 1230、跳过 21、
失败 0），21 条跳过与阶段 20 记录的集合逐名相同。

### 范围一：支持矩阵统一

README 的逐协议证据矩阵是唯一事实源。本阶段核对的六处，逐处列明改了什么：

**1. `README.md` · Components 表 · Observation history 行（阶段 19 脱节）**

原文把状态写成「Bounded local tables, self-written file writer」，边界里还写着「迁到维护中
的驱动是计划」。阶段 19 已经换成 `modernc.org/sqlite`，这两句都过期了。改为：
状态「Bounded local tables in SQLite, through a pure-Go driver (`modernc.org/sqlite` v1.62.0)」，
边界保留保全语义并写清代价——「三张表每次整表重写；schema 不认识或读不开的文件原样保全、
写入挂起」。没有再写「迁移计划」，因为它已经不是计划。

**2. `README.md` · Other known gaps · 最后一条（阶段 20 脱节）**

原文「No fuzz corpus, no independent CI interop job, and no version-linked machine reports for
release tags.」三件事里前两件已经变了。拆成两条，按事实分述：

- fuzz 目标与种子语料已在树里，但**只跑过限时的本地会话**，CI 还没有定时任务；
- CI 工作流带独立 interop job，**从未在 Actions 上跑过**，所以资产名没核对过 404，也没有
  任何 tag 背后的机器报告。

「已定义」不写成「已运行」：两条都用了完成时描述文件存在、用「has never run」描述执行。

**3. `README.md` · Hysteria2 / TUIC 两行的状态标签**

原文「Known failing — fix in progress」，但修复阶段 15 就落码了。标签改成
「**Unusable** — fix landed, interop not re-run」，一句话同时承载三件事：修复已落码、真实
互通未复验、按不可用对待。图例里「Known failing」那条同步换成「Unusable」并写明后果
（不进任何稳定声明、不得出现在稳定包里），因为表里已经没有行再用旧标签。两行的「证据与边界」
补上「Stage 15 repaired … but nothing has been carried against a reference server since」。
「Source-level scope」里的「Hysteria2, TUIC v5 — known failing, fix in progress」同批改成
「implemented, but unusable until their real interoperability has been re-run」——同一份 README
里两处说法不能不一样。

**VLESS + REALITY 行未动**：仍是「Project record」（TCP，阶段 16 的 16 KiB 往返），UDP 仍是
「Unverified」。没有升级成「Verified」。

**4. 配置期警告（新代码，`internal/outbound/unusable.go` + `cmd/melonarc-core/unusable.go`）**

配置里写 `hysteria2` / `tuic` 节点原来会被静默接受，与矩阵「按不可用对待」不一致。现在：

- `outbound.UnusableProtocols()` / `IsUnusable(typ)` 是纯函数，列出「已知不可用」的协议与
  一句原因；类型匹配与 `outbound.New` 同规则（小写 + 去空白）。
- `warnUnusableProtocols(cfg, logger)` 在**装配点**逐条打结构化 warn：
  `msg="outbound protocol is known to be unusable in this build"`，带 `proxy` / `type` / `reason`。
  只警告不拒绝：拒绝会让一份订阅里有一个坏节点就整份配置起不来。
- 调用点两处：`run()` 在 `buildDialers` 之后（此时订阅已导入，所以订阅带进来的节点也会被
  点到），`reloader.reload` 在 `buildDialers` 之后（配置已被接受才警告）。
- 已用真进程验：一份含 `hysteria2` + `tuic` 各一个节点的配置启动后 stderr 有 2 条 warn，
  文案含协议名与原因，**不含**口令（`TestUnusableProtocolWarningCarriesNoCredentials` 守着）。
- `-check` 不警告：它不走 `buildDialers`，是纯校验路径，输出到 stdout 的摘要里也不该混日志。
  这是有意的，记在这里免得被当成漏掉。

**5. CLI 与 GUI 的核对结果（无改动）**

- **CLI**：通读 `internal/cli` 的 usage 与全部子命令输出，没有一句协议级支持表述（`status`
  只转述核心的 `/healthz`、`/v1/*`），与矩阵不冲突。除版本字符串随范围二统一外，没有加任何
  命令、没有加支持矩阵文案。
- **GUI 关于区**：`settings.js` 的 `aboutBlock` 只有四样东西——Logo、`APP_VERSION`、
  `APP_LICENSE`、一条 Logo 说明（`settings.about.body`）。**已核对、无协议级表述**，locales
  文案未动。
- 「两个版本号」的问题按范围二处理：发布构建用同一个版本参数同时注入核心与前端，而不是让
  UI 去读核心的版本。本阶段 tar 只含核心 + CLI，前端同源是给后续桌面包预备的。

**6. `docs/development-doc-v1.md` · 开头状态说明**

§2.3 把 XTLS-Vision flow 列在 VLESS 范围内，而实现是配置期拒绝、矩阵写明不支持。在文档头部
（元信息之后、`---` 之前）加了一段「状态说明（2026-11-15，阶段 21）」：本文是 v1 **目标规格**，
当前实现状态以 README 支持矩阵为准，两处不一致时以 README 为准，并点名 Vision 就是这类差异。
**只加说明段，§2 的范围条目一字未改。**

### 范围二：发布工程

**1. 版本注入：`internal/version` 成为唯一来源**

- 新包 `internal/version`：`const Default = "0.1.0-dev"` 与 `var Version = Default`。是变量而
  不是常量，因为链接器只能写变量。
- 删掉两处各自的常量：`cmd/melonarc-core/main.go` 的 `const version`、
  `internal/cli/cli.go` 的 `const Version`（对外可见的 `cli.Version` 一并消失，仓库里没有第二
  个引用点）。API status、`/healthz`、CLI `version` 命令全部读 `version.Version`。
- 构建注入：`-ldflags "-X github.com/melon-tgj/melonarc/internal/version.Version=<v>"`。不带注入
  的 `go build` 仍报 `0.1.0-dev`（实测 `/tmp/s21/cli-plain version` → `melonarc-cli 0.1.0-dev`）。
- **顺手加了一行 `-check` 横幅**：`printSummary` 的第一行现在是 `melonarc-core <version>`。理由
  不是好看，而是它让「注入是否生效」在不启动守护进程的前提下可观测、可测（`TestCheckReports…`），
  也让「哪个构建校验了这份配置」有答案。这是本阶段唯一一处核心输出格式变化。
- 测试：`internal/version` 3 条（单行可打印、可被链接器写、占位符是 0.1.0-dev）、`internal/cli`
  1 条（version 命令报的是同一个变量）、`cmd/melonarc-core` 1 条（-check 报注入值）。

**2. 前端同源：`MELONARC_VERSION`**

- `apps/desktop/scripts/build.mjs` 读 `MELONARC_VERSION`；给出时**只改 `dist/src/version.js`**
  里那一行 `APP_VERSION`（`stampVersion`），源码模块的缺省值一字不动。值先按
  `^[0-9A-Za-z][0-9A-Za-z._+-]*$` 校验——它要进 JS 字符串字面量，也要进 shell 参数。
- 缺省行为与现状完全一致：输出仍是 `melonarc-desktop 0.1.0` / `output` / `files` / `size` 四行，
  产物里 `APP_VERSION` 仍是 `0.1.0`。带变量时多打一行 `version: <v> (MELONARC_VERSION overrides …)`。
- 测试 `test/build.test.mjs`（2 条）：不设变量 → dist 的 `APP_VERSION` 等于源码值、输出里没有
  `MELONARC_VERSION`；设变量 → dist 是注入值、`APP_LICENSE` 不变、**源码文件仍是 `0.1.0`**。
  测试用 `--root` 指向临时目录（readdir/readFile/writeFile 复制，不用 `fs.cp`），不碰真实 `dist/`。
- `test/version.test.mjs` 的三方一致性检查**未改**，仍然通过（源码值没变）。

**3. `scripts/build-release.sh`（POSIX sh，与 `check-interop.sh` 同风格）**

`scripts/build-release.sh <version>` 做三件事，与任务书一致：

- `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X …=<version>"` 出
  `melonarc-core` 与 `melonarc-cli`，打印两者字节数；
- 组 `dist-release/melonarc-<version>-linux-amd64/`：两个二进制 + `melonarc.conf`（示例配置）+
  `LICENSE` + `README.md` + `THIRD-PARTY-NOTICES.md` + `SECURITY.md`；
- 打 `dist-release/melonarc-<version>-linux-amd64.tar.gz` 并打印 sha256（`sha256sum`，没有则
  `shasum -a 256`）。

可重复运行：每次先删自己的 staging 与同名 tar。版本参数先校验（只允许
`[0-9A-Za-z._+-]`、首字符必须是字母数字），因为那个字符串会进被 `rm -rf` 的路径和 `-o` 参数；
`1.0/../x` 与 `-1.0` 都被拒（实测退出码 1，无参数退出码 2）。脚本**自检**：在 linux/x86_64 上
运行构建出的 CLI 并要求它报 `melonarc-cli <version>`，不一致就失败；非 linux 主机跳过这一步
（交叉编译的产物在那台机器上跑不了）。不打 tag、不建 release、不推送。
`/dist-release/` 补进 `.gitignore`（`git check-ignore` 确认命中）。

实测（本机）：`melonarc-core` 16,400,544 B、`melonarc-cli` 6,852,768 B；tar 在最终提交上重跑为
9,765,940 B、`sha256 110cf2f0a370adb69bfa3b59e3402cc75a8136be6cf9cd583ccf1864e9acb423`
（同一棵树前后两次是 9,765,930 / 9,765,928 / 9,765,940 B、三个不同 sha）。**大小与 sha 每次
重跑都会变**：tar 记 mtime、gzip 记时间，脚本注释里写明**不声称**可复现构建——首发若要写校验和，
以实际发布那一次的脚本输出为准。

**4. 示例配置 `examples/melonarc.conf`**

仓库原来没有示例配置。新增一份，随 tar 以 `melonarc.conf` 名字发布（打成 `melonarc.conf`
而不是带 `examples/` 前缀，因为收包的人只想要一个能改的文件）。内容最小可跑：`[General]`
回环 http/socks5 + api-listen + 相对 `data-dir`；一个 `socks5` 出站（口令是
`username=example, password=change-me`）；`select`/`url-test`/`fallback` 各一（成员里用内置
`DIRECT`）；7 条规则以 `FINAL` 收尾；`[Host]` 一条。地址只用文档段（`192.0.2.0/24`、
`198.51.100.0/24`、`203.0.113.0/24`）与 RFC 2606 保留域名，没有任何真实服务器或真实凭据。
**自验**：先在本机构建的核心上 `-check` 通过；再在**发布 tar 里的**核心上对**tar 里的**
配置 `-check` 通过（7 规则 / 1 代理 / 3 组 / 1 host，`-check` 未创建 `melonarc-data`）。

**5. `THIRD-PARTY-NOTICES.md`（仓库根，同时进 tar）**

- **全集怎么来的**：`go list -m all` 在本机不可用（`GOPROXY=off` 下缺 `.info`，阶段 16 已记），
  文件里如实写了这一点，并列出替代办法：`go mod graph`（109 条边）算 MVS + 两个发布二进制的
  `go version -m` 的 `dep` 行（产物里到底有什么，以它为准）+ `go.mod` 的 `require`。三者一致，
  共 **45 个模块**，其中 **17 个进二进制**。
- **许可证怎么核对**：逐个读模块缓存里**该版本自带**的 `LICENSE` / `LICENCE` / `COPYING` /
  `NOTICE` 原文，多许可证文件的（`modernc.org/sqlite`、`modernc.org/libc`、
  `modernc.org/memory`、`klauspost/compress`）逐个点名，不从网页或印象写。
- 结构：① 17 个进二进制的模块（含 `what it does in this product`）；② 28 个只在模块图里的
  模块，逐条写「为什么不进二进制」；③ 驱动带进来的 C（SQLite 3.54.1 公有领域、musl MIT、
  go-netdb/nixpkgs MIT、Go BSD-3，`sqlite-vec` 与 `test_demovfs` **未链接**）；④ 前端一节
  （零 npm 依赖，`package-lock.json` 里没有 `node_modules/` 条目，美术资源原创）；⑤ Rust 一节
  （`tauri-build` 2 / `tauri` 2 / `serde` 1，**本地没有 Cargo.lock 也没有 registry，许可证未核**，
  原文标注「传递依赖待首次联网构建生成 Cargo.lock 后复核」）；⑥ 这个文件不做什么。
- **四个模块核不了**：`davecgh/go-spew`、`pmezard/go-difflib`、`quic-go/qpack`、
  `jordanlewis/gcassert` 在模块缓存里没有副本。表格里写「not verified here — no copy in the
  local module cache」，**不猜**。四个都不进二进制。

### 范围三：公开前检查

**1. `SECURITY.md`**

私密渠道写 GitHub Security Advisories（仓库页 → Security → Report a vulnerability）；若账号用
不了该表单，就开一个**不含任何细节**的公开 issue 请求私密渠道。要求附版本（`-check` 横幅、
`melonarc-cli version`、`/healthz`）、平台、最小复现、**脱敏后的**配置；明说公开 issue 里不要
贴凭据、订阅链接、访问历史，并写明「已贴出的凭据先轮换，删评论不等于撤回」。响应预期按实际写：
个人项目、尽力而为、**不承诺固定时限**，但承诺三件事（确认收到、给出受理/需信息/超范围的决定、
受理则下一预览修并记 DEVLOG）。

**2. 全仓脱敏扫描（工作区 + 全部 50 个可达提交）**

方法：`git grep -n -I -E <pattern> $(git rev-list --all)`（50 个提交、单分支 `master`、无 tag、
无 remote），命中逐条人工复核。结果：

| 检查项 | 命中 | 分类与结论 |
|---|---|---|
| `BEGIN … PRIVATE KEY` 块 | 0 | — |
| `Bearer <16+ 字符>` | 0 | — |
| 带凭据 URL（`://user:pass@`） | 155 处（去重后 24 行） | **文档示例 / 测试夹具**：`ss://method:pass@host:port` 等六种分享链接语法（`internal/share` 注释与 DEVLOG）、`share_test.go`/`fuzz_test.go` 里的 `hy2://user:pass@hy.example.com`、`tuic://<uuid>:secret@tu.example.com`。主机全是 `example.com` 系，名称全是占位值 |
| 带 `token=`/`key=`/`password=` 的 https 链接 | 37 处（去重后 2 行） | **测试夹具**：`https://example.com/sub?token=abc`（订阅解析用例） |
| 私钥文件扩展名（`.pem`/`.key`/`id_rsa`/`.p12`/`.pfx`/`.jks`/`.kdbx`/`.gpg` …） | 0 | 从无此类文件被跟踪 |
| `.env` / `credentials` / `secret` 文件名 | 0 | — |
| `/home/<name>/` | 夹具 home 目录 196 处、本机环境路径 56 处（跨提交计数，按当时的字面量统计） | **测试夹具 + 本机环境路径**：前者是 `paths.test.mjs`/`settings.rs` 的 home 目录夹具；后者是 DEVLOG 与 `docs/interop-testing.md` 里互通二进制的位置。无凭据，但当时确实写了账号名——清单 A7 已处理：文档与日志侧自阶段 24 起改写为 `$HOME`，测试夹具按语义保留 |
| `/Users/<name>/` | macOS 配置目录夹具 34 处（同上，按当时字面量统计） | **测试夹具**（macOS 配置目录用例）；同上，文档侧改写为 `$HOME`，测试代码里的夹具输入按语义保留 |
| `C:\Users\<name>` | `paths.test.mjs` 2 行 | **测试夹具** |
| 非保留段 IPv4 | 历史里 89 个唯一地址，17 个不在保留/文档段 | 全部**夹具或刻意的近邻值**：`1.0.1.x`（geoip mmdb 夹具）、`8.8.8.8`/`1.1.1.1`/`9.9.9.9`（解析器入参，只解析不连接）、`128.0.0.1`（回环判定反例）、`198.51.101.1`/`203.0.114.x`/`2001:db9|dba|dbb`（文档段外一位，证明规则不外溢）、`4.5.1.2` 是 RFC 章节号误报 |
| 全局 IPv6 | 仅 `2001:db8::/32` 与上述近邻、`2606:4700::/32`（ASN 夹具） | 同上 |
| 长 hex / base64（≥32） | 全部是 64 字符 SHA-256 | **测试向量与文档里的校验和**（BLAKE3 known-answer、参考实现二进制哈希） |
| JWT 形状（`eyJ…`） | 0 | — |
| `rules.test`（仓库根的 5 MB 二进制） | 1 个文件 | 阶段 1 遗留的 `go test -c` 产物，**未被跟踪**（`*.test` 在 `.gitignore`），不在提交里 |

**没有发现疑似真凭据或真订阅 URL。** 测试夹具里的假口令（`alice` / `s3cret`，阶段 2 起就在
测试文件里）按夹具登记，不算泄漏。

一处**没做完**：用于找「字面量 `password=<值>`」的那条 `git grep` 被环境拦下（敏感内容审批
超时，输出被扣下），没有结果可分类。按要求不重试、不绕过，记进清单 A6，公开前必须补跑。

**3. `docs/pre-release-checklist.md`**

逐项挂账，每条写「卡住什么、谁能解、怎么解」，分四组：A 转公开前（六个图标资产未随快照推送、
Cargo.lock、CI 三 job 未实跑、私密报告入口未开启、许可证 only/or-later、脱敏扫描两个尾巴、
DEVLOG 里的私人路径）、B 发二进制前（tar 已可产出、第三方许可证**全文**未随包、四个模块许可
未核、Rust 壳未编译、Hysteria2/TUIC 互通未复验）、C 发布目标前（Windows 未实机、五项性能未测、
打包安装未端到端）、D 预览可接受的代价（Flush ~40ms、整表重写、fuzz 只跑限时会话）。

### 范围四：许可证口径差异（**只汇总，不改**）

本阶段**没有改动任何一处许可证文本与元数据字段**。现状差异如下，待所有者决定：

| 文件 | 位置 | 现值 |
|---|---|---|
| `LICENSE` | 全文 | GNU GPL v3 全文（未写 only / or-later） |
| `README.md` | 末节 License | 「GNU General Public License, **version 3**」 |
| `apps/desktop/src-tauri/Cargo.toml` | `[package] license` | `GPL-3.0-or-later` |
| `apps/desktop/package.json` | `license` | `GPL-3.0-or-later` |
| `apps/desktop/src-tauri/tauri.conf.json` | `bundle.license` | `GPL-3.0-or-later` |
| `apps/desktop/src/version.js` | `APP_LICENSE` | `GPL-3.0-or-later` |

六处的差异只有两类：根 LICENSE/README 说「v3」（不限定），四个前端/打包元数据说「or-later」。
选 only 还是 or-later 是版权所有者的决定，不是工程决定；决定后要改的是同一批文件的同一批字段
（清单 A5）。

### 关键决策及理由

1. **新造 `Unusable` 标签，而不是继续用「Known failing」。** 旧标签描述的是「试过，失败」，
   而现在的状态是「修过，但没再试」——两句话对读者的含义完全不同（前者说别用，后者容易被读成
   「快好了」）。标签必须自己把三件事说完，因为有人只看表不看正文。
2. **配置期警告只警告、不拒绝。** 拒绝会让一份订阅里一个坏节点带走整份配置——正是订阅导入
   路径最常见的形态。警告的落点是装配点（`buildDialers` 之后）而不是 `config.Validate`：校验
   层不该知道「哪个协议目前不可信」，那是出站层的事实；而且 `-check` 与测试不该被日志污染。
3. **警告的文案带上「修复已落码、互通未复验」，并且不带口令。** 前者防止读者以为实现缺失，
   后者是因为守护进程的日志会被粘进 issue（`TestUnusableProtocolWarningCarriesNoCredentials`）。
4. **版本做成变量 + 单一包，而不是给两个 main 各留一个 `-X` 目标。** 两处 `-X` 就是两个可以
   各写一半的注入点；一个包 + 一个变量，`status`/`healthz`/`version`/`-check` 不可能互相不一致。
5. **`-check` 加一行横幅。** 这是本阶段唯一的核心输出变化，换来的是「注入生效」可在不启守护
   进程的情况下被断言。风险是有人按行解析 `-check`，但仓库内没有这样的调用方（CI 与测试都用
   `Contains`）。
6. **前端只改 `dist` 的副本，不改源码模块。** `test/version.test.mjs` 拿 `src/version.js` 与
   三个清单比对；让发布版本写进源码，等于让「源码 checkout 自称的版本」随每次发布变化，下一次
   `npm test` 就会在干净 checkout 上红。
7. **发布脚本自己校验版本，并且在 linux 上回读注入值。** 版本字符串会进 `rm -rf` 的路径、
   `-o` 的参数和文件名；回读则是唯一能证明 `-ldflags` 那条路真的通的办法（比读构建元数据稳）。
8. **`THIRD-PARTY-NOTICES.md` 用「进没进二进制」分组，而不是按直接/间接依赖分组。** 许可证
   义务跟的是「分发出去的字节」，不是 `go.mod` 的写法。17 vs 28 的分界就是义务的分界，四个
   核不了许可证的模块正好都在 28 那一侧。
9. **四个没有本地副本的模块写「未核」，不写猜的值。** 任务书要求许可证必须从模块缓存原文
   核对；做不到就明说，并给出补法（联网机器 `go mod download` 后重读）。
10. **`docs/development-doc-v1.md` 只加状态说明段。** 这份文档此前各阶段都是只读；本阶段任务
    书明确要求加说明段，所以加了，但**没有动 §2 的范围条目**——那是目标规格，改了就不是
    「目标 vs 现状」的对照了。
11. **清单里把「本阶段自己留下的两个尾巴」也列成条目**（第三方许可证全文、被拦下的脱敏子检查）。
    清单如果只列别人的活，它就变成了免责声明而不是工作单。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                              通过
go vet ./...                                                通过
gofmt -l .                                                  无输出
go test ./... -count=1 -v                                   1266 条目 / 1245 通过 / 21 跳过 / 0 失败
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
scripts/build-release.sh 0.1.0-preview.1                    通过，产出 tar 并打印 sha256
<h>melonarc-<v>-linux-amd64/melonarc-core -config …/melonarc.conf -check   通过
```

- **逐项对基线**（`96238a1`，1251/1230/21/0）：**条目 +15、通过 +15、跳过 ±0、失败 0**。
  增量拆解：`internal/outbound` +4（unusable 列表与匹配）、`cmd/melonarc-core` +7（警告
  1 父 + 4 子 + 不带凭据 1 + `-check` 版本 1）、`internal/version` +3、`internal/cli` +1。
- **21 条跳过与基线逐名 `diff` 完全一致**（同一份命令输出对比，无新增）。
- **前端**（系统 Node 24.22.1，清代理，`--test-concurrency=1`）：
  **77 条目 / 75 通过 / 2 跳过 / 0 失败**（基线 75 / 73 / 2 / 0；+2 来自 `build.test.mjs`）。
  2 条跳过仍是「需真实核心」的既有用例。`npm run build` 缺省输出与尺寸未变（28 文件 / 208.3 KiB）。
  注：托管 Node 22 在本沙箱跑整套离线套件时，5 条 `bridge-contract` 用例因 undici Wasm
  分配失败（vmemory 上限，阶段 14 起已知的环境瑕疵）红掉——**同一棵树在系统 Node 24 上全绿**，
  与本次改动无关，记录在此以免下次误判为回归。
- **二进制体积**（同机同工具链）：

  | 产物 | 大小 | 相对 |
  |---|---|---|
  | `melonarc-core`（默认构建，未 strip） | 24,301,446 B | 阶段 19 记录的 24,287,933 B **+13,513 B** |
  | `melonarc-core`（发布构建：`-trimpath -s -w`） | 16,400,544 B | **-32.5%** |
  | `melonarc-cli`（默认构建） | 10,186,969 B | 首次测量 |
  | `melonarc-cli`（发布构建） | 6,852,768 B | -32.7% |
  | `…-linux-amd64.tar.gz` | 9,765,940 B | 最终提交上测（每次打包略有出入，见上） |

  +13,513 B 是 `internal/version` + 警告代码 + `-check` 横幅的代价；`-s -w` + `-trimpath`
  把核心从 24.30 MB 压到 16.40 MB，与阶段 19「下一步计划」的预估（-25%~-30%）一致。
- 命名红线：本阶段新增/修改的源码、脚本、文档、配置与六笔提交信息（含本条记录）已按已知清单扫描
  （`clash|surge|quantumult|shadowrocket|stash|loon|kitsunebi|mellow|surfboard|nekobox|v2ray|
  sing-box|mihomo|…`），零命中。新文件里出现的第三方名字都是开源项目（`modernc.org`、
  `quic-go`、`uTLS`、`tauri`、`serde`、SQLite、musl 等），不涉及红线。
- 提交（本地，未推送，每笔单独 checkout 都绿）：
  `54badd4`（矩阵统一 + 配置期警告）→ `974f9f2`（版本注入 + 前端同源）→
  `5139668`（THIRD-PARTY-NOTICES + SECURITY + README 许可指向）→
  `4de221f`（发布脚本 + 示例配置 + gitignore）→ `6932b65`（公开前清单）→ 本条目。

### 遗留问题

- **第三方许可证全文未随 tar。** `THIRD-PARTY-NOTICES.md` 列了组件、版本与许可证名，但 tar 里
  只有项目自己的 `LICENSE` 与这份声明。GPLv3 §6 关于「随二进制提供声明」的具体做法需要所有者
  拍板（补全文，或在发布说明里给源码获取方式）——清单 B2。
- **四个模块的许可证未核**（没有本地副本，均不进二进制）——清单 B3。
- **脱敏扫描有一条子检查被环境拦下**（字面量 `password=<值>`），公开前必须补跑——清单 A6。
- **DEVLOG 与 `docs/interop-testing.md` 里有本机账号路径**（阶段 24 起统一写作
  `$HOME/interop-bin`），`paths.test.mjs` 等夹具里有 Linux / macOS 两套 fixture home。
  不是凭据，但当时确实写了账号名；清单 A7 由所有者定「文档与日志改写为 `$HOME`、
  测试夹具按语义保留」，阶段 24 落地。
- **CI 仍未实跑**，且阶段 20 留下的 `TestInteropQUICFixtureReachesSendtoBoundary` 在宽松
  runner 上会把 interop job 判红；本阶段按任务书**未动**（改名与判定口径都属明确排除项）。
- **前端同源只是预备**：本阶段 tar 不含桌面包，`MELONARC_VERSION` 在真实打包链里还没跑过。
- 阶段 8–20 的既有挂账照旧：Windows 实机、Rust 壳编译、QUIC/UDP 真实互通、REALITY UDP 证据、
  预览桥 query string、`core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、枯竭计数的对外出口、
  Flush 成本与整表重写。

### 下一步计划

1. 让所有者处理清单 A 组：推图标资产、开私密报告入口、定 only/or-later、补跑那条被拦下的扫描。
2. 在能出网的机器上跑一次 CI（先补 Snell 两个仓库变量、核对三个资产 glob），并决定
   `TestInteropQUICFixtureReachesSendtoBoundary` 的去留。
3. 在允许 UDP 的环境复验 Hysteria2 / TUIC，通过后才把 README 那两行从「Unusable」移走。
4. 补第三方许可证全文进 tar（或在发布说明给源码获取方式），并把四个未核模块补上。
5. 桌面包：联网生成 `Cargo.lock`、`cargo build --release --locked`、把 `MELONARC_VERSION`
   接进真实打包链，然后按清单 B4/C3 验收。

---

## 阶段 22 — GPT 决策收尾批：枯竭计数对外出口、夹具改名、解析期静态校验（2026-11-15）

范围：三项已定案决策的落地。决策原文在仓库外
`~/workspace/projects/melonarc-gpt-answers-20261115.md`（可回读）：① `/v1/inbound` 加可选字段
`fake_ip_pool_exhausted_queries_total`（选 a）；② 两条 `TestInteropQUICFixture*` 改名
`TestQUICFixture*`（选 a）；③ `share.Parse` 与 `outbound.New` 共用静态参数校验、混合订阅采用
有效节点（选 b）。硬约束逐条照办：**只本地提交，没有 push、没有改仓库可见性、没有打 tag**；
命名红线照旧；**许可证 only vs or-later 仍是所有者待决事项，本阶段没有碰任何许可证文本与
元数据文件**——`LICENSE`、`README.md` 的许可段、`apps/desktop/package.json`、
`src-tauri/Cargo.toml`、`tauri.conf.json`、`src/version.js` 全部未改。`spikes/` 未动，
`docs/development-doc-v1.md` 未动。

开工前：`HEAD = 6ab0a4b`，工作区干净。按任务书先读 `DEVLOG.md` 与
`docs/development-doc-v1.md`（后者是 v1 目标规格，头部状态说明要求当前状态以 README 支持矩阵
为准）。阶段 21 末状态核对：Go 1266 条目 / 1245 过 / 21 跳 / 0 败，前端离线 77 条目 /
75 过 / 2 跳 / 0 败、实时 77/77。本机重跑确认：`go build ./...`、`go vet ./...`、
`gofmt -l .` 全过，`go test ./... -count=1 -v` 1266 条目 / 21 跳 / 0 败，21 条跳过与阶段 20
记录的集合逐名一致。基线输出存 `/tmp/s22-baseline-v.txt`（仓库外的临时证据）。

### 任务一：`/v1/inbound` 暴露 fake-IP 枯竭计数（选 a）

- `internal/api/views.go`：`InboundView` 新增
  `FakeIPPoolExhaustedQueriesTotal uint64`，JSON 名
  `fake_ip_pool_exhausted_queries_total`，**不带 `omitempty`**——零次也发 `0`。语义是「因
  fake-IP 池满而回 SERVFAIL 的 DNS 查询累计次数」。
- `cmd/melonarc-core/state.go`：把 `snap.NameAddressExhausted` 映到该字段。顺手把
  snapshot → view 的转换抽成纯函数 `inboundView(snap inbound.Snapshot)`：本机没有真 TUN 设备，
  真进程里跑不出「池满」这一态，纯函数才能让测试把手写的非 0 快照喂进去。
  `internal/inbound/metrics.go` 只改注释——原注释写着「刻意不进 /v1 视图，契约已冻结」，
  现在改成「日志一行 + /v1 字段」两个出口；计数器本身一字未动。
- `internal/cli/cli.go`：`describeInbound` 一行尾部追加 `, %d fake-IP pool exhausted`，
  零也打印，不新增命令、不新增支持矩阵文案。
- GUI **已有**入站统计展示位（`apps/desktop/src/panels/connections.js` 的四个 stat tile），
  所以按要求同步加第五个 tile，两个语言包各加一个键
  `connections.totals.fake_ip_exhausted`（zh「假地址池耗尽」/ en「Fake-address pool
  exhausted」）。**没有新造页面**。tile 写 `?? 0`：旧核心不送这个键时
  `formatNumber(undefined)` 会画成「—」，而契约要求按 0 处理。
- 兼容与测试：Go 侧 `encoding/json` 缺键即零值，`TestInboundViewReadsAnOlderCore` 用一份
  不含字段的旧响应解码断言 0；`TestInboundPoolCounterIsAlwaysPresent` 钉住零态仍发字段；
  `TestInboundEndpoint` 改成非零 4 并断言 JSON 名。CLI 侧
  `TestStatusShowsTheExhaustedPoolCounter` 用两份手写 JSON（新核心 / 旧核心）各跑文本与
  `-json` 两种输出，断言 4 / 0 且退出码 0；`TestDescribeInboundAlwaysNamesThePool` 钉住零态
  文案。`cmd/melonarc-core` 新增 `TestInboundViewCarriesThePoolCounter`（0 与 6 两态 + 其它
  计数器不丢），并在既有的 `TestAPIShowsInboundMetricsAndFailures` 加一条真 daemon 的 0 态断言。
  GUI 侧 `test/panels.test.mjs` 加两条用例（有键 1234 → 「1,234」、无键 → 「0」），用
  fake DOM 直接读 tile 的数字；`test/live-core.test.mjs` 加一条真核心断言。
  **真进程实测**：挂临时演示核心后 `/v1/inbound` 输出含
  `"fake_ip_pool_exhausted_queries_total":0`。

### 任务二：夹具用例改名（选 a）

- `internal/outbound/interop_quic_test.go`：
  `TestInteropQUICFixtureInjectsTrustAtConstruction` →
  `TestQUICFixtureInjectsTrustAtConstruction`，
  `TestInteropQUICFixtureReachesSendtoBoundary` →
  `TestQUICFixtureReachesSendtoBoundary`，两条都**保留在常规 `go test ./...` 里**。文件头补了
  一段说明为什么不带 `TestInterop` 前缀：判定门把 `TestInterop*` 的 Skip 当成「这次没验证」，
  而这两条在任何装了 TLS 栈的机器上都能跑，不该有能力把一个真正的互通结论弄错。
- `scripts/check-interop.sh` **一字未改**（`git diff` 为空），真正与参考实现通信的
  `TestInterop*` 继续执行「设置参考目录后，任何 Skip 都失败」。
- 现行文档同步改净：`docs/interop-testing.md` §8 第 2 条从「冲突未解、只记账」改写成改名后的
  判定说明；`docs/pre-release-checklist.md` A3 原本写「预计两处修复」，现在写明第二处已由
  改名消掉、资产 glob 仍需首跑核对。全仓 grep 旧名：代码 / 脚本 / 现行文档零命中；只剩
  DEVLOG 历史条目与 `.workbuddy/memory/` 的私有记忆（不跟踪、被 `.gitignore` 命中），
  按任务书「历史记录不改」保留，新条目在此注明改名即可。
- `go test ./internal/outbound/ -run TestQUICFixture -v`：两条父用例 PASS（各带 2 个子用例），
  都不在 21 条跳过集合里。

### 任务三：解析期静态校验（选 b）

- **`internal/outbound/validate.go`（新）**：`Validate(spec)` = 清掉 `Name` 后调 `New(spec)`、
  丢弃拨号器（QUIC 的 `Disown`）、只回 error。理由见「关键决策」1：不在 share 里复制一份规则
  表，也不把每个构造函数拆成两半；唯一能保证两端永不漂移的做法，是让共用校验真的调用同一段
  构建代码。构造阶段只读 options，不开 socket、不起 goroutine；一个本构建未实现的类型在这里
  也**不是**错误，与 `New` 返回 `Unsupported` 的语义一致。
- **`internal/share/share.go`**：`Parse` 在 switch 之后统一调 `validateStaticParameters`，六种链接
  都过这一关；单条链接的非法静态参数（`ss://aes-999:…`）现在 Parse 直接报错。
  `registryReason` 去掉 `typ: ` / `outbound: invalid proxy option: ` 这些前缀，让 reason 保持本包
  的措辞风格且不重复协议名；`Error` 增加私有 `cause` + `Unwrap()`，只供
  `errors.Is(err, outbound.ErrInvalidOption)` 分类，`Error()` 永不渲染 cause。**对外契约不变**：
  错误仍只带 `Scheme` + `Reason`，绝不回显链接（新用例逐条断言假口令没出现在错误里）。
- **`ParseAll` 签名改为 `([]config.Proxy, []Rejection)`**：不再把拒绝塞进一个 joined error。
  `Rejection{Item, Reason}` 带 1-based 位置。理由：订阅要按条目报告，joined error 的文本不能被
  结构化消费；同时保留「部分结果」语义，由调用方决定一份部分可用的列表算不算成功。
- **契约方向反转（任务书要求写明）**：原契约是「能解析必能构建」——`TestParseBuildsEveryLink`
  在 Parse 之后手工调 `outbound.New` 兜底，防的是解析器吐出一个建不起来的节点。现在 Parse
  自己就跑构建期的静态校验，那个蕴含由**构造**保证、再测就是同义反复；契约反过来变成
  「构建会拒的，解析期就拒」，失败面从启动期前移到导入期。测试随之重命名为
  `TestParseAndBuildAgreeOnStaticParameters` 并重写说明（每个通过夹具同时断言
  `Validate` 与 `New`），新增 `TestParseRejectsInvalidStaticParameters` 逐协议断言 reason 是
  registry 的措辞且保留 `ErrInvalidOption` 因由；`fuzz_test.go` 的注释同步改掉（原注释写
  「构建拨号器是更强的契约，fuzz 里不做以省预算」，现在 Parse 已经做了）。包注释从「两条规则」
  改成三条，把这条写进去。
- **六种链接各一条非法静态参数**：ss 未知套件 `aes-999`、vmess `scy=rc4`、vless Vision flow、
  trojan `sni=bad_host`、hysteria2 `obfs=salamander` 缺 `obfs-password`、tuic `sni=bad_host`。
  Trojan / TUIC 的静态参数面除必填口令外只有共享 TLS 键，所以这两条用 SNI——那是它们的
  builder 真正校验的东西，不是凑数。**Snell / SOCKS5 / HTTP 在 v1 没有分享链接拼法**
  （`snell://` 会先被 `unsupported link type` 拒），因此它们的校验在
  `TestValidateRejectsProtocolsWithoutALinkSpelling` 里从 `outbound.Validate` 这一侧验：
  snell 的 version / cipher、SOCKS5 与 HTTP 的半对凭据；再加
  `TestValidateAcceptsTheSameSpecNewAccepts` 钉住通过方向两端一致。
- **`internal/subscription/subscription.go`**：`parseBody` 改签名
  `([]config.Proxy, []Skip, error)`。混合体返回有效节点 + 每条跳过的原因，**error 只在没有任何
  可用节点时非 nil**（空 body 仍是 `ErrEmpty`；全坏是新的 `ErrEmpty`：「all N links … were
  rejected」）。`refresh` 成功路径写缓存、把 skips 记进 `state.skipped`、INFO 行带
  `nodes` / `skipped`；失败路径原样走「保留上次结果 → 读缓存 → 都没有就返回错误」，所以全坏
  刷新**不覆盖缓存**。`reportSkips` 每条打一条 warn（带 item 与 reason），超过 8 条改成一条计数
  行以避免一份千行坏订阅刷屏，完整列表仍在 `Status.Skipped`（新增字段，`Snapshot` 返回副本）。
  理由：一份订阅里混着坏节点是最常见的形态，一个坏节点不该带走整份；但一份全坏的东西也
  不能把在跑的节点换成空列表。
- 测试：混合体保留有效节点 / 逐条原因与日志 / 全坏保留旧节点并退避 / 全坏回退缓存且缓存字节
  不变 / 首次导入全坏报错且没有节点被合并 / parseBody 全坏仍是 `ErrEmpty`；
  `FuzzParseBody` 同步改成三返回值并校验 skip 的形状。

### 关键决策及理由

1. **`Validate` 直接调 `New`，而不是把校验逻辑复制进 share，也不是把九个构造函数拆成
   「解析 options」+「构造」两半。** 两处各自的规则表就是两份会漂移的表；拆构造函数则要动
   九个文件、给每个协议新增一个导出函数，收益只是避免一次没有 I/O 的对象构造。让共用校验
   真的走同一段构建代码，是这三者里唯一从结构上排除漂移的做法。
2. **字段不带 `omitempty`，零也发。** 「池没满过」和「这个核心不会数」对读数是同一件事，
   客户端不该靠缺键来判断版本；反过来，旧核心缺键时 Go 侧零值、CLI 打 0、GUI `?? 0`，
   三条路都按 0 处理且不报错。
3. **快照转换抽成纯函数 `inboundView`。** 非 0 态需要一个真 TUN 设备和饱和的租约表，本机
   `TestTUNLinuxLoopback` 因缺 `CAP_NET_ADMIN` 跳过；把映射做成纯函数，是让这一态在本机
   也可被断言而不伪造进程状态的唯一低成本办法。
4. **改名不改判定口径。** `scripts/check-interop.sh` 把 Skip 当失败是对的——对真正与参考实现
   通信的用例，Skip 就是「这次没验证」。错的只是把一条不需要参考实现的夹具用例算进那扇门。
   改名只移动用例的归属，严格规则、脚本、七个槽位都未动。
5. **`ParseAll` 变成结构化的拒绝列表，而不是继续返回 joined error。** 「采用有效节点 + 按条目
   报告原因」要求调用方能拿到位置与原因；字符串解析既脆弱也会把链接带进日志。
6. **契约方向反转后把「反向」写进测试。** Parse 调了构建期校验之后，「能解析必能构建」是
   构造性成立的同义反复；真正需要守的是反方向：构建会拒的参数，Parse 必须也拒，并且 reason
   得是 registry 的措辞（否则说明有人又在 share 里复制了一份规则）。
7. **订阅只在「一个可用节点都没有」时判失败。** 部分可用就替换成部分列表是可用的；全部不可用
   还替换，等于把正在路由的组清空。失败路径不写缓存，是「保留上次有效结果与缓存」的落点。
8. **跳过原因逐条打 warn，但日志有上限 8 条、完整列表进 `Status.Skipped`。** 日志既要能查
   「第几条为什么坏」，也不能被一份坏订阅刷爆；结构化状态留给以后接 /v1 用，本阶段不新造端点。
9. **GUI 用已有的 connections 面板，不新造页面。** 任务书明确「没有则在 DEVLOG 注明留待后续」；
   这里有现成的入站统计位，加一个 tile 和一对 locale 键就是最小改动，且不碰壳、不碰令牌路径。
10. **许可证口径只挂账、不改。** only / or-later 是版权所有者的决定，不是工程决定；清单 A5
    与阶段 21 的汇总表保持原样，本阶段连 `README.md` 的许可段都没碰。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                              通过
go vet ./...                                                通过
gofmt -l .                                                  无输出
go test ./... -count=1 -v                                    1292 条目 / 1271 通过 / 21 跳过 / 0 失败
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
go test ./internal/outbound/ -run TestQUICFixture -v          2 条 PASS（各 2 个子用例），无 Skip
```

- **逐项对基线**（`6ab0a4b`，1266/1245/21/0）：**条目 +26、通过 +26、跳过 ±0、失败 0**。
  按 `=== RUN` 名单逐行拆：`internal/api` +2、`internal/cli` +4（2 条新用例，其中 1 条带
  2 个子用例）、`cmd/melonarc-core` +1、`internal/share` 净 +13
  （新契约/非法参数/无链接拼法三族共 13 行；原 `TestParseBuildsEveryLink` 的 13 行整体
  改名，净 0）、`internal/subscription` 净 +6（7 条新用例减去删掉的
  `TestParseBodyReportsABadLink`）、两条 QUIC 夹具用例改名的 6 行同名替换净 0。
  `TestSOCKS5Connect/<随机端口>` 两行在两次 -v 输出里名字不同，是端口夹具而非用例增删。
- **21 条跳过与基线逐名 `diff` 完全一致**（`comm` 比对 `--- SKIP` 名单，输出 IDENTICAL），
  改名后的 `TestQUICFixture*` 都在通过侧。
- **前端**（系统 Node 24.22.1，清代理，`--test-concurrency=1`）：离线
  **79 条目 / 77 通过 / 2 跳过 / 0 失败**（基线 77/75/2/0，+2 条来自 `panels.test.mjs`）；
  实时（挂 `/tmp/s22-live/demo.conf` 起的真核心 + 真实令牌文件，
  `MELONARC_TEST_API` / `MELONARC_TEST_DATA_DIR`）：**79 / 79 / 0 / 0**（基线 77/77）。
  实时核心用的是 17890/17891 两个空闲入站端口：7890/7891 被上一阶段留下的演示核心占着，
  没有动那个进程。两条跳过的实时用例在真核心上都跑了。`npm run build` 未改源码模块，
  三方一致性检查仍通过。
- 命名红线：本阶段新增/修改的源码、注释、文档、配置与四笔提交信息按阶段 21 条目里记录的
  同一份已知清单扫描**零命中**（这里不复写清单本身，避免把被禁名称再抄一遍）；新出现的
  第三方名字都是公开协议名或开源项目。许可证文本与元数据文件在
  `git diff --name-only` 里零命中。
- 提交（本地，未推送）：`aa9862f`（任务一）→ `0a695eb`（任务二）→
  `b8cad6a`（任务三）→ 本条目。前三笔各用干净的临时 `git worktree` 单独 checkout，
  逐笔跑 `go build ./...` / `go vet ./...` / `go test ./... -count=1`，
  每笔都是 17 个包 `ok`、0 失败。没有 push、没有 tag、没有改可见性。

### 遗留问题

- **许可证 only vs or-later 仍待所有者**（清单 A5）；阶段 22 按任务书一字未动。
- **枯竭计数的非零态只有映射层与传输层证据**：`inboundView` 的手写快照 + fakeProvider 的
  API 用例 + GUI 的数字用例。要让真进程把池跑满仍需真 TUN 与饱和租约表
  （`TestTUNLinuxLoopback` 因缺 `CAP_NET_ADMIN` 仍是 21 条跳过之一）。
- **`Status.Skipped` 与逐条 warn 没有 /v1 出口**：契约冻结，本阶段不新造端点；要让 GUI 看到
  「第几条为什么被跳过」得等下一次 API 决策。
- **第五个 GUI tile 未在真窗口里目视验收**：证据是 fake DOM 面板用例与真核心的应答；
  Rust 壳至今只交付源码（清单 B4）。
- **CI 仍未实跑**；A3 里「第二个预期修复」已由改名消掉，但三个资产 glob 从未联网核对过
  404。`TestQUICFixtureReachesSendtoBoundary` 在允许 `sendto` 的 runner 上仍会 `t.Skip`
  ——只是现在它属于常规套件，不再让 interop job 判红；严格门本身没有放宽。
- 阶段 8–21 的既有挂账照旧：Windows 实机、Rust 壳编译、QUIC/UDP 真实互通、REALITY UDP
  证据、预览桥 query string、`core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、
  Flush 成本与整表重写、第三方许可证全文与四个未核模块、脱敏扫描被拦下的那条子检查。

### 下一步计划

1. 等所有者定 only / or-later 后统一六处字段；再按清单 A 处理图标资产、私密报告入口、
   被拦下的脱敏子检查。
2. 在能出网的机器上首跑 CI：核对三个资产 glob 与 Snell 两个仓库变量；改名后 interop job
   的判定面已经收窄到真正与参考实现通信的用例。
3. 在允许真 TUN 的环境验一次枯竭计数的非零端到端（池满 → SERVFAIL → `/v1/inbound` → GUI
   tile）；本机 `TestTUNLinuxLoopback` 仍是跳过态。
4. 决定 `Status.Skipped` 要不要有 `/v1` 出口（若要，先定分页与保留窗口），让 GUI 能展示
   每条订阅节点的跳过理由。
5. 桌面包：联网生成 `Cargo.lock`、真窗口里目视验第五个 tile、把 `MELONARC_VERSION` 接进
   真实打包链，再按清单 B4/C3 验收。

## 阶段 23 — 许可证口径统一：全仓 GPL-3.0-only（2026-11-15）

范围：小批次，只统一许可证口径的**元数据字段与文档状态**，不动产品行为、Go 代码、构建脚本
逻辑与根许可证正文。硬约束：只本地提交，**没有 push、没有改仓库可见性、没有打 tag**；
`spikes/` 只读，`docs/development-doc-v1.md` 未动。开工前 `HEAD = 8d4092e`、工作区干净；
按任务书先读 `DEVLOG.md` 阶段 21「范围四：许可证口径差异」表（六处现值）、阶段 22 条目
（写明 only / or-later 仍是所有者待决事项、该阶段一字未碰）与 `docs/pre-release-checklist.md`
A5（**owner decision**，写着「pick one and make the other five places say it」）。

### 决策与边界

版权所有者已于 **2026-11-15 本人定夺：全仓统一为 `GPL-3.0-only`**。根 `LICENSE` 是 GPLv3
全文、README 的 License 节写「GNU General Public License, version 3」，两者都属 only 口径，
按任务书**保持原样、全文不动**；`LICENSE` 正文里两处「or any later version」是 GPLv3 标准
条款文字（解释版本号机制），不是本项目的授权声明，同样不动。四处前端/打包元数据统一改为
SPDX 写法 `GPL-3.0-only`。`.workbuddy/` 私有记忆不算产品文件、不碰；`apps/desktop/dist`
是 gitignore 的构建产物，不手改（测试构建时自然刷新）。

### 全仓 grep 逐处核对（`or-later` 及变体）

开工前对全部 git 跟踪文件跑 `or[- ]?later`、`any later version`、`GPLv3+`、`GPL-3.0+`、
`either version 3` 的并集扫描，现行文件共 **7 处命中**，逐处处理如下：

| # | 文件 | 位置 | 处理 |
|---|---|---|---|
| 1 | `apps/desktop/src-tauri/Cargo.toml` | `[package] license` | `GPL-3.0-or-later` → `GPL-3.0-only` |
| 2 | `apps/desktop/package.json` | `license` | 同上 |
| 3 | `apps/desktop/package-lock.json` | `packages[""].license`（镜像 package.json） | 同上，保持一致 |
| 4 | `apps/desktop/src-tauri/tauri.conf.json` | `bundle.license` | 同上 |
| 5 | `apps/desktop/src/version.js` | `APP_LICENSE` | 同上 |
| 6 | `apps/desktop/test/build.test.mjs` | 第 100 行写死 `APP_LICENSE` 的断言 | 正则同步改为 `GPL-3\.0-only`，否则构建用例必红 |
| 7 | `docs/pre-release-checklist.md` | A5 标题里的 `-or-later` 与状态 | 标题改为「Licence scope: `GPL-3.0-only` (decision closed)」，状态 `owner decision` → `ready (resolved)` |

第 6 处是任务书点名的连带项：`build.test.mjs` 用 scratch root 复制 `src/version.js` 后断言
dist 里的 `APP_LICENSE` 字面量，源码一改断言必须跟着改。第 3 处（lockfile 镜像）与第 7 处
（清单标题里的 `-or-later` 表述）是本次额外发现并一并改齐的现行文件。改完后**现行产品
文件里 `or-later` 零命中**；仅剩的两类保留项是 `DEVLOG.md` 历史条目 13 处（记录当时状态，
任务书明确不改）与根 `LICENSE` 正文 2 处（GPLv3 标准条款，任务书明确不动）。

逐处核对后**判定不改**的相邻表述（都不是 or-later、与 only 不冲突）：README License 节只有
「version 3」；`apps/desktop/locales/{en,zh-CN}.json` 的 `settings.about.license` 是
「Released under the GPLv3 license」/「按 GPLv3 许可证发布」；`docs/development-doc-v1.md`
的「GPLv3」；`app-smoke-run.mjs` / `panels.test.mjs` 里 about 块的 `/GPLv3/` 断言来自上述
locale 文案、不读 `APP_LICENSE`，因此不受本阶段影响；`version.test.mjs` 的三方一致性检查
（`pkg.license`、`tauri.bundle.license` 对 `APP_LICENSE`）随四处同改继续通过。

### 清单 A5 关闭

`docs/pre-release-checklist.md` A5 从 **owner decision** 改为 **ready (resolved)**（沿用 D 组
`ready (accepted)` / `ready (noted)` 的带括号状态写法，没有新增状态词），正文注明所有者
2026-11-15 定夺 GPL-3.0-only、四处元数据已改齐、`package-lock.json` 与构建断言同步、
阶段 21 差异表就此关闭，并指向本条目。README 的 License 节按任务书第 3 条**一字未动**。

### 验证

```
go build ./...                                     通过（go1.27.4，Go 侧零代码改动）
前端离线（系统 Node 24.22.1，清代理，--test-concurrency=1）
                                                    79 条目 / 77 通过 / 2 跳过 / 0 失败
前端实时（真核心 + 真实令牌文件）                  79 条目 / 79 通过 / 0 跳过 / 0 失败
node scripts/build.mjs                             通过，28 文件 / 208.8 KiB
全仓 git grep 复核                                现行产品文件零 or-later
```

- 离线与实时**均与阶段 22 基线持平**（79/77/2/0 与 79/79/0/0），没有回退。离线 2 条跳过
  仍是 `live-core.test.mjs` 的两条，实时下在真核心上全部跑过。
- 实时装置：临时目录 `/tmp/s23-live/`（仓库外），`go build` 出核心、`-check` 通过后后台起
  真核心、带令牌轮询 `/healthz` 到 `{"status":"ok",...}`，再带 `MELONARC_TEST_API=127.0.0.1:7946`
  与 `MELONARC_TEST_DATA_DIR=/tmp/s23-live/data` 跑同一套；入站用 17890/17891 两个空闲端口，
  **没有动** 7890/7891 上阶段 21 留下的演示核心（pid 5058），核心在用例结束后已停。
- `apps/desktop/dist` 由 `node scripts/build.mjs` 自然刷新，回读 `dist/src/version.js` 的
  `APP_LICENSE` 已是 `GPL-3.0-only`；该目录仍被 `apps/desktop/.gitignore` 忽略，未进提交。
- `git status --porcelain`：7 个修改文件全部在上表范围内，**无本任务之外的意外改动**；
  加上本条目共 8 个文件进提交。命名红线：本阶段只写 SPDX 字符串、清单与文档文案，未引入
  任何新第三方名称。

### 遗留问题

- **清单 A5 已关闭**，但 LICENSE 正文与 README 仍是「GPLv3 / version 3」的自然语言口径，
  没有写机器可读的 `GPL-3.0-only` SPDX 字样——这是任务书要求保持的状态；若发布环节需要
  在打包元数据之外再补一处显式声明，需所有者另定，不属本阶段范围。
- 阶段 8–22 的既有挂账照旧：A1 图标资产、A2 `Cargo.lock`、A3 CI 首跑、A4 私密报告入口、
  A6 脱敏子检查、A7 私有路径、B2 第三方许可证全文、B3 四个未核模块、B4 Rust 壳未编译、
  B5 QUIC/UDP 真实互通、C1 Windows 实机、C2 性能实测、C3 端到端安装、真 TUN 枯竭计数
  非零态、`Status.Skipped` 的 `/v1` 出口、第五个 GUI tile 的真窗口目视验收。
- 本阶段未新增功能性缺陷；许可证口径差异不再是公开前挂账项。

### 下一步计划

1. 按清单 A 剩余项推进（A1 图标资产、A4 私密报告入口、A6 脱敏子检查、A7 私有路径），
   A2/A3 等一台能出网的机器首跑 CI 并生成 `Cargo.lock`。
2. 二进制发布前处理 B2（第三方许可证全文或源码获取方式）与 B3（四个未核模块）。
3. 沿用阶段 22 的下一步 3/4/5：允许真 TUN 的环境验枯竭计数端到端、`Status.Skipped`
   出口决策、桌面包 `MELONARC_VERSION` 接进真实打包链与 B4/C3 验收。

---

## 阶段 24 — 公开前收尾批：许可证全文随包、脱敏补扫、四模块补核、发布说明草稿（2026-11-16）

范围：四件事——B2 把 17 个进二进制模块的许可证全文收进发布 tar（用户已定「随包附全文」）、
A6(b) 补跑阶段 21 被环境拦下的口令字面量赋值子检查、B3 补核四个 `not verified` 模块、
写一份**不发布**的发布说明草稿。任务五（A7 本机路径改写）按任务书在前四项完成后单独一笔
提交，见本条目后的「任务五补记」。本批不动产品行为：Go/前端源码零改动，改的是构建脚本、
台账、清单、文档。

开工前：`HEAD = 580a770`（阶段 23），工作区干净，`git rev-list --all` 为 **58 笔**
（阶段 21 记的 50 笔之后又多了 8 笔），单分支 `master`、无 tag、无 remote。按任务书先读
`DEVLOG.md`（重点阶段 21「范围二·发布工程」「范围三·全仓脱敏扫描」、阶段 23 条目）与
`docs/pre-release-checklist.md`；按工程约定同时读了 `docs/development-doc-v1.md`（v1 目标
规格，头部状态说明要求当前状态以 README 支持矩阵为准）。基线：Go **1292 条目 / 1271 过 /
21 跳 / 0 败**，前端离线 **79 / 77 / 2 / 0**、实时 **79 / 79 / 0 / 0**。

硬约束逐条照办：**只本地提交，没有 push、没有改仓库可见性、没有打 tag、没有生成正式
release**；`spikes/` 未动；许可证口径文件（根 `LICENSE`、`apps/desktop/package.json`、
`src-tauri/Cargo.toml`、`tauri.conf.json`、`src/version.js` 的 `GPL-3.0-only`）**一字未动**；
命名红线照旧。

### 任务一：B2 —— 17 个模块的许可证全文随 tar（用户已定）

**改动 `scripts/build-release.sh`**（第 3 步新增，前两步逻辑未动）：

- **模块集合不写死在另一份清单里**：对刚构建出的 `melonarc-core` 跑 `go version -m`，
  取其 `dep` 行（`模块@版本`，本机实测恰好 17 行，与 `THIRD-PARTY-NOTICES.md` §1 的 17 行
  表格逐行一致）；再用 awk 从该文件的 §1 表格读出同一集合，`sort` 后 `cmp -s` 比对——
  **不一致或条数不是 17 就 `die`**。台账是索引，产物是事实，两边不许各自漂移。
- **全文来源只认本机模块缓存**：`GOPROXY=off GOSUMDB=off go mod download -json <模块@版本>`
  取 `Dir`（缓存外就失败，绝不联网取文本），再 `find` 该目录根层的所有
  `LICENSE*` / `LICENCE*` / `COPYING*` / `NOTICE*` 文件；**逐个 `[ -s ]` 核对存在且非空**，
  任一不满足即失败。
- **每模块一个文件**：落到 `licenses/<模块>@<版本>.txt`（模块路径里的 `/` 写成 `_`），
  文件头列出模块、缓存路径与所含文件数，随后每节以 `===== 原文件名 =====` 起头，
  节内是**逐字节原样** `cat` 的许可证正文；分隔行是脚本加的元数据，不混进正文。
  多许可证文件的模块（libc 2 个、memory 4 个、sqlite 4 个）全部收进同一份 bundle。
- 打包仍用原来的 `tar -czf … -C "$out" "$name"`，`licenses/` 作为 staging 子目录自然入包；
  脚本注释与「做什么」清单同步改，`GOPROXY=off` 这条写进注释。

**`THIRD-PARTY-NOTICES.md` 保持索引角色**：§6 第一条从「不复制全文、全文是首发前置条件」
改写为「本文件是索引；全文在包内 `licenses/`，命名规则、逐字节来源与脚本名一并写明」；
§1 的 17 行表格**一字未改**（脚本要读它）。清单 B2 从 `blocked` 改 **ready** 并写明做法。

**实跑证据（同一次会话内、同一棵树前后对比）**：

| 项 | 改动前（干净 HEAD 580a770） | 改动后 |
|---|---|---|
| tar 清单 | 8 条（1 目录 + 7 文件） | **26 条**（多 `licenses/` 1 条 + 17 个 bundle） |
| tar 体积 | 9,768,766 B | **9,795,437 B（+26,671 B）** |
| 许可证 | 0 | **17 bundle / 24 个许可证文件** |
| 二进制 | core 16,404,640 B、cli 6,852,768 B | 完全相同 |

- 清单 `diff` 只多出 `licenses/` 目录与 17 个文件，其余 8 条逐字不变。
- **逐字节校验**：解包到 `/tmp/s24-unpack/` 后逐 bundle 解析 `===== … =====` 分节，
  与模块缓存里同名原文件比较，24 节全部 `byte-identical`，`problems: []`；17 个文件名
  都与 `<模块>@<版本>.txt` 规则一致。
- **沿用阶段 21 验收配方**：解包后的核心对**包内** `melonarc.conf` 跑 `-check`，首行
  `melonarc-core 0.1.0-preview.1`，7 规则 / 1 代理 / 3 组 / 1 host 全部读对，且没有创建
  `melonarc-data`；`melonarc-cli version` 回报 `melonarc-cli 0.1.0-preview.1`。
- 脚本自身在 linux/x86_64 上仍有 CLI 版本回读自检；`rm -rf` 的路径仍只来自白名单版本串。
  **不声称可复现**：tar/gzip 记时间，同树重跑的字节数与 sha 会小幅变化（阶段 21 已记）。

### 任务二：A6(b) —— 阶段 21 被拦下的口令字面量赋值子检查补跑

**目标模式**：键名 + 等号 + 一个非空字面量值的口令赋值形态（阶段 21 记作「字面量赋值子检查」）。
**范围**：`git grep -n -I -E` 跑全部 **58 个可达提交**（54 笔有命中，历史 2,215 行），
外加**工作区**全部文本文件（跟踪文件 54 行 + 全量遍历 74 行；后者含 tar staging 里的示例
配置副本，以及大小写不敏感扫到的驼峰式口令字段变量赋值）。合计 2,343 条记录，去重后
**73 条 (路径, 行文本)** 逐条分类。

**环境的两次表现**：首轮按阶段 21 的口径输出全明细，报告文件被环境的敏感内容审批拦下
（「审批超时、输出被扣下」，与阶段 21 同一现象）。**没有重试被扣下的那份输出、没有重建
其内容**；改为只输出计数、分类、路径、值形状（长度/字符类/sha 前缀）与**脱敏行**的口径
重跑，扫描覆盖与分类完整，报告落在仓库外 `/tmp`。这是本阶段能补出结论的关键：脱敏扫描
本来就不该把口令字面量打印出来。

**分类表**（去重行 / 原始命中；五类即任务书给的五类）：

| 分类 | 去重行 | 原始命中 | 文件数 | 说明 |
|---|---|---|---|---|
| 测试夹具 | 45 | 1,828 | 16 | `*_test.go`、`fuzz_test.go` 里的短占位口令、大小写变量赋值、`"键名=" + 变量` 拼接、带保留域名的链接夹具、两条 `_test.go` 常量声明 |
| 生产代码 | 17 | 298 | 12 | **195 条 `== ""` 判空**、54 条注释/键名残片（含 `spec.go` 的两个键名常量）、49 条变量或常量赋值；没有一条是写死的凭据 |
| 文档 | 8 | 158 | 2 | `DEVLOG.md` 与 `docs/pre-release-checklist.md` 的历史记录、表格行与占位符说明 |
| 语法示例 | 1 | 47 | 1 | `internal/share/quic.go` 注释里的 QUIC 链接语法示例 |
| 示例配置 change-me | 2 | 12 | 2 | `examples/melonarc.conf` 与 tar staging 里同一份配置，值都是 `change-me` |

- **带凭据的 URL（`://user:值@host`）指向保留/示例段之外主机的条数：0**；主机全是
  `example.*`、`127.0.0.1`、`localhost` 一类。
- 值形状：35 个不同值，最长 20 字符；长度 ≥12 的 5 个、达到「长/高熵」阈值的 3 个
  **逐个核过结构**：2 个是 `_test.go` 里连字符词组的夹具常量（含 `secret` / `pass` 一类
  夹具词），1 个是 `subscription_test.go` 里故意写坏的配置字符串中的转义序列；三者都只
  出现在测试文件，且都不与非保留主机配对。没有 UUID、hex blob 或随机串形状的值。
- **结论：没有发现疑似真凭据，也没有真订阅 URL；不需要停下、不需要自行处理任何凭据。**
  与阶段 21 的结论一致（那里把 `alice` / `s3cret` 一类假口令登记为夹具）。
- 清单 A6 更新：因为任务三把 (a) 的四个模块也核完了，**(a)、(b) 两条尾巴本阶段都已关闭**，
  A6 整体从 `blocked (partly)` 改 **ready (resolved)**，正文分 (a)/(b) 两段如实写明，
  并注明首轮输出被扣下、补跑口径只输出聚合/脱敏结果，没有把被扣内容重建出来。

### 任务三：B3 —— 四个 `not verified` 模块补核（成功）

- 开工先探网络：模块代理 `.info` 返回 200 且内容是真 JSON——**本阶段这台机器能出网**，
  与阶段 21/16 记的「本机无外网」不同，按事实记录、不改历史条目。
- `go mod download` 对四个模块**一次尝试全部成功**（没有触发重试上限）：
  `github.com/davecgh/go-spew@v1.1.1`、`github.com/pmezard/go-difflib@v1.0.0`、
  `github.com/quic-go/qpack@v0.6.0`、
  `github.com/jordanlewis/gcassert@v0.0.0-20250430164644-389ef753e22e`。下载只落在仓库外的
  模块缓存，`git status` 无变化。
- 逐个读**该版本自带**的许可证原文：go-spew `LICENSE` → **ISC**；go-difflib `LICENSE`
  → **BSD-3-Clause**（三条件含「不得以贡献者名义背书」）；qpack `LICENSE.md` → **MIT**；
  gcassert `LICENSE.txt` → **MIT**。
- `THIRD-PARTY-NOTICES.md` §2 四行从「not verified here」换成实际许可证 + 读取阶段与文件名，
  表后段落改写为补核经过，并写明「四个都不进二进制，关的是台账缺口而非分发义务」、
  「Go 模块行已无未核项，Rust 壳 §5 仍待联网构建」；文件头的 Checked on / Checked how 补一行
  说明。清单 B3 从 `blocked` 改 **ready (resolved)**。
- 口径一致性：B2 全文仍只从**本机模块缓存**取（且用 `GOPROXY=off` 钉死），B3 的四个拉取
  后也是从同一缓存读原文，没有从网页或印象写。

### 任务四：发布说明草稿（**只是草稿，不发布**）

新建 `docs/release-notes-0.1.0-preview.1.md`，开头即声明「Draft, not a release」——没有 tag、
没有 release 对象、没有上传。内容：① 这是什么（0.x 源码预览、linux/amd64 的 core+CLI，
非稳定版）；② 包内清单（含新增的 `licenses/` 17 份 bundle / 24 个文件，sha 以实际构建那次
输出为准）；③ 从 tar 安装运行：解包 → 改 `melonarc.conf` 里那条文档地址上的占位 SOCKS5
节点 → `melonarc-core -config ./melonarc.conf -check`（首行版本横幅、`-check` 不建数据目录）
→ 前台起核心 → `melonarc-cli -data-dir ./melonarc-data status`，监听器全在回环
（7890/7891/7946），与 `examples/melonarc.conf` 逐项对齐；④ 支持矩阵只复述 README 的
状态词；⑤ 已知问题与反馈渠道（指向 `SECURITY.md`）。

**诚实边界逐条写明、不比证据乐观**：Hysteria2 / TUIC v5 是 **Unusable**（修复已落码、互通
未复验，启动只警告不拒绝，不得进稳定包）；REALITY 是 **Project record**（TCP 16 KiB 往
返）、UDP **Unverified**，且**只有 Chrome 形状的 ClientHello 模板过了真实互通**，不是指纹
承诺，其它浏览器模板未验；桌面前端不在包内、Rust 壳从未编译、`Cargo.lock` 缺失；五项性能
目标**未在真实硬件实测**；CI 工作流**从未在 Actions 上跑过**；Windows 只是交叉编译、
TUN 会话未实现；没有安装器、签名产物、打包安装的端到端证据；XTLS-Vision 配置期拒绝。

### 关键决策及理由

1. **全文用「构建产物的 `dep` 行」定集合，再与台账比对，而不是再抄一份 17 行清单。**
   义务跟的是分发出去的字节；`go version -m` 是产物自己的回答，抄第三份表只会多一处漂移。
   比对失败即 `die`，把「台账忘更新」变成构建期错误而不是发布后才发现。
2. **`GOPROXY=off` 取模块目录。** 任务书要求全文来自本机缓存原文；把网络关掉后，
   「缓存缺一份」必然失败，不可能悄悄用下载件冒充本地核对过的文本。
3. **一个模块一个文件，多许可证文件合并成带分隔线的节。** 既满足「每模块一个文件、
   文件名带模块名与版本」，又不丢 `LICENSE-3RD-PARTY.md` / `LICENSE-SQLITE` /
   `LICENSE-LOGO` 这类额外文本；分隔线由脚本生成并在文件头声明不是许可证正文，
   验收时再逐节做字节级比对，把「原样」变成可断言的事实。
4. **A6(b) 用聚合/脱敏输出补跑，不去碰被扣下的那份输出。** 阶段 21 的拦截针对的是
   「把口令字面量打出来」，而分类根本不需要看到原值；改成只输出计数、路径与值形状后，
   扫描覆盖完整、结论可得，也不重试、不绕过、不重建被拦内容。
5. **B3 成功就把 A6 整体写成已关，但分 (a)/(b) 写清各自证据。** 任务书允许「(a) 也在本阶段
   解决」时整体关闭；本阶段四个模块确实逐个读到了原文，所以不把 A6 留在「部分关闭」的
   假状态里，也不把 (a) 的功劳记到扫描头上。
6. **网络可达只记本阶段这一事实，不改历史条目。** 阶段 16/21 记的是当时的环境；把今天的
   结果写进阶段 24，并在清单 B3 里点明「旧备注不再适用于本次运行」，比回写流水账准确。
7. **发布说明只做草稿，边界与 README 逐字对齐。** 它是将来发布时要念的那段话，不是现状的
   升级声明；凡是没有真实互通/实机/实测证据的，一律用 README 的状态词或明确否定句。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                              通过
go vet ./...                                                通过
gofmt -l .                                                  无输出
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
go test ./... -count=1 -v                                   1292 条目 / 1271 通过 / 21 跳过 / 0 失败
scripts/build-release.sh 0.1.0-preview.1                    通过（17 bundle / 24 文件、tar +26,671 B）
解包后 melonarc-core -config …/melonarc.conf -check          通过（首行版本横幅、7/1/3/1、未建数据目录）
解包后 melonarc-cli version                                 melonarc-cli 0.1.0-preview.1
```

- **逐项对基线**（`580a770`，1292/1271/21/0）：条目 ±0、通过 ±0、跳过 ±0、失败 0；
  21 条跳过逐名与阶段 20 记录的集合一致（缺参考实现的互通 10、未连接 `sendto` 的 UDP 9、
  上游 UDP 截断改 TCP 1、真 TUN 1）。本批没有 Go/前端源码改动，条目数不变是预期。
- **前端**（系统 `/usr/bin/node` 24.22.1、清代理、`--test-concurrency=1`）：离线
  **79 / 77 / 2 / 0**（基线 79/77/2/0）；实时 **79 / 79 / 0 / 0**（基线 79/79/0/0）。
  实时装置在仓库外 `/tmp/s24-live/`，`go build` 的核心 `-check` 通过后后台起真进程，
  令牌轮询 `/healthz` 到 `{"status":"ok",...}`，入站/API 用 17890/17891/17946 三个空闲端口，
  **没有动** 7890/7891/7946 上的任何遗留进程；用例结束后核心已停。
- 命名红线：本批新增/修改的脚本、台账、清单、发布说明草稿与提交信息按阶段 21 记录的
  已知清单扫描**零命中**；新出现的第三方名字都是开源项目/公开协议名。许可证口径文件在
  `git diff --name-only` 里**零命中**。
- `git status` 的改动面只有：`scripts/build-release.sh`、`THIRD-PARTY-NOTICES.md`、
  `docs/pre-release-checklist.md`、新增 `docs/release-notes-0.1.0-preview.1.md`，加上本条目。

### 遗留问题

- **A7 路径改写**按任务书单独一笔提交，见「任务五补记」；本条目不含那部分内容。
- 清单 A1（图标资产未随快照推送）、A2（`Cargo.lock`）、A3（CI 从未实跑、三个资产 glob
  未核 404）、A4（私密报告入口未开启）仍 **blocked**，本批未触碰。
- B4（Rust 壳未编译）、B5（Hysteria2/TUIC 真实互通未复验）、C1（Windows 实机）、
  C2（五项性能未测）、C3（打包安装端到端）照旧；`THIRD-PARTY-NOTICES.md` §5 的 Rust
  三个 crate 仍是「本地未核」，与 B3 关闭的四行不是同一件事。
- 发布说明是**草稿**：没有 tag、没有 release、没有上传；正式发布前还得按清单过一遍，
  并把 sha 换成发布那一次构建的输出。
- 阶段 8–23 的既有挂账照旧：真 TUN 枯竭计数非零态、`Status.Skipped` 的 `/v1` 出口、
  第五个 GUI tile 的真窗口目视验收、REALITY UDP 证据、预览桥 query string、`core.log`
  无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、Flush 成本与整表重写。
- 本机「能出网」只在本次会话成立；阶段 24 的 B3 结论不依赖以后是否还能连上代理。

### 下一步计划

1. 任务五（A7）：把 DEVLOG 与 `docs/interop-testing.md` 里的本机账号路径改写为 `$HOME`
   口径，逐处判断桌面测试夹具里的 home 路径，给出全仓 grep 对照；**单独一笔提交**。
2. 让所有者处理 A1/A4，并在能出网的机器上首跑 CI（补 Snell 两个仓库变量、核三个资产
   glob）、生成 `Cargo.lock`；之后才有 B4/C3 的桌面包与端到端安装验收。
3. 在允许 UDP 的环境复验 Hysteria2 / TUIC，通过后才把 README 与发布说明那两行从
   「Unusable」移走；REALITY 若开放其它浏览器模板，按模板逐个复跑互通。
4. 正式发布前：把草稿里的边界按当时的证据再核一遍，用实际发布那次构建的 sha256，
   并按 `docs/pre-release-checklist.md` 的 A/B/C 组逐项销账。

### 任务五补记：A7 —— 本机路径改写为 `$HOME` 口径（单独一笔提交）

按任务书，本项在前面四项**提交完成**（`65480a8`）之后才动手，并且**单独一笔 git 提交**，
不与前四项混提交。所有者已定：本机路径字样统一改写为 `$HOME` 口径。本补记里不复述账号名，
以免文档本身又变成 grep 命中。

**1. 文档与日志类文本：全部改写**

- `DEVLOG.md` 里 5 处互通二进制目录（阶段 16 的服务端路径与 `go test` 命令、阶段 20 的
  本机实测与 `check-interop.sh` 命令、阶段 21 遗留问题）统一为 `$HOME/interop-bin`；
  命令仍可照抄执行（`MELONARC_INTEROP_DIR=$HOME/interop-bin …`），句子结构未变。
- `DEVLOG.md` 阶段 21 脱敏扫描表两行 home 目录计数：**保留 196 / 56 / 34 三个当时的字面量
  计数**（历史证据不改数），把具体账号目录换成「夹具 home 目录 / 本机环境路径 / macOS
  配置目录夹具」的类别描述，并注明阶段 24 起文档侧改写为 `$HOME`、夹具按语义保留。
- `DEVLOG.md` 阶段 21 遗留问题的 A7 条目：从「留给所有者决定」改为「所有者已定、阶段 24
  落地」，不再复述账号名。
- `docs/interop-testing.md` §6「本机的预期输出」一处改为 `$HOME/interop-bin`；该文件其余
  位置原本就是 `$HOME/interop-bin` / `~/interop-bin`，未动。
- `docs/pre-release-checklist.md` A7：`owner decision` → **ready (resolved)**，正文写明决策、
  改法、保留理由与 grep 对照的出处。

**2. 构建产物里新发现的一处本机路径（同属 A7，一并修掉）**

B2 的许可证 bundle 文件头原先把 `go mod download -json` 返回的绝对 `Dir` 写了进去，于是
17 个**随包分发**的文本文件各带一行本机账号路径。改 `scripts/build-release.sh`：文件头改成
符号化的 `$GOMODCACHE/<模块>@<版本>/`（单引号 `printf`，`$GOMODCACHE` 不展开），并在脚本里
写明理由。重跑打包后，17 个 bundle 与解包产物里**零本机账号路径**；许可证正文仍逐字节来自
本机模块缓存，B2 的证据链不受影响。这一处是 A7 扫描时才暴露的，属于「发布件不该带本机
路径」的同一条规则，所以放在本笔提交里。

**3. 测试夹具：逐处判断后保留**

| 文件 | 保留行 | 判断 |
|---|---|---|
| `apps/desktop/test/paths.test.mjs` | 10 | `configHome` / `resolveDataDir` 的 Linux、macOS 两套 home 夹具输入与成对的字面量期望值，验的就是 `~/.config` 与 `~/Library/Application Support` 的真实绝对路径形状 |
| `apps/desktop/test/supervisor.test.mjs` | 4 | 一份 `defaults` 夹具常量 + `settingsPath` 的 home 输入与 `path.join` 期望值 |
| `apps/desktop/src-tauri/src/settings.rs` | 3 | `#[cfg(test)] mod tests` 里 `resolve_with` 的设置文件输入，以及默认数据目录/核心配置的两条断言 |
| `apps/desktop/test/client.test.mjs` | 2 | shell 设置 wire 夹具的 `settings_path` 及其映射断言 |
| `apps/desktop/test/gui-settings.test.mjs` | 1 | 设置面板视图夹具的 `settingsPath` |

**共同理由**：这些字符串都是夹具输入或成对的字面量期望值，断言的是平台目录拼接结果；
`$HOME` 在 JS / Rust 字符串字面量里不会展开，替换后用例会从「验证平台目录约定」退化成
「验证占位符拼接」，**改变测试语义**。按任务书「若改动会改变测试语义则保留」逐处保留并在此
登记。另有 `paths.test.mjs` 两行 Windows 夹具用反斜杠形式写同一账号名，不在本次 grep 的
正斜杠模式内；同属夹具输入，按同一理由保留、未改。

**4. grep 对照（任务书给定的三种路径模式，排除 `.git/` 与 `.workbuddy/`）**

| | 改前 | 改后 |
|---|---|---|
| 命中行 | **47** | **20**（21 处字符串，有一行两个） |
| 文档与日志（`DEVLOG.md` 8 行、两份 `docs/` 各 1 行） | 10 | **0** |
| `dist-release/` 里 17 个 bundle 的文件头 | 17 | **0** |
| 测试代码 | 20 | 20（上表逐文件登记保留理由） |

改前的 47 行里，17 行是本阶段 B2 刚引入、由 A7 一并修掉的；剩余 20 行全部是上表的夹具
字符串，**没有一条是生产代码、配置、文档或日志**。仓库里已经没有任何一处写出本机账号的
绝对 home 路径，除了这些被明确登记为「按语义保留」的测试夹具。

**5. 收尾验证（A7 改动之后重跑）**

```
go build ./... / go vet ./... / gofmt -l . / GOOS=windows 交叉编译      全过
go test ./... -count=1 -v                    1292 条目 / 1271 过 / 21 跳 / 0 败
21 条跳过逐名 diff                            IDENTICAL（与基线及本批先前那次相同）
前端离线（系统 Node 24，清代理）             79 / 77 / 2 / 0
前端实时（真核心 + 真令牌）                  79 / 79 / 0 / 0
```

- 实时装置沿用本阶段前面那套（仓库外临时目录、空闲端口、用例结束即停核心），没有动
  7890/7891/7946 上的任何遗留进程。
- **提交 `65480a8` 后从干净状态实跑打包**：26 条清单、17 bundle / 24 节逐字节一致、
  9,795,710 B、sha256 `0dae6207…`；解包 `-check`（首行版本横幅、7/1/3/1、未建数据目录）
  与 `melonarc-cli version` 全过。**A7 头部修正后重跑**：9,795,724 B、
  sha256 `f87e4423…`，清单与逐字节校验不变。两次与正文记的 9,795,437 B 的差额来自
  `THIRD-PARTY-NOTICES.md` 台账更新与 tar/gzip 时间戳，**不声称可复现**。
- A6(b) 提交后复扫：可达提交 58 → 59，历史命中行 2,215 → 2,269（新提交把同一批字节写进
  历史），去重后**仍是同一批 73 条 (路径, 行)**，三个「长/高熵」值的结构与归属不变，
  **没有新值、新主机或新形状**；分类表与结论不用改。
- 命名红线：本笔新增/修改文本按阶段 21 的已知清单扫描零命中；许可证口径文件在
  `git diff --name-only` 里零命中。改动面只有 `DEVLOG.md`、`docs/interop-testing.md`、
  `docs/pre-release-checklist.md`、`scripts/build-release.sh` 四个文件。

**6. 提交与遗留**

本补记连同 A7 的四处改动**单独一笔本地提交**；没有 push、没有改仓库可见性、没有打 tag、
没有生成正式 release。清单 A7 关闭；A1（图标资产）、A2（`Cargo.lock`）、A3（CI 首跑）、
A4（私密报告入口）仍 **blocked**，B4/B5/C1/C2/C3 与阶段 8–23 的既有挂账照旧，见本条目
「遗留问题」与「下一步计划」。

## 阶段 25 — 运行时告警与发布说明对齐 CI 复验结果（2026-11-16）

范围：两处没跟上事实的旧口径。① `internal/outbound/unusable.go` 的 `unusableProtocols` 仍列着
hysteria2 与 tuic，理由是「修复已落码、真实互通未复验」，于是核心在启动与重载时对含这两类
出站的配置打 `known unusable` 警告——而 2026-11-16 的 CI 已在锁定参考服务端上把两者的 TCP 与
UDP 业务跑过，README 矩阵那两行已是 Verified。② `docs/release-notes-0.1.0-preview.1.md` 仍写
两者 Unusable（约第 109 行），另有同类过时结论三处：Snell 行停在「Project record / UDP
Unverified」、CI 一条写「从未在 Actions 上跑过」、私密报告入口一条写「可能尚未开启」。

本阶段只对齐告警与文档口径：**协议实现零改动，README 矩阵（含四个语言版本）一字未动**，
`spikes/` 未动，许可证口径文件未动；只本地提交，没有 push、没有打 tag、没有生成 release。

开工前：`HEAD = 621b8c1`（阶段 24 之后的发布脚本补丁），工作区干净，`git rev-list --all` 为
**69 笔**，单分支 `master`、无 tag、无 remote。按任务书先读 `DEVLOG.md`（重点阶段 21 的支持
矩阵统一、阶段 24 的发布说明草稿与 B5 记法）与 `docs/development-doc-v1.md`（v1 是目标规格，
其头部状态说明要求当前实现状态以 README 支持矩阵为唯一事实源）。README 矩阵按任务书当作唯一
事实来源，逐行读出 Hysteria2 / TUIC / Snell 三行的现状。基线按阶段 24 记录：Go 全量
**1292 / 1271 / 21 / 0**，前端离线 **79 / 77 / 2 / 0**、实时 **79 / 79 / 0 / 0**；动手前先跑了
一次 Go 全量，四个数字与基线逐项相同，21 条跳过逐名一致。

### 任务一：两个协议移出不可用列表（机制与出口保留，列表为空）

**`internal/outbound/unusable.go`**

- `unusableProtocols` 改为空切片；`Unusable` 类型、`UnusableProtocols()`、`IsUnusable()` 三个
  出口的签名、拷贝语义与「大小写不敏感 + 去首尾空白」的匹配规则**一字未改**。
- 变量注释改写：说明它为什么为空（旧条目的原话是「修复已落码但此后没再复验」，这份证据现在
  有了——两者在 CI 对锁定参考服务端通过，TCP 与 UDP 业务皆然，矩阵随之改 Verified），并写明
  「条目回来要靠证据与文档改动，不是为了让警告闭嘴去改代码」。
- `UnusableProtocols()` 的注释补一句：**空列表是合法答案**，调用方不得当作缺数据。

**`cmd/melonarc-core/unusable.go`**

- `warnUnusableProtocols(cfg, logger)` 的签名与两个调用点（`main.go:157` 启动、`reload.go:103`
  重载）都没变；循环体抽成 `warnUnusable(cfg, logger, lookup)`，生产路径传入的仍是
  `outbound.IsUnusable`。
- 抽这一层的理由只有一条：列表空掉之后，「警告会点名节点、但绝不回显节点参数」这条性质唯一
  的可测入口就是给测试注入一条条目；否则用例只能退化成「什么都没打」，把一条真正的安全属性
  测没了。它不导出、只有一个生产调用者，不是给生产加的开关。

**测试（两个包，条目数不变）**

| 文件 | 用例 | 现在断言什么 |
|---|---|---|
| `internal/outbound/unusable_test.go` | `TestNoImplementedProtocolIsUnusable` | 列表长度为 0；`New` 接受的 11 个类型（`socks5`、`socks5-tls`、`http`、`https`、`ss`、`vmess`、`trojan`、`snell`、`vless`、`hysteria2`、`tuic`）逐个 `IsUnusable` 为假 |
| 同上 | `TestIsUnusableMatchesTheWayNewDoes` | 临时注入一条 hysteria2 后，`Hysteria2` / `  hysteria2  ` / `HYSTERIA2` 命中，`tuic` / `vless` / `socks5` / 空串不命中（匹配语义仍被覆盖） |
| 同上 | `TestUnusableProtocolsReturnsACopy` | 注入一条后改返回值，取第二次仍是原条目 |
| 同上 | `TestUnusableProtocolsAreImplemented` | 注入两条后逐条确认 `New` 不走 `Unsupported`（条目回来时的守门） |
| `cmd/melonarc-core/unusable_test.go` | `TestUnusableProtocolsWarnAtLoad` | 表驱动 4 个子用例，形状与旧用例一致；断言从「会警告」翻成「不警告」：曾列出的两类、混合大小写的一类、从未列出的三类、空配置，一律 `level=WARN` 计数 0 且**日志缓冲区为空** |
| 同上 | `TestUnusableProtocolWarningCarriesOnlyTheNodeAndTheReason` | 注入条目 + 一个未被列出的节点：只打 1 条，含 `proxy` / `type` / `reason`，未列出的节点不出现，`Args` 里的哨兵串不出现 |

- 注入用 `withUnusable(t, …)` + `t.Cleanup` 把出厂列表放回去，用例间不串状态，也不并行。
- 文案用例的 `Args` 用**非凭据形状的哨兵串**（`argument-must-not-be-logged`），不是旧用例里的
  口令字面量：断言的性质没变（Args 不进日志），但测试文件里不再需要出现任何口令形状的字符串。

**CLI / GUI / API 兼容**：`grep -rn Unusable internal/cli internal/api apps` **零命中**——这个列表
没有对外出口，CLI、GUI 与本地 API 都不消费它，因此不存在「空列表解析失败」的路径；核心侧唯一
消费者是 `IsUnusable`，空列表下恒为 `false`。

**行为证据（不止单测）**：同一份含 `hysteria2` + `tuic` + `ss` 的配置，用 `HEAD` 的临时 worktree
构建出旧核心、再用本阶段的工作树构建新核心，各起一次：

| | 旧核心（`621b8c1`） | 新核心（本阶段） |
|---|---|---|
| `/healthz` | `{"status":"ok",…}` | `{"status":"ok",…}` |
| `known to be unusable` 行数 | **2**（H2、TUIC 各一条，文案即旧条目的 reason） | **0** |

启动与重载调的是同一个函数，重载路径没有第二份判断。

### 任务二：发布说明全文与矩阵对齐

`docs/release-notes-0.1.0-preview.1.md` 逐段核过，改了七处：

| 位置 | 旧口径 | 改后 |
|---|---|---|
| Hysteria2 / TUIC 行 | **Unusable**，启动只警告不拒绝，不得进稳定包 | **Verified (CI, 2026-11-16)**：保留外审失败的具体症状（QPACK 字段段解码错误 512；文本形式 UUID 导出标签导致认证失败）与阶段 15 的修复，写明七个参考槽位齐备的 CI 复跑 TCP/UDP 皆过，并补「两者已不在核心的不可用列表上，配置启动不再警告」 |
| Snell 行 | **Project record** TCP（阶段 11），UDP **Unverified** | **Verified (CI, 2026-11-16)**：阶段 11 首次跑通 TCP，CI 对 snell-server 5.0.0 两套版本配置全过；B6 记的瞬时 UDP 失败按「同树重跑全绿」如实写入 |
| 状态词段落 | 只列五个词 | 补一句：今天 Unusable 行里没有协议，词保留是因为矩阵定义了它，回归时可以再放回 |
| 「Not claimed」首条 | 「Hysteria2 / TUIC 可用」是不可声称项 | 换成**范围限定**：一次通过 = 每个协议一套配置（Hysteria2 口令认证；TUIC `cubic` + `h3` ALPN + 关 0-RTT）、32 KiB TCP + 单个数据报；未涉及其它 obfs、拥塞控制或证书设置 |
| 「Not claimed」CI 条 | 工作流**从未在 Actions 上跑过**，没有核过参考资产名 | 2026-11-16 首跑，第五次跑三个 job 全绿，之前四轮修的是抓取/校验参考实现那几步；保留「没有 release tag 背后有机器报告」「fuzz 只在有界本地会话跑过」 |
| 已知问题 | XTLS-Vision **与** Hysteria2/TUIC 配置不可用（后者只警告） | 只留 XTLS-Vision 配置期拒绝 |
| 反馈渠道段 | 私密报告「可能尚未开启」（清单 A4） | 已于 2026-11-16 开启；无细节公开 issue 保留作镜像/分叉的兜底 |

- 范围限定的依据是 `internal/outbound/interop_quic_test.go` 里**实际写下的**服务端配置
  （hysteria2：listen + 自签证书 + 口令认证；tuic：`cubic`、`["h3"]`、`zero_rtt_handshake:false`）
  与用例体（32 KiB 回显 + 单数据报），不是凭印象。
- 未改的段落逐项核过：包内清单（17 bundle / 24 节）、安装步骤、版本横幅、许可证段都与当前
  tree 一致；`README.md` 的四个语言版本已由前一笔提交改成 Verified，本阶段只 grep 确认、未编辑。

### 任务三：全量回归与基线对照

| 命令 | 结果 | 基线 | 差异 |
|---|---|---|---|
| `go build ./...` | 通过 | 通过 | 无 |
| `go vet ./...` | 通过 | 通过 | 无 |
| `gofmt -l .` | 无输出 | 无输出 | 无 |
| `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...` | 通过 | 通过 | 无 |
| `go test ./... -count=1 -v` | **1292 / 1271 / 21 / 0** | 1292 / 1271 / 21 / 0 | 条目 ±0、通过 ±0、跳过 ±0、失败 0 |
| 21 条跳过逐名 `diff` | `IDENTICAL` | 固定集合 | 无 |
| 前端离线（系统 `/usr/bin/node` 24.22.1、清代理、`--test-concurrency=1`） | **79 / 77 / 2 / 0** | 79 / 77 / 2 / 0 | 无 |
| 前端实时（真核心 + 真令牌，仓库外 `/tmp/s25-live`，端口 17890/17891/17946） | **79 / 79 / 0 / 0** | 79 / 79 / 0 / 0 | 无 |

- **条目数为什么不变**：两个包的用例形状被刻意保持——`internal/outbound` 前后都是 4 个顶层
  用例（无子用例），`cmd/melonarc-core` 前后都是「1 个表驱动父用例 + 4 个子用例 + 1 个文案用例」
  （6 条）。所以条目、通过、跳过三项都是 ±0，而不是「测试改写了，数字顺便变了」。
- 21 条跳过仍是固定集合：缺参考实现的互通 10、未连接 `sendto` 的 UDP 9、上游「UDP 截断改
  TCP」1、`TestTUNLinuxLoopback` 1。
- 前端两套在 Go 侧改动之后跑；本阶段前端源码零改动（`git status` 只有 5 个文件，其中没有
  `apps/`），数字仍与基线相同。实时装置沿用阶段 24 的做法：`go build` 的核心先 `-check`，再
  后台起真进程、轮询 `/healthz` 拿真令牌，用例结束即停核心，**没有动** 7890/7891/7946 上的
  任何遗留进程。

### 关键决策及理由

1. **清空列表，保留类型与两个查询出口。** 任务书要求「机制保留、列表为空」；做法上最省事的
   是连 `Unusable`/`IsUnusable` 一起删，但那会把「下次证据变差时怎么回来」也一起删掉，矩阵
   里的 Unusable 定义就失去了机器可读的一半。
2. **为文案用例留一个 lookup 注入点。** 列表空掉之后，「警告点名节点但不回显参数」不可能再用
   真实列表测到；删掉那条用例等于承认这条性质以后不再验证。抽一个不导出的 `warnUnusable`，
   让注入只存在于测试侧，是能保住这条断言的代价最小做法。
3. **文案用例改用非凭据哨兵，而不是保留旧的口令字面量。** 要证的从来不是「这个口令没被打
   出来」，而是「`Args` 整体不进日志」。用哨兵串断言同一个性质，测试文件里也不必留口令形状
   的字符串。
4. **发布说明把「不可用」换成「范围限定」，而不是把那条边界直接删掉。** 矩阵只写「CI 复跑
   通过」，读者很容易把它读成「这两种协议的任意配置都可依赖」；写清一次通过覆盖的是哪套
   配置（口令认证 / `cubic` + `h3` + 关 0-RTT、32 KiB + 单数据报），边界才是可核的。
5. **改写测试时保持用例形状。** 条目数、跳过数与基线逐项相同，才能把「本阶段没改变测试覆盖
   面」变成可断言的事实；否则任何数字变化都要读者自己判断是新增覆盖还是覆盖丢失。
6. **只动告警与文档，不碰协议实现与 README 矩阵。** 矩阵已由前序提交改对，是唯一事实源；
   这一阶段的任务是让代码与发布说明向它看齐，而不是再引入一个可以漂移的副本。

### 当前状态

全部命令在仓库根目录执行，工具链 `~/sdks/go/bin` 的 Go 1.27.4，Linux/x86_64：

```
go build ./...                                              通过
go vet ./...                                                通过
gofmt -l .                                                  无输出
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...  通过
go test ./... -count=1 -v                                   1292 条目 / 1271 通过 / 21 跳过 / 0 失败
前端离线（系统 Node 24，清代理）                             79 / 77 / 2 / 0
前端实时（真核心 + 真令牌）                                  79 / 79 / 0 / 0
含 hysteria2 + tuic 的配置起核心                             无 known unusable 警告，/healthz ok
```

- 改动面只有 5 个文件：`internal/outbound/unusable.go`、`internal/outbound/unusable_test.go`、
  `cmd/melonarc-core/unusable.go`、`cmd/melonarc-core/unusable_test.go`、
  `docs/release-notes-0.1.0-preview.1.md`，加上本条目。
- 命名红线：本批新增/修改文本沿用阶段 21 的已知清单扫描**零命中**；新出现的名字都是公开
  协议名与已登记的开源参考实现名。许可证口径文件在 `git diff --name-only` 里零命中。
- `go tool` 与临时装置（`/tmp/s25-live`、`/tmp/s25-warn`、临时 worktree）全在仓库外，用后即删；
  临时 worktree 已 `git worktree remove` 并 `prune`，`git worktree list` 只剩主树。

### 遗留问题

- **Hysteria2 / TUIC 的 Verified 只覆盖互通套件那套配置**：无 obfs、TUIC 用 `cubic`、单数据报。
  其它 obfs / 拥塞控制 / 证书组合仍无证据；要扩大结论得先扩用例。
- **REALITY 仍是 Project record、UDP Unverified**，本阶段按任务书未触碰；规格里 `xtls-rprx-vision`
  与实现（配置期拒绝）的差异照旧。
- 清单 **A2（`Cargo.lock`）、B4（Rust 壳）、C1（Windows 实机）、C2（五项性能）、C3（打包安装
  端到端）** 仍 blocked；A1/A3/A4/A5/A6/A7、B2/B3/B5/B6 已关闭。
- 发布说明仍是**草稿**：没有 tag、没有 release、没有上传；正式发布前要按清单再核一遍边界，
  并把 sha256 换成本次发布构建的输出。
- 阶段 8–24 的既有挂账照旧：真 TUN 枯竭计数非零态、`Status.Skipped` 的 `/v1` 出口、第五个 GUI
  tile 的真窗口目视验收、`core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、Flush 成本与
  整表重写、预览桥 query string。
- 环境侧：本阶段未再触发敏感内容拦截（改写后的测试文件不含口令形状字面量）；若以后仍要从
  该文件读全文，需注意这一层的审批行为。

### 下一步计划

1. 所有者侧：联网生成 `Cargo.lock`（A2）→ 编译 Rust 壳（B4）→ 才能谈打包安装端到端（C3）。
2. 性能五项（C2）需要有线测试台与固定构建，本工作区出不了结论。
3. REALITY 若要离开 Project record，先补 UDP 证据与其它浏览器模板的互通复跑。
4. 正式发布前：按 `docs/pre-release-checklist.md` 的 A/B/C 组逐项销账，用实际构建的 sha256，
   并把发布说明里「Draft, not a release」的头部换成发布版本的声明。

---

## 阶段 26 — 订阅跳过明细的 `/v1` 只读出口（2026-11-16）

范围：阶段 22 留下的那条挂账——「`Status.Skipped` 要不要有 `/v1` 出口（若要，先定分页与保留
窗口）」。阶段 22 已经让订阅刷新按条目记录跳过原因（`share.ParseAll` 返回 `[]Rejection`、
`Status.Skipped` 计数、日志里逐条 Warn 但**只打前 8 条**），但这份明细没有任何出口：GUI 与
CLI 只能看到一个数字，看不到「第几条、为什么」。本阶段按 2026-11-16 的所有者决策 A 补一个
独立的只读端点，并让它同时被 CLI 与桌面 UI 用上。

本阶段**不改**解析与跳过的判定逻辑（一个字都没动 `share` / `outbound` 的判定），**不改**现有
订阅响应的结构（明细单独成端点，摘要仍然只有计数），不新增第三方依赖，`spikes/` 与 `docs/`
未动；只本地提交，没有 push、没有打 tag。

开工前：`HEAD = 37577fb`（阶段 25），工作区干净，`git rev-list --all` 为 **70 笔**，单分支
`master`、无 tag、无 remote。按任务书先读 `DEVLOG.md`（重点阶段 22 的保留语义与阶段 25 的
遗留清单）与 `docs/development-doc-v1.md`。基线按阶段 25 记录：Go 全量 **1292 / 1271 / 21 / 0**，
前端离线 **79 / 77 / 2 / 0**、实时 **79 / 79 / 0 / 0**；动手前先跑了一次 Go 全量，四个数字与
基线逐项相同，21 条跳过逐名一致。

### 完成了什么

**核心保留（`internal/subscription`）**

- `state.skipped` 的语义写进类型注释：它是**最近一次完成的刷新**的**完整**跳过明细，不是日志
  里那前 8 行；日志有上界是怕坏订阅刷屏，明细不设上界、按页送出。
- 成功路径（`refresh`）：整份替换，**包括替换成空**——供应商修好了列表就必须停止「看起来坏着」，
  于是节点与明细永远描述同一份响应体。
- 失败路径（`refresh`）：**故意不动**明细。理由写在代码里：明细描述的是「正在生效的节点」，
  而这次失败恰恰保留了那些节点；把一次被拒的响应体的拒收原因换成明细，等于让端点解释一份
  守护进程并未使用的列表。从缓存读回的旧响应体也不是「完成的刷新」，因此不带自己的明细。
- `maxReportedSkips` 的注释改成「上界属于日志，不属于管理器保留的东西」，避免下一个人把它当成
  明细的长度上限。
- 新增 `Status(name) (Status, bool)`（按名取一份状态，`Skipped` 是拷贝）与 `statusOf(st)`，
  让 `Snapshot` 与 `Status` 共用同一个渲染点，不会一处改了另一处忘了。
- 新增分页出口：

  ```go
  const (
      DefaultSkippedPage = 100
      MaxSkippedPage     = 500
  )
  type SkippedPage struct {
      Name      string
      Refreshed bool
      FetchedAt time.Time
      Total     int
      Offset    int
      Limit     int
      Items     []Skip
  }
  func (m *Manager) Skipped(name string, offset, limit int) (SkippedPage, bool)
  func ClampSkippedPage(offset, limit int) (offset, limit int)
  ```

  `Skipped` 的 `Items` 恒为非 nil（空页是 `[]Skip{}` 而不是 `null`），`Refreshed` 取
  `!fetchedAt.IsZero()`，未知名字返回 `false` 让调用方能与「没跳过」区分。窗口钳制抽成导出的
  `ClampSkippedPage`，因为守护进程层在「配置声明了这个订阅、但管理器还没见过它」时也要给出
  一个空页，那一页必须报**调用方本来会拿到**的窗口，而不是自己另定一个尺寸。

**API（`internal/api`）**

- 两条新路由，沿用既有 `/v1` 命名与 `only(method, handler)` 包装：

  ```go
  mux.HandleFunc("/v1/subscriptions", s.only(http.MethodGet, s.handleSubscriptions))
  mux.HandleFunc("/v1/subscriptions/{name}/skipped", s.only(http.MethodGet, s.handleSubscriptionSkipped))
  ```

- 新文件 `internal/api/subscriptions.go`：`maxSkippedPage = 500`、两个 handler、`parseSkippedPage`、
  `parseOffset`。`server.go` 里把原来的 `parseLimit` 拆成 `parseLimit`（用 `maxRulePage`）与
  `parseLimitWithin(raw, max)`，于是跳过明细对 `limit=501` 回的是**带原因的 400**
  （`limit 501 is above the maximum of 500`），而不是悄悄截断。
- 线上类型（`views.go`）与内部类型分开：`SubscriptionView` / `SubscriptionListView` /
  `SkippedListView` / `SkippedEntryView`，`Provider` 接口加两个方法。摘要里**没有** `skipped`
  明细数组，**也没有** `URL`（订阅地址常带 token，不能顺手送进只读视图）。
- 名字是路径段，配置名允许含 `/`，因此客户端按单段转义（`airport%2Fus`）；Go 1.22+ 的 mux 会把
  `%2F` 解码回一个段、不再当成多段（开工前单独写了一个 6 行程序验过）。空名字不服务：`//` 会被
  mux 以 307 折叠，handler 对空名字另给 404 `unknown_subscription`。
- 错误沿用既有风格：未知订阅 404 `unknown_subscription`、参数非法 400 `bad_request`、无令牌 401、
  非 GET 405 带 `Allow: GET`；响应照旧 `Cache-Control: no-store`。

**守护进程（`cmd/melonarc-core`）**

- `daemonState` 加 `subs *subscription.Manager`，注释说明它**不进**重载快照：管理器跨重载保留
  状态（阶段 11 的语义），所以一次重载不重取、明细也跟着活下来。
- `Subscriptions` 按**当前生效的配置**列，不按管理器记忆列：重载删掉一个订阅后，管理器还留着它
  的上一次结果，照记忆列会报出一个守护进程已经不再有的订阅。
- `subscriptionView` 对「配置里有、管理器还没见过」给零值（计数 0、时间空串），这是诚实的答案，
  首次导入尚未完成时就会出现。
- `SubscriptionSkipped` 先查配置声明（`declaresSubscription`），再取页；管理器不认识时返回空页 +
  `refreshed:false`，而不是 404——「有订阅但还没刷新完」与「根本没有这个订阅」是两件事。

**CLI（`internal/cli`）**

- 新命令 `subscriptions [name] [offset] [limit]`：无参时一张摘要表
  （`NAME NODES SKIPPED LAST REFRESH NEXT ATTEMPT ATTEMPTS ERROR`，空配置打印
  `no subscription is configured`）；带名字时按页打印 `ITEM REASON` 两列，页脚
  `1-1 of 2 skipped entries`，后面还有时给一行 `next: melonarc-cli subscriptions <name> <to> <limit>`。
- 三种空答案分别有话说：「还没完成过一次刷新」/「最近一次刷新没有跳过任何条目」/
  「offset N 之后没有条目」。`-json` 原样透传。名字用 `url.PathEscape` 拼进路径。
- usage 文本补了这条命令与两行示例；原本只查一条命令的 `TestUsageDocumentsHistory` 改名
  `TestUsageDocumentsEveryCommand` 并同时校验 `history` 与 `subscriptions` 的用法行。

**GUI（`apps/desktop`）**

- 新面板 `subscriptions`（`order: 25`，落在 policies 20 与 connections 30 之间），图标、标题键、
  注册表一并补齐。摘要每 10s 轮询一次（面板可见时才轮）；**明细只在点开时取一页**，不预加载，
  收起即丢。每个打开动作带票号，晚到的应答直接丢弃，不会把上一页画到这一页上。
- 明细卡片按五种状态渲染：取数错误 / 载入中 / `refreshed:false`（还没刷新完）/ `total:0`
  （最近一次没跳过）/ 表格 + 分页条。分页条用**服务端回的 `limit`** 走下一页，不自己假设页大小。
- 文案 en / zh-CN 各加 24 键（`nav.subscriptions` + 23 条 `subscriptions.*`），两份包现在各
  **270 键**；两处文件都是按行插入，没有重排既有分组。
- `client.js` 加 `Paths.subscriptions`、`subscriptions()`、`subscriptionSkipped(name, {offset, limit})`；
  `panels.css` 加 `/* ---- subscriptions */` 一段列宽与分页条样式。

**测试**

- `internal/subscription`（+8 条）：完整性与分页（12 条拒收、四页、条目号 1..12）、默认页与大页
  上限、下一次完成的刷新整体替换（脏→干净→部分脏）、刷新失败时明细与 `FetchedAt` 不变、
  明细不受日志 8 条上界影响（日志 8 行 / `count=4` / 明细 12 条）、未知名字、从未完成的刷新，
  以及 `ClampSkippedPage` 的窗口表。
- `internal/api`（+5 条）：摘要只有计数（响应体里没有 `"reason"`）、单页与参数透传（含
  `airport%2Fus` 的解码）、空与未知分开、非法分页（`offset=-1/abc`、`limit=-1/abc/501` 全部 400，
  边界值 `""`/`0`/`500`/`offset=12&limit=1` 全部 200）、方法与令牌契约（405 + `Allow: GET`、401）。
- `internal/cli`（+4 条参数表用例 + 3 条用例）：摘要表、两页明细（断言请求的 offset 依次是
  `0|2`、`2|2`）、三种空答案不混。新增的假核心需要错误体，补了 `writeErrorBody` 小助手。
- `cmd/melonarc-core`（+1 条）：装配级用例——摘要 2 节点 / 2 跳过且不含 `"reason"`，翻页拿到
  条目号 2 与 3，理由不引用被拒主机名，`typo` 404，`limit=999` 400。
- 前端（+3 条）：点开才取（断言 `calls` 只有一次 `{name:"airport",offset:0,limit:20}`，翻页后
  才出现 offset 2）、三种空答案分开、收起之后再到的应答被丢弃（用可控 promise 制造晚到）。
  实时套件加了订阅摘要与一页明细的断言（配置里有订阅时才深入明细）。
- 两条按面板数量写死的旧断言随新面板更新：`app-smoke-run.mjs` 的导航 7 项（并新增点开
  「跳过明细」、翻页条文案、收起后明细消失三段断言，末尾日志改为 7 panels）、`registry.test.mjs`
  的「至少七个面板」与前三个 id 改为 `overview, policies, subscriptions`。这不是放宽断言，
  是新面板的应有结果。

### 关键决策及理由

1. **两个端点，而不是把明细塞进 `GET /v1/subscriptions`。** 任务书红线是「现有订阅响应保持
   轻量」，而且一份坏订阅的明细可以是几千条：摘要回答「有几个节点、跳过几个」，明细回答
   「第几条为什么」，两个问题的读者与频率完全不同。
2. **路径 `/v1/subscriptions/{name}/skipped`。** 名字是配置名（可含 `/`），用单段 `%2F` 表达；
   明细属于某个订阅，放在名字下面比 `?name=` 更贴合既有 `/v1/rules/explain?name=` 之外的路由
   习惯（explain 是查询语义，这里是资源语义）。
3. **保留窗口 = 最近一次完成的刷新；成功即整体替换（含空），失败不动。** 这条是为了让「明细」
   与「节点」永远同源。若失败也换明细，用户会看到一份解释「没被采用的列表」的原因表；若成功
   空结果不覆盖，供应商修好后端点仍旧报旧错误，排障方向被带偏。
4. **日志上界与保留分离。** `maxReportedSkips = 8` 是打印预算，不是保留预算；两者混用会让
   「端点只给 8 条」变成一条看不见的静默截断。
5. **默认 100 / 上限 500，两处都实现。** API 对 `limit>500` 回 400 并说明原因（客户端能改），
   管理器再钳一次（防绕过 API 的调用方把一次应答变成整张表）。默认值存在的理由是「有人打开
   屏幕」不该触发一次全量序列化。
6. **三种空答案必须分开。** `refreshed:false`（从未完成）、`total:0`（最近一次没跳过）、
   偏移越界（空页但 `total` 还在）；未知名字走 404。全合成一个空数组，会让「订阅没生效」和
   「订阅很干净」长得一模一样。
7. **摘要不含 `URL`，明细不含链接。** 订阅地址常带凭据；跳过理由由链接解析产生，用例断言理由
   不引用被拒主机名（阶段 22 的 warn 口径在这里继续成立）。
8. **GUI 单开一个面板。** 订阅名不在任何既有载荷里，塞进连接面板要么改结构、要么让连接面板
   去猜名字；新面板 25 位既符合导航顺序，也让「点开才取」有一个自然的位置。
9. **`subs` 不进重载快照。** 管理器本来就是跨重载保留状态的（阶段 11），明细跟着它走才对；
   把管理器塞进快照会在每次重载时把明细重置成「还没刷新」。
10. **导出 `ClampSkippedPage`。** 守护进程层要为「还没见过」的订阅合成一页空答案，窗口必须与
    真页一致；与其在 `cmd/` 里抄一份 100/500，不如把这条规则留在一个地方。

### 当前状态

```
go build ./...                                     通过（go1.27.4）
go vet ./...                                       通过
gofmt -l .                                         无输出
GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...
                                                   通过
go test ./... -count=1 -v                          1313 条目 / 1292 通过 / 21 跳过 / 0 失败
前端离线（系统 Node 24.22.1，清代理，--test-concurrency=1）
                                                   82 条目 / 80 通过 / 2 跳过 / 0 失败
前端实时（真核心 + 真实令牌文件）                  82 条目 / 82 通过 / 0 跳过 / 0 失败
node scripts/build.mjs                             通过，29 文件 / 221.4 KiB
```

Go 条目 **1313 / 1292 / 21 / 0**（基线 1292 / 1271 / 21 / 0，+21 条，跳过集合逐名一致，
21 条仍是「缺参考实现的互通 10 + 未连接 `sendto` 的 UDP 9 + 上游 UDP 截断改 TCP 1 +
`TestTUNLinuxLoopback` 1」）。新增逐项：

| 包 | 新增条目 | 内容 |
|---|---|---|
| `internal/subscription` | +8 | 7 条跳过明细用例 + `ClampSkippedPage` |
| `internal/api` | +5 | 摘要、单页、空与未知、非法分页、方法与令牌 |
| `internal/cli` | +7 | 4 条参数表用例 + 摘要/翻页/三种空答案 |
| `cmd/melonarc-core` | +1 | 装配级端到端（含翻页与 404/400） |

对照全量 `=== RUN` 名单，**减少的只有两条**：`TestUsageDocumentsHistory`（改名成
`TestUsageDocumentsEveryCommand`，一减一增）与 `TestSOCKS5Connect/<addr>:<port>` 的两个子用例
（子用例名字里带随机端口，每次跑都不同，属既有噪声，不是用例增减）。

前端离线 **82 / 80 / 2 / 0**（基线 79 / 77 / 2 / 0，+3 = 三条新面板用例；2 条跳过仍是
`live-core.test.mjs` 的两条），实时 **82 / 82 / 0 / 0**（基线 79 / 79 / 0 / 0，同样 +3）。

实时装置（仓库外 `/tmp/s26-live/`）：`go build` 出核心与 CLI，配置用 17946（API）/17890（HTTP）
/17891（SOCKS5），另起一个 `python3 -m http.server` 在 17947 上提供订阅体（5 行：3 条可用、
2 条被拒），`-check` 通过后后台起核心、带令牌轮询 `/healthz` 到 200，再跑前端实时套件；
**没有动** 7890/7891 上更早阶段留下的演示核心。实测四个答案与预期一致：

```
GET /v1/subscriptions
{"subscriptions":[{"name":"airport","nodes":3,"skipped":2,"fetched_at":"...","next_at":"...","attempts":0}]}

GET /v1/subscriptions/airport/skipped?offset=0&limit=1
{"subscription":"airport","refreshed":true,"total":2,"offset":0,"limit":1,
 "skipped":[{"item":2,"reason":"ss link: the link has no method:password pair"}]}

GET /v1/subscriptions/typo/skipped          → 404 unknown_subscription
GET /v1/subscriptions/airport/skipped?limit=501 → 400 "limit 501 is above the maximum of 500"
```

CLI 对同一个真核心：摘要表一行 `airport 3 2 ...`；`subscriptions airport 0 1` 打印
`2  ss link: ...` 与页脚 `1-1 of 2 skipped entries` + `next:` 提示；`offset=1` 打印第 3 条与
`2-2 of 2 skipped entries`（无提示）；`subscriptions typo` 退出码 1 且 stderr 只有
`unknown_subscription: no subscription is named "typo"`。跑完两个进程都已停，端口已释放。

### 遗留问题

- **阶段索引表停在阶段 22**（23/24/25 三条都没有行）。本阶段按最近三阶段的做法只追加记录、
  不擅自回填别人的摘要；要不要补齐由所有者定。
- 条目数 +21 是本阶段唯一的结构性变化：以后若同一批文件再改测试，仍以「条目无增减」为对照
  基准时，要记得基线已从 1292 变成 1313。
- 明细的**理由文本**由链接解析产生，用例断言它不引用主机名/凭据；这是用例守着的性质，不是
  类型保证——以后改解析错误文案时不能把链接片段带进去。
- 桌面侧只在无头 DOM（假 DOM + 实时核心）里验过；新面板的真窗口目视验收仍属 B4 的挂账
  （Rust 壳本机编不出来）。
- 实时装置用的是回环 `http.server` 提供订阅体，**真实供应商**的路径（gzip、重定向、大响应体）
  仍未覆盖；这些走的是 `internal/subscription` 既有取数路径，本阶段没改它。
- 摘要里没有 `refreshed` 字段（只有 `fetched_at` 为空表示没刷新过），明细页才有。这是有意的：
  摘要要保持「计数 + 时间」的最小形状，若以后 GUI 需要在摘要上直接区分，得另议。
- 阶段 8–25 的既有挂账照旧：A1/A2 打包资产与 `Cargo.lock`、B4 Rust 壳、C1 Windows 实机、
  C2 性能实测、C3 端到端安装、真 TUN 枯竭计数非零态、第五个 GUI tile 的真窗口目视验收、
  `core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放、Flush 成本与整表重写、预览桥 query string。
  **本阶段关闭了「`Status.Skipped` 的 `/v1` 出口」这一条。**

### 下一步计划

1. 若要收尾 GUI：先解决 B4（联网生成 `Cargo.lock` 并编译壳），订阅面板的真窗口验收才可做。
2. 订阅侧下一件有价值的事是「供应商真实形态」的取数覆盖（gzip/重定向/超大响应体），以及
   明细的理由文案统一（现在直接来自各协议解析器的错误文本）。
3. 发布侧仍按 `docs/pre-release-checklist.md` 推进；本次改动不涉及打包清单，但 `core.log`
   仍无轮转，订阅刷新的警告量一旦变大值得一并处理。
4. 索引表回填、发布说明里对订阅明细的描述，等所有者确认口径后再动（避免与 README 矩阵、
   发布说明草稿的说法打架）。

## 阶段 M1 — macOS 构建打通（2026-11-17）

范围：macOS 桌面端 MVP 的第一步，按仓库外计划 `~/workspace/projects/melonarc-macos-plan.md`
的 M1 节与 D1（A：只做系统代理）、D2（A：ad-hoc 签名）推进。本阶段**只做构建链路**：让 CI
能产出一份 arm64 的 `.app` 与首份 `Cargo.lock`。不改核心逻辑、不改订阅与解析、不改壳的 Rust
代码，不碰 `spikes/` 与 `docs/`，不新增 Go / npm / Rust 依赖，不推进 macOS 的系统代理与 TUN
实现（那是 M2）。只本地提交，不 push、不打 tag、不发 release。

开工前：`HEAD = c229437`（阶段 26），工作区干净，`git rev-list --all` **71 笔**，单分支
`master`、无 remote、无 tag。按任务书先读 `DEVLOG.md`（阶段 13/17 的壳、21 的发版工程、
24/25/26 的清单与口径）、计划文档 M1 与 D1/D2、`docs/development-doc-v1.md`。基线按阶段 26：
Go 全量 **1313 / 1292 / 21 / 0**，前端离线 **82 / 80 / 2 / 0**。

### 完成了什么

**CI：`.github/workflows/ci.yml` 追加第 4 个 job `macos`**（`runs-on: macos-15`，12 步）

- 工具链：`setup-go@v5` 用 `go-version-file: go.mod`（`go 1.27`，与既有 job 同一口径）、
  `setup-node@v4` Node 22、rustup 装 stable 并 `rustup target add aarch64-apple-darwin`，
  显式断言 `rustc >= 1.89`（`Cargo.toml` 的 `rust-version` 下限）后打印 host triple。
- 构建：`GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w"` 分别产出
  `cmd/melonarc-core`（落到 `src-tauri/binaries/melonarc-core-aarch64-apple-darwin`）与
  `cmd/melonarc-cli`（落到 runner 临时目录，只证明能编译，不上传）。
- 锁文件：`Cargo.lock` 不存在时 `cargo generate-lockfile`；已提交时先
  `cargo metadata --locked --format-version 1` 做一致性闸门。随后把 CLI 装在仓库外的临时目录、
  直接调用其二进制执行 `tauri build --target aarch64-apple-darwin --bundles app -- --locked`，
  使锁文件成为构建的硬输入。
- 校验：`Contents/MacOS/melonarc-core` 必须存在且可执行、两个 Mach-O 必须是 arm64、
  `Info.plist` 的 `LSMinimumSystemVersion` 必须是 `13.0`、`codesign -dv` 必须报
  `Signature=adhoc` 且 `codesign --verify` 通过；再用包内核心对一份最小配置跑 `-check`
  （只解析、不监听、不落盘）。
- 产物：`ditto -c -k --keepParent` 把 `.app` 打成 zip，与 `Cargo.lock` 一起由
  `upload-artifact@v4` 上传（`melonarc-macos-arm64`，保留 14 天），并打印 SHA-256。
- 现有 go / frontend / interop 三个 job **一字未改**：与 `HEAD:ci.yml` 逐字节对照，原 9416
  字节完全相同，追加段之前只多了一个分隔空行。

**打包配置：`apps/desktop/src-tauri/tauri.conf.json`**

- `bundle.targets` 由 `["deb","appimage","nsis"]` 变成 `["deb","appimage","nsis","app"]`；
  新增 `externalBin: ["binaries/melonarc-core"]`；新增
  `macOS: { minimumSystemVersion: "13.0", signingIdentity: "-" }`。
- `license` 仍是 `GPL-3.0-only`；`productName` / `version` / `identifier` 全部未动。

**配套：`apps/desktop/.gitignore` 与 `apps/desktop/src-tauri/binaries/README.md`（新文件）**

- 忽略 `src-tauri/binaries/*`，只放行那张说明卡；卡上写明三元组命名规则、生成命令、
  sidecar 落点与「`cargo run` 不需要、`tauri build` 需要」。二进制产物永不进版本库。

### 关键决策及理由

1. **选 `externalBin`，不选 bundle 资源。** 查上游 `tauri-bundler` 源码确认：
   `app.rs` 把 `bin_dir = Contents/MacOS` 交给 `settings.copy_binaries`，而
   `settings.rs::copy_binaries` 用 `.replace("-<target>", "")` 去掉三元组后缀，于是
   `binaries/melonarc-core-aarch64-apple-darwin` 最终落在
   `MelonARC.app/Contents/MacOS/melonarc-core`。这**恰好**是 `settings::core_search_paths`
   的第一个候选（`env::current_exe().parent()` 拼上核心名，壳自身也在 `Contents/MacOS/`），
   所以 2200 行 Rust 壳一行都不用改，也不需要 shell 插件或 capability。反过来，bundle 资源
   落在 `Contents/Resources/`，不在现有查找顺序里，必须改 `core.rs` / `settings.rs`——本机
   无 rustc，写一段编不了、测不了的 Rust 代码是本阶段最不该冒的险。附带收获：同一份源码里
   sidecar 被收进 `sign_paths`，在签 `.app` 之前由内向外逐个签名，包里不会留一个未签名的
   Mach-O。
2. **ad-hoc 签名按 D2 落到配置而不是命令行。** `"signingIdentity": "-"` 是官方文档给出的
   ad-hoc 写法；job 因此不需要任何证书、密钥或公证凭据。`hardenedRuntime` 不显式写，保留
   默认 `true`：以后按 D2 的触发条件升级正式签名时不必再翻这个开关；真机放行流程归 M5。
3. **`minimumSystemVersion = "13.0"` 有实测依据。** 本阶段交叉编译出的核心与 CLI，其
   `LC_BUILD_VERSION` 是 `platform=1 minos=13.0.0 sdk=26.2.0`；另外 CLI 源码会把这个值设成
   `MACOSX_DEPLOYMENT_TARGET` 再构建 Rust 侧。核心、壳、对外声明三者对齐，而不是照抄计划
   文档里的结论。
4. **只加 `app`，不动其它 target；只打 `app`。** 保留 deb/appimage/nsis 是任务书的红线，
   `--bundles app` 让本次 CI 只产 .app；DMG 与下载说明属于发布阶段（M5），M1 不预先承诺。
5. **CLI 不做 npm devDependency。** `apps/desktop` 是零依赖前端，现有 frontend job 的
   `npm ci` 因此不需要网络；往 `package.json` 加一条会改变那条 job 的语义。改成装到
   `$RUNNER_TEMP` 再直接调用二进制，还有一个实际好处：`npx <cmd> -- --flag` 的尾部 `--`
   是否被转发给子命令并不确定，直接调用才能保证 `--locked` 原样交给 `cargo build`。
6. **产物先打包再上传。** 裸目录上传会丢可执行位，一个双击不起来的 `.app` 没有验收价值；
   `ditto` 保留 bundle 的权限与符号链接。上传 `.app` 的 zip 与 `Cargo.lock` 两件。
7. **Runner 与目标都锁 arm64。** `macos-15` + 显式 `--target aarch64-apple-darwin` + Go 的
   `GOOS/GOARCH`，Go 侧再关掉 CGO（纯 Go，不依赖 SDK）；即使 runner 标签哪天换了架构，
   产物仍由显式三元组决定。
8. **M1 不加 `cargo test --locked`。** 壳的测试从未在任何机器上编过；首跑若因测试代码失败，
   会把「构建是否打通」这个唯一要回答的问题搅浑。`cargo test` 列为下一步第一件。
9. **文件头 "Three jobs" 注释也保留不改。** 它现在与 4 个 job 不符，但任务书要求现有 job
   一个字都不动，连同注释一起留给所有者在网页端维护时顺手改。

### 构建与测试结果

| 检查 | 结果 |
| --- | --- |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `gofmt -l .` | 0 行 |
| `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...` | exit 0 |
| `go test ./... -count=1 -v` | **1313 / 1292 / 21 / 0**，与阶段 26 基线逐项相同，0 FAIL |
| 前端离线套件（系统 node，`--test-concurrency=1`） | **82 / 80 / 2 / 0**，与基线一致 |
| `GOOS=darwin GOARCH=arm64` 核心 + CLI | 两者均为 `Mach-O 64-bit arm64 executable, flags:<\|DYLDLINK\|PIE>`（15,298,002 B / 6,490,146 B） |
| Mach-O 部署目标 | `LC_BUILD_VERSION platform=1 minos=13.0.0 sdk=26.2.0`（核心与 CLI 相同） |
| `tauri.conf.json` | `python3 -m json.tool` 通过；`externalBin`、`macOS.signingIdentity`、`macOS.minimumSystemVersion`、`BundleType` 的 `app` 逐个对官方 schema 核过 |
| `ci.yml` | 用模块缓存里的 `gopkg.in/yaml.v3@v3.0.1` 离线做真解析：4 个顶层键、4 个 job（7 / 11 / 6 / 12 步）、`runs-on=macos-15`；12 步中 8 个 `run:` 块逐个 `bash -n` 全过 |
| 既有 job 对照 | 原 9416 字节逐字节相同 |
| CI 用的最小 smoke 配置 | 本机用真核心跑 `-check`：打印 `melonarc-core 0.1.0-dev` 后 exit 0，`data-dir` 目录未被创建 |

前端离线套件里有一条用例读 `tauri.conf.json` / `Cargo.toml` 与 `src/version.js` 对齐，改完
配置仍绿；`go.mod` / `go.sum` / `package.json` / `package-lock.json` / `Cargo.toml` 均未进入
改动集。本机没有 PyYAML / ruby / yq，pip 装包被代理 502 挡下，所以 YAML 解析改走 Go 模块
缓存里的 `yaml.v3`（`replace` 到 `$GOMODCACHE`，`GOPROXY=off`）。

本地踩到并当场修掉两处：① `-s -w` 是链接器参数，直接给 `go build` 会报
`flag provided but not defined: -s`，改成 `-ldflags "-s -w"`（与 `scripts/build-release.sh`
一致），CI 与说明卡同时改；② 尾部 `--` 经 `npx` 转发的语义不确定，换成仓库外安装 CLI 后
直接调用，避免 `--locked` 被包装器吃掉。

**没有验的，如实列出**：Rust 壳编译、`cargo generate-lockfile`、Tauri 打包、`codesign` /
`plutil` / `ditto`、图形界面双击启动、原生桥读核心状态。本机无 rustc / cargo / macOS SDK /
网页视图依赖，也没有 macOS 运行环境；这些正是新 job 与 M5 存在的理由，不得当作已通过。

### 遗留问题

- **macos job 首跑是否绿，本阶段不知道**：`ci.yml` 由所有者经网页端维护，这里只负责本地改对
  并提交，无 CI 运行权。首跑可能暴露的真问题：从未编译过的 `src-tauri` Rust 代码、首次解析
  出的依赖版本、icns 生成、ad-hoc 签名与 sidecar 的封印。
- **`Cargo.lock` 尚未提交**：要等首跑绿后从 artifact 取回并提交，再按清单 A2 的要求据锁定
  版本重写 `THIRD-PARTY-NOTICES.md` 第 5 节。在那之前 **A2 仍 blocked**；**B4 也仍 blocked**
  —— 本 job 只做 `cargo build --release`，没有 `cargo test --locked` 与真窗口验收。计划文档
  说的「A2/B4 顺带销账」是**机制到位**，不是已经销账。
- **图标**：bundler 的 `create_icns_file` 会把现有 512/256/128/32 PNG 打包成 icns（非 2 的幂
  尺寸会 `resize_exact`，不要求 1024），所以 M1 没有新增 icns；但缺 1024 条目，大图标观感与
  icns 确认仍按计划归 M3。
- macOS 上核心的系统代理仍是 unsupported，TUN 仍无实现；按 D1=A，MVP 只做系统代理模式，
  TUN 在矩阵标未实现。M1 的 `.app` 因此**至多只能**用于验启动与读一次状态，不能验接管与恢复。
- `hardenedRuntime` 取默认 `true`；ad-hoc + 硬化运行时在干净系统上的首次放行流程只能由 M5
  实测。
- 分发形态：M1 只产 `.app`（任务书指定的 `app` bundle target），DMG、下载处的 ad-hoc 说明与
  SHA-256 是 M5 / 发布阶段的事。
- 文件头 "Three jobs" 注释因「现有 job 一字不改」而保留，现已与实际 4 个 job 不符。
- 阶段索引表仍停在阶段 22（23–26 与 M1 都没有行），沿用阶段 26 的做法不擅自回填。
- 其余阶段 8–26 的既有挂账照旧：Windows 实机 C1、性能实测 C2、端到端安装 C3、真 TUN 枯竭
  计数非零态、`core.log` 无轮转、用户态 TCP 的 IPv6 / 乱序 / 窗口缩放、Flush 与整表重写、
  预览桥 query string、订阅明细理由文案统一。

### 下一步计划

1. 由所有者触发 CI 看 macos job 首跑：绿了就下载 `Cargo.lock` 提交、按 A2 重写 notices
   第 5 节；红了按日志**只修 job 与壳的构建问题**，不动订阅与解析。
2. 给 job 补 `cargo test --locked`（B4 的第一半），再谈真窗口、单实例锁与设置文件路径验收。
3. M2：datadir 路径核对 + 系统代理 macOS 后端（按网络服务记录 HTTP / HTTPS / SOCKS / PAC /
   旁路列表，快照、接管、恢复，专测部分写入成功且回滚也失败），M3：干净账户首启、首份配置
   与令牌路径定死、icns 确认。
4. M4/M5：完整网页视图 → invoke → Rust → Go 链路（读状态 + 一次写操作）、强杀与代理恢复、
   干净虚拟机的 ad-hoc 首次放行流程；通过后才动 README 四语矩阵与预发布清单。

## 阶段 M2 — macOS 核心适配：`networksetup` 后端与数据目录核对（2026-11-18）

范围：仓库外计划 `~/workspace/projects/melonarc-macos-plan.md` 的 M2 节，按 D1（A：MVP 只做
系统代理，TUN 标未实现）与 D2（A：ad-hoc 签名，M1 已配好）推进。本阶段只动核心：
`internal/sysproxy`（新增 darwin 后端、修控制器的一条恢复语义）与 `internal/datadir`（只加
用例，不改实现）。不碰 `.github/workflows/ci.yml`、不碰 `apps/desktop`（壳适配是 M3）、不实现
TUN、不改 `examples/melonarc.conf` 的 `data-dir` 语义（首份配置的生成策略在 M3 定死）、不新增
依赖。只本地提交，不 push、不打 tag、不发 release。

开工前：`HEAD = 7ee76d5`（M1），工作区干净，go1.27.4，单分支 `master`。按任务书先读
`DEVLOG.md`（M1 与阶段 22–26）、计划文档 M2 与 D1/D2、`internal/sysproxy` 全部源文件与
`sysproxy_test.go`、`internal/config` 的 `data-dir` 处理、`apps/desktop/src-tauri/src/` 的
`settings.rs` 与 `core.rs`。基线用 `git worktree` 在 7ee76d5 上重跑确认：Go
**1313 / 1292 / 21 / 0**，前端离线 **82 / 80 / 2 / 0**。

### 完成了什么

**一、darwin 路径与数据目录逐项核对**

| 项 | 核心（Go） | 壳（Rust） | 结论 |
|---|---|---|---|
| 配置目录根 | `os.UserConfigDir()`；Go 1.27 源码的 darwin 分支是 `$HOME/Library/Application Support` | `config_home()` 返回同一目录 | 一致 |
| 默认 data-dir | `<配置根>/melonarc`（`datadir.Default`） | `shell.json` 的父目录，默认同一路径 | 一致，前提是 `shell.json` 没改 `data_dir` |
| 令牌文件 | `<data-dir>/api-token`，0600，临时文件 + rename | `settings.token_path()` = `<data_dir>/api-token` | 一致；名字由新用例守着 |
| 核心配置 | 只认 `-config` 给的路径 | 默认 `<data-dir>/melonarc.conf`，经 `-config` 传 | 一致 |
| API 地址 | 配置里的 `api-listen` | 每次启动都传 `-api-listen` 覆盖 | 壳优先（M1 起如此） |
| `core.log` | 核心只写 stdout/stderr | 壳打开 `<data-dir>/core.log` 作为子进程的 stdout/stderr | 一致 |
| 系统代理快照 | `<data-dir>/system-proxy.json` | 不读 | 核心独占 |
| 观察历史 | `<data-dir>/history.sqlite3` | 不读 | 核心独占 |
| 订阅缓存 | `<data-dir>/subscriptions/` | 不读 | 核心独占 |

核对出四件事，都只记录、不改：

1. **核心没有 `-data-dir` 旗标**（只有 CLI 有，用来找令牌）。壳启动核心时只传 `-config` 与
   `-api-listen`，所以核心的 data-dir 完全由配置文件决定：`data-dir` 为空 → OS 默认；相对路径
   → **相对配置文件所在目录**（`cfg.BaseDir`）。两侧是两套独立计算，谁都没有核对谁。
2. **示例配置的陷阱确认成立**：`examples/melonarc.conf` 写的是 `data-dir = ./melonarc-data`。
   若 M3 把这份示例复制成 `~/Library/Application Support/melonarc/melonarc.conf`，核心会把令牌
   写到 `.../melonarc/melonarc-data/api-token`，而壳读 `.../melonarc/api-token`：壳能把核心拉
   起来，但它的 API 客户端拿不到令牌（请求 401），面板看起来是「核心在跑、读不到状态」。
   同一份 `data-dir` 还会带走历史库、订阅缓存与系统代理快照。
3. **反向也成立**：若 `shell.json` 的 `data_dir` 改成非默认值而配置里 `data-dir` 留空，核心写
   OS 默认目录、壳读新目录，同样错位。也就是说两侧一致只在两种情况下成立——都用默认值，或者
   配置里写了与壳 effective data_dir 相同的**绝对**路径。M3 定首份配置策略时要在这两条里选。
4. 快照在核心 data-dir 内：配置里的 `data-dir` 一旦变化，上一次残留的接管记录就留在旧目录，
   下次启动不会去那里恢复。M3 若允许改 data-dir，这条要一起处理。

**二、`networksetup` 后端（新文件 `internal/sysproxy/networksetup.go`）**

- 平台接线：新增 `platform_darwin.go`（`//go:build darwin`，`platform()` 返回
  `newNetworkSetup(osRunner)`）；`platform_other.go` 的构建标签从 `!linux && !windows` 收紧为
  `!linux && !windows && !darwin`，unsupported 后端只留给其余系统。后端实现本身**不带构建
  标签**（与 `gsettings.go` / `registry.go` 同构），所以整套用例能在 Linux 上跑。
- 作用范围：`-listallnetworkservices` 列出的**每个启用中的网络服务**（首行说明跳过、`*` 前缀
  表示禁用即跳过）。理由见决策 2/3。
- 每个服务写入的字段与顺序（也就是快照 `Fields` 的顺序）：

  ```
  1 autoproxy-state      -setautoproxystate <svc> off          PAC 先关
  2 autoproxy-url        仅记录（Observed），不写
  3 auto-discovery       -setproxyautodiscovery <svc> off
  4 bypass-domains       -setproxybypassdomains <svc> d1 [d2…] 或 Empty
  5 web-proxy            -setwebproxy <svc> host port  + -setwebproxystate <svc> on
  6 secure-web-proxy     同上（HTTPS 用的就是 HTTP 入站，它答 CONNECT）
  7 socks-proxy          -setsocksfirewallproxy … + -setsocksfirewallproxystate …
  ```

  配置里没有某一类监听时，对应的字段只剩开关（`web-proxy-enabled` / `socks-proxy-enabled`），
  只写 `-set<kind>proxystate <svc> off`，不动原来的地址。
- 快照值：一个代理的三部分合成一个值 `"on|127.0.0.1|7890"`，因为工具没有「只写地址不动开关」
  的命令，`-setwebproxy` 本身会把代理打开。所有权判断因此按整个代理做：用户改了地址或端口，
  这个字段就整个不还原。
- 恢复：`restoreFields` 反向走（socks → secure → web → bypass → discovery → PAC），每步先读回
  当前值，只有等于本程序写的值才动。原来地址为空的代理只还原开关，不写空地址（工具没有清空
  地址的命令；与 registry 后端「留着地址、关掉开关」的处理一致）。
- `Clear`：只把每个启用服务的三个开关关掉，PAC 与旁路列表不动（它们从不指向本程序的监听），
  单个失败不中断其余服务，错误用 `errors.Join` 汇总。
- `Enabled`：任一启用服务上，web / secure / socks / PAC / 自动发现有一个开着就算开。
- 读的命令与容错：`-getautoproxyurl`（URL + Enabled）、`-getproxyautodiscovery`、
  `-get{web,secureweb,socksfirewall}proxy`（Enabled / Server / Port / Authenticated Proxy
  Enabled）、`-getproxybypassdomains`（有列表时是 `Bypass Domain(s): a, b`，空列表时是
  `There aren't any …` 一句整句）。缺 `Enabled` 行、端口不是数字、旁路两种形状都不是 →
  **报错而不是当成空值**：错的 Before 值比没有更危险。标签分隔按第一个冒号切，所以
  `Server: fe80::1%en0` 与带端口的 PAC URL 都不会被截坏。
- 认证代理：读到 `Authenticated Proxy Enabled: 1` 且配置要求替换这一类代理时，`Plan` 直接
  拒绝并点名服务（见决策 8）。
- 权限与等待：全程用 `/usr/sbin/networksetup`、进程自身权限，不 sudo、不装 helper、不弹自定义
  对话框、不写偏好设置 plist。写批次有 12 秒预算（决策 10），超时把「signal: killed」翻成一句
  能行动的话：`networksetup did not finish in time; macOS may be waiting for an administrator…`。

**三、控制器：部分写入成功且回滚也失败时保留恢复依据**

- 原来的 `Controller.Enable` 在 `Commit` 报错后无条件 `removeSnapshot`，注释写的是「Commit 已经
  回滚，机器上没有我们的值了」。这句话在回滚**也**失败时不成立：机器上还留着本程序写的一半
  值，而唯一描述它们的文件被删掉，下次启动无从恢复。
- 新增 `ErrRollbackIncomplete`；三个后端在回滚有字段没还原时用双 `%w` 的 `fmt.Errorf` 同时包住
  原始错误与这个哨兵（`errors.Is` 两处都看得见）。`Enable` 见到哨兵时**保留**记录、打一条
  Error 日志、返回明说「记录已保留，下次启动可以恢复」的错误；同时把内存快照与 `Applied()` 置
  为真，让同进程内仍会发生的优雅关停还有一次机会。回滚成功的那条路径行为不变，只是删除记录
  失败时从 `_ =` 改成记一条 Warn。
- 三个后端都改：`gsettings`（回滚在第一个失败处停下）、`registry`（add 或 delete 失败）、
  `networksetup`（反向逐字段重写 Before，失败即 incomplete）。

**四、15 秒启动预算：代码层面的等待路径**

`core.rs` 的事实：`STARTUP_BUDGET = 15s`、`TICK = 500ms`、`MAX_FAILURES = 5`、退避
1/2/5/5 秒，第 5 次失败后状态变 `crashed` 且不再自动重试；子进程自己退出或超预算都算一次失败。
核心侧的顺序是「入站 → TUN → 系统代理 → … → API 开始应答」，所以系统代理的写入**在预算之内**。

原来这条路径没有上界：`networksetup` 的第一次写可能停在授权对话框上等人，核心既不应答 API 也
不退出，15 秒一到壳把子进程杀掉——对话框被连根拔掉，下一次尝试再弹一个。现在的代码层面约定：

- 写入批次 12 秒（`writeBudget`）< 壳的 15 秒，中间留给读取阶段与进程退出。超时由核心**自己**
  结束并带原因退出，壳永远不会在对话框中途杀它。
- 核心内部**不重试**：一次 `Enable` 只写一遍，失败就报。
- 读取路径不设预算：读设置不需要授权，也不可能弹出对话框。
- 残留：壳仍会退避重试最多 5 次（这是 `apps/desktop` 的行为，本阶段不许改），所以「每次都
  弹窗」的极端情况最坏是 5 次。macOS 通常会记住刚授予的授权，但这一条本机无法验证，记在
  「没有验的」里；壳侧的一次性策略留给 M3。

### 关键决策及理由

1. **后端实现不带构建标签，只有 `platform()` 在 `platform_darwin.go` 里。** 与 gsettings /
   registry 同构，换来的是整套解析、快照、回滚、预算逻辑都能在 Linux 上跑用例；darwin 独有的
   只剩一行接线，另有一个 `//go:build darwin` 的小用例在真机上验它。
2. **覆盖每个启用中的服务，不只挑一个「主服务」。** 要判断哪个服务在承载流量，得把默认路由
   的接口映射回服务名，多一层易错的推断；笔记本在 Wi-Fi 与有线之间切换时，只改一个服务等于
   换个网络就失效。逐服务记录、逐服务恢复，范围变大但语义不变。
3. **禁用服务（`*` 前缀）不碰。** 它不在承载流量，写它只是给用户添一条看不见的改动。
4. **一个代理的地址与开关合成一个快照值。** 工具的两条命令无法分开写：`-setwebproxy` 会顺手
   把代理打开。若拆成两个字段，恢复顺序里「先还原开关、后还原地址」会把刚关掉的代理又打开；
   合成一个值后，写入与恢复都以「这个代理当时是什么样」为单位，所有权判断也以它为单位。
5. **写入顺序：PAC → 自动发现 → 旁路 → 三个代理。** PAC 关掉是因为客户端优先用脚本，不关就
   等于没接管；旁路列表先于任何代理打开，是因为本机流量不该在接管过程中绕一圈；恢复反向，
   于是三个代理先关、旁路与脚本最后回。
6. **PAC 只记地址、只写开关。** `-setautoproxyurl` 会「设置并启用」，用它来关就等于把地址也
   改了；`-setautoproxystate` 只动开关不动 URL，正是需要的那一半。地址记进快照（`Observed`）
   是为了让人看记录时知道原来指向哪里，恢复时没有它的事。
7. **`-setautoproxystate` 在旧 man page 里没有条目，仍然用它。** 没有别的命令能在不碰 URL 的
   前提下关掉 PAC；新系统上这条命令存在且被广泛使用，但本机无从验证，M5 真机必查（见「没有
   验的」）。
8. **认证代理直接拒绝，不接管。** `-getwebproxy` 只说「要口令」，从不给口令；接管后再恢复，
   地址回来了、口令没有，用户的代理会开始 407。宁可让启动失败并点名哪个服务要关掉认证代理，
   也不做这种静默破坏。M5 若证明 `-setwebproxy` 不会清掉钥匙串里的口令，这条可以放宽成「记录
   认证标志并照常接管」。
9. **空的旧地址不还原成空。** 工具没有「清空地址」的命令；把开关关掉、留一个指向本程序的旧
   地址，危害与 registry 后端 `Clear` 留下的旧地址同级（代理关着，不会有人走它）。这一条有
   用例守着，免得以后有人以为是漏写。
10. **12 秒预算按「写批次」而不是按命令或整个 `Enable`。** 弹窗只可能出现在写上，读不会；按
    命令设预算会让「9 次写 × N 个服务」累加成几十秒，按整个 `Enable` 设又要把预算塞进控制器
    （Linux/Windows 不需要）。一个批次一个上界，最坏路径是 Plan（快）+ Commit（≤12s），仍在
    15 秒内。
11. **给控制器而不是给后端加「保留记录」的判断。** 快照归控制器管，后端只负责「我有没有把
    自己写的东西收干净」，用哨兵错误表达；这样三个后端的失败语义一致，删除与否只有一处决定。
12. **不在本阶段给核心加 `-data-dir` 旗标。** 加了就等于替 M3 定死首份配置策略（示例配置的
    相对 `data-dir` 还要不要保留、`shell.json` 与配置谁赢）。本阶段只把不变量写清楚：两侧一致
    ⇔ 都用默认值，或配置里是与壳 effective data_dir 相同的绝对路径。

### 构建与测试结果

| 检查 | 结果 |
| --- | --- |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `gofmt -l .` | 0 行 |
| `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...` | exit 0 |
| `GOOS=darwin GOARCH=arm64 go build ./cmd/... ./internal/...` | exit 0；核心与 CLI 均为 `Mach-O 64-bit arm64 executable, flags:<\|DYLDLINK\|PIE>`（未加 `-trimpath -s -w`，22,964,562 B / 9,641,746 B） |
| `GOOS=darwin GOARCH=arm64 go vet ./internal/sysproxy ./internal/datadir` | exit 0（两个 darwin-only 用例文件也过了类型检查） |
| `go test ./... -count=1 -v` | **1338 条目 / 1317 通过 / 21 跳过 / 0 失败** |
| 前端离线（系统 Node 24，清代理，`--test-concurrency=1`） | **82 / 80 / 2 / 0**，与基线逐项相同 |
| 与基线名单对照（`git worktree` 在 7ee76d5 上重跑） | 基线 1313 / 1292 / 21 / 0；减少的只有两条带随机端口的 `TestSOCKS5Connect/<addr>:<port>` 子用例（既有噪声），其余 +25 条全部是新增 |

跳过集合仍是固定那 21 条（缺参考实现的互通 10、未连接 `sendto` 的 UDP 9、上游 UDP 截断改 TCP
1、`TestTUNLinuxLoopback` 1），逐名一致。新增 25 条：

| 包 | 新增条目 | 内容 |
|---|---|---|
| `internal/sysproxy` | +24 | `networksetup` 13 条用例 + `Enabled` 1 条（含 6 条子用例）+ 3 条控制器 + 1 条 gsettings 回滚 |
| `internal/datadir` | +1 | 壳/核心常量交叉核对 |

`networksetup` 的用例覆盖：整套写入的命令行与顺序（含禁用服务不被碰）、`Plan` 的字段顺序与
Before/Written 值、只配置一类监听时另一类只关开关、写失败后逐字段回滚到原值、回滚也失败时报
`ErrRollbackIncomplete`、用户改过的字段不被覆盖、旧地址为空时只还原开关、`Enabled` 的六种输入、
`Clear` 的三条命令与服务覆盖、没有启用服务时报错、认证代理被拒绝（且拒绝时一个写都没发生）、
等待授权的写入被预算截断并给出可行动的文案、`Restore` 会先读回每个字段、快照值的字符串往返。
控制器三条：回滚失败时记录仍在、`Applied()` 为真、随后的 `Release` 仍能收尾并删掉记录；同一个
文件被**下一个**控制器 `Recover` 读到时能真的恢复（这条直接对应「下次启动仍有恢复依据」）；
回滚成功时记录被删、`Applied()` 为假。

前端实时套件**没有重跑**（本阶段没动 `apps/desktop`，M1 也未重跑），口径同 M1。

### 没有验的（如实列出）

- **真机 `networksetup` 接管与恢复**：本机没有 macOS、没有 `networksetup`，全部写入路径只在
  fake 上跑过，命令字符串与解析是按手册与文档写的。
- **授权路径**：授权弹窗的出现条件、拒绝后的行为、拒绝是否会被记住、12 秒预算够不够一个人
  读完并点「允许」——这台机器没有可测的标准账户或管理员账户。
- **15 秒启动预算的真机表现**：壳在真实弹窗存在时的表现（是否真的不会中途杀进程、重试期间
  弹窗是否叠加）只能上 Mac 才能看。
- **`-setautoproxystate`**：目标系统上是否可用未验（旧 man page 无此条目）。
- **`-setwebproxy` 对钥匙串口令的影响**：是否会清掉已保存的认证口令未知，所以本阶段选择拒绝
  认证代理（决策 8）。这一条决定以后能不能放宽。
- **干净账户下的路径**：首次启动时目录创建、0700/0600 在 APFS 上的实际效果、`os.UserConfigDir`
  在真实 `$HOME` 下的返回值——只有 darwin-only 用例能在 Mac 上验，本机只保证它能编译。
- **多个服务同时活动**（Wi-Fi + 有线）时的接管与切换行为。
- **打包后的核心**在 `.app` 内的查找（M1 的 `externalBin` 结论未变，本阶段没有复验）。
- **两个 darwin-only 用例**（`TestDefaultMatchesTheShellOnMacOS`、
  `TestPlatformIsTheNetworkSetupBackend`）本机不运行，也不在 1338 条里。

### 遗留问题

- **M3 必须定死首份配置的 `data-dir` 策略**：三条候选是（a）省略 `data-dir`，两侧都用 OS 默认；
  （b）写与壳 effective data_dir 相同的绝对路径；（c）给核心加 `-data-dir` 旗标、由壳传值，
  让 `shell.json` 成为唯一来源。本阶段只把不变量与陷阱写清楚，没有动示例配置。
- 若 M3 允许用户改 data-dir：核心 data-dir 里的 `system-proxy.json` 会留在旧目录，旧接管记录
  失去恢复入口；历史库与订阅缓存同理。
- 认证代理的拒绝是保守选择，代价是这类机器开不了系统代理；M5 真机复验后再决定是否放宽。
- 壳的 5 次重启策略不受核心控制：预算只保证「不死在对话框里」，不保证「只弹一次」。壳侧是否
  改成首启单次或读退出码，归 M3。
- `-setautoproxystate` 是否存在、`-getproxybypassdomains` 空列表那句的确切文案随系统版本可能
  变化；自动发现的解析只依赖「标签里带 discovery 的行」，旁路列表两种形状都认，但真机文案
  仍可能不同。
- 阶段索引表仍停在阶段 22（23–26、M1、M2 都没有行），沿用既有做法不擅自回填。
- 其余阶段 8–26 的既有挂账照旧：Windows 实机 C1、性能实测 C2、端到端安装 C3、`Cargo.lock`
  与 A2/B4、Rust 壳编译与真窗口验收、真 TUN 枯竭计数非零态、`core.log` 无轮转、用户态 TCP 的
  IPv6 / 乱序 / 窗口缩放、Flush 与整表重写、预览桥 query string、订阅明细理由文案统一。

### 下一步计划

1. M3：壳适配与首次启动——把首份配置的 `data-dir` 策略定死（在上面三条里选一条并写进壳与
   文档）、复核 `core.rs` 的查找顺序与 bundle 布局、icns 生成、单实例锁与 `shell.json` 路径。
2. 有 Mac 时先跑两个 darwin-only 用例，再按「Wi-Fi 单服务 → 有线 → 两者同时」的顺序验接管与
   恢复；授权拒绝、等待超时、弹窗次数一并记下来。
3. 若 M1 的 macos job 首跑已绿：取回 `Cargo.lock` 提交、据锁定版本重写 notices 第 5 节，销
   A2/B4 的第一半；再给 job 补 `cargo test --locked`。
4. M4/M5 按计划：完整链路与写操作、强杀后的代理恢复、干净虚拟机的 ad-hoc 首次放行流程。

## 阶段 M3 — 最小原生 macOS 应用：Xcode 工程、托管核心与 xcodebuild 入口（2026-11-18）

范围：仓库外计划 `~/workspace/projects/melonarc-macos-plan.md` 与决策附录
`~/workspace/projects/melonarc-gpt-answers-native-shell-20261118.md` 的 M3 节，按 D4/D5/D6/D7/D8/
D9/D10/D11 推进。只新增 `apps/macos/`、给核心加两个托管旗标及其用例、把 `.github/workflows/
ci.yml` 的 macOS job 换成 xcodebuild 入口；`apps/desktop`（Windows/Linux 的 Tauri 壳）、
`spikes/`、`docs/`、`examples/melonarc.conf` 都不动，TUN 仍标未实现，不新增依赖。不 push、不打
tag、不发 release。

开工前 `HEAD = 95fc25e`（M2），基线 Go **1338 / 1317 / 21 / 0**、前端离线
**82 / 80 / 2 / 0**。本机是 Linux 虚拟机：没有 Xcode、macOS、Swift 编译器、codesign、hdiutil，
Swift 代码从未被编译过，`.app` 从未被启动过；凡属这部分一律写进「没有验的」，不冒充验过。

### 完成了什么

**一、首份配置的 `data-dir` 策略定死：选 (c)——核心加旗标，壳每次显式传值**

- `cmd/melonarc-core/main.go` 新增两个旗标：
  - `-data-dir <path>`：覆盖配置文件里的 `data-dir`，与配置值一样经 `datadir.Resolve` 解析
    （相对路径仍相对配置文件所在目录）。旗标优先；若配置也写了且不相等，启动日志打一条 Warn
    同时点名两个目录，不静默选一个。
  - `-supervise-stdin`：仅在托管模式启用。要求标准输入是具名管道（`/dev/null` 与普通文件直接
    拒绝启动），EOF 即视为父进程消失，走与正常退出相同的优雅关停；管道里若有杂字节只计数、
    不当命令解析。
- 新增 `cmd/melonarc-core/supervise.go` 与 7 条用例（`supervise_test.go`）：旗标优先、两者一致
  时静默、缺省落到平台默认、管道形状校验、EOF 关停、写端未关时不误判、`-check` 报旗标的目录。
- 壳侧 `FirstRunConfig.contents` **不写 `data-dir`**，并把理由写进文件注释；`CoreSupervisor.makeChild`
  每次启动都显式传
  `-config <path> -api-listen <addr> -data-dir <path> -supervise-stdin`。
  `ShellSettings` 解析出的 effective data-dir（`shell.json` 的 `data_dir` → 环境变量
  `MELONARC_DATA_DIR` → 平台默认，沿用旧壳优先级）就是这一项的值；令牌、日志、锁、配置、
  历史库、订阅缓存与系统代理快照都从同一目录读。`shell.json` 是规范来源，环境变量只作兼容
  覆盖，壳把**解析后的最终值**传给核心，不再让两侧各自算一遍。
- `examples/melonarc.conf` 里的 `data-dir = ./melonarc-data` 保持原样（不改示例语义）：它不再是
  首份配置的来源；即使有人手抄成首份配置，旗标也赢，且那条 Warn 会点名目录分歧。
- 本机实核验证：`-check -data-dir <dir>` 首行仍为 `melonarc-core 0.1.0-dev`，`data:` 与
  `token:` 都指向旗标的目录且不建文件；真实启动的 `api token file:` 也落在该目录；
  `( sleep 2 ) | core … -supervise-stdin` 在约 3 秒内自行退出 0，`< /dev/null` 被明确拒绝并
  退出 1。

**二、原生工程与最小界面**

- `apps/macos/MelonARC.xcodeproj`：app target + `MelonARCTests` target，共享 scheme
  `xcshareddata/xcschemes/MelonARC.xcscheme`，`project.xcworkspace/contents.xcworkspacedata`；
  `MACOSX_DEPLOYMENT_TARGET = 13.0`、`ARCHS = arm64`、`CODE_SIGN_IDENTITY = "-"`、
  `ENABLE_HARDENED_RUNTIME = YES`、`ENABLE_APP_SANDBOX = NO`。CopyFiles 阶段
  `dstSubfolderSpec = 6` 把 `Core/melonarc-core` 放进 `Contents/MacOS`，带 `CodeSignOnCopy`。
- `App/MelonARCApp.swift`：一个 `Window` + `NavigationSplitView`，一个 `Settings` scene，
  一个 `MenuBarExtra`。关闭最后一个窗口不退出（`applicationShouldTerminateAfterLastWindowClosed
  → false`），只有「退出」停核心；macOS 13 用原生「设置…」与 ⌘,，不用需要 macOS 14 的
  `SettingsLink`。`AppDelegate` 用 `NSApplicationDelegateAdaptor` 接管激活、Dock 重开、
  第二实例的窗口唤起，并在 `applicationShouldTerminate` 里 `.terminateLater` 等核心恢复代理。
- `Services/CoreSupervisor.swift`：`Foundation.Process` 托管真实核心，15 秒启动预算、500 ms
  心跳、1/2/5 秒退避、连续 5 次失败上限与手动重试；私有管道确认「本次子进程」已绑定端口并写
  好令牌，再用带 Bearer 的 `/v1/status` 判就绪；`terminationHandler` 区分主动/意外退出；
  端口占用从核心输出的 `address already in use` 归类。正常退出先取消自动重启、关管道、
  SIGTERM，再异步等最多 12 秒（核心自身 5 秒预算 + 系统工具余量）；强杀 GUI 时写端 EOF 让
  核心自己走同一条退出路径。
- `Services/APIClient.swift`：专用 `.ephemeral` `URLSession`、`connectionProxyDictionary = [:]`
  （空字典＝不用系统代理/PAC，`nil` 才是跟随系统）、无缓存无 Cookie、重定向委托一律拒绝；
  `Codable` + `convertFromSnakeCase`，`APIError` 只回稳定 `code` 与英文 `detail`，不回显令牌。
  `Info.plist` 的 ATS 例外**只有 `127.0.0.1`**；`APIAddress.parse` 相应只接受 127.0.0.0/8 与
  `localhost`（映射到 127.0.0.1），`[::1]` 明确拒绝并指引改用 IPv4 回环，避免出现第二个需要
  例外的地址。
- `Services/FirstRunConfig.swift`：干净数据目录首次启动写最小直连配置（只监听回环、
  `FINAL,DIRECT`、无代理/订阅/系统代理/TUN），目录 0700、文件 0600，已有配置绝不覆盖。
  `SingleInstanceLock.swift`：`flock(LOCK_EX|LOCK_NB)` 的 `shell.lock`，占用时唤起已有进程后
  退出，锁文件不可用则显示原因但继续运行（沿用旧壳的宽容策略）。
- `UI/PanelRegistry.swift` 先注册 7 个面板（总览 + 六个业务/设置），总览读鉴权后的
  `/v1/status` 与 `/v1/config`，其余先给占位页；2 秒轮询在离开窗口时停，列表有界。
  `Resources/Localizable.xcstrings` 59 个 key、en + zh-Hans；`AppIcon.png` 由现有图标用图像
  工具重采样为 1024×1024 sRGBA（见「没有验的」：Xcode 的 icns 编译未跑）。

**三、订阅能力按 D9 先核对再决定**

- 工作树里只有 `GET /v1/subscriptions` 与 `GET /v1/subscriptions/{name}/skipped` 两条只读
  出口，没有刷新/启用/删除端点；公开版本确实没有专用订阅管理接口。因此本阶段**不在 Swift
  里另造一套订阅逻辑**：订阅面板只注册、显示占位；缺失的能力留到后续补进 Go API，再由
  `APIEndpoint` 增一个 case 和一个方法接上。阶段 26 的 `Status.Skipped` 出口与三种空答案语义
  没有改动。

**四、CI macOS job 换入口（D10 顺序）**

`.github/workflows/ci.yml` 第四个 job 从 Tauri 构建整体替换为：

1. 单一环境变量 `XCODE_APP` 锁定 Xcode，不存在就报出候选列表并失败；`xcode-select -s` 后把
   Xcode/Go/Swift/`sw_vers`/`uname -m` 原样记进 `toolchain.txt` 并上传。
2. 跑 `apps/macos/scripts/check-project.py`（工程对象闭包、引用完整、源文件归属）与
   `check-strings.py`（catalog JSON、双语占位符一致、源码字面引用）。
3. `build-core.sh` 按 `go.mod` 构建 `darwin/arm64`、`CGO_ENABLED=0`、`-trimpath -s -w`、
   `MACOSX_DEPLOYMENT_TARGET=13.0` 的核心，输出即 Xcode 的 `Core/melonarc-core` 输入。
4. `xcodebuild test -destination 'platform=macOS,arch=arm64'`，注入 `MELONARC_TEST_CORE` 跑真
   sidecar 用例；日志里若出现「MELONARC_TEST_CORE is not set」直接判失败，不让跳过冒充通过。
5. `xcodebuild -configuration Release build`，再 `verify-binaries.sh` 用 `lipo`/`vtool` 分别查
   主程序与核心的架构和 `minos 13.0`。
6. `package-dmg.sh` 先签核心再签 `.app`（ad-hoc + Hardened Runtime、无额外 entitlement），
   `codesign --verify --deep --strict` 递归校验并检查两个二进制的 runtime 标志；
   `hdiutil create -format UDZO` → `hdiutil verify` → 只读挂载后再验包结构与签名 → 卸载；
   最后对 `.dmg` 文件本身 `shasum -a 256`，DMG、校验文件与日志一起上传。

Tauri 壳继续留在 `apps/desktop` 供 Windows/Linux 使用；本阶段既不删它的打包配置，也不再在
macOS job 里生成 `Cargo.lock`/`.app.zip`。M1 计划里「取回 Cargo.lock」那一步因此不再属于
macOS 主线，A2/B4 仍挂在跨平台壳上。

### 关键决策及理由

1. **首份配置选 (c)，并让旗标赢。** (a) 只靠「双方都用默认」在用户编辑配置或 `shell.json` 后
   立刻失效；(b) 要求用户维护一份绝对路径，示例里的相对 `data-dir` 就是反例。(c) 把唯一来源
   放在壳解析出的 effective data-dir，核心按旗标使用，两侧不可能再各算一遍；配置里若写错，
   警告点名两个目录，不静默吞掉。代价是核心多一个旗标、旧配置里的 `data-dir` 对新壳不再具有
   决定性——这正是要的效果。改动 data-dir 后的旧快照不迁移，见遗留问题。
2. **存活管道用独立旗标而不是默认行为。** 手工运行核心时 stdin 常是终端或 `/dev/null`，默认
   把它当关停信号会误伤；只有壳显式加 `-supervise-stdin` 且 stdin 确为管道才启用。
3. **退出等 12 秒而不是旧壳的 3 秒。** D7 要求先给 Go 完整恢复代理的机会；核心自身 5 秒预算
   加上每次 `networksetup` 的 12 秒写批次上界，留 12 秒才不至于把「等待恢复」变成「杀掉恢复」。
4. **ATS 只开一个例外。** D5 明确只允许 `127.0.0.1`，所以解析器也随之收紧：与其在 plist 里
   为 IPv6 回环再开一个洞，不如把地址限制在唯一有例外的回环字面量上，令牌不会被送到没有例外
   的地址。
5. **控制会话不用系统代理、不跟随重定向。** 该会话要在「本程序刚把机器代理改错」的状态下仍
   能工作；`connectionProxyDictionary = [:]` 是苹果文档定义的「无代理」，`nil` 才是跟随系统。
   重定向会把 Bearer 带去另一个 origin，因此委托一律拒绝。
6. **AppKit 管生命周期、SwiftUI 管界面，不引 XPC。** 只有 `.terminateLater` 能异步回答
   `applicationShouldTerminate`；XPC 会为这一版引入额外的服务安装与权限面，D5 的回环 HTTP
   已经够用。菜单、设置、窗口都由原生 scene 承担，不嵌 WKWebView。
7. **M3 只填总览。** D11 把「原生菜单栏 → 真核心 → 安全退出」定为最高优先级，其余面板按计划
   在 M4 接；面板注册表先把位置占住，后面新增面板不用改导航代码。
8. **签名与打包全用苹果工具。** ad-hoc + Hardened Runtime、沙盒关、不预加调试/JIT/禁用库校验
   entitlement；先签核心再签 `.app`，`codesign --verify --deep --strict` 递归验；DMG 用
   `hdiutil`，只读挂载复验，哈希取 `.dmg` 文件本身。预览不公证，首次放行留给 M5 干净 VM。
9. **CI 里保留「跳过即失败」的显式闸门。** 真核心用例若因环境变量没传进而跳过，日志会被抓出
   来让 job 变红；这与 interop job 的 Gate 同一口径。
10. **Xcode 版本锁在一个变量上，但本机无法证明版本号对。** 选 `Xcode_16.4.app` 作为可审计的
    默认值；runner 镜像换了版本时第一跑会明确失败并列出候选，届时只改这一行，不让工具链悄悄
    漂移。

引用的苹果官方文档（按任务书决策附录登记）：
[Foundation Process](https://developer.apple.com/documentation/foundation/process) ·
[URLSessionConfiguration.connectionProxyDictionary](https://developer.apple.com/documentation/foundation/urlsessionconfiguration/connectionproxydictionary) ·
[信息属性列表 NSAppTransportSecurity / NSExceptionDomains](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity) ·
[Hardened Runtime](https://developer.apple.com/documentation/security/hardened-runtime) ·
[macOS 代码嵌套签名](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac) ·
[String Catalog](https://developer.apple.com/documentation/xcode/localizing-and-varying-text-with-a-string-catalog) ·
[xcodebuild（TN2339）](https://developer.apple.com/library/archive/technotes/tn2339/_index.html) ·
[macOS 软件打包](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution) ·
[首次打开指引](https://support.apple.com/zh-cn/102445) ·
[SwiftUI Window](https://developer.apple.com/documentation/swiftui/window) ·
[SwiftUI MenuBarExtra](https://developer.apple.com/documentation/swiftui/menubarextra) ·
[NSApplicationDelegate](https://developer.apple.com/documentation/appkit/nsapplicationdelegate)。
除标准库与苹果工具外没有引入第三方运行时；`flock`/`lipo`/`vtool`/codesign/hdiutil 的分工都写在
对应脚本注释里，便于以后复核。

### 留出的扩展点

- **面板**：`PanelRegistry.all` 一项即一个面板（`id` / `titleKey` / `symbol` / `order` /
  `availability`），`RootView` 从 `navigation()` 生成侧栏，不数数量、不写死顺序；新面板只加
  描述符和视图。
- **API 客户端**：`APIEndpoint` 一个 case + `APIClient` 一个方法；`APIError.code` 与
  `Localizable.xcstrings` 的 `error.*` 对齐。新增端点不改会话、令牌与重定向策略。
- **出站协议**：核心 `outbound.New` 的唯一注册点没动；Swift 不认识协议名，只显示核心返回的
  成员与状态。
- **规则类型与策略组**：`internal/rules` / `internal/policy` 的既有扩展点没动；壳只消费
  `ConfigurationView` 与 `PolicyView`，不复制规则表。
- **设置键**：`ShellOverrides` 四个 `CodingKeys` + `ShellPaths` 常量；新增键只改这两处和
  `SettingsView` 的展示，不改启动与令牌路径的计算顺序。
- **i18n**：`Localizable.xcstrings` 的 key + `Localization.text/format`；核心状态与失败原因用
  `rawValue` 拼出 `core.state.*` / `core.failure.reason.*`，新增状态自带 key。
- **数据目录**：旗标与 shell.json 优先级集中在 `resolveDataDir` 与 `ShellSettings.load` 两处，
  以后要迁移目录只改这两个入口。

### 构建与测试结果

| 检查 | 结果 |
| --- | --- |
| `go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `gofmt -l .` | 0 行 |
| `GOOS=windows GOARCH=amd64 go build ./cmd/... ./internal/...` | exit 0 |
| `GOOS=darwin GOARCH=arm64 go build ./cmd/... ./internal/...` | exit 0 |
| `go test ./... -count=1 -v` | **1345 条目 / 1324 通过 / 21 跳过 / 0 失败** |
| 前端离线（系统 Node 24，清代理，`--test-concurrency=1`） | **82 / 80 / 2 / 0**，与基线逐项相同 |
| 前端实时（临时配置 17890/17891/17946，真核心 + 真令牌） | **82 / 82 / 0 / 0**，与阶段 26 一致 |
| `check-project.py` | `ok: project has 102 objects, 19 app sources, 17 test sources` |
| `check-strings.py` | `ok: 59 keys, 42 literal references, 2 languages`（`common.on` 以运行时拼接引用，catalog 内有） |
| `ci.yml` YAML 解析（yaml.v3 离线） | 4 个 job：7 / 11 / 6 / 10 steps，macos = `macos-15` |
| 全部 `run: |` 块 `bash -n` | 13 块，0 失败；新增 3 个脚本各自的 `bash -n` 也通过 |
| `Info.plist` 解析（plistlib） | ATS 例外仅 `127.0.0.1` |

Go 条目比 M2 基线 +7，全部来自 `cmd/melonarc-core/supervise_test.go`；21 条跳过仍是固定名单
（缺参考实现的互通 10、未连接 `sendto` 的 UDP 9、上游 UDP 截断改 TCP 1、`TestTUNLinuxLoopback`
1），逐名不变。前端实时套件用本阶段新增的 `-data-dir` 旗标把令牌指向临时目录，端口没有占用
7890/7891/7946 上的遗留进程。

**没有验的（如实列出）**

- **Swift 编译、XCTest 与 `.app` 启动**：本机没有 Xcode/macOS，19 个 app 源文件与 8 个
  测试文件从未过编译器；语法、API 可用性与 target 成员资格只由 `check-project.py` 做静态核对，
  这不是编译。
- **xcodebuild 入口本身**：只验了 YAML 结构、`bash -n` 与项目文件引用闭包；`xcodebuild test /
  build`、`-destination 'platform=macOS,arch=arm64'`、派生目录产品路径、共享 scheme 是否被
  正确发现，都要 CI 首跑才知道。
- **Xcode 版本**：`Xcode_16.4.app` 是锁定的默认选择，runner 镜像是否安装未验；失败信息与
  候选列表已写好，第一跑按实际版本改那一行。
- **bundle 布局与查找顺序**：CopyFiles 的目标 `Contents/MacOS` 与 `coreSearchPaths` 的首个候选
  （壳自身同目录）是按苹果 bundle 规范推的，运行时是否真找到核心未验。
- **icns 与资源编译**：`AppIcon.png` 的像素尺寸与色彩空间已核对，asset catalog 编译成 icns、
  `CFBundleIconName` 生效、String Catalog 在真机上的占位符/复数形式都未验。
- **签名、DMG、Gatekeeper**：ad-hoc 签名的实际结果、`--deep --strict` 的递归校验、runtime
  标志、只读挂载复验、`shasum` 产物都只在脚本里写死，未在本机执行；首次打开的放行流程归 M5。
- **菜单栏与关窗行为**：`MenuBarExtra` 常驻、关窗后核心继续、退出时才恢复代理、第二实例唤起
  与强杀后的 EOF 关停，都是 D11 的目标，但只有 CI/M5 能确认。
- **系统代理四态**：`ConfigView` 目前只暴露 `system_proxy` 与 `pending_restart`，「已接管」与
  「恢复失败」没有可读的 API 字段；总览只能显示前两态，后两态需要给 Go API 补出口，见遗留。
- **macOS 13 与 Apple Silicon 真机**：最低版本、架构、ATS 在数字 IP 上的实际行为、授权弹窗
  次数与 12 秒预算都未验。

### 遗留问题

- **CI 首跑待办**：上传后先看 macOS job 的 `toolchain.txt` 与 Xcode 路径；若锁版不对，改
  `XCODE_APP` 一行；若派生目录产品路径或 scheme 发现失败，按日志修工程而不是放宽检查。
- **系统代理四态与开关**：M4 要给 `internal/api` 的 `ConfigView` 增加「本次接管中 / 快照恢复
  失败」出口（缺失能力补在 Go，不在 Swift 重算），再把保存配置 → 受控重启 → 按实际结果更新的
  开关接上；本阶段总览只显示已配置的开关与 `pending_restart`。
- **订阅刷新等操作**：公开版本仍没有写端点；按 D9 先补 Go API，再接 `APIEndpoint`。
- **data-dir 变更不迁移**：改 `shell.json` 的 `data_dir` 后，旧目录的 `system-proxy.json`、
  历史库与订阅缓存不会跟过来，旧接管记录失去恢复入口。本阶段只保证解析唯一、不造迁移逻辑；
  是否提供迁移或拒绝变更留到 M4/M5 决定。
- **5 次重启策略**：本阶段沿用旧壳的 1/2/5 与连续 5 次上限，没有改成首启单次或读退出码；
  授权弹窗叠加的极端情况仍可能发生。
- 阶段索引表仍停在阶段 22（23–26、M1、M2、M3 都没有行），沿用既有做法不擅自回填。
- 其余既有挂账照旧：Windows 实机 C1、性能实测 C2、端到端安装 C3、跨平台 Tauri 壳的
  `Cargo.lock` 与 A2/B4、真 TUN 枯竭计数非零态、`core.log` 无轮转、用户态 TCP 的 IPv6/
  乱序/窗口缩放、Flush 与整表重写、预览桥 query string、订阅明细理由文案统一。

### 下一步计划

1. 上传新 CI 后跑 macOS job 首跑：按日志校准 Xcode 锁版与产品路径，确认真核心用例没有被跳过，
   取回 DMG 与 `.dmg.sha256` 存档；第一跑之前不声称原生构建通过。
2. M4：补 Go 侧系统代理状态出口与订阅写端点，接上六个业务面板的读写；日志/连接页保持有界、
   离窗停刷新；把中英文案与错误码全部迁移完。
3. M5：干净 arm64 VM 下载 DMG、先验哈希，按 ad-hoc 首次放行说明安装并验收系统代理接管/恢复、
   强杀后的代理恢复、最低版本兼容性。
4. Windows/Linux 主线另排：决定跨平台 Tauri 壳的 `Cargo.lock` 与 A2/B4 收尾方式，不把 macOS
   的 xcodebuild 结果套到那一边。

## 阶段 M4 — 原生 macOS 壳功能齐全并冻结候选包（2026-11-18）

开工基线：`HEAD = ed9bedd`（M3），Go **1345 / 1324 / 21 / 0**，前端离线
**82 / 80 / 2 / 0**，前端实时 **82 / 82 / 0 / 0**。本机仍是 Linux 虚拟机：没有 Xcode、
Swift 编译器、codesign、hdiutil 或 macOS 桌面；Swift 只做工程/文案静态核对，原生编译、
签名、DMG 与 XCUITest 的实际运行留 CI 首跑。开工前重读了 M3 末尾、计划 M4 节与 D3–D11；
重复 import 已逐文件复查，未发现重复项。

### 完成了什么

**一、Go 侧补齐壳需要的能力（D9：缺失能力补在 Go）**

- `internal/api/views.go` 给 `ConfigView` 增加稳定的 `system_proxy_state`：单一 `state` 字符串
  外带 `configured`、`pending_restart`、`applied`、`recovery_failed` 与 `detail` 事实位。
  `internal/sysproxy/status.go` 暴露控制器真实状态，并在部分回滚失败、快照恢复失败时记住原因；
  `cmd/melonarc-core/state.go` 固定优先级：恢复失败 > 待重启 > 已接管 > 已配置 > 关闭。
  旧核心缺少该字段时 Swift 解码为 `off`，不会崩溃。
- 新增 `POST /v1/subscriptions/{name}/refresh`：`internal/subscription.RefreshNow` 是强制刷新原语；
  未知名字回 `404 unknown_subscription`；抓取失败但保留旧节点回 200 并在视图里带 `error`；
  节点变化走既有受控 reload。刷新写入审计与历史记录。
- 新增 `POST /v1/config/update` 与 `internal/config.UpdateGeneralFile`，用于设置的受控写入。
  更新只改 `[General]` 的 `log_level` / `system_proxy`，保留注释和其余行，写前后都做校验并原子替换；
  写操作进审计。`system-proxy` 改变后由壳调用既有 `POST /v1/config/reload`，并按 `pending_restart`
  决定是否重启核心，符合 D6 的“保存 → 受控重启 → 按实际结果更新”。
- 新增 Go 用例覆盖四态优先级、旧视图兼容、sysproxy 运行时状态、订阅强制刷新/未知名/保留失败、
  配置编辑/原子写入/非法值拒绝、写端点鉴权与方法约束。

**二、Swift 侧接通六面板、设置与系统代理状态**

- `APIClient` 增加统一 POST 传输、错误码映射、路径段转义，以及规则、订阅、刷新、连接、日志、
  策略选择、配置写入/重载方法；新端点仍是“一处枚举/构造器 + 一处方法”的扩展点。
- `APIModels` 解码四态代理视图、写端点视图、订阅、连接、日志和选择结果；未知状态保留为
  `unknown`，不误报成 `off`。
- `Services/PanelModels.swift` 为策略、订阅、规则、连接、日志提供有界模型：每页最多 200 条、
  整页替换、离页停表；`RootView` 按当前选择只启动一个页面模型，关窗全部停止。
- 六个业务面板全部有真实视图，设置窗可写系统代理开关；概览与设置都显示四态及恢复详情。
  TUN 在概览和设置里都明示「尚未实现」（英文 `Not implemented`），与 D1 预览口径一致。
- `data-dir` 决策：拒绝变更而非迁移。首次解析后把生效目录记在 `shell.json` 旁的 `data-dir` 标记中；
  后续若解析到不同目录则拒绝启动并说明原因。理由：令牌、配置、历史库、订阅缓存与系统代理快照
  同属一个目录，部分迁移会造出“像全新安装但旧接管记录无人恢复”的分裂状态；本阶段不做用户级迁移。
  界面不提供 `data_dir` 编辑，设置页说明这一固定策略。

**三、双语、测试与工程**

- `Localizable.xcstrings` 扩到 109 个键；运行状态、系统代理五态、写端点错误码与壳错误码都进目录，
  中文对应「尚未实现」「待重启生效」「本次已接管」「快照恢复失败」等。`check-strings.py` 的运行时
  家族清单同步扩展，占位符奇偶校验仍通过。
- 新增 `APIModelsTests`、`LocalizationTests`；`PanelRegistryTests` 改为要求七项注册全部可用；
  `ShellSettingsTests` 覆盖数据目录固定策略；新增 `MelonARCUITests` target 与
  `PanelNavigationUITests`，用无障碍标识遍历六个侧栏页面（本机未实际运行）。
- `project.pbxproj` / 共享 scheme 增加新 Swift 源、测试 target、UI 测试 target 与随包声明资源；
  `check-project.py` 增补 UI 测试 target 与资源清单检查。

**四、CI 候选包、元数据与隐私声明**

- 根目录新增双语 `PRIVACY.md`，说明不上传分析/遥测/崩溃数据、订阅与代理流量由用户配置决定、
  本地数据清单、系统代理快照与恢复、删除数据方式。它随 `.app` 一起打包。
- 新增 `apps/macos/scripts/check-candidate.sh`：校验候选 DMG 名
  `melonarc-<version>-macos-arm64.dmg`、bundle 名、GPL-3.0-only 文案、`LICENSE`、
  `THIRD-PARTY-NOTICES.md`、`SECURITY.md`、`README.md`、`PRIVACY.md` 随包、双语隐私声明、
  `.sha256` 与 `.dmg` 文件本身一致，并生成 `candidate.json`（commit、build number、version、
  license、declarations、sha256）。
- CI macOS job 把 `CURRENT_PROJECT_VERSION` 设为 `GITHUB_RUN_NUMBER`，产出带版本号的候选 DMG，
  冻结 manifest，并把 DMG、校验文件、manifest、工具链与构建日志一并上传。

### 关键决策及理由

- 四态优先级放在 Go 核心：Swift 不读配置/文件系统，也不重算 sysproxy 事实；与 D6 的归属一致。
- 配置写入放在 Go API 而非 Swift 直接改 INI：保留配置解析/校验的唯一来源，避免壳与核心各写一份。
- `data-dir` 选择拒绝变更：以可恢复性优先，不做半迁移；后续若要做迁移需另立阶段并附旧快照处理。
- 日志/连接页采用“固定上限 + 整页替换 + 离窗停表”，不追加、不在隐藏窗口后台轮询，满足 D9 的有界要求。
- 候选发布件以提交 + 构建编号 + DMG 本身 SHA-256 三元组标识；名字与随包声明由脚本阻塞式检查，
  不让缺声明的 DMG 进入候选集。

### 构建与测试结果

- Go 全量：`go test -v ./...` **1376 条目 / 1355 通过 / 21 跳过 / 0 失败**；21 条跳过仍是固定名单，
  没有新增跳过。相对 M3 增加的 31 条均来自本阶段新增用例，无回退。
- 前端离线：**82 / 80 / 2 / 0**；前端实时：**82 / 82 / 0 / 0**，均与 M3 基线逐项一致。
- Go 验收：`go build ./...`、`go vet ./...`、`gofmt -l .` 无输出、
  `GOOS=windows go build ./cmd/... ./internal/...` 通过。
- 静态检查：`check-project.py`（134 objects / 21 app sources / 20 test sources / 1 UI test source）、
  `check-strings.py`（109 keys / 2 languages）、`bash -n`、`git diff --check`、CI YAML 离线解析均通过。
- 未验：Swift 编译、xcodebuild、codesign/hdiutil、DMG 挂载复验、XCUITest 实际运行、macOS 13/Apple
  Silicon 真机与 Gatekeeper；这些只能由 CI 首跑和 M5 虚拟机确认。候选 DMG 与 manifest 是 CI 产物，
  本机没有生成也不声称已生成。

### 遗留问题

- CI 首跑仍要按日志校准 Xcode 锁版、scheme/产品路径，并确认 XCUITest 与真 sidecar 用例没有跳过。
- 系统代理的真实接管/恢复、预置代理与绕过列表行为、强退恢复仍只在 Go 单测与脚本层覆盖，M5 才验真机。
- `data-dir` 变更目前是硬失败；未来若提供迁移，需要同时设计旧快照恢复、历史库与订阅缓存迁移。
- XCUITest 依赖无障碍标识；真机上的窗口/侧栏行为未验。
- 其余既有挂账照旧：Windows 实机 C1、性能实测 C2、端到端安装 C3、Tauri 壳的 A2/B4、真 TUN
  枯竭计数非零态、`core.log` 无轮转、用户态 TCP 的 IPv6/乱序/窗口缩放等。

### 下一步计划

1. 上传后跑 macOS CI 首跑：确认工具链、XCTest/XCUITest 和真核心用例，取回候选 DMG、`.sha256`
   与 `candidate.json`；第一跑之前不声称原生构建或候选包已验证。
2. M5：先验 SHA-256，再在 arm64 虚拟机完成安装、系统代理四态与异常恢复、强退恢复、Gatekeeper
   首开、最低版本兼容性验收。
3. 发布：M5 通过后把同一候选文件提为发布资产；任何修复都生成新候选包与新验收记录。

### 本阶段留出的扩展点

- `PanelRegistry` 仍是侧栏唯一来源，新增面板只需注册项与视图；`startPanel` 的分支只描述行为。
- `APIEndpoint` / `APIClient` 分层保留，新增端点只加路径构造器与方法；`Provider` 的写方法沿用同一
  鉴权、审计与错误形状。
- `BoundedPanelModel` 统一有界替换与离窗停表；新高频页面继承即可，不必重写定时逻辑。
- `SystemProxyState` 与 `error.*` 键值化；新增状态或错误码只改枚举/常量、目录和运行时家族清单。
- 出站协议注册表、规则类型与策略组扩展点未改动；`config.GeneralPatch` 用指针区分“未设置”与显式值，
  后续新增设置项不改传输形状。

## 阶段 M4.1 — CI 首跑 Swift 编译失败修复（2026-11-19）

开工基线：`HEAD = 02f2250`（M4）。上传后 CI 首次运行（macos-15、Xcode 16.4）：Go、前端、互通
三 job 全绿，macOS job 在 `Test the app and the real sidecar`（`xcodebuild test`，exit 65）失败。
本机仍是 Linux 虚拟机：没有 Swift 编译器、SwiftUI 与 Xcode，不能本地编译验证；修复只做静态核对，
结论待推送后的 CI 重跑确认。开工前重读 M4 一节、开发文档与 `PanelViews.swift` 全文。

### 完成了什么

**一、CI 报错原文（三条，全部落在 `SubscriptionsView`）**

```
PanelViews.swift:85:24: error: cannot convert value of type '[SubscriptionView]' to expected argument type 'Binding<Data>'
PanelViews.swift:85:13: error: generic parameter 'Data' could not be inferred
PanelViews.swift:88:25: error: initializer 'init(_:)' requires that 'Binding<Subject>' conform to 'StringProtocol'
```

编译器附带的 note：`List` 选中了 `init<Data, RowContent>(_ data: Binding<Data>, ...)` 重载，
而非普通集合重载。对应源码是 85 行 `List(model.subscriptions) { subscription in` 与
88 行 `Text(subscription.name)`。

**二、根因（静态核对结论）**

不是 `List` 也不是模型层：`SubscriptionView` 已 `Identifiable`（`id = name`），
`SubscriptionsModel.subscriptions: [SubscriptionView]`、`refreshing: Set<String>`、
`lastResult: SubscriptionRefreshView?`、`APIClient.refreshSubscription(_:)` 全部对得上；
同文件 PoliciesView / RulesView / ConnectionsView / LogsView 的 `List` 写法 CI 已编过。
逐表达式核对闭包后，唯一不能定型的是 118 行：

```swift
.foregroundStyle(result.error == nil ? .secondary : .orange)
```

苹果官方文档：`foregroundStyle<S>(_ style: S) -> some View where S : ShapeStyle`，要求三元两支
合成同一个 `ShapeStyle` 具体类型。`.secondary` 在 `ShapeStyle` 语境下首选层级样式
`HierarchicalShapeStyle.secondary`（文档明确它是层级前景样式，会修饰当前前景样式），而 `.orange`
只能是 `Color.orange`，两支合不到一个 `S`。同文件 67 行 `.red : .secondary` 能编过，是因为首支
`.red` 先把 `S` 定为 `Color`，`.secondary` 随之解析成 `Color.secondary`（苹果文档确有
`static let secondary: Color`）；LogsView 的 `.green : .orange` 同理，两支都是 `Color`。
闭包类型检查失败 → `@ViewBuilder` 把普通集合重载排除 → 编译器退到 `Binding<Data>` 重载，
`subscription` 被当作 `Binding<Data.Element>`，`subscription.name` 变成 `Binding<Subject>`，
于是 85 / 88 行连锁报出上面三条错；真正出错的表达式在 118 行。
本机无 Swift 工具链，无法用编译器直接证实这一推断，故按「静态类型核对 + 官方文档 + 同文件
已编过的对照写法」定位，不据此扩大改动。

**三、修复内容**

只改 `apps/macos/MelonARC/UI/PanelViews.swift:118` 一行，给三元两支写明具体类型：

```swift
.foregroundStyle(result.error == nil ? Color.secondary : Color.orange)
```

`Color` 由文件首行 `import SwiftUI` 提供且符合 `ShapeStyle`，三元不再依赖静态成员推断，闭包即可
正常定型，普通 `List` 集合重载自然被选中。`List` 写法、闭包其余表达式、布局、刷新行为、其他面板、
扩展接口一律不动，无新依赖。父级 `VStack` 没有外层 `foregroundStyle`，层级 `.secondary` 与语义
`Color.secondary` 在此等效，与同文件已编过的 `.red : .secondary` 口径一致。另在根
`.gitignore` 增加一条 `__pycache__/`，避免本地脚本缓存被带入提交。

### 关键决策及理由

- 按官方文档把三元两支锚定到同一个 `ShapeStyle` 具体类型，不动 `List`、不改四个已编过的面板：
  这是能让闭包定型的最小改动，其余都是无关重构。
- 不用 `AnyShapeStyle` 类型擦除：虽也合法，但会把 `.secondary` 保留成层级样式并多两层包装，
  比直接写明 `Color` 改动大；也不用条件 modifier 拆分视图，避免改变视图身份。
- 不据猜测同时改 `Task { try? await ... }` 或 `if let result = ...`：前者与 PoliciesView:53
  同形且已编过，后者 `String == String` 无类型问题。

### 构建与测试结果

- 静态核对通过：`check-project.py`（134 objects / 21 app sources / 20 test sources / 1 UI test source）、
  `check-strings.py`（109 keys / 2 languages）、`git diff --check` 无输出；`git check-ignore` 确认
  `__pycache__/` 命中。改后通读 80–130 行，除该行外无差异。
- Go 与前端套件未重跑：本阶段只改一个 Swift 源文件、DEVLOG 与 `.gitignore`，未触碰 Go / JS，
  基线仍按 M4 记录（Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、实时 82 / 82 / 0 / 0）。
- **未验证项**：Swift 编译、`xcodebuild test`、XCTest / XCUITest 与真 sidecar 用例、Release 构建、
  ad-hoc 签名、DMG 与候选包校验，全部仍待推送后的 CI 重跑确认；本机 Linux 无 Swift / Xcode，
  不声称已编译通过，也不声称候选包已生成。

### 遗留问题

- M4 原有挂账不变：CI 工具链/产品路径校准、XCUITest 无障碍标识真机行为、系统代理真实接管与恢复、
  强退恢复、M5 干净 arm64 VM 验收，以及 Windows/Linux 主线的 A2/B4/C1/C2/C3。
- 根因是静态推断结论；若 CI 重跑仍报同一处或给出新诊断，须按新日志重新定位，不继续猜改 Swift。
- `check-strings.py` 的三条既有 note（`common.on`、`subscriptions.result`、
  `subscriptions.result_failed` 由运行时拼键）与本次改动无关。

### 下一步计划

1. 走快照流程推送，重跑 macOS CI，确认 `Test the app and the real sidecar` 转绿且真核心用例未跳过。
2. 转绿后再按 M4 计划取候选 DMG、`.sha256` 与 `candidate.json`，进入 M5 虚拟机验收。
3. 任何新失败按新日志定位；本机只做静态核对，不做盲改。

## 阶段 M4.2 — CI #20 测试文件 Swift 编译错误修复（2026-11-19）

开工基线：`HEAD = a2dfbe6`（M4.1），Go **1376 / 1355 / 21 / 0**，前端离线
**82 / 80 / 2 / 0**，前端实时 **82 / 82 / 0 / 0**。CI 运行 #20（提交 `a9382a39`）里
M4.1 的 `PanelViews.swift` 三条错误已不再出现，Go / 前端 / 互通三 job 全绿；macOS job
仍在 `Test the app and the real sidecar`（`xcodebuild test`，exit 65）失败，候选
DMG 未产出。本机仍是 Linux 虚拟机：没有 Swift 编译器、SwiftUI 与 Xcode，不能本地编译验证；
修复只做静态核对，结论待推送后的 CI 重跑确认。开工前重读了 M4 与 M4.1 两节、
`docs/development-doc-v1.md` 与四个改动点的上下文。

### 完成了什么

**一、CI 报错原文（八条，全部落在测试文件）**

```
CoreSupervisorTests.swift:125:59: error: value of type '[CoreSnapshot]' has no member 'containsFailure'
CoreSupervisorTests.swift:125:76: error: cannot infer contextual base in reference to member 'startupBudget'
CoreSupervisorTests.swift:180:59: error: value of type '[CoreSnapshot]' has no member 'containsFailure'
CoreSupervisorTests.swift:180:76: error: cannot infer contextual base in reference to member 'coreMissing'
CoreSupervisorTests.swift:206:59: error: value of type '[CoreSnapshot]' has no member 'containsFailure'
CoreSupervisorTests.swift:206:76: error: cannot infer contextual base in reference to member 'configurationMissing'
SidecarTests.swift:201:48: error: value of type '[CoreSnapshot]' has no member 'containsFailure'
SidecarTests.swift:201:65: error: cannot infer contextual base in reference to member 'portInUse'
```

**二、根因（静态核对结论）**

`containsFailure(_:)` 只定义在 `SnapshotRecorder`（`TestSupport.swift:44`，内部读 `all`
后按 `failure?.reason` 判断），不是 `[CoreSnapshot]` 的成员。四处调用点把 `wait(until:)`
的闭包参数 `snapshots` / `$0`（类型 `[CoreSnapshot]`）当成了接收者；偶数的四条
`cannot infer contextual base` 是同一错误的下游连锁——接收者类型未知，`CoreFailure.Reason`
的静态成员无法定型。同文件其余 `wait(until:)` 用的是数组自有的 `.contains` / `.last`，
不受影响。

**三、修复内容**

只改四处调用点的接收者，闭包参数改 `_`（其快照已由 `wait(until:)` 内部的 `all` 提供）：

- `CoreSupervisorTests.swift:125` → `recorder.wait(until: { _ in recorder.containsFailure(.startupBudget) }, timeout: 15)`
- `CoreSupervisorTests.swift:180` → `recorder.wait(until: { _ in recorder.containsFailure(.coreMissing) }, timeout: 5)`
- `CoreSupervisorTests.swift:206` → `recorder.wait(until: { _ in recorder.containsFailure(.configurationMissing) }, timeout: 5)`
- `SidecarTests.swift:201` → `contenderRecorder.wait(until: { _ in contenderRecorder.containsFailure(.portInUse) }, timeout: 30)`

`recorder` 的方法内部重新加锁读 `all`，语义与原意图一致。没有给 `[CoreSnapshot]` 加扩展
（会与 recorder 的方法重复），没有动其他测试、产品代码、扩展接口或 `docs/` 下的开发文档，无新依赖。

### 关键决策及理由

- 只把接收者改回持有锁的 `SnapshotRecorder`，不重写为 `snapshots.contains { ... }`：
  后者虽然也合法，但会绕开 recorder 的统一判断入口，改动更大且与任务书指定的修复不一致。
- 不动 `wait(until:)` 的签名与轮询逻辑：它仍用 `all` 喂条件；忽略闭包参数是显式表达
  「判断只看带锁的 recorder 快照」，不引入未使用变量告警。
- 不据报错顺手改其他测试或 `TestSupport.swift`：八条错误同源，改完四个接收者即可消解。

### 构建与测试结果

- `go test -v ./...`：**1376 条目 / 1355 通过 / 21 跳过 / 0 失败**，与 M4 基线逐项一致；
  21 条跳过仍是固定名单，没有新增跳过（第一次统计只计了顶层用例 699 条，改为含缩进
  子用例的计数后得到上述结果）。
- 静态检查：`check-project.py`（134 objects / 21 app sources / 20 test sources /
  1 UI test source）、`check-strings.py`（109 keys / 2 languages，三条既有 note 与本次无关）、
  `bash -n apps/macos/scripts/*.sh`、`git diff --check` 全部无错误；`git status` 确认
  `__pycache__/` 未出现在未跟踪列表。
- 通读四个改动处及其上下文（125 / 180 / 206 / 201 行）与全仓 `containsFailure` 用法：
  仅 `TestSupport.swift` 保留方法定义，四处调用点接收者均为对应 recorder，无新增调用。
- **未验证项**：Swift 编译、`xcodebuild test`、XCTest / XCUITest 与真 sidecar 用例、Release
  构建、ad-hoc 签名、DMG 与候选包校验，全部仍待推送后的 CI 重跑确认；本机 Linux 无 Swift /
  Xcode，不声称已编译通过，也不声称候选包已生成。

### 遗留问题

- M4 / M4.1 原有挂账不变：CI 工具链/产品路径校准、XCUITest 无障碍标识真机行为、系统代理
  真实接管与恢复、强退恢复、M5 干净 arm64 VM 验收，以及 Windows/Linux 主线的
  A2/B4/C1/C2/C3。
- 若 CI 重跑给出新的 Swift 诊断，按新日志重新定位，不继续猜改。

### 下一步计划

1. 走快照流程推送，重跑 macOS CI，确认 `Test the app and the real sidecar` 转绿且真核心用例
   未跳过。
2. 转绿后再按 M4 计划取候选 DMG、`.sha256` 与 `candidate.json`，进入 M5 虚拟机验收。
3. 任何新失败按新日志定位；本机只做静态核对，不做盲改。

---

## 阶段 M4.3 — CI #21 UI 断言失败与真核心测试被跳过修复（2026-11-20）

开工基线：`HEAD = 3e26b02`（M4.2），Go **1376 / 1355 / 21 / 0**，前端离线
**82 / 80 / 2 / 0**，前端实时 **82 / 82 / 0 / 0**。CI 运行 #21（提交 `a9cf0508`）里
#20 的 8 条 Swift 编译错误全部消失，MelonARC / MelonARCTests / MelonARCUITests 三个目标
均编译通过，Go / 前端 / 互通三 job 全绿，52 项单元测试 0 失败；macOS job 仍在
`Test the app and the real sidecar` 失败，候选 DMG 未产出。本机仍是 Linux 虚拟机：没有
Swift / Xcode / macOS 桌面，不能本地编译或跑 UI 测试；改动只做静态核对，结论待推送后的
CI 重跑确认。开工前重读了本文件的 M4 / M4.1 / M4.2 三节与阶段索引、
`docs/development-doc-v1.md`、两个测试文件、`RootView.swift`、共享 scheme、`build-core.sh`
与 CI 步骤上下文。

### 完成了什么

**一、CI #21 报错原文**

```
PanelNavigationUITests.swift:23: error: -[MelonARCUITests.PanelNavigationUITests testEveryBusinessPanelCanBeOpened] : XCTAssertTrue failed - no sidebar item for overview
MELONARC_TEST_CORE is not set; the real-core tests were skipped
```

经过：应用 `org.melonarc.app` 正常启动，UI 测试在 10 秒内反复查找标识为 `panel.overview`
的 Button（t = 2.84s 至 12.90s，多次检查均不存在），随后断言失败；Executed 1 test,
with 1 failure。同时 4 项 SidecarTests 被跳过，本轮实际没有验证真实 sidecar。

**二、两个问题的根因（按苹果官方文档核对）**

1. **UI 断言**：`RootView.swift:22` 的 `.accessibilityIdentifier("panel.\(panel.id)")` 加在
   `List(selection:)` 侧栏的行视图上；测试却用 `app.buttons[...]`（只匹配 button 控件）。
   苹果 `XCUIElementQuery` 官方文档的 macOS 示例是
   `list.outlines["Sidebar"].cells.containing(.button, identifier:"Untitled Book").count`：
   侧栏是 outline，侧栏项是其中的 **cell**，而不是按钮。`XCUIElementTypeQueryProvider`
   文档也分别定义 `cells`（cell 元素）与 `buttons`（button 控件）两套查询。标识符没有变化，
   错的是查询的元素类型。
2. **真核心用例被跳过**：CI 步骤 env 里的 `MELONARC_TEST_CORE` 只进入 `xcodebuild` 进程，
   没有进入 XCTest 测试运行器进程；`SidecarTests.swift:14` 从
   `ProcessInfo.processInfo.environment` 读到空值，于是 `XCTSkip`。苹果 Xcode 13 发行说明
   明确：`xcodebuild` 只把调用环境中带 `TEST_RUNNER_` 前缀的变量传给测试运行器进程，并去掉
   前缀；`Environment variable reference` 也写明该前缀是测试运行器按原名读到变量所必需的。
   因此路径本身没错（`build-core.sh` 默认输出正是该路径），错的是送值机制。
3. **防跳过检查被绕过**：同一 `run` 块用 `set -euo pipefail`，`xcodebuild` 失败时脚本立即退出，
   后面的 `grep` 防跳过检查根本不执行。

**三、修复内容（只动确诊处）**

- `apps/macos/MelonARCUITests/PanelNavigationUITests.swift:22`：
  `app.buttons["panel.\(panel)"]` → `app.cells["panel.\(panel)"]`。只改查询的元素类型；
  标识符、等待、点击与 root view 断言全部不变，产品代码 `RootView.swift` 不动。
- `.github/workflows/ci.yml:325` 的测试步骤 env 改名为
  `TEST_RUNNER_MELONARC_TEST_CORE`（值仍是同一个 workspace 路径）；测试代码继续读
  `MELONARC_TEST_CORE`，由 `xcodebuild` 去前缀后送入运行器。不改测试代码、不写死绝对路径、
  不加 test plan / scheme 环境变量，也不动其余 CI 步骤。
- 同一步 `run` 块：`status=0`；`xcodebuild ... | tee "$log" || status=$?` 先记下退出码；
  `grep` 防跳过检查照常执行，命中跳过消息时把 `status` 置 1；最后 `exit "$status"`。
  正常失败仍按原码退出（例如 65），跳过在任何情况下都会让步骤失败。

### 关键决策及理由

- 修测试查询而不是把侧栏行包成 Button：苹果文档确认侧栏行暴露为 cell，改一行测试即可；
  改 `RootView.swift` 会碰产品代码与视图身份，且与「二选一、只动一处」的约束相悖。
- 用 `app.cells[...]` 而不限定 `app.outlines["..."].cells[...]`：项目没有给 outline 容器设
  标识符，`cells` 后代查询直接按已有行标识符匹配，改动最小；文档已确认 cell 这一元素类型。
- 用 `TEST_RUNNER_` 前缀而不是新增 test plan：发行说明给出的就是 `xcodebuild` 的原生机制；
  新增 test plan 要同时改 scheme 与工程文件清单，牵动无关检查，且不能按 CI 运行号动态传路径。
- 保留 `SidecarTests.swift` 的跳过逻辑与 `grep` 文案：跳过仍是开发者本机无核心时的诚实行为，
  CI 里则通过前缀送值 + `grep` 兜底把它判失败，两道防线都不放宽。
- 退出码用 `|| status=$?` 捕获而不是 `set +e`：保持 `set -euo pipefail` 全程生效，
  且 `grep` 无论 `xcodebuild` 成功失败都会执行。

### 构建与测试结果

- 静态检查：`bash -n` 通过（CI 测试步骤从 YAML 抽出后单独检查、`apps/macos/scripts/*.sh`），
  PyYAML 6.0.1 解析 `.github/workflows/ci.yml` 成功并确认 4 个 job 与测试步骤 env；
  `check-project.py`（134 objects / 21 app sources / 20 test sources / 1 UI test source）、
  `check-strings.py`（109 keys / 2 languages，三条既有 note 与本次无关）、`git diff --check`
  均无错误。逐行核对了测试步骤：`env` 前缀、传给测试代码的键名、`tee` 日志路径、`grep`
  文案、退出码传递一致。
- 退出码逻辑用假 `xcodebuild` 做了 4 种组合仿真：成功且无跳过 → 0；失败且无跳过 → 65；
  成功但有跳过 → 1；失败且有跳过 → 1，全部符合预期。仿真只验证 shell 控制流，不替代
  `xcodebuild` 实跑。
- Go 与前端套件未重跑：本阶段只改一个 UI 测试文件与 `ci.yml`，未触碰 Go / JS；基线仍按
  M4.2 记录（Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、实时 82 / 82 / 0 / 0）。
- **未验证项**：Swift 编译、`xcodebuild test`、UI 测试、真实核心用例，全部待推送后的 CI
  重跑确认；Release 构建、ad-hoc 签名、DMG 与候选包校验同样未验。本机 Linux 无 Swift /
  Xcode，不声称 UI 断言已通过，也不声称候选包已生成。

### 遗留问题

- M4 / M4.1 / M4.2 原有挂账不变：系统代理真实接管与恢复、强退恢复、M5 干净 arm64 VM 验收，
  以及 Windows / Linux 主线的 A2 / B4 / C1 / C2 / C3。
- cell 这一元素类型是苹果文档与静态核对的结论；若 CI 重跑仍报 `no sidebar item`，须按新日志
  或无障碍树快照重新定位，不继续猜改。
- **ci.yml 需用户经网页端上传，快照推送带不上去**：本地提交包含 UI 测试修复、`ci.yml`
  与本文；快照推送不会把 `ci.yml` 的 env 前缀与退出码修复带上去，必须另行经网页端上传，
  否则 CI 重跑不会带上这两处改动。

### 下一步计划

1. 推送本地提交，并把 `ci.yml` 经网页端上传，重跑 macOS CI：确认 UI 断言通过、四个真核心
   用例执行且未跳过、`Test the app and the real sidecar` 转绿。
2. 转绿后再按 M4 计划取候选 DMG、`.sha256` 与 `candidate.json`，进入 M5 虚拟机验收。
3. 任何新失败按新日志定位；本机只做静态核对，不做盲改。

---

## 阶段 M4.4 — XCUITest 侧栏标识跨类型查询修复（2026-11-20）

开工基线：`HEAD = d41cabc`（M4.3）。CI #23（提交 `eb37791`）中 Go / Frontend /
Interop 全绿，52 项单元测试与 4 项 SidecarTests 全部通过，macOS job 仍只在
`PanelNavigationUITests.testEveryBusinessPanelCanBeOpened` 失败：`PanelNavigationUITests.swift:23`
的 `XCTAssertTrue failed - no sidebar item for overview`，exit 65，候选 DMG 未产出。
CI #23 已证明 M4.3 的 `app.cells["panel.\(panel)"]` 仍未找到侧栏项；本机是 Linux，
无 Xcode / SwiftUI / AppKit / XCUITest，不能 dump XCTest 无障碍树，也不能编译或运行 UI 测试。
开工前重读了 `.m44-brief.md`、本文件 M4.3 节、`docs/development-doc-v1.md`、
`PanelNavigationUITests.swift`、`RootView.swift` 与 `PanelRegistry.swift`。

### 完成了什么

- `apps/macos/MelonARCUITests/PanelNavigationUITests.swift` 新增私有辅助方法
  `sidebarItem(for:in:)`，替代直接 `app.cells["panel.\(panel)"]`：
  1. 先按 `app.descendants(matching: .any).matching(identifier: "panel.\(panel)").firstMatch`
     等待标识出现，保留原来的 10 秒超时与 `no sidebar item for \(panel)` 断言文案。
  2. 再依次尝试 `.outlineRow` / `.cell` 上按标识直接匹配与 `containing(.any, identifier:)`
     匹配，只返回行/单元格候选，避免点击普通文本元素。
  3. 若标识挂在行内子视图而非行本身，则用标识元素的 `frame` 在 `.outlineRow` /
     `.cell` 后代中反查包含它的行，并返回该行供 `click()`。
- `item.click()` 与 detail root 断言保持原样；未改 `app.otherElements["panel.\(panel).root"]`，
  因为失败尚未跑到该步，没有确诊它有问题。
- `RootView.swift` 未改；侧栏仍由 `PanelRegistry.navigation()` 生成，未新增面板数量或清单。
- 未改 Go、JS / 前端、`ci.yml`、SidecarTests、其他测试与产品行为。

### 关键决策及理由

- 只改测试文件：CI 已排除 `button` 与 `cell` 两种单一类型假设，但本机不能导出真实无障碍树；
  按苹果官方 API 覆盖 `.outlineRow` / `.cell` 并用 frame 反查可点击行，是当前能做的
  最小、可验证修复。改 `RootView.swift` 的无障碍结构会动产品代码与视图身份，留到 CI
  给出新诊断后再决定。
- 优先按现有 `accessibilityIdentifier` 查询，不按本地化文案查询：标识与语言/翻译加载无关，
  也与既有测试约定一致。
- 使用 `app.descendants(matching: .outlineRow)`，不用 `XCUIElementQueryProvider.outlineRows`
  属性：苹果文档将 `outlineRows` 标为 Xcode 16.3+ 可用，后代查询在本项目工具链约束下更稳。
- 只点击 `.outlineRow` / `.cell` 候选：简报明确要求不能查到不可交互文本后直接 `click()`；
  frame 反查的目的正是把行内标识提升回可点击行。
- 不改 detail root 查询：它尚未执行到，按「只动确诊问题」红线保留。

### 苹果官方文档依据

- `XCUIElementQuery` — `descendants(matching:)`、`containing(_:identifier:)` 与 macOS
  outline/cell 示例：`https://developer.apple.com/documentation/xcuiautomation/xcuielementquery.md`
- `XCUIElementQuery.matching(identifier:)` — 按 identifier/title/label/value/placeholderValue 匹配：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielementquery/matching(identifier:).md`
- `XCUIElementQuery.containing(_:identifier:)` — 匹配含指定类型后代的元素：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielementquery/containing(_:identifier:).md`
- `XCUIElementQuery.descendants(matching:)` — 返回指定类型的全部后代：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielementquery/descendants(matching:).md`
- `XCUIElementQuery.subscript(_:)` — 按标识符取后代元素：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielementquery/subscript(_:).md`
- `XCUIElement.ElementType` — 区分 `.any`、`.cell`、`.outlineRow`、`.staticText`，且无 `.row`：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielement/elementtype.md`
- `XCUIElementTypeQueryProvider.outlineRows` — 确认为 outline row 查询，但标注 Xcode 16.3+：
  `https://developer.apple.com/documentation/xcuiautomation/xcuielementtypequeryprovider/outlinerows.md`
- SwiftUI `View.accessibilityIdentifier(_:)` — 测试用、用户不可见的稳定标识：
  `https://developer.apple.com/documentation/swiftui/view/accessibilityidentifier(_:).md`
- SwiftUI `View.accessibilityElement(children:)` — 仅作为核查过的产品侧备选方案；本阶段未采用：
  `https://developer.apple.com/documentation/swiftui/view/accessibilityelement(children:).md`
- WWDC25 What's new in accessibility — SwiftUI 无障碍树可能只暴露文本元素，查询类型需与实际树匹配：
  `https://developer.apple.com/videos/play/wwdc2025/344/`

### 构建与测试结果

- 静态检查：`git diff --check` 通过；`check-project.py`（134 objects / 21 app sources /
  20 test sources / 1 UI test source）通过；`check-strings.py`（109 keys / 2 languages，
  三条既有 note 与本次无关）通过；`git status --short` 仅有目标 UI 测试文件被跟踪修改，
  `.m44-brief.md` 仍是未跟踪简报，不纳入提交。
- Go 与前端套件未重跑：本阶段只改一个 UI 测试文件，未触碰 Go / JS；基线仍按 M4.2/M4.3
  记录（Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、实时 82 / 82 / 0 / 0）。
- **未验证项**：Swift 编译、`xcodebuild test`、XCUITest、detail root 断言、Release 构建、
  ad-hoc 签名、DMG 与候选包校验，全部待推送后的 CI 确认。本机 Linux 无 Swift / Xcode，
  不声称 UI 断言已通过，也不声称候选包已生成。

### 遗留问题

- CI #23 没有无障碍树快照；本阶段按官方文档覆盖可点击行类型并以 frame 反查，仍属待 CI
  验证的修复。若再失败，须按新日志或树快照定位，不继续盲改。
- detail root 查询 `app.otherElements["panel.\(panel).root"]` 未改、未验证；若侧栏查询转绿后
  root 断言失败，按新日志单独处理。
- M4 / M4.1 / M4.2 / M4.3 原有挂账不变：系统代理真实接管与恢复、强退恢复、M5 干净 arm64 VM
  验收，以及 Windows / Linux 主线的 A2 / B4 / C1 / C2 / C3。

### 下一步计划

1. 推送本地提交，重跑 macOS CI：确认 `testEveryBusinessPanelCanBeOpened` 转绿，
   `Test the app and the real sidecar` 全绿，四个真核心用例继续执行且未跳过。
2. 若 root 断言成为新的失败点，只按该步日志处理，不回退本阶段的侧栏查询修复。
3. macOS job 转绿后按 M4 计划取候选 DMG、`.sha256` 与 `candidate.json`，进入 M5 VM 验收。

---

## 阶段 M4.5 — XCUITest detail root 标识未暴露修复（2026-11-20）

开工基线：`HEAD = 5d93ec9`（M4.4）。CI #24（提交 `1a53b88e`，2026-11-20 12:27 跑完）
证实 M4.4 的侧栏修复生效（找到并点击了 OutlineRow，`no sidebar item for overview` 消失），
UI 测试在 `PanelNavigationUITests.swift:52` 失败于新点：
`XCTAssertTrue failed - no root view for overview`，exit 65。Sidecar 4 项与 52 项单元测试
全过，Go / Frontend / Interop 全绿，候选 DMG 未产出。开工前重读了 `.m45-brief.md`、
本文件 M4.4 节、`docs/development-doc-v1.md`、`RootView.swift` 与
`PanelNavigationUITests.swift`。

### 完成了什么

- `apps/macos/MelonARC/UI/RootView.swift`：`detail:` 闭包里在
  `.accessibilityIdentifier("panel.\(selection ?? "none").root")` 之前加一行
  `.accessibilityElement(children: .contain)`。不改布局、文案与导航逻辑，面板仍由
  `PanelRegistry` 与 `selection` 决定。
- `apps/macos/MelonARCUITests/PanelNavigationUITests.swift`：detail root 查询从
  `app.otherElements["panel.\(panel).root"]` 改为跨类型
  `app.descendants(matching: .any).matching(identifier: "panel.\(panel).root").firstMatch`；
  保留 10 秒超时，失败时先 `print(app.debugDescription)` 再以原文案
  `no root view for \(panel)` 调 `XCTFail` 并返回，便于下次 CI 失败时直接看无障碍树。
- M4.4 的 `sidebarItem(for:in:)` 未动；未改 Go、JS / 前端、`ci.yml`、SidecarTests、
  其他测试与产品行为；未新增标识到六个面板内部，未加等待时间或占位视图。

### 关键决策及理由

- 根因已确诊：`RootView.swift` 的 root 标识挂在 `@ViewBuilder` 条件容器（`detail`，
  if/switch 返回不同面板）上。`accessibilityIdentifier(_:)` 只是给视图加标识字符串，
  本身不创建无障碍元素；容器自身不是无障碍元素时标识无处可挂，`app.otherElements[...]`
  永远查不到。决定性证据：overview 是 `@State selection` 的初始值，应用启动即显示
  overview，无需点击；10 秒等不到说明标识未暴露，不是慢或点击未生效。
- 选 `.contain` 而不是 `.ignore` / `.combine`：苹果文档写明 `accessibilityElement(children:)`
  会创建新的无障碍元素或改变已有元素的子元素行为；`.contain` 让子元素成为新元素的子元素，
  容器成为可查询节点且内部按钮、文本照常可查，符合「保留面板内容可访问」的需求。
  `.ignore` 会隐藏子元素，`.combine` 会把子元素合并，均不满足。
- 测试侧同样不假设元素类型：跟 M4.4 侧栏查询保持同一模式，避免再次猜
  `app.otherElements` 是否对应 SwiftUI 容器类型；失败路径打印整棵树，杜绝继续盲改。
- 只动这三处，符合「最小改动、只修确诊问题」红线；未改 `ci.yml`，无需网页端重传。

### 苹果官方文档依据

- SwiftUI `View.accessibilityIdentifier(_:)` — 用指定字符串标识视图、供测试使用：
  `https://developer.apple.com/documentation/swiftui/view/accessibilityidentifier(_:).md`
- SwiftUI `View.accessibilityElement(children:)` — 创建无障碍元素或改变其子元素行为：
  `https://developer.apple.com/documentation/swiftui/view/accessibilityelement(children:).md`
- SwiftUI `AccessibilityChildBehavior.contain` — 子元素成为新无障碍元素的子元素，
  作为无障碍容器分组；新元素在包含多个/零个无障碍元素，或单个无子元素时创建：
  `https://developer.apple.com/documentation/swiftui/accessibilitychildbehavior/contain.md`

### 构建与测试结果

- 静态检查：`git diff --check` 通过；`check-project.py`（134 objects / 21 app sources /
  20 test sources / 1 UI test source）通过；`check-strings.py`（109 keys / 2 languages，
  三条既有 note 与本次无关）通过；`swiftc -parse`（Swift 6.4.2 Linux 工具链）对两个改动的
  Swift 文件通过；红线 grep 在两个改动文件中零命中，`git status --short` 仅有两个目标文件
  被跟踪修改，`.m45-brief.md` 仍是未跟踪简报，不纳入提交。
- Go 与前端套件未重跑：本阶段只改一个 SwiftUI 文件与一个 UI 测试文件，未触碰 Go / JS；
  基线仍按 M4.2/M4.3 记录（Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、
  实时 82 / 82 / 0 / 0）。
- **未验证项**：`xcodebuild test`、XCUITest、六面板 root 断言、Release 构建、ad-hoc 签名、
  DMG 与候选包校验，全部待推送后的 CI 确认。本机 Linux 无 SwiftUI / AppKit / Xcode，
  `swiftc -parse` 只证明语法可解析，不声称 SwiftUI 编译通过或 UI 断言已转绿。

### 遗留问题

- 若 CI 再次失败，按新日志里的 `app.debugDescription` 无障碍树定位，不回退本阶段改动、
  不猜测式追加标识。
- M4 / M4.1 / M4.2 / M4.3 / M4.4 原有挂账不变：系统代理真实接管与恢复、强退恢复、
  M5 干净 arm64 VM 验收，以及 Windows / Linux 主线的 A2 / B4 / C1 / C2 / C3。

### 下一步计划

1. 推送本地提交，重跑 macOS CI：确认 `testEveryBusinessPanelCanBeOpened` 转绿，
   `Test the app and the real sidecar` 全绿，四个真核心用例继续执行且未跳过。
2. 若仍失败，只用失败路径打印的无障碍树诊断单点问题。
3. macOS job 转绿后按 M4 计划取候选 DMG、`.sha256` 与 `candidate.json`，进入 M5 VM 验收。

---

## 阶段 M4.6 — 合并 GPT 的侧栏点击修复与打包 bug 修复（2026-11-20）

开工基线：`HEAD = 2498223`（M4.5），远端 `fb8683dc`。CI #25（`fb8683dc`，
2026-11-20 12:54 跑完）UI 测试失败于新点：点击 policies 侧栏行三次均
`Not hittable: OutlineRow`（`PanelNavigationUITests.swift:50`，exit 65）；
M4.5 的 root 修复已证实生效（`panel.overview.root` 在 3.34 秒出现）。
用户把 Muse 整理的提示词交给 GPT 最强模型，GPT 在分支
`codex/fix-macos-sidebar-hit-testing` 上修复（提交 `2ff2574`、`5185d13`），
Muse 独立核验（分支文件、CI #26/#27 日志、本地 `ci.yml`）全部属实后，
原样并入 main。本阶段无新写的产品代码：测试文件逐字节采用 `5185d13` 版本，
`ci.yml` 改动为 GPT 的诊断补丁加一行打包修复。

### 根因（GPT 定位，CI #26/#27 日志证实）

- `sidebarItem` 找到的行是对的，但 `OutlineRow` 本身不可点击：
  policies、subscriptions、connections、rules 四行的 `rowHittable=false`；
  同一行里带 `panel.<id>` 标识的 `StaticText` 标签 `hittable=true`，
  点击标签后目标根节点随即出现。应用前台、窗口 980×620 均已排除。
- #26 还验证了一个决定修复方式的细节：logs 行报告 `isHittable == true`，
  点击也无报错，但失败时的无障碍树显示 rules 仍被选中——`isHittable`
  只说明框架能为该元素算出命中点，点击是否完成导航仍须以目标根节点验证。
  启动时 overview 已选中，所以原测试第一次通过也无法验证切换。

### 完成了什么

- `apps/macos/MelonARCUITests/PanelNavigationUITests.swift`：逐字节采用
  `5185d13` 版本。新增 `clickSidebarItem`：找到行后优先点行内带目标标识的
  标签，标识直接在行上时仍点原行；每次点击前打印 `[sidebar]` 诊断
  （面板、前台状态、窗口与行 frame、选中状态、行 `isHittable`、实际点击
  目标）；失败时在 teardown 里附加全屏截图并打印无障碍树；循环末尾从 logs
  切回 overview 再验一次。`sidebarItem` 查询、detail `.contain`、root 断言未动。
- `.github/workflows/ci.yml` 两处：
  1. 打包修复（Sign and package 步骤）：`$GITHUB_ENV` 写入的变量只在后续步骤
     生效，同一步内读 `${CANDIDATE_DMG}` 得到空值——#27 日志证实它造出了
     `macos.dmg` 却去 `hdiutil verify` 验证 `macos/` 目录（exit 1）。改为
     本步骤内用 shell 变量 `dmg`，`$GITHUB_ENV` 写入保留供下一步
     Check and freeze 步骤读取。
  2. 并入 GPT 的失败诊断补丁（用户 Mac 本地 `macos-test-diagnostics.patch`，
     已通过 `git apply --check`）：测试步骤加 `id: app_tests` 与
     `-resultBundlePath "$RUNNER_TEMP/macos/Tests.xcresult"`；新增
     Upload failed test diagnostics 步骤，测试失败时上传 `Tests.xcresult`
     与 `xcodebuild-test.log`（保留 14 天）。

### 构建与测试结果

- 分支 CI #27（`5185d13`）：测试步骤全绿，UI 测试 28.571 秒、六个面板逐个
  打开且最后切回 overview，52 项单元测试与 4 项 SidecarTests 全部执行且通过；
  唯一失败是 Sign and package（即本阶段修的打包 bug）。
- 本地验证：`git apply --check` 通过；PyYAML 解析 `ci.yml`（4 个 job）通过；
  改动的 `run` 块 `bash -n` 通过；`swiftc -parse` 对测试文件通过；
  `git diff --check` 通过；红线 grep 零命中；`check-project.py` /
  `check-strings.py` 通过。
- **未验证项**：打包修复与诊断上传步骤待 main 上 CI 验证；DMG 产出、
  候选包校验与 M5 VM 验收仍待 CI 转绿后进行。

### 遗留问题

- 互通 job 在 CI #25 红（exit 1），细节未查；若新一轮 CI 仍红再定位。
- M4 / M4.1–M4.5 原有挂账不变：系统代理真实接管与恢复、强退恢复、
  M5 干净 arm64 VM 验收，以及 Windows / Linux 主线的 A2 / B4 / C1 / C2 / C3。

### 下一步计划

1. 推送本地提交并上传新 `ci.yml`，重跑 CI：确认测试步骤全绿、Sign and
   package 通过、候选 DMG 与 `.sha256`、`candidate.json` 产出。
2. macOS job 转绿后按 M4 计划取候选包，进入 M5 VM 验收。

---

## 阶段 M4.7 — 修复候选包冻结校验缺少许可声明（2026-11-20）

开工基线：`HEAD = 99ca31e`（M4.6），工作区干净；`.m47-brief.md` 为未跟踪简报，
不纳入提交。开工前重读了本文件 M4.6 节与下一步计划、
`~/workspace/projects/melonarc-macos-plan.md` 的 M4 / M5 两节，并确认全局配置
自动加载的项目简报已读（含 D1–D11、测试基线与工作红线）。

### CI #29 失败与根因

- CI #29（提交 `0e6d9f23`，2026-11-20 14:11 查完）总耗时 3m40s：Go / Frontend /
  Interop 三 job 全绿；macOS job 的 UI 测试（31.624 秒，六面板逐个打开并切回
  overview）、52 项单元测试、4 项 SidecarTests（3.558 秒，未跳过）、Sign and
  package 全绿，DMG 已生成并校验 VALID（SHA-256
  `c11a52d5e542a6f9be0d4568948954270581f795d454106be1f95736e574dfa2`）。
- 唯一失败：最后一步 `Check and freeze the candidate manifest`（0 秒），
  报错原文：`Error: the bundled notices do not state GPL-3.0-only`（exit 1）。
  失败步骤后的 Upload-artifact（melonarc-macos-arm64）被跳过，DMG / `.sha256` /
  `candidate.json` 均不可下载；`candidate.json` 由该失败步骤写入，故候选包未冻结。
- 根因已定位：`apps/macos/scripts/check-candidate.sh:36` 执行
  `grep -q 'GPL-3.0-only' "$resources/THIRD-PARTY-NOTICES.md"`；包内该文件即仓库
  根目录同名文档（Xcode 工程引用 `../../../THIRD-PARTY-NOTICES.md`）。原文件开头
  只说明它列第三方组件及其许可，从未声明 MelonARC 项目自身的许可，grep 必然失败。
  同脚本 `Info.plist` 的 `NSHumanReadableCopyright` 校验排在后面，尚未跑到。

### 完成了什么

- 仅在仓库根目录 `THIRD-PARTY-NOTICES.md` 的 `What this file is` 段落之后增加一段：
  MelonARC 自身以 GPL-3.0-only 发布（见 LICENSE），本文件仅列第三方组件，
  且不改变任何第三方组件的许可。措辞不声称任何第三方组件是 GPL-3.0-only。
- `apps/macos/MelonARC/Info.plist:34` 的 `NSHumanReadableCopyright` 原值已是
  `MelonARC contributors. GPL-3.0-only.`，已含所需字样，未改动。
- 未改 `check-candidate.sh`、`ci.yml`、任何代码与测试；未改打包逻辑。本阶段无
  代码改动、无新增扩展点；macOS 原生优先原则仍适用于后续实现，本阶段未涉及
  新增 Swift / AppKit 实现，无需引用新的苹果官方文档。

### 本地验证结果（全部实跑）

- `grep -q 'GPL-3.0-only' THIRD-PARTY-NOTICES.md`：通过（输出确认 PASS）。
- `apps/macos/MelonARC/Info.plist` 的 `NSHumanReadableCopyright`：确认值为
  `MelonARC contributors. GPL-3.0-only.`，含 GPL-3.0-only；无需补写。
- `python3 apps/macos/scripts/check-project.py`：通过，输出
  `ok: project has 134 objects, 21 app sources, 20 test sources, 1 UI test sources`。
- `scripts/build-release.sh` 第 1 节解析只读核对：用脚本第 118–128 行同一段 awk 对
  `HEAD:THIRD-PARTY-NOTICES.md` 与当前文件抽取模块表并排序比较，结果完全一致
  （17 行），新增声明位于 `## 1.` 之前，不进入第 1 节，不破坏与核心链接模块的同步校验。
- `git diff --check`：通过（输出确认 PASS）。
- 红线 grep：按已知非开源商业产品名清单扫描新增改动行，零命中；未触碰
  `.github/workflows/ci.yml`，无需用户经网页端重传。
- Go 与前端套件未重跑：本阶段只改一个文档文件，未触碰 Go / JS / 依赖；基线仍按
  M4.2/M4.3 记录（Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、
  实时 82 / 82 / 0 / 0）。
- **未验证项**：`xcodebuild`、签名、DMG 打包、`check-candidate.sh` 全流程、
  `Check and freeze the candidate manifest` 与候选包冻结，全部待推送后 CI 确认。
  本机 Linux 无 Xcode / macOS 工具链，不声称上述任一环节已验证。

### 遗留问题

- M4 / M4.1–M4.6 原有挂账不变：系统代理真实接管与恢复、强退恢复、预置代理 /
  PAC / 绕过列表行为、M5 干净 arm64 VM 验收，以及 Windows / Linux 主线的
  A2 / B4 / C1 / C2 / C3。
- 若新一轮 CI 在 Check and freeze 之后暴露新的校验失败（例如 Info.plist 或
  `candidate.json` 内容问题），按该步日志单独定位，不回退本阶段文档修复。

### 下一步计划

1. 推送本地提交后重跑 CI，确认 `Check and freeze the candidate manifest` 通过，
   候选 DMG / `.sha256` / `candidate.json` 产出并可下载。
2. 取候选包进入 M5：用户在自己的 arm64 macOS 虚拟机先验 SHA-256，再做真实使用、
   强退恢复、预置代理 / PAC / 绕过列表的接管与恢复、真实 Gatekeeper 首开验收；
   通过后发 v0.1.0-preview.1。任何修复都产生新候选包与新验收记录。

---

## 阶段 M5.1 — 固定桌面构建工具链并补齐应用图标（2026-11-20）

开工基线：`HEAD = 002c0db`（M4.7），工作区只有未跟踪的 `.m51-brief.md` /
`.m51-plan.md`。开工前重读了本文件 M4.7 与下一步计划、
`~/workspace/projects/melonarc-macos-plan.md` 的 D10 / D11 与 M4 / M5 两节、
`docs/development-doc-v1.md`，再读了 `.m51-plan.md` 全文。严格只做方案 §1 的
工具链部分与 §4 的图标部分；§2（订阅创建 / 面板状态）、§3（信息架构 / 布局）、
§5（更新检查）与 §1 的侧栏实现均不在本阶段范围内。

### 完成了什么

**M5.1a 工具链（提交 1）**

- `.github/workflows/ci.yml` 两个 Mac 作业的 `XCODE_APP` 都固定为
  `/Applications/Xcode_26.3.app`；原有 `macos-15` 作业继续做回退 UI 测试并
  产出唯一的候选 DMG，新增 `macos-glass-ui`（`runs-on: macos-26`）作业：
  同一套件、同一提交、先跑 `build-core.sh` 构建真实 sidecar、跑
  `xcodebuild test` 界面用例并把 `.xcresult`（含 XCUITest 截图附件）与日志上传，
  不签名、不打包、不冻结候选。
- 两个作业的选择步骤相同：路径失效时打印 `/Applications/Xcode*.app` 后退出；
  记录 `xcode-select -p`、`xcodebuild -version`、SDK 版本、`xcrun swift --version`、
  Go 版本、`sw_vers`、架构到 `toolchain.txt`，再断言 Xcode 26.3 / 17C529 /
  SDK 26.2 / Swift 6.2.3 / arm64。部署下限 13.0、`SWIFT_VERSION = 5.0`
  语言模式、Go 1.27.4（go.mod）与 arm64 均未改。
- `apps/macos/scripts/verify-binaries.sh` 改用 `xcrun vtool -show-build`：
  对壳与核心分别断言 `minos 13.0`，并额外断言壳的 `sdk 26.2`（Go 交叉编译的
  核心不带 SDK 加载命令，故只查壳）。`check-candidate.sh` 交付前再核对成品
  `LSMinimumSystemVersion` 为 13.0（Info.plist 中该键展开
  `$(MACOSX_DEPLOYMENT_TARGET)`）。

**M5.1b 图标（提交 2）**

- 根因复核：build 30 的 `xcodebuild-release.log` 第 156、191 行把唯一的
  `mac / 1024x1024 / 1x` 图片报为 `unassigned child`；苹果官方
  App Icon Type 参考表明确 1024×1024 是 App Store 图标，macOS 槽位是
  16/32/128/256/512 pt，故该图从未被资源编译器采用。
- 保留 `AppIcon.png`（1024×1024）作 `512x512 / 2x` 输入，另生成九张 PNG
  （16/32/128/256/512 的 1x 与 2x，其中 32/256/512 的两种比例各有独立文件名；
  2x 的 1024 复用原图）。本机是 Linux、无 `sips`，改用已安装的 ImageMagick
  `convert -resize NxN!` 从原图直接缩放，逐张用 `identify` 核对像素
  （16/32/64/128/256/512/1024 全部正确）。这是静态资源生成，不进入产物代码；
  苹果工具在本开发机确实不可用，故按红线要求在此说明理由。
- `Contents.json` 改为十个 `idiom: mac` 的不重复槽位；`check-project.py`
  新增第 6 节：解析目录、断言恰好十槽位且 `(idiom,size,scale)` 不重复、
  文件存在、直接读 PNG 的 IHDR 得到实际像素并与 `size × scale` 一致。
- 新增 `scripts/verify-app-icon.sh`：从 plist 同时解析 `CFBundleIconFile`
  （可省略扩展名）与 `CFBundleIconName`，要求对应 `.icns` 存在且能被
  `iconutil -c iconset` 解码；抽验 16/128/512 三种表示并用 `sips` 核对像素，
  另要求至少一张 `@2x` 高分辨率表示；存在 `Assets.car` 时用
  `xcrun assetutil --info` 检查并记录图标条目数。发行日志里涉及 AppIcon 的
  `unassigned child`、非法槽位报告直接失败。脚本输出相对资源路径与 SHA-256。
- `package-dmg.sh` 在签名后与 DMG 只读挂载副本上各跑一次该脚本，`diff`
  两份报告要求完全一致；`check-candidate.sh` 在冻结前再跑一次作为图标门槛。
  CI 加了一个合成反例：只有 `CFBundleIconName`、没有任何图标资源的应用必须被拒。
- 顺带核查并修复 `check-candidate.sh` 末尾 `digest: unbound variable`：
  `digest` 只在 heredoc 内的 Python 里定义，shell 在 `set -u` 下确实未绑定；
  该命令替换在子 shell 里报错但外层 `echo` 仍返回 0，所以 CI #30 只打印警告
  却照常成功。现改为直接输出已校验的 `$expected`，不影响清单内容。

官方文档依据：App Icon Type 参考
（<https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/AppIconType.html>）、
Xcode 系统要求兼容矩阵（<https://developer.apple.com/xcode/system-requirements>）、
打包与公证要求（<https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution>）。
实现只用苹果工具解析成品；唯一的第三方工具是 Linux 上生成静态 PNG 的 ImageMagick。

### 关键决策及理由

1. **保留 `macos-15` 为唯一产包作业，把 26 作业定为纯界面测试。**
   两种托管镜像都列有 Xcode 26.3，但候选包只能有一份；新作业验证玻璃分支
   （系统 26 起可用），旧作业继续覆盖回退样式，发布路径不变，避免双份 DMG
   与双份摘要。
2. **版本探测与断言内联在两个作业里，不新添脚本。**
   两个作业各有一份 `env.XCODE_APP` 作为唯一版本开关；探测步骤输出完整
   工具链清单后再断言，失败时日志里保留实际版本与可用套件列表，便于定位。
3. **图标按传统桌面槽位而不是继续用 1024 @1x。**
   部署下限 13.0 走传统 ICNS 路径；十槽位让资源编译器产出多尺寸表示，
   校验脚本再从成品反向核对，而不是只看 `Info.plist` 里的图标名。
4. **签名前后各验一次且比较报告。**
   签名能封装一份没有图标的应用；只验源码目录或只验镜像都可能漏掉某一环节。
   相对路径 + 摘要的报告在两处必须一致，能同时发现缺失、错位与替换。

本阶段留出的扩展点：槽位表由 `Contents.json` 数据与 `check-project.py` 的
期望集合共同描述，新槽位只改这两处；`verify-app-icon.sh` 接受应用路径与可选
构建日志，可被任意打包 / 验收步骤复用；`macos-glass-ui` 作业是后续玻璃界面
用例的落点，新增用例无需再改 CI 结构。

### 当前状态（本地验证结果）

- `python3 apps/macos/scripts/check-project.py` 通过（134 objects / 21 app /
  20 test / 1 UI test）；用 build 30 式单槽位目录做负例，检查器返回 1 并报出
  槽位数与槽位集合两处错误。
- `python3 apps/macos/scripts/check-strings.py` 通过（109 keys / 2 languages）。
- PyYAML 解析 `ci.yml` 得到 5 个 job（go、frontend、interop、macos、
  macos-glass-ui），30 个 `run` 块全部通过 `bash -n`；五个脚本自身也通过
  `bash -n`。
- 用临时桩替换 `plutil` / `iconutil` / `sips` / `shasum` 做纯 shell 逻辑检查：
  合规样本输出 `icon: Contents/Resources/AppIcon.icns sha256=…`；无图标资源
  与日志含 `unassigned child` 两种样本均被拒绝。这只是本地脚本流程检查，
  不代表苹果工具已在本机验证。
- `git diff --check` 干净；红线 grep 未命中非开源商业产品名。
- Go / 前端套件未重跑（本阶段未触碰 Go、JS 与依赖），基线仍按 M4.2/M4.3：
  Go 1376 / 1355 / 21 / 0，前端离线 82 / 80 / 2 / 0、实时 82 / 82 / 0 / 0。
- **本地未验**：`xcodebuild`、`actool`、图标实际编译、`codesign`、DMG 挂载、
  `assetutil`、真实 Gatekeeper 首开，全部待推送后 CI 与 M5 虚拟机确认。

### 遗留问题

- 本机没有 Swift / Xcode，新作业里的玻璃界面用例目前仍是现有导航测试
  （截图作为 XCUITest 附件保存在 `.xcresult`）；专门的玻璃控件用例随方案 §1
  的侧栏实现进入后续阶段，本阶段未改任何 Swift 源码。
- 新版套件 26.3 对现有工程的完整编译结果、图标 ICNS 的实际表示集合、
  `XCODEBUILD_RELEASE_LOG` 传入后的日志门槛是否命中，均待 CI 实测。
- M4 / M5 原有挂账（系统代理真实接管与恢复、强退恢复、预置代理 / PAC /
  绕过列表、干净 arm64 VM 验收，以及 A2 / B4 / C1 / C2 / C3）不变。

### 下一步计划

1. 本地提交后由 Muse 走快照流程：代码推送 + `ci.yml` 经网页端上传，重跑 CI；
   核对五个 job、工具链断言、图标门槛、合成反例与唯一候选 DMG 全部通过。
2. 按方案顺序进入后续阶段：§2 订阅创建与面板状态、§3 信息架构、§5 更新检查；
   每阶段单独记录 CI 与虚拟机证据。
3. 新候选通过后在用户 arm64 macOS 虚拟机做 M5 验收，再发 v0.1.0-preview.1。

### M5.1 修复记录（CI #33 工具链断言，2026-11-20）

- **失败原因**：CI 运行 #33（提交 `fec0dfd1`）中 `macos-15` 与 `macos-26` 两个
  job 都在第一步「Select Xcode and record the toolchain」报 `expected Swift 6.2.3`
  并以 exit 1 退出。Go / Frontend / Interop 三个 job 全绿；图标验证、签名、
  打包均未执行，九张新图标尚未被 CI 验证。
- **证据**：CI 日志显示两个 runner 镜像中 Xcode 26.3（Build 17C529）自带的
  Swift 实为 **6.2.4（Apple Swift version 6.2.4，swiftlang-6.2.4.1.4）**；
  Xcode 26.3 与 SDK 26.2 的断言均已通过，两个镜像表现一致。根因是工具链方案
  误写为 6.2.3，应以 Xcode 26.3 实测自带的 6.2.4 为准。
- **修复内容**：只改 `.github/workflows/ci.yml` 三处——约第 278 行注释里的
  `Swift 6.2.3`，以及约第 314、480 行两个 macOS job 的断言
  `grep -q 'version 6\.2\.3'` 与报错文案 `expected Swift 6.2.3`，全部改为
  6.2.4。Xcode 路径、SDK 版本、图标、脚本及其他文件均未改动。
- **本地验证**：PyYAML 解析 `ci.yml` 得 5 个 job（go、frontend、interop、
  macos、macos-glass-ui），30 个 `run` 块全部通过 `bash -n`，
  `git diff --check` 干净。本机无 Swift / Xcode，未本地重跑真实工具链探测。
- **待验证**：本地提交后由 Muse 走快照流程推送（`ci.yml` 仍需网页端上传），
  重跑 CI 确认两个 macOS job 的工具链步骤转绿、图标门槛与合成反例执行、
  唯一候选 DMG 正常产出。

### M5.1 修复记录（CI #35 iconutil 输出路径，2026-11-20）

- **失败原因**：CI 运行 #35（提交 `1ae8c66`）中工具链断言全过，52 个单元测试
  与 UI 测试全过、`** TEST SUCCEEDED **`，玻璃界面作业全绿，日志全文检索
  `unassigned` 为 0（图标槽位问题已解决），Go / Frontend / Interop 全绿；
  新失败点在 `macos-15` 作业的 Sign and package 步骤：codesign 签名与校验已通过，
  随后图标校验脚本因参数错误退出，与工具链版本无关。
- **证据**：Sign and package 日志原文为
  `Invalid arguments, --output argument. The file extension must equal iconset.`；
  `apps/macos/scripts/verify-app-icon.sh` 原第 52 行为
  `iconutil -c iconset -o "$iconset/$name" "$icns" \`，输出路径缺少 `.iconset`
  后缀，而 iconutil 要求 `-o` 路径扩展名必须为 `iconset`。第 55、64 行的后续
  读取沿用了同一无后缀路径。
- **修复内容**：只改 `apps/macos/scripts/verify-app-icon.sh` 三行——第 52 行输出
  路径改为 `"$iconset/$name.iconset"`，第 55 行读取改为
  `"$iconset/$name.iconset/$representation"`，第 64 行通配改为
  `"$iconset/$name.iconset"/*@2x.png`。输出目录与两处读取目录一致；
  `iconset` 仍是 `mktemp -d` 创建的同一个临时根目录，`trap 'rm -rf "$iconset"' EXIT`
  继续覆盖整个临时目录（含新建的 `.iconset` 子目录）。`ci.yml`、图标文件、
  其他脚本与其他文件均未改动。
- **本地验证**：`bash -n` 通过，`git diff --check` 干净，逐行复核路径拼接一致；
  `shellcheck` 本机不可用，未执行。本机是 Linux、没有 `iconutil` / `sips`，
  无法实跑该脚本，真实结果待 CI 确认。
- **待验证**：本地提交后由 Muse 走快照流程推送，重跑 CI 确认 Sign and package
  步骤的图标校验通过、唯一候选 DMG 正常产出。

### M5.1 修复记录（CI #36 图标校验输出可见性，2026-11-20）

- **定位过程**：CI 运行 #36（提交 `045dd027`）仍红；`macos-15` 作业 Sign and
  package 步骤日志仅 20 行，codesign 对 `melonarc-core` 与 `.app` 的签名、
  以及 `--verify --deep --strict` 校验全部通过，随后无任何错误行直接
  `Process completed with exit code 1`。按 `package-dmg.sh`（`set -euo pipefail`）
  顺序，`codesign --verify` 之后第一条命令就是 `verify-app-icon.sh`，日志中
  也没有任何 hdiutil 输出，故失败发生在图标校验，DMG 创建根本未执行。
- **根因**：`package-dmg.sh` 原第 37–38 行把 `verify-app-icon.sh` 的全部 stdout
  重定向到 runner 临时目录下的 `$icon_work/signed.txt`，而该脚本的 `fail()`
  与成功报告都走 stdout；后续步骤全部跳过、未上传该报告，runner 已销毁，
  因此确切的失败分支在 GitHub 日志里不可读。这是诊断可见性问题，并非图标
  本身已被定罪：构建日志中 `unassigned child` 与非法槽位报告 0 命中，actool
  已生成 thinned 的 `AppIcon.icns` 与 `Assets.car`，Info.plist 声明
  `CFBundleIconName=AppIcon`，Contents.json 十槽位齐全；剩余候选分支（`.icns`
  不在 Resources 内、iconutil 解码失败、必需表示缺失或像素不对、缺 @2x、
  assetutil 读 `Assets.car` 失败）仅为推断，未确认。
- **修复内容**：只改 `apps/macos/scripts/package-dmg.sh` 两行——签名后的图标
  校验 `> "$icon_work/signed.txt"` 改为 `| tee "$icon_work/signed.txt"`；挂载副本
  上的校验 `> "$icon_work/mounted.txt"` 改为 `| tee "$icon_work/mounted.txt"`。
  文件开头 `set -euo pipefail`（第 5 行）已确认启用，管道中任一命令失败仍使
  脚本退出；`tee` 同时把校验输出写进日志与同名文件，后面 `diff -u` 仍能读到
  两份报告。`ci.yml`、图标文件、`verify-app-icon.sh` 本身、其他脚本与文件、
  Go 代码均未改动。
- **本地验证**：`bash -n` 通过，`git diff --check` 干净，复核了 `set -euo pipefail`
  与两处写入文件的路径不变；本机是 Linux、没有 `iconutil` / `sips` / `hdiutil`，
  无法实跑，真实结果待 CI 确认。Go job 另有 `TestRealityRejectsWrongCredential`
  （`reality_handshake_test.go:173`，dial succeeded、应拒未拒）失败，M5.1 未动
  Go 代码且 #35 同轮曾绿，疑似偶发，本次不改，待重跑确认。
- **待验证**：本地提交后由 Muse 走快照流程推送，重跑 CI 时直接从 Sign and
  package 日志读取图标校验的实际输出以确定失败分支；若图标校验通过则确认
  唯一候选 DMG 产出，同时观察 Go 测试是否复现。

### M5.1 修复记录（CI #37 图标 512 表示缺失，2026-11-20）

- **失败原文**：CI #37（提交 `c1502089`）中 Go / Frontend / Interop / 玻璃 UI
  全绿，Go 的 `TestRealityRejectsWrongCredential` 未复现；`macos-15` 作业在
  Sign and package 失败，原文
  `Error: Contents/Resources/AppIcon.icns has no icon_512x512.png representation`
  （exit 1）。CI #36 修复的 `tee` 已生效，报错直接进入 CI 日志，DMG 创建未执行。
- **构建日志核查**：按随简报提供的逐行核查结论，CI #37 发布构建日志中两次
  `actool` 调用均带 `--notices --warnings`，但 `com.apple.actool.document.warnings`
  段为空，只有产物列表；没有 `unassigned child`、非法槽位、跳过项或按尺寸列出的
  表示。唯一的 `CompileAssetCatalogVariant` 是 thinned 变体，产物为
  `assetcatalog_output/thinned/AppIcon.icns` 与 `Assets.car`，随后
  `builtin-linkAssetCatalog` 只把 thinned 产物链接进 `.app`。故资源编译未报错，
  问题在 thinned 产物 `AppIcon.icns` 自身的表示集合。
- **定因过程与证据**：
  1. 源槽位：`Contents.json` 十个槽位全部 `idiom: mac`，16/32/128/256/512 的
     1x/2x 与苹果 App Icon Type 参考表一致；1024×1024 是 App Store 图标，已按
     M5.1b 映射为 `512x512 / 2x`。`check-project.py` 的唯一槽位与 PNG IHDR 像素
     检查全通过，CI #37 的 actool 也无警告，排除槽位映射错误。
  2. 远端漂移：用 `curl` 从 `raw.githubusercontent.com/.../main` 取回
     `Contents.json` 与 10 张 PNG，与本地逐字节一致，排除网页端上传与快照不一致。
  3. 重复 PNG：`AppIcon_512x512.png` 与 `AppIcon_256x256@2x.png` 同为 512×512、
     SHA-256 相同。苹果 High Resolution 指南明确同像素的不同文件名代表不同点尺寸
     （如 16×16@2x 与 32×32 不等价），且两槽位唯一、actool 无告警，故属合法复用，
     不是 512 表示缺失的原因。
  4. iconutil 与校验脚本：`iconutil -c iconset` 成功解码出 `icon_16x16.png` 与
     `icon_128x128.png`，仅 `icon_512x512.png` 缺失，说明解码链正常；苹果 High
     Resolution 指南把 512×512 列入完整 ICNS 表示集，脚本抽验 16/128/512 再加一个
     @2x 的期望本身正确，不能删检查。
  5. **定因**：苹果《Build settings reference》的 “Standalone Icon File Behavior”
     （`ASSETCATALOG_COMPILER_STANDALONE_ICON_BEHAVIOR`）明确说明：默认只为
     primary app icon 生成 “a small subset of sizes” 的 loose PNG/ICNS，供外部
     管理工具显示代表图；该设置可设为 `all` 或 `none` 以增减 loose 文件的尺寸。
     工程此前未设置该值，Xcode 26.3 走默认“小子集”，与观察到的 loose
     `AppIcon.icns` 含 16/128、缺 512 完全吻合；图标数据仍另行进入 `Assets.car`，
     但传统 ICNS 路径在 Finder/Dock 的大尺寸上会退化。这是构建配置问题，
     不是脚本误报。
- **修复内容**：只在 `apps/macos/MelonARC.xcodeproj/project.pbxproj` 的 app target
  Debug / Release 两处 `ASSETCATALOG_COMPILER_APPICON_NAME` 之后各加一行
  `ASSETCATALOG_COMPILER_STANDALONE_ICON_BEHAVIOR = all;`，共新增 2 行。
  `verify-app-icon.sh` 的 16/128/512 与 @2x 校验一字未改，实质强度不降反升：
  loose `.icns` 从子集变为完整尺寸集。图标源文件与 `ci.yml` 未改，无需网页端上传。
- **官方文档依据**：Build settings reference “Standalone Icon File Behavior”
  （<https://developer.apple.com/documentation/xcode/build-settings-reference#Standalone-Icon-File-Behavior>）；
  Asset Catalog Format Reference “App Icon Type” 表 6-2
  （<https://developer.apple.com/library/archive/documentation/Xcode/Reference/xcode_ref-Asset_Catalog_Format/AppIconType.html>）；
  High Resolution Guidelines for OS X “Create a Set of Icons That Includes
  High-Resolution Versions”
  （<https://developer.apple.com/library/archive/documentation/GraphicsAnimation/Conceptual/HighResolutionOSX/Optimizing/Optimizing.html>）。
- **本地验证**：两个脚本通过 `bash -n`；`check-project.py` 报 134 objects /
  21 app / 20 test / 1 UI test，`check-strings.py` 报 109 keys / 2 languages；
  Python 复核 10 个唯一 mac 槽位与全部 PNG 的 IHDR 像素一致；pbxproj 括号配平、
  新增设置出现两次；`git diff --check` 干净。本机是 Linux，无
  `xcodebuild` / `actool` / `iconutil` / `sips` / `hdiutil`，未本地实跑图标编译与校验。
- **下轮 CI 待验证**：`macos-15` 作业图标校验通过（512 表示出现、签名前后两份
  报告一致），Sign and package 与 DMG 挂载校验全绿，唯一候选 DMG＋`.sha256`＋
  `candidate.json` 产出；同时观察 Go 偶发测试是否复现。

### M5.1 修复记录（CI #38 版权赋值行被拆坏，2026-11-20）

- **CI #38 结果**（提交 `9a266b11`，运行
  <https://github.com/Melon-tgj/MelonARC/actions/runs/44890775612>，3m18s）：
  Go / Frontend / 玻璃 UI 全绿；M5.1 的图标修复已生效——`macos-15` 的
  Sign and package 通过，日志出现 `icon:` / `car:` 成功行，DMG 已生成并校验
  `VALID`，上一轮的 512 表示缺失报错未再出现。新的失败点前移到
  Check and freeze the candidate manifest（exit 1），原文
  `apps/macos/scripts/check-candidate.sh: line 48: MelonARC: command not found`
  与 `Error: the bundle copyright could not be read`。
- **根因与证据**：用 `git log -L` 核实，M5.1 提交 `f4ee8a6a` 在
  `check-candidate.sh` 插入 `bash "$here/verify-app-icon.sh" "$app"` 时，把原本
  正确的单行赋值拆成了两行：`copyright=` 独占一行置空，下一行的
  `$(plutil -extract NSHumanReadableCopyright raw -o - "$app/Contents/Info.plist") \`
  变成了独立命令；命令替换展开后，plutil 输出的版权字符串以 `MelonARC` 开头，
  bash 遂尝试执行 `MelonARC` 命令而报 command not found（exit 127），触发
  `|| fail`。这解释了为何 CI #30 能通过：当时该行尚未被拆开，写法是正确的；
  只有 #38 引入了拆行才暴露此故障。同一脚本后续的
  `minimum=$(plutil ...)` 仍是正确写法，可直接作为范本。
- **修复内容**：只把第 46–48 行恢复为单行赋值
  `copyright=$(plutil -extract NSHumanReadableCopyright raw -o - "$app/Contents/Info.plist") \`
  加 `|| fail "the bundle copyright could not be read"`，上方的
  `verify-app-icon.sh` 调用原样保留；脚本其余内容一字未动。Go 代码零改动。
- **本地验证**：本机 Linux 无 `plutil`，故用 shell 函数 mock `plutil` 输出以
  `MelonARC` 开头并含 `GPL-3.0-only` 的版权文本：修复后赋值正确落到
  `copyright` 且 `grep -q 'GPL-3.0-only'` 通过；修复前的拆行写法稳定复现
  `MelonARC: command not found`（rc=127）。`bash -n` 语法通过，
  `git diff --check` 干净。未本地实跑 macOS 签名与冻结流程。
- **Interop 超时判定**：本轮 Interop 的 `TestInteropSnell/v5/udp` 报 10.00s
  超时，但 M5.1 全程未改任何 Go 代码，#37 在相同 Go 代码下 Interop 为绿，
  #37 与 #38 之间只差 `project.pbxproj` 与 DEVLOG，不可能影响 Go 测试；
  判定为偶发/瞬时，不改 Go 代码，留待下一轮 CI 重跑验证。
- **下轮 CI 待验证**：Check and freeze 通过并产出唯一候选 DMG＋`.sha256`＋
  `candidate.json`；Interop 的 Snell v5 UDP 超时自行消失；图标、签名与
  DMG VALID 结论保持。

### M5.2：订阅创建、面板状态、侧栏重做与卡片布局（2026-11-21）

- **基线**：以 build 39 / `HEAD 0b5eba6` 为起点。用户虚拟机反馈内容页面可用，
  但侧栏按钮过紧；本阶段同时回应侧栏间距、首条订阅创建、六面板空状态与
  概览信息层级。
- **Go 核心改动**：
  - `internal/api/views.go` 增加 `SubscriptionCreateRequest` 和
    `Provider.CreateSubscription`；`internal/api/server.go` 在
    `/v1/subscriptions` 同路径按 GET/POST 分派，其他方法仍为 405 并给出
    `Allow: GET, POST`；`internal/api/subscriptions.go` 增加创建 handler，
    首次成功 201、同声明重试 200，并在审计中只记录名称、不记录订阅地址。
  - `internal/config/edit.go` 增加 `[Subscription]` 定点编辑、规范化声明、
    往返校验、整份配置 parse/validate、同目录临时文件原子替换与并发版本复核；
    `cmd/melonarc-core/reload.go` 复用准备/提交路径，加入 `Manager.Fork/Adopt`
    私有暂存，提交前持共享锁复核原文件，失败恢复原文件，不留下无法启动的配置。
  - 稳定错误码覆盖 `invalid_subscription`、`subscription_conflict`、
    `config_changed`、`subscription_import_failed`、`subscription_apply_failed`
    等；测试覆盖端到端创建、重复点击、冲突、非法字段、并发写和重启保留。
- **桌面壳改动**：
  - `APIClient` 增加创建与跳过明细方法，显式接受创建响应的 200/201，写请求
    35 秒时限而普通读仍为 5 秒；修正连接记录 `duration_ms` 解码键；新增
    `SubscriptionCreateRequest` 与跳过明细 DTO。
  - `PanelModels` 为五个列表页加入 `idle/loading/loaded/empty/failed` 阶段、
    generation 与单次主线程发布；迟到读取不得覆盖新读取，写失败独立记录，
    停止面板时递增请求代数；策略选择与订阅刷新去掉 `try?`，订阅刷新遇到响应内
    `error` 非空也进入失败状态。
  - 新增 `SidebarPanelButton.swift`：侧栏由 GeometryReader 计算可用高度，
    六键等分、最小 56pt、四周 12pt、行间距 8pt，整行 `.contentShape` 可点；
    保留 `panel.<id>` 与 `onMoveCommand`。系统 26 用 `.glass`，旧系统用
    `SidebarFallbackStyle`（按下底色、约 120ms 复位、减少动态效果时只改底色）。
  - 新增 `SubscriptionEditorView.swift`、`PanelStateView.swift`：
    表单含名称、地址、可选间隔（默认 6 小时，显式最少 5 分钟），本地校验
    HTTP/HTTPS 绝对地址，提交防双击；错误只展示稳定码与本地化文案，不回显地址；
    旧核心返回 404/405 时提示当前核心不支持添加订阅并提供配置详情入口。
    状态组件在系统 14+ 使用 `ContentUnavailableView`，系统 13 用等价 VStack。
  - 新增 `PanelCard.swift`、`PanelDetailView.swift`：首页 20–24pt 外边距、
    卡片 16pt 内边距、12–16pt 间距，宽窗两列、窄窗 `ViewThatFits` 单列；
    `RootView` 用 `NavigationStack` + Hashable 路由承载概览/组/订阅/连接详情，
    切页重置路径，轮询不影响正在阅读的详情。规则默认行紧邻显示 `FINAL → DIRECT`。
  - `OverviewModel` 为 status 与 configuration 分别保存成功值与错误；未读到
    代理状态显示“尚未读取”，读后失败保留上次值；`AppEnvironment` 增加结构化
    首次写入事件，首页不再展示配置路径，诊断页可查看并定位。设置分为
    “网络与能力”“诊断与文件”“关于与更新”。
- **关键决策及理由**：创建链路把网络导入放在 `commitMu` 外，只在最终换文件和
  安装快照时持锁，避免慢订阅阻塞其他设置写入；先完成全部可失败校验再写文件，
  以失败恢复保证“创建失败不留坏配置”。侧栏只在版本样式入口切换原生 API，
  公共存储与参数保持最低系统可识别类型，便于 13 回退与 26 玻璃分支共存。
- **原生接口与文档依据**：玻璃按钮
  <https://developer.apple.com/documentation/swiftui/glassbuttonstyle>；
  空状态
  <https://developer.apple.com/documentation/swiftui/contentunavailableview>；
  响应式布局 <https://developer.apple.com/documentation/swiftui/viewthatfits>；
  文件定位
  <https://developer.apple.com/documentation/appkit/nsworkspace/activatefileviewerselecting(_:)>；
  回环 API 会话约束
  <https://developer.apple.com/documentation/foundation/urlsessionconfiguration>。
- **本地验证**：`~/sdks/go/bin/gofmt -l internal/api internal/config internal/subscription cmd/melonarc-core`
  无输出；`~/sdks/go/bin/go test ./...` 全包通过；
  `python3 apps/macos/scripts/check-project.py` 通过（146 objects / 26 app sources /
  21 test sources / 1 UI test source）；`python3 apps/macos/scripts/check-strings.py`
  通过（186 keys / 2 languages，仅有未直接引用的说明键提示）；
  `git diff --check` 干净；红线 grep 未发现产品仓库禁用词。
  Linux Foundation Swift 架子 50 项中 49 过，唯一失败仍是既有的
  CoreSupervisor 预算测试（Linux Foundation 进程/主队列行为差异，macOS CI 全绿，
  非本阶段引入）；新增连接解码、创建请求编码与本地化断言均通过。
  本机 Linux 无 Xcode/SwiftUI/AppKit，界面编译、资源编译、签名、DMG 与
  XCUITest 均留待 CI，不声称已在本机编译通过。
- **扩展点**：面板仍由 `PanelRegistry` 单一注册表生成，侧栏高度按实际条目数计算；
  详情路由为可追加的 Hashable enum；API 路径集中在 `APIEndpoint`，写请求通过
  `send` 的 accepted statuses 与超时参数扩展；面板状态机与卡片组件可复用于后续
  页面，文案继续键值化。
- **待验**：CI 需验证 13 回退样式与 26 玻璃分支、六按钮命中范围与键盘操作、
  六个面板零项/有内容/失败/旧数据状态、订阅创建 201/200/409/400/422 与旧核心
  404/405、慢响应与断线重试、非空连接解码、详情跳转与返回、浅深色与中英文排版。
  候选 DMG 产出后由用户在 macOS 虚拟机实测“零条 → 添加 → 列表出现 → 重启仍存在”
  与侧栏间距、按下反馈、短窗口滚动。

### M5.2 修复：CI #40 四处 Swift 编译错误（2026-11-21）

- **背景**：CI #40（提交 a4076a5e）整体 Failure。Go/Frontend/Interop 全绿；
  macOS 与 macOS 26 UI (glass) 两个作业红在 4 处 Swift 编译错误，52 项单元测试
  与 UI 测试未执行，签名打包与 Check and freeze 被跳过，无候选 DMG。本机 Linux
  无 Xcode/SwiftUI，只修编译错误，不改行为、不动架构、不碰工具链配置。
- **版本差教训**：CI 钉的是 Xcode 26.3 / Swift 6.2.4，本机 Linux 工具链是
  Swift 6.4.2。修复 1 的根因是 M5.2 代码按 6.4 才加入标准库的 SE-0530
  （`Result.init(catching:)` 的异步重载）语义写成——6.4 本地能过、6.2.4 CI 会红。
  今后写代码一律按 CI 钉的 6.2.4 语言版本，不依赖 6.4 才有的新语法。
- **三处根因与改法**：
  - `UI/OverviewModel.swift`：`await Result { try await … }` 在 6.2.4 下
    `Result.init(catching:)` 只接受同步闭包，报 `cannot pass function of type
    '() async throws -> StatusView' to parameter expecting synchronous function type`。
    改为标准 do/catch 构造 `Result<StatusView, Error>` 与
    `Result<ConfigurationView, Error>`；`async let status` / `async let configuration`
    保持不动，两请求仍并行启动，只是顺序 await，不改变并行性（苹果官方文档
    Concurrency 章 "Calling Asynchronous Functions in Parallel"）。
  - `UI/OverviewView.swift`：第 40 行漏写 `model.`，`statusFailure` /
    `configurationFailure` 属 OverviewModel 而非 View，报
    `cannot find 'statusFailure' in scope`。同文件其余处均正确带 `model.`，
    补上前缀即可。
  - `Services/PanelModels.swift`：`writeFailure` 在基类 BoundedPanelModel 里是
    `@Published private(set)`，private 限于声明类型内部，子类即使同文件也不能写，
    报 `cannot assign to property: 'writeFailure' setter is inaccessible`。
    改用基类已有的 `clearWriteFailure()`，并把它移出 `MainActor.run` 块
    （该方法内部已自行派发到 MainActor）。
- **被否掉的方案**：不升工具链；不自写
  `extension Result { init(catching body: () async throws -> Success) async }`
  （将来升到 6.4 会与标准库撞名）；不把 setter 放宽到 `fileprivate(set)` 或
  internal（那是拆基类有意设的封装）。
- **未复现的警告**：CI 日志里另有一条 PanelModels.swift:210:25 的 `statusFailure`
  未使用警告，本地复核整个 PanelModels.swift 无该名字，210 行附近是
  `refreshNow`。未凭猜测改动，待下一轮 CI 日志确认原文再处理。
- **本地验证**：`python3 apps/macos/scripts/check-project.py` 通过（146 objects /
  26 app sources / 21 test sources / 1 UI test source）；
  `python3 apps/macos/scripts/check-strings.py` 通过（186 keys / 2 languages，仅有
  未直接引用的说明键提示）；`git diff --check` 干净。Go 代码未动，未重跑 Go 测试；
  Linux 测试架子不覆盖 SwiftUI/Combine 文件，未跑；本机 Swift 6.4.2 编译不了这些
  文件，真正的验证靠 CI 重跑，不声称已在本机编译通过。
- **扩展点**：本阶段只修编译错误，未新增或改动扩展点。
- **待验**：CI 重跑确认四处编译错误全消、52 项单元测试与 UI 测试执行、
  签名打包与 Check and freeze 通过并产出候选 DMG；未复现的
  PanelModels.swift:210:25 警告待日志原文确认。

### M5.3：macOS 自研手动更新检查（2026-11-21）

- **基线**：CI #41（2026-11-20）已全绿并冻结候选
  build 41（`melonarc-0.1.0-preview-candidate.41-macos-arm64.dmg`，
  SHA-256 `20ab6ee61a0e0e4b750d0c40efd61a21a384ffd1737bbd0d61671fb175eb684d`）。
  本阶段按用户附件 `.m53-brief.md` 与 GPT 答复 §5 落地手动更新检查；
  起点本地 HEAD `9469dfb`，远端 `aa80fb0e`。M5.2 修复已验证，
  本阶段不再改动侧栏、面板、CI 工作流或签名公证配置。
- **完成内容**：
  - 新增纯 Foundation 模型 `Services/ReleaseVersion.swift`：渠道筛选
    （preview 含 prerelease、release 排除 prerelease、一律排除 draft）、
    短版本/十进制 build 与最低系统版本比较、Release 分页去重、
    `candidate.json` 清单解码与资产匹配、下载初始 URL 与重定向白名单、
    GitHub `digest: sha256:<base64>` 与 manifest `sha256` 双重比对。
    所有 JSON 键用显式 `CodingKeys` 映射，避免
    `convertFromSnakeCase` 把 `browserDownloadURL` / `htmlURL` 猜成 `...Url`。
  - 新增 `Services/ReleaseUpdateService.swift`：固定
    `https://api.github.com/repos/Melon-tgj/MelonARC/releases?per_page=100`，
    最多 5 页且只接受同 API host/path 的 `rel="next"`；403/429 读取
    `Retry-After` / `X-RateLimit-Reset`；ephemeral URLSession 不带 Cookie、
    凭据与缓存；请求头只有 `Accept` 与 `User-Agent`；绝不携带回环 API
    令牌、订阅地址、诊断数据。下载走可信 github.com 发布资产与
    GitHub 对象存储重定向链，流式 SHA-256 校验失败即清理本次临时文件，
    未校验文件不交付给界面。通过可注入 `ReleaseHTTPTransport` 支持假传输测试。
  - 新增 `UI/UpdateModel.swift` 与 `UI/UpdateView.swift`：单一共享状态机，
    同时服务于菜单“检查更新…”、设置页“关于与更新”分组和结果 alert；
    generation 防迟到结果覆盖；同步只允许一个检查或下载；取消会递增代际、
    取消下载任务并清理已校验临时文件；保存使用 `NSSavePanel`，
    保留/补写 quarantine 属性后验证，成功才 `NSWorkspace` 定位到文件。
  - 接线 `AppEnvironment`（新增 `let update: UpdateModel`）、`MelonARCApp`
    （菜单项与设置构造）、`SettingsView`（UpdateView）、`RootView`
    （UpdateAlertModifier）、`Info.plist`（`MelonARCUpdateChannel` 读取 build
    setting `MELONARC_UPDATE_CHANNEL = preview;`，`LSFileQuarantineEnabled`），
    `project.pbxproj`（新增 4 个 app 源文件、2 个测试文件及其引用/编译阶段）。
  - `check-candidate.sh` 冻结清单新增 `schema_version`、`short_version`、
    `arch`、`minimum_system_version`、`bundle_id`，并读取最终 bundle 的
    `CFBundleShortVersionString` / `CFBundleIdentifier` / `CFBundleVersion`
    与 lipo 架构复核；保留 `candidate`、`version`、字符串 `build_number`、
    `commit`、`sha256` 及既有冻结校验。`ci.yml` 未改，无需网页端上传。
  - `Localizable.xcstrings` 新增 31 个中英键；`check-strings.py` 把动态
    状态与动作键加入运行时白名单；`PRIVACY.md` 增补中英文说明：仅主动检查
    才联系发布服务，请求不含令牌、订阅或诊断数据。
  - 新增 `MelonARCTests/ReleaseVersionTests.swift`（9 项纯 Foundation，
    已纳入 Linux 架子）与 `MelonARCTests/ReleaseUpdateTests.swift`
    （8 项 macOS/Xcode 传输注入测试，覆盖空列表、预览构建、分页、限速、
    断网、坏 JSON、下载校验、校验失败不交付、不可信资产零请求）。
- **关键决策及理由**：沿用 ad-hoc／未公证发布现实，不做后台轮询、不静默安装、
  不绕过 Gatekeeper；只把“已校验 DMG 保存到用户选择位置”作为成功终点，
  由用户正常退出恢复代理后再手动替换应用。manifest 带 `schema_version`
  与显式平台字段，后续渠道/架构/最低系统变化不必改客户端解析分支。
  网络传输与业务判定分离，测试用假传输即可覆盖限速与恶意资产，不碰真实网络。
- **关键错误与修复**：Linux 架子首轮抓到
  `MelonARCUpdateChannel.accepts` 误用可选 `Bool?` 而非 `isDraft` /
  `isPrerelease`，已修；随后抓到 `browser_download_url` 被
  `convertFromSnakeCase` 映射成 `browserDownloadUrl` 导致解码失败，
  改为显式 `CodingKeys` 并在所有相关解码器移除该策略；
  用带 stub CryptoKit + FoundationNetworking 的 `swiftc -typecheck`
  抓到 `check` 返回 `ReleaseCatalogResult` 未映射为 `UpdateCheckOutcome`，
  已补显式 case 转换。以上均在提交前修完并复验。
- **原生接口与文档依据**：`NSSavePanel.begin() async`
  <https://developer.apple.com/documentation/appkit/nssavepanel/begin(completionhandler:)>；
  `NSWorkspace.activateFileViewerSelecting`
  <https://developer.apple.com/documentation/appkit/nsworkspace/activatefileviewerselecting(_:)>；
  quarantine 属性
  <https://developer.apple.com/documentation/foundation/urlresourcevalues/quarantineproperties>；
  `URLSessionTaskDelegate.urlSession(_:didCreateTask:)`
  <https://developer.apple.com/documentation/foundation/urlsessiontaskdelegate/urlsession(_:didcreatetask:)>；
  `URLSessionConfiguration.ephemeral`
  <https://developer.apple.com/documentation/foundation/urlsessionconfiguration/ephemeral>；
  `CryptoKit.SHA256`
  <https://developer.apple.com/documentation/cryptokit/sha256>。
  实现遵循苹果官方文档，不凭经验猜 API 行为。
- **本地验证**：`~/sdks/go/bin/go test ./...` 全包通过；
  `python3 apps/macos/scripts/check-project.py` 通过（160 objects /
  30 app sources / 25 test sources / 1 UI test source）；
  `python3 apps/macos/scripts/check-strings.py` 通过（217 keys / 2 languages，
  仅剩既有未直接引用的说明键提示）；`bash -n apps/macos/scripts/check-candidate.sh`
  通过；`git diff --check` 干净；`swiftc -parse` 覆盖全部新增/改动 Swift 文件；
  带 stub CryptoKit 的 Linux `swiftc -typecheck` 验证服务与两项测试的类型。
  Linux Foundation Swift 架子 59 项中 58 过，唯一失败仍是既有
  CoreSupervisor 预算测试（Linux Foundation 进程/主队列行为差异，macOS CI 全绿，
  非本阶段引入）；新增 9 项 ReleaseVersion 测试全过。
  本机 Linux 无 Xcode/SwiftUI/AppKit，界面编译、资源编译、签名、DMG 与
  XCUITest 均留待 CI，不声称已在本机编译通过。
- **扩展点**：渠道来自 `MelonARCUpdateChannel(infoValue:)` 与 Info.plist，
  可扩展为 stable/preview 之外的值；manifest _schema_ 与平台字段使未来
  新增架构、最低系统或资产格式只需扩展 `CandidateManifest` /
  `ReleaseCatalog`；`ReleaseHTTPTransport` 可替换真实会话用于测试或企业镜像；
  `UpdatePhase` / 状态文案键驱动 UI，菜单、设置与 alert 共用同一 `UpdateModel`；
  面板注册表与 API 客户端分层未动，后续可接更多设置项。
- **待验**：CI 需确认新增 17 项测试执行、SwiftUI/AppKit 编译、资源与字符串
  编译、签名与 DMG 校验、Check and freeze 产出唯一候选 DMG；
  macOS 真机需验证菜单与设置入口、空 Release 显示“此渠道尚未发布版本”、
  同 build 正式发布显示已安装、旧 build 升级、403/429 文案、下载校验失败、
  保存后 quarantine 保持、Gatekeeper 首开与正常退出恢复代理。
  当前公开 Release 列表为空是真机预期场景，不代表更新失败。

### M5.4：macOS 排版与视觉逐项优化（2026-11-22）

- **基线**：本地 HEAD `964a2bc`（M5.3），远端基线 `aa80fb0e`。按用户附件
  `.m54-brief.md` 与仓库外 GPT 排版答复 §5 的 8 个步骤逐项实施；方案审阅
  基线为 build 41 反馈，方案存档只在
  `/home/hatch/workspace/projects/melonarc-gpt-answers-layout-20261122.md`，
  未复制进产品仓库。本阶段不回退 M5.3 自研更新检查，只改排版/视觉，
  不碰业务逻辑、API、数据模型、签名、公证或 CI 工作流。
- **完成内容**：
  - 步骤 1：新增 `UI/LayoutMetrics.swift`，集中页面/分区/卡片/行/状态间距、
    三列门槛、概览信息标签宽、侧栏与 sheet 尺寸令牌，并提供
    `View.panelPageInsets()`；已登记进 `.xcodeproj` 的 UI 分组与 app Sources。
  - 步骤 2：`RootView.swift` 改为从 `PanelRegistry.navigation()` 生成侧栏，
    用 `GeometryReader` + `ScrollViewReader` 按行高/间距令牌计算可视范围，
    选中项变化时滚动到可见；`SidebarPanelButton.swift` 删除负左缩进和旧双层样式，
    改为单一 `SidebarPanelButtonStyle`，覆盖普通/hover/pressed/selected 四态、
    焦点环、1 pt/2 pt 边界、减少透明度与高对比度分支。
  - 步骤 3：`PanelViews.swift` 抽出 `PanelPage`、`PanelList`、`PanelRowInsets`
    与短列表范围偏好键；`PanelStatus` 不再为缺失错误/更新时间留空行；
    `RulesView` 实现 0/1/多条规则排法、1–3 条短列表、浅底与 1 pt 边界、
    索引格式键和状态区 12 pt 间距；`PanelStateView.swift` 统一加载/空/失败
    状态的 icon→title→desc→actions 节奏。
  - 步骤 4：`PanelCard.swift` 去掉 GroupBox 外额外 16 pt，新增局部
    `PanelCardBoxStyle`：16 pt 内容边距、12 pt 连续圆角、
    `controlBackgroundColor`；`OverviewView.swift` 接入页面 inset、卡片间距、
    872 pt 三列 `ViewThatFits`、`InfoRow` 默认 120 pt 标签与窄宽上下排、
    本地化 pid/inbound 格式键，footer 仅在有 notice 时出现。
  - 步骤 5：`PoliciesView`、`SubscriptionsView`、`ConnectionsView`、
    `LogsView` 全部迁移到共用页面/列表/行内边距，删除重复水平 padding 和
    底部 8 pt；策略短列表数量计入组头与成员，连接字节与日志时间用等宽数字，
    日志图标列固定 20 pt。
  - 步骤 6：`SubscriptionEditorView.swift` 去掉 `Form`/`NavigationStack`，
    改为标题 + `ScrollView` + `Grid` + 固定页脚；最小/默认/展开/最大尺寸
    448×240、520×248、520×288、640×480；`SheetSizing` 用
    `NSViewRepresentable` 设置 `contentMinSize`/`contentMaxSize` 并只设置一次
    初始 `setContentSize`。自定义间隔 5…10080、5 分钟步进、校验、创建接口、
    错误文案和 macOS 26 `.glassProminent` 分支均保留。
  - 步骤 7：`Localizable.xcstrings` 新增 `overview.subtitle.pid_format`、
    `overview.inbound_format`、`rules.index_format` 三个中英键，动态值作参数，
    不写死数字或状态。
  - 步骤 8：`PanelNavigationUITests.swift` 保留原导航测试，新增边缘命中、
    方向键首尾不绕回、短规则索引可见、订阅 sheet 几何边界四项回归；
    对无键盘焦点/无 accessibility 暴露的环境使用 `XCTSkip`，不把环境差异
    当成产品缺陷。
- **关键决策及理由**：间距和设计常量集中在 `LayoutMetrics`，避免五个面板
  各自硬编码导致继续漂移；侧栏只重做样式与几何，`PanelRegistry`、键盘上下键
  首尾钳制和 `panel.<id>` 标识保持原样；五个面板共用容器/行组件，减少重复
  padding；订阅 sheet 用原生 `Grid` 与 AppKit 窗口尺寸护栏替代 `Form`，同时
  不触碰已验证的校验和创建逻辑；M5.3 的更新 UI/逻辑只在 `SettingsView.swift`
  调间距，不做功能改写。
- **原生接口与文档依据**：`ViewThatFits`
  <https://developer.apple.com/documentation/swiftui/viewthatfits>；
  `Grid` <https://developer.apple.com/documentation/swiftui/grid>；
  `GroupBoxStyle`
  <https://developer.apple.com/documentation/swiftui/groupboxstyle>；
  `ScrollViewReader`
  <https://developer.apple.com/documentation/swiftui/scrollviewreader>；
  `NSViewRepresentable`
  <https://developer.apple.com/documentation/appkit/nsviewrepresentable>；
  `NSWindow.contentMinSize`
  <https://developer.apple.com/documentation/appkit/nswindow/contentminsize>；
  `NSWindow.contentMaxSize`
  <https://developer.apple.com/documentation/appkit/nswindow/contentmaxsize>；
  `NSWindow.setContentSize(_:)`
  <https://developer.apple.com/documentation/appkit/nswindow/setcontentsize(_:)>。
  实现按苹果官方文档约束在 macOS 13.0 部署目标内，不引入第三方库。
- **本地验证**：`python3 apps/macos/scripts/check-project.py` 通过
  （162 objects / 31 app sources / 25 test sources / 1 UI test source）；
  `python3 apps/macos/scripts/check-strings.py` 通过
  （220 keys / 144 literal references / 2 languages，仅有未直接引用说明键提示）；
  `git diff --check` 干净；`~/sdks/swift/usr/bin/swiftc -parse` 覆盖 11 个新增/
  改动 Swift 文件，结果 `ALL_PARSE_OK`；命名红线 grep 对提交文件无命中，
  唯一命中是 `.m54-brief.md` 自述检查规则的那一行，简报在收尾时删除。
  本机 Linux 无 Xcode/SwiftUI/AppKit，界面编译、资源编译、XCUITest、
  签名与 DMG 均留待 CI，不声称本机已编译通过。
- **扩展点**：`LayoutMetrics` 可按页面/组件继续细分；`PanelPage` 与
  `PanelList` 是后续新面板的统一入口；`SidebarPanelButtonStyle` 的状态层可
  继续扩展强调色/图标；`SheetSizing` 可复用给其他需要尺寸护栏的 sheet；
  规则索引、pid 与入站格式均为字符串键，便于后续中英文案或格式调整。
- **待验**：CI 重跑确认 SwiftUI/AppKit 编译、资源与字符串编译、35 项
  现有 XCUITest 与单元测试执行、签名打包与冻结流程不受影响；用户虚拟机确认
  macOS 13 与 26+ 下三列/窄宽切换、侧栏四态与焦点环、高对比度与暗色模式、
  订阅 sheet 四档尺寸、中英文案、规则短列表、键盘上下键以及 M5.3 更新入口
  仍正常工作。

### M5.3+M5.4 修复：CI #42 五条 Swift 编译错误（2026-11-22）

- **基线**：CI #42（远端提交 `f2a5c490`，运行页
  https://github.com/Melon-tgj/MelonARC/actions/runs/44989943155）失败。
  Go、Frontend、Interop 三个 job 全绿；macOS 与 macOS 26 UI (glass)
  两个 job 报同一组 5 条 Swift 编译错误。按用户附件 `.m53m54f-brief.md`
  只修这 5 条错误，不回退 M5.3 自研更新检查与 M5.4 排版优化，
  不碰业务逻辑、API、数据模型、签名、公证与 CI 工作流。
- **完成内容**（5 条错误、4 个根因）：
  - `UI/SubscriptionEditorView.swift:8`「argument passed to call that takes
    no arguments」：类没有逐成员初始化器，`SheetSizingNSView` 未自定义初始化器，
    继承来的只有无参 `init()`；在 `viewDidMoveToWindow` 之前补
    `init(idealHeight:)`（先赋值再 `super.init(frame: .zero)`）与
    子类化必需的 `required init?(coder:)`。
  - `UI/SubscriptionEditorView.swift:37`「value of type 'NSWindow' has no
    member 'contentSize'」：`NSWindow` 没有 `contentSize` 读属性，尺寸只通过
    `setContentSize(_:)` 写入；且读出的宽高随后都被重写，读取本身多余。
    删掉读取与两项赋值，直接构造 `NSSize` 再 `setContentSize`。
  - `UI/UpdateModel.swift:246` 与 `:257`（两处同错）「type 'URLResourceKey'
    has no member 'quarantineProperties'」：键名与值属性名混用；
    `URLResourceKey` 上是 `quarantinePropertiesKey`，`URLResourceValues`
    上才是 `quarantineProperties`。两处 `forKeys` 改用
    `.quarantinePropertiesKey`，`values.quarantineProperties` 读写不动。
  - `UI/UpdateModel.swift:255`「cannot use mutating member on immutable value:
    'file' is a 'let' constant」：`URL` 是结构体，`setResourceValues(_:)`
    是变异方法，`file` 为 let 参数不可调用；先复制到 `var mutableFile`
    再调用。
  - 改动文件仅 `UI/SubscriptionEditorView.swift`、`UI/UpdateModel.swift`
    与本文档。
- **关键决策及理由**：按苹果官方文档区分 `URLResourceKey.quarantinePropertiesKey`
  与 `URLResourceValues.quarantineProperties`、`NSWindow.setContentSize(_:)`
  单向写入、`NSView` 子类的指定初始化器与 `required init?(coder:)` 要求；
  只做最小修复，不动 `await panel.begin()`（不在 5 条错误内，当前 SDK 可编译）、
  不处理 `UpdateModel.swift:191` 的 `allowedFileTypes` 废弃警告（仅警告）、
  不给 NSWindow 加 extension、不改函数签名、不升工具链。
- **本地验证**：`python3 apps/macos/scripts/check-project.py` 通过
  （162 objects / 31 app sources / 25 test sources / 1 UI test source）；
  `python3 apps/macos/scripts/check-strings.py` 通过（220 keys / 144 literal
  references / 2 languages，仅有未直接引用说明键提示）；
  `~/sdks/swift/usr/bin/swiftc -parse` 覆盖两个改动文件，结果 `ALL_PARSE_OK`；
  `git diff --check` 干净；命名红线 grep 对改动文件无命中（DEVLOG 既有两行
  是历史 grep 模式说明，非产品引用）。`swiftc -parse` 只查语法，本机 Linux
  无 Xcode/SwiftUI/AppKit，类型错误本地查不出，不声称已编译通过，
  最终验证靠 CI 重跑。
- **扩展点**：本阶段只修编译错误，未新增或改动扩展点；`SheetSizing` 与
  `ensureQuarantine` 的接口和调用方保持原样。
- **待验**：CI 重跑确认两条 macOS job 的 5 条错误全消、SwiftUI/AppKit 编译与
  资源/字符串编译通过、UI 测试与单元测试执行、签名打包与 Check and freeze
  通过并产出候选 DMG；无新的编译错误出现。
