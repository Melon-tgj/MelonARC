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
