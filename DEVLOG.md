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
