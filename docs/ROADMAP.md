# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 的对齐进度**：已完成的工作，以及仍
**有意简化 / 尚未移植 / 架构受限**的更大子系统与少数边缘算子。

> 现状快照：73 个注册算子中 **70 个**已在运行时应用，另有别名算子层、本地文件/模板家族
> （含两遍替换与 `${var}` 运行时变量）、`@`-includes、规则行级属性；
> 单元测试 **342** 项全绿、构建 0 警告。
> 已完整验证：HTTP 正向代理、HTTPS MITM、HTTP/2、WebSocket（含逐帧抓取）、上游代理、
> 自研插件体系 v2（Rust 进程内 + JS/TS SDK）、流量检查（头 + Body 预览 + gzip/br/deflate 解码）、
> HAR 导出、`cipher` TLS 版本固定、流量落盘持久化、请求重放、规则分组管理。

---

## 已完成（本轮）

| 领域 | 状态 |
|------|------|
| 插件运行时（Rust 进程内 + 子进程 + 远程） | ✅ 二进制响应体、就绪等待、失败重试 |
| `@`-includes（从 URL / 文件引入规则） | ✅ 加载时解析 |
| `${port}` / `${version}` 配置变量 | ✅ |
| 响应体解码（gzip / deflate / brotli）用于查看 | ✅ 流式解码，界限 16 KB，不影响转发 |
| HAR 1.2 导出（`/sessions.har` + UI 下载） | ✅ |
| Web UI 过滤/搜索 | ✅ 按 URL/方法/状态/目标 |
| Body 预览上限可配置（`--body-preview-limit`） | ✅ |
| `internal-http-proxy` / `internal-https-proxy` | ✅ |
| `x`/`xs` 前缀代理变体 | ✅ 以基础代理近似 |
| `locationHref` 算子 | ✅ HTML 注入跳转脚本 |
| 流量落盘持久化 | ✅ JSONL 追加写入 + 每日轮转 + 启动恢复 (`--no-persist` / `--persist-days`) |
| 请求重放 | ✅ `POST /api/replay` self-loopback + UI ↻ 按钮 |
| 规则分组管理 | ✅ 多组 CRUD + toggle + 持久化到 `storage_dir/rules/` |
| 自研插件体系 v2 | ✅ 能力清单 (`GET /manifest`)、请求/响应双钩子、请求头改写、按需 body 投递 |
| JS / TS 插件 SDK | ✅ 零依赖运行时 + `.d.ts` 类型定义（`sdk/`），`satisfies Plugin` 可用 |
| 响应阶段规则二次解析 | ✅ `s:` / `resH.` / `serverIp:` 等条件在响应到达后真正求值；无相关规则时零开销 |

---

## 仍未对齐 / 后续计划

### 大型子系统（多天工作量）

- [x] ~~**向插件传递请求体**~~ → 已完成，见 [`PLUGINS.md`](PLUGINS.md)。请求体与响应体
      都可投递给插件，但**由插件的能力清单决定是否缓冲** —— 未声明的插件保持流式零开销
      （已用 SSE 实测双向验证）。
- [x] ~~**流式 body 钩子**（原版 `reqRead`/`resRead`）~~ → 已完成，见
      [`PLUGINS.md`](PLUGINS.md#流式钩子--pipe)。传输选了 HTTP/1.1 chunked 而非原版的
      CONNECT + `transproto` 分帧 —— 后者重新发明的正是 chunked，而 hyper 与 Node 两端都
      已实现好；代价是与原版 `pipe://` 插件不互通，理由与「不复刻原版插件 API」一致。
      握手先于字节：插件应答 200 之前的任何失败都零代价（body 原样放行）。
- [x] ~~**`pipe://` 真正的流式管道**~~ → 已完成。`pipe://` 现在选中流式钩子、支持
      `pipe://name(value)` 取值语法；指向没有流式钩子的插件时退化为 `plugin://`。
- [x] ~~**WebSocket 帧级拦改**（原版 `wsReqRead`/`wsResRead` 一族）~~ → 已完成，见
      [`PLUGINS.md`](PLUGINS.md#websocket-帧钩子--onwsframe)。每会话每方向一条长连接
      （`POST /ws/frames`），逐帧一进一出；控制帧不交付，帧类型与分片结构不可改，
      插件出错只丢钩子不丢连接。实测每帧约 38µs（p50），不挂插件的会话零开销。
- [ ] **更多插件钩子**：`uiServer`/`statsServer`（插件自带 UI/统计页）、`auth`、
      `sniCallback`。

### 规则解析（本轮审计修复）

- [x] ~~一行多个 pattern~~ → 已修。此前只取第一个 pattern，`host://x a.com b.com` 对 b.com 静默失效。
- [x] ~~行内 `#` 注释~~ → 已修。此前只处理行首 `#`。
- [x] ~~多行 `` line` `` 块~~ → 已实现。

### 响应阶段（已完成，遗留一项）

- [ ] **`serverIp:` 对具名源站不可判定** —— IP 字面量或 `host://` 覆盖时可答；具名源站
      本移植把主机名交给 `TcpStream::connect`，看不到实际选中的地址，重查 DNS 可能得到
      不同结果（轮询 DNS），因此保持不可判定并失败关闭，而非匹配一个猜测。
      需 `upstream::forward` 回传 socket 对端地址（`origin_stream` 在 `TcpStream::connect`
      处已持有），会波及 `ws.rs` 等调用点。
- [ ] `rule://` / `rulesFile://` 与插件注入的规则仍只解析一次（上游会重解析这些管理器）。

### 上游代理 / PAC / SOCKS / CA（本轮首次审计）

这一层决定**流量去哪、用什么 TLS**，因此失败开放的后果比规则层严重。已修：

- [x] 绝对形式 URI 用了**连接地址**而非请求的 Host —— `host://` 覆盖会被泄露给上游代理，
      且 `Host` 改写被忽略（`res.js:606-612`）。**失败开放。**
- [x] HTTPS 代理、以及与代理同时出现的 `host://` 覆盖，必须强制 CONNECT（`res.js:292-297`）；
      原先两者都发绝对形式。**失败开放。**
- [x] 叶证书缓存无上限 —— 每个伪造 SNI 都增长内存；上游折叠为 `*.parent` 并 LRU 限 5120。**失败开放。**
- [x] `ignore://proxy` 只丢弃字面写作 `proxy://` 的算子，`socks://` 等仍走代理。**失败开放。**
- [x] `http2https-proxy://` 未升级 TLS，用户以为加密的上游跳转走了明文。**失败开放。**
- [x] `proxy://user@host` 丢弃凭据；IPv6 代理地址在错误的冒号处切分；出站 SOCKS5 把 IPv6
      源站当域名发送；CONNECT 缺少 `Proxy-Connection`/UA/回退凭据；入站 SOCKS 无视客户端
      提供的认证方法而恒答 `0x00`（导致流失步）；叶证书有效期写死 2024–2044。
- [x] **源站证书校验** —— 上游默认**不校验**（`rejectUnauthorized = false`，仅 `--safe` 开启）。
      本移植**刻意反转**该默认：默认校验，`--insecure-upstream` 可关闭并打警告。
      这是唯一一处不照抄上游默认值的地方 —— 忠实原则一直只适用于「规则如何解析」，
      不适用于安全姿态。见 [`RULES.md`](RULES.md)。

仍未修（均已实测确认，非推断）：

- [x] ~~**自循环无防护**~~ → 已修：返回 302，与上游一致。
- [x] ~~**`pac://` 远程抓取与辅助函数缺失**~~ → 已修。另**刻意偏离上游**：
      PAC 抛错时返回 502 而非静默直连 —— 抛错的脚本没有说「走直连」，它什么都没说。
- [x] ~~**空 `proxy://` 静默直连**~~ → 已修：无法兑现的代理规则返回 502。
- [ ] 失败关闭若干：`x`/`xs` 代理失败时不回退直连、代理 URL 的 `?host=` 被忽略、
      `internal-*` 未走 whistle 间的 `x-whistle-https-request` 握手、`proxyTunnel` 未实现、
      代理选择按固定协议优先级而非规则顺序。

> 未改动并记录：上游把根 CA 密钥复用为每张叶证书的密钥（`ca.js:203-260`），
> 本移植为每张叶证书新生成密钥 —— **严格更强**，故不对齐。

### 模式匹配（本轮审计修复）

同一个根因的三处实例，都是**失败开放**（规则悄悄匹配了不该匹配的请求）：

- [x] ~~`:8080` 端口 pattern 匹配一切~~ → 已按上游编译为 `^[\w]+://[^/?]+:<port>/`。
- [x] ~~`example.test:8080` 忽略端口~~ → `Pattern::Prefix` 现在携带 `port`，匹配时校验。
- [x] ~~`!pattern` 取反~~ → 已支持，且与上游一致地**只作用于正则与端口 pattern**；
      上游对取反的字面量/通配 pattern 是在解析期直接丢弃的（`rules.js:1259-1268`），本移植照做。

### 多值算子（本轮审计遗留）

- [ ] **同名 header 的争用优先级相反** —— `reqHeaders`/`resHeaders`/`reqCookies`/
      `resCookies`/`reqCors`/`resCors`/`trailers` 在上游走同一套 `parseRuleJson` 折叠，
      同一个 header 名被两行指定时取**首行**的值，本移植取**末行**。指定不同 header 的
      多行行为一致。修复所需的 `merge_line_maps` 辅助已存在。
- [ ] `rulesFile` / `resScript` 上游会拼接/取首，本移植仍只用首行。
- [ ] `params://` 合并进请求体（当前折叠只作用于查询串）。

### 筛选器（本轮审计发现）

原版文档的条件语法见 `_original/docs/docs/rules/filters.md`；以下差异均已用运行中的代理实测：

- [x] ~~**`reqH.<key>:<pattern>` 头筛选语法**~~ → 已实现，含 `req.`/`reqHeader.`/`reqHeaders.`
      与 `h:`/`header:` 全部拼写；头值按**包含**比较（上游 `filterHeader`），不再是相等。
- [x] ~~`chance:<概率>` 随机采样~~ → 已实现（`Math.random() < p`，含 `<n>%` 写法）。
- [x] ~~条件值的 `/regexp/[i]` 形式~~ → 已实现（上游 `util.toRegExp`，编译失败降级为字面量）。
- [x] ~~`s:` 响应状态、`resH.` 响应头、`serverIp:`~~ → 已实现，见下「响应阶段」。
- [x] ~~`clientPort:` / `serverPort:` / `remoteAddress:` / `remotePort:`~~ → 已实现；
      客户端一侧来自 accept 到的 socket（`peer` 现在按 `SocketAddr` 传递），
      服务端一侧来自本次转发的目标地址。
- [x] ~~`i:` 上游同时匹配客户端**与服务端** IP，本移植只匹配客户端~~ → **不是差异**：
      上游那条服务端分支不可达（`filterProp` 在 `req.clientIp` 为空时即报「已处理」，
      下面的 `req.hostIp` 一行对 ip 筛选器永远不会执行，`rules.js:1824-1830,:1875-1880`）。
      要匹配服务端地址请写 `serverIp:`。
- [ ] `b:` 请求体筛选（需要在规则解析**之前**缓冲请求体）、`env:`（插件环境）、
      `from:`（`tunnel`/`composer`/`sni` 等来源标记）。

未知条件会落到 URL 正则回退，因此不支持的筛选器让规则**惰性失效**而非错误命中 ——
失败是保守的，但静默。

### 响应阶段（本轮实现）

上游对每个请求解析两次规则：发出前 `resolveReqRules`，响应头到达后 `resolveResRules`
（`rules.js:2302-2308`、`plugins/index.js:1322`）。本移植此前只解析一次，因此所有关于
响应的条件都恒为「未知」而**惰性失效**。现在两遍都做，细节见
[`RULES.md`](RULES.md#the-response-phase)：

- 响应阶段拥有上游的 `pureResProtocols`（`protocols.js:82-111`）；`host://` 一类请求期
  算子不会被响应事实打开 —— 请求早已发出，这与上游一致。
- 两遍结果按**书写顺序**合并（每个算子带着所在行的解析序号），而非上游 `mergeRule` 的
  「响应遍优先」：上游两遍读的是互不相交的协议集，永远不会遇到同一文件的两个同名算子。
- 响应阶段的 `ignore://` 可以撤销请求阶段已解析的响应期算子（上游
  `ignoreRules(origin, …, isResRules)`）。
- **开销**：每个规则分组在解析时记下哪些行可能需要第二遍。文件中没有相关规则时整遍跳过
  （实测每响应约 2ns，对照 500 条规则的请求遍约 2.4µs）；500 条里有 1 条相关时约 24ns。
- 尚未覆盖：`rule://` / `rulesFile://` 引入的规则与插件注入的规则只解析一遍
  （上游会一并重解析）；WebSocket 与 `CONNECT` 隧道没有响应阶段。
- `serverIp:` 仅在目标地址**确切已知**时求值（IP 字面量或 `host://` 覆盖）。域名源站的
  实际连接地址本移植看不到，再查一次 DNS 可能得到不同答案，因此保持「未知」并失败关闭。

### 观测与持久化

- [x] ~~**流量落盘持久化**~~ → 已完成（JSONL + 每日轮转 + 启动回加载）
- [x] ~~**请求重放**~~ → 已完成（self-loopback 通过代理自身端口）
- [x] ~~规则的导入/导出与分组管理~~ → 已完成（多组 CRUD + UI toggle/edit/delete）

### 模板与变量（原版本身很窄）

- [x] ~~`tpl`/`dust`/`jsonp` 升级为完整 dust.js / handlebars 语义~~ → **前提有误，已按上游实情完成**，
      见 [`TEMPLATES.md`](TEMPLATES.md)。原版**根本没有模板引擎**：`tpl`/`dust`/`jsonp`
      字节级等价，没有 section/循环/嵌套。真正缺失的是第二遍 `${var}` 运行时变量替换，
      现已实现（封闭白名单 + `.key` 子路径 + `${{var}}` URI 编码）。同时修正了三个缺陷：
      未知占位符曾被置空（上游是原样保留）、`jsonp://` 的 callback 包装是本移植凭空发明的
      （已移除）、第一遍正则曾每请求重新编译。
- [ ] `{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 插件包变量（与插件运行时耦合）。
- [x] ~~`lineProps`（whistle 规则行级属性系统）~~ → 见 [`LINE_PROPS.md`](LINE_PROPS.md)。
      解析层与原版完全对齐；`important`、`safeHtml`/`strictHtml` 注入门禁、
      `internal`/`internalOnly` 作用域、`proxyFirst`/`proxyHost`/`proxyHostOnly`、
      `weakRule` 均已端到端接线并验证。其余属性经核对**在本移植中无对应可接之处**
      （如本移植不发自动 CORS，`disableAutoCors` 无物可抑制），已在文档中逐条说明理由。

### 架构受限（rustls / MITM 时序）

- [ ] **`sniCallback`** —— 在 TLS SNI 阶段用插件选证书。我们的 MITM acceptor 在 SNI 阶段
      按域名构建，早于按请求的规则解析，且需插件运行时在该时点介入；当前架构下不可达。
- [ ] **`cipher` 扩展** —— rustls 只暴露 TLS 1.2/1.3、不接受 OpenSSL cipher 字符串，故只支持
      版本固定（已实现），无法完整对齐 Node 的 TLS 选项。

### 非功能项

- [ ] 性能剖析（大响应体、并发连接下 tee 抓取开销）。
- [ ] 清理较新工具链带来的 clippy 风格提示（`collapsible_if` 等）。

---

## 不打算做的事（Non-goals）

- **现成 npm `whistle.*` 包的兼容运行** —— 原版插件 API 建立在对 Node `req`/`res` 对象的
  装饰之上（约 2600 行加载器、位置式 CSV 头协议、单端口多钩子分发）。与其被这套历史包袱
  绑定，whistle-rs 选择了一套显式、有类型、语言无关的自研协议，配 JS/TS SDK。
  见 [`PLUGINS.md`](PLUGINS.md)。

- **逐字节复刻 React 前端** —— 内建轻量 UI 已覆盖核心检查/编辑需求；除非有明确诉求，
  不重写 `biz/webui`。
- **硬绑定 Node.js 运行时** —— 项目目标是单一静态二进制。JS/TS 插件跑在子进程里，
  是**可选**特性：不写插件就完全不需要 Node。
- **`G` / `style` 算子的「流量效果」** —— `G` 是全局插件变量基础设施、`style` 是规则列表
  配色，二者都不是逐请求的流量算子；保持「解析但不产生效果」。

---

## 参与

剩下的多为增量工作。真正被架构挡住的只剩 **`sniCallback`** —— 它要在 TLS SNI 阶段挑证书，
早于按请求的规则解析，当前 MITM 结构够不着。

模块地图见 [`ARCHITECTURE.md`](ARCHITECTURE.md)，算子覆盖见 [`RULES.md`](RULES.md)，
插件编写见 [`PLUGINS.md`](PLUGINS.md)，模板见 [`TEMPLATES.md`](TEMPLATES.md)，
规则行级属性见 [`LINE_PROPS.md`](LINE_PROPS.md)。
