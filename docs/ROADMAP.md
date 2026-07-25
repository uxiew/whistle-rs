# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 的对齐进度**：已完成的工作，以及仍
**有意简化 / 尚未移植 / 架构受限**的更大子系统与少数边缘算子。

> 现状快照：73 个注册算子中 **70 个**已在运行时应用，另有别名算子层、本地文件/模板家族
> （含两遍替换与 `${var}` 运行时变量）、`@`-includes、规则行级属性；
> 单元测试 **390** 项全绿、构建 0 警告。
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
| `x` 前缀代理变体 | ✅ 九个拼写全部识别（按 `PROXY_RE` 的 `x?` 推导），握手无法建立时回退直连 |
| 代理 URL 的 `?host=` / `proxyTunnel` 链式 CONNECT | ✅ |
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

- [x] ~~**`serverIp:` 对具名源站不可判定**~~ → 已修：`upstream::forward_with_addr` 回传
      socket 对端地址，具名源站也可判定，且不需要重查 DNS（轮询 DNS 下会答出请求从未
      到达的地址）。经代理时该地址是**代理的**地址 —— 上游亦然
      （`req.hostIp` 取自解析后的代理地址，`res.js:238,:259`）。
- [x] ~~`rule://` / `rulesFile://` 与插件注入的规则仍只解析一次~~ → 已修。这些规则文本的
      **已解析形态**现在被保留到响应阶段并再解析一遍（上游对 `pRules`/`fRules`/`hRules`
      同样如此，`_original/lib/plugins/index.js:1326-1335`）。请求遍改用
      `resolve_scoped`（会扣留），第二遍恰好补上被扣留的那些 —— 因此**不会重复应用**，
      也不会把 `chance:` 重掷一次（整体重解析就会）。合并进来的算子在两遍里都排在
      引入它们的文件之后。**开销**：无合并规则时约 7ns/响应，合并了但没有响应相关行时
      约 9ns，有一行时约 250ns。
      仍不覆盖：WebSocket / `CONNECT` 隧道没有响应阶段；插件直接应答、自循环 302、
      `enable://abort` 三条出口本来就不应用任何响应期算子（顶层规则同理）。

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
- [x] ~~`x` 代理失败时不回退直连~~ → 已修：`xproxy://`、`xsocks://` 等在**握手无法建立**时
      回退直连（`X_RE`，`res.js:31,:546-560`）。请求一旦写上 socket 就不再重试 —— 无法重放，
      上游同样以 `piped` 设防（`res.js:529`）。
- [x] ~~代理 URL 的 `?host=` 被忽略~~ → 已修：`P_HOST_RE`（`lib/rules/index.js:81,:243`）。
      `host://` 规则优先；两者都会把该跳转成 CONNECT。
- [x] ~~`proxyTunnel` 未实现~~ → 已实现：带地址覆盖时对上游代理再发一层 CONNECT，
      内层带 `x-whistle-policy: intercept`（`lib/tunnel.js:535-537`，`lib/util/patch.js:120-140`）。
      仅 HTTP/HTTPS 代理，SOCKS 跳不理会该标志（与上游一致）。
- [x] ~~代理选择按固定协议优先级而非规则顺序~~ → 已修：上游把所有拼法归入同一 `proxy` 键
      （`PROXY_RE` → `protocol = 'proxy'`，`lib/rules/rules.js:1286`），因此**先写的行胜出**。
      本移植按算子的解析顺序（`RuleOp::order`）取最小者。
- [x] ~~`internal-*` 未走 whistle 间的 `x-whistle-https-request` 握手~~ → 该项**记录有误**：
      握手早已实现（`mark_stripped_tls` / `take_https_marker`），本轮实测两个 whistle-rs
      串联，far 端确实按 `https://` 解析规则。握手中其余部分依赖本移植没有的机制：
      `x-whistle-client-id`（无 client-id 概念）、`x-whistle-policy: intercept`（本移植
      对 CONNECT 一律 MITM，无需协商，仅 `proxyTunnel` 内层发送）、`x-forwarded-from-whistle-<uid>`
      （值含每进程 uid，不可移植）、`x-whistle-request-tunnel-ack` 流控。

以下需要规则层配合，本轮未做（属 `src/rules/*`）：

- [x] ~~四个 `x` 拼写完全不被识别~~ → 已修（本轮）。`canonical()` 手写列表漏了
      `xinternal-http-proxy` / `xinternal-https-proxy` / `xhttps2http-proxy` /
      `xhttp2https-proxy`；不能规范化的名字在本移植里**根本不算协议**
      （`is_protocol` 要查 `canonical`），因此这四条规则不产生任何代理算子、请求**直连**
      —— **失败开放**，已实测（改前 200 直连，改后按规则走代理）。现按上游 `PROXY_RE`
      的 `x?` 前缀从 `UPSTREAM_PROXY_PROTOCOLS` 推导，不再手写。
- [ ] `xhost://` 的直连回退（`retryXHost`，`res.js:571-600`）未实现。

> 未改动并记录：上游把根 CA 密钥复用为每张叶证书的密钥（`ca.js:203-260`），
> 本移植为每张叶证书新生成密钥 —— **严格更强**，故不对齐。

### 模式匹配（本轮审计修复）

同一个根因的三处实例，都是**失败开放**（规则悄悄匹配了不该匹配的请求）：

- [x] ~~`:8080` 端口 pattern 匹配一切~~ → 已按上游编译为 `^[\w]+://[^/?]+:<port>/`。
- [x] ~~`example.test:8080` 忽略端口~~ → `Pattern::Prefix` 现在携带 `port`，匹配时校验。
- [x] ~~`!pattern` 取反~~ → 已支持，且与上游一致地**只作用于正则与端口 pattern**；
      上游对取反的字面量/通配 pattern 是在解析期直接丢弃的（`rules.js:1259-1268`），本移植照做。

### 多值算子（已完成）

- [x] ~~**同名 header 的争用优先级相反**~~ → 已修。`reqHeaders`/`resHeaders`/`reqCookies`/
      `resCookies`/`reqCors`/`resCors`/`trailers` 现在与上游一样走 `parseRuleJson` 折叠
      （`merge_line_maps`）：同一个 header 名被两行指定时取**首行**的值，与其余「首个匹配
      获胜」一致；指定不同 header 的多行仍全部生效。顺带按 `setReqCors`
      （`_original/lib/util/index.js:2899-2921`）补齐了 `reqCors` —— 此前它把整个值当作
      `Origin` 写入（`reqCors://enable` 会写出 `Origin: enable`），现在只认 URL / `*`，
      并支持 `method=` / `headers=` 两个预检头。
- [x] ~~`rulesFile` / `resScript` 上游会拼接/取首，本移植仍只用首行~~ → 已修。
      `rulesFile` 现按上游的过滤规则累积（`_original/lib/rules/rules.js:2258-2272`）：
      写作 `reqRules://` 的行**全部保留**，其余拼写只保留**第一条**（候选脚本），
      保留者按解析顺序拼成**一份**规则文本再解析 —— 因此跨文件争用单值算子由包含顺序决定。
      `resScript` 现在跳过 `resRules://` 拼写去找真正的脚本（此前会把规则文件丢给 JS 引擎）。
      仍未做：上游会把内容像 JS 的候选项**执行**并把它吐出的规则拼回去（`isRulesContent`），
      本移植没有动态规则脚本；`resScript` 的 `resRules://` 条目也无处安放 ——
      本移植的 `resScript` 是直接改响应的 JS 钩子，不是规则生产者。
- [x] ~~`params://` 合并进请求体~~ → 已完成，三种体都实现了：`multipart`（按 `name=` 整段替换 /
      追加新段）、`x-www-form-urlencoded`（仅 POST，与上游 `isUrlEncoded` 一致）、JSON
      （深合并进第一段 JSON 形状的子串）。与上游一样**二选一**：体接走了 `params` 就不再
      进查询串（`_params = hasBody ? null : params`，`_original/lib/inspectors/req.js:421`），
      `urlParams` 恒进查询串。`delete://reqBody.<path>` 同乘一条变换，因此也一并接线。
      判定所用的 method / content-type 取**转发时**的值（即 `method://`、`reqType://` 之后），
      与上游 `handleReq` → `handleParams` 的顺序一致。
      **开销**：没有 `params://` 命中时判定为两次 map 查找，实测 ~19ns/请求（对照 500 条规则
      的解析 ~2.6µs、既有的 `body_ops_present` ~245ns）；请求路径上调用两次，合计 ~38ns。
      不对齐处：上游按块流式改写 multipart，本移植缓冲后整体改写（其余请求体算子本来就缓冲），
      因此没有 `reqMergeBigData` / `MAX_REQ_SIZE` 上限；非 UTF-8 请求体不处理（上游试 GB18030）。

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
- [x] ~~`b:` 请求体筛选、`env:`~~ → 已实现。
      `b:` 沿用上游的**两段式**：解析期把带 `b:` 的行收进独立候选表（上游 `_bodyFilters`，
      `_original/lib/rules/rules.js:1390-1392`），解析规则**之前**先问「除了 body 条件之外，
      这些行会命中本请求吗」，只有会才缓冲请求体（上游 `resolveBodyFilter`，`rules.js:2455-2465`）。
      实测 500 条规则下：无 `b:` 行 **4.2ns**/请求，有一条但不命中 **11ns**，命中 **12ns**
      （另加一次非竞争 `RwLock` 读约 5ns），对照其后的解析约 2.8µs。
      比较方式与 header 一致（包含、忽略大小写），空体也是**已知**答案因此 `b:!x` 会翻转。
      `env:` 读的是 **whistle 自己的进程环境变量**（`env = process.env`，`rules.js:14,:1961`），
      不是插件环境 —— 此前本文件的描述有误。键**区分大小写**、只用 `=` 分隔。
      不对齐：上游缓冲有 `MAX_REQ_SIZE`（2MB / `reqMergeBigData` 16MB）上限并按前缀匹配，本移植不设上限。
- [ ] `from:`（`tunnel`/`composer`/`sni` 等来源标记）。

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
- `rule://` / `rulesFile://` 引入的规则与插件注入的规则**同样走两遍**：它们的已解析
  管理器被保留到响应阶段（上游对 `pRules`/`fRules`/`hRules` 亦然）。开销：无合并规则时
  约 7ns/响应，合并了但无响应相关行时约 9ns，有一行时约 250ns。
- 尚未覆盖：WebSocket 与 `CONNECT` 隧道没有响应阶段；插件直接应答 / 自循环 302 /
  `enable://abort` 三条出口不应用任何响应期算子（顶层规则同理）。
- `serverIp:` 取自**已建立的 socket**（`upstream::forward_with_addr` 回传对端地址），
  域名源站同样可判定，且不必重查 DNS —— 轮询 DNS 下重查可能答出请求从未到达的地址。
  经上游代理时该地址是**代理的**地址，与上游一致（`res.js:238,:259`）。
  完全没有建立连接时仍为「未知」并失败关闭。

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
