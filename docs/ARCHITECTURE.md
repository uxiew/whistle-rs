# 架构与开发

> 当前的验证结果和限制见 [STATUS.md](STATUS.md)，构建和测试命令见[DEVELOPMENT.md](DEVELOPMENT.md)。下文的基准数据是历史测量，并没有在之后的每个提交上重新测过。控制台是 `ui-src/` 里的 Vue 应用；`build.rs` 把它构建出的 HTML 嵌进二进制，没有构建产物时嵌一个占位页。

whix 是怎么搭起来的，各部分对应原版 whistle 源码的哪里，以及怎么扩展它。

- [模块地图](#模块地图)
- [请求的生命周期](#请求的生命周期)
- [依赖](#依赖)
- [扩展：新增一个规则算子](#扩展新增一个规则算子)
- [上级代理是怎么接入的](#上级代理是怎么接入的)
- [测试](#测试)
- [项目目录结构](#项目目录结构)

---

## 模块地图

每个 Rust 模块对应 `../_original/lib` 下原版 JS 的一部分：

> **`Ported from`（“移植自”）这一列指向上游 whistle 2.10.4 的源码树**，本仓库已经不再附带这份源码。怎么取回、取哪个提交，见 [`UPSTREAM.md`](UPSTREAM.md)——表里的行号只对那个提交有效。

| Rust 模块 | 移植自 | 职责 |
|-------------|-------------|----------------|
| `src/config.rs` | `lib/config.js` | 运行时配置、存储路径、默认值 |
| `src/rules/protocols.rs` | `lib/rules/protocols.js` | 算子注册表，以及可多次匹配的算子集合 |
| `src/rules/mod.rs` | `lib/rules/rules.js` | 逐行解析、匹配串的种类、算子解析 |
| `src/rules/matcher.rs` | `lib/rules/rules.js`（`resolveRules`） | 拿请求去匹配规则，为每个算子选出胜出的那条 |
| `src/rules/wildcard.rs` | `lib/rules/rules.js`（`parseWildcard`、`isRegUrl`） | 两种通配符匹配串，以及筛选器自己的那种 |
| `src/rules/regexp.rs` | `lib/util/index.js`（`toRegExp`、`toOriginalRegExp`） | 用户写的每个 `/…/`——匹配串、筛选器、`*Replace`、模板——都用同一个正则类型，由 regress 按 JavaScript 语法编译；编译不过时给出的报告也在这里 |
| `src/rules/url.rs` | `lib/rules/rules.js`（`joinUrl`、`setProtocol`） | 目标地址的路径从哪来，以及几种括号写法 |
| `src/rules/replace.rs` | `lib/util/replace-pattern-transform.js` | `$0`–`$9` 展开，匹配串的捕获组和 `*Replace` 都用它 |
| `src/rules/storage.rs` | `lib/rules/util.js`（`rulesStorage`） | 磁盘上的规则组和 Values，以及其中哪些被启用了 |
| `src/rules/include.rs` | `lib/rules/util.js`（`getRemoteRulesResolver`） | `@` 行（引入）：拉取它指向的内容，保持更新，内容变了就重新解析 |
| `src/ca.rs` | `lib/https/ca.js` | 根证书的生成和持久化，按域名签发站点证书 |
| `src/proxy/mod.rs` 及其同级文件 | `lib/index.js`、`lib/tunnel.js` | 代理服务本体，一个文件管一类事：`listen`（端口、accept 循环）、`tunnel`（CONNECT、中间人解密、隧道里的 h1/h2）、`serve`（请求流水线）、`response`（响应阶段和 body 类算子）、`upgrade`（WebSocket）、`ledger`（每个请求一条会话，失败的也算）、`session`/`capture`（控制台显示的内容）、`state`、`markers`、`dumps`。`mod.rs` 里有总览 |
| `src/proxy/upstream.rs` | `lib/handlers/http-proxy.js` | 出站转发（连接地址和 Host/SNI 分开处理），HTTP/SOCKS 上级代理 |
| `src/proxy/apply.rs`、`src/proxy/apply/` | `lib/inspectors/{req,res}.js` | 把解析出的规则落实成对请求/响应的修改，一类算子一个文件（`req_ops`、`res_ops`、`header_ops`、`body_ops`、`route`、`local`……）；`apply.rs` 里有总览 |
| `src/proxy/dest.rs` | `lib/inspectors/rules.js:40` | URL 替换类规则生效之后，请求最终发往哪里 |
| `src/proxy/header_rules.rs` | `lib/rules/index.js:558-657` | 请求可以在五个头里自带规则——每个请求上的这五个头都会被摘掉，但只有在 `-M enableRequestHeaderRules` / `-M multiEnv` 下才会读取 |
| `src/proxy/forwarded.rs` | `lib/util/index.js:3697-3728`、`util/common.js:1231-1266` | 前置代理声称的信息——`x-forwarded-host`/`-proto` 要开对应模式才认；另有两个 whistle 自有写法的头，上游不设任何开关就直接读取 |
| `src/qr.rs` | `qrcode@1.2.0`（上游的一个依赖） | 二维码编码器，给控制台显示局域网地址用：字节模式、纠错等级 M、版本 1-10。由 `tests/differential/qr-bench.js` 拿它和那个模块逐一对照 |
| `src/proxy/template.rs` | `lib/handlers/file-proxy.js`（`render`） | `tpl`/`dust`/`jsonp` 的两遍渲染，以及 `${var}` 变量 |
| `src/proxy/persist.rs` | — | 会话持久化（JSONL，按天轮转）。body 预览连同它的标记（`truncated`、`binary`、`undecodable`）一起写入；预览文本和原始字节对不上时，原始字节也一起写。读回时直接用这些还原，不重新推算 |
| `src/proxy/search.rs` | `biz/webui/htdocs/src/js/network-modal.js`（`h:`/`b:`） | 搜索框里的 `h:` 和 `b:`，在当前保留的所有会话上查找；其中的正则由 regress 编译，所以含义和浏览器里的 `RegExp` 一致 |
| `src/proxy/outcome.rs` | `lib/inspectors/data.js`（`reqError`/`resError`） | 请求没走完时是怎么结束的：哪个阶段、什么原因、把这两样从 `upstream` 带出来的错误标签，以及发现响应中途断掉的 body 包装层 |
| `src/proxy/sni.rs` | `lib/https/index.js:1281`、`lib/https/load-cert.js` | SNI 阶段：预读 ClientHello，选证书，或者原样转发这条连接 |
| `src/proxy/socks.rs` | `lib/index.js`（socks 服务） | 入站 SOCKS5 服务 |
| `src/proxy/script.rs`、`src/proxy/script_prelude.js` | `lib/rules/index.js`（`getScriptContext`、`execRulesScript`）、`lib/socket-mgr.js`（`execHandleFrame`） | JS 引擎（boa），以及脚本在里面能用到什么：规则脚本、在每条连接自己的线程上跑的 `frameScript`、PAC。prelude（预置脚本）是用 JavaScript 写的 Node `Buffer`、`url.parse`、`querystring.parse` 和 `iconv` 辅助函数 |
| `src/proxy/pagelog.rs` | `lib/inspectors/log.js`、`assets/js/log.js` | `log://`：注入页面或脚本的采集器、它上报日志用的那个页面同源路径，以及 Console 面板读取的有界存储 |
| `src/proxy/tls_options.rs` | `lib/rules/index.js`（`getTlsOptions`） | `tlsOptions://` 给源站连接配的客户端证书（PEM 或 PFX）和信任设置（`ca`、`rejectUnauthorized`）；也是连接池键的一部分 |
| `src/proxy/ws.rs` | `lib/socket-mgr.js` | WebSocket 帧编解码 + 会抓包的隧道：先跑 `frameScript`，再跑插件的帧钩子。另外还有 `inspected_relay`：`enable://inspect` 的隧道用的逐块转发 |
| `src/proxy/webui.rs`、`src/proxy/webui/` | `biz/webui` | 控制台：路由表（`webui.rs` 里的 `handle`）和它的 API，一个功能区一个文件——`access`、`sessions`、`har`、`rules`、`values`、`bundle`、`composer`、`console_hosts`、`plugin_pages`、`logs`（Console 面板的页面日志）、`switches`（HTTPS、全部规则、插件这几个开关） |
| `ui-src/` | `biz/webui/htdocs` | 控制台前端：Vue 3 / Vite / TypeScript 应用，构建成单个文件，编译时内联进二进制；没构建时 `build.rs` 换上占位页，所以构建代理本身不需要 Node |
| `ui-src/src/editor/whistle-classify.js` | — | 规则分类器；和解析器共用 `index_of_pattern`，有一个 Rust 测试保证两边一致 |
| `src/plugins/mod.rs` | `lib/plugins/` | 插件注册表、能力清单（manifest）、请求/响应钩子、远程 JSON 协议 |
| `src/plugins/builtin.rs` | （示例） | 内置的 Rust 插件（`echo`、`tag`、`stamp`、`upper`、`ws-upper`、`gate`、`no-mitm`） |
| `src/plugins/pipe.rs` | `lib/util/transproto.js` | 流式 body 传输（`pipe://`），用 chunked HTTP，而不是上游自己的分帧格式 |
| `src/plugins/wsframe.rs` | `load-plugin.js`（ws 钩子） | 逐帧的 WebSocket 传输，每个方向一条长连接，按记录分帧 |
| `src/plugins/auth.rs` | `load-plugin.js:1746`、`plugins/index.js:831` | 认证关卡——出故障时**默认拒绝**（fail closed）：关卡本身坏了返回 502，被拒返回 403 |
| `src/plugins/ui.rs` | `biz/webui/lib/index.js:466` | `/plugin/<name>/…`，用插件自带的页面响应 |
| `src/plugins/sni.rs` | `plugins/index.js:228`、`load-plugin.js:1841` | `sniCallback`——决定给连接出示哪张证书，或者干脆不拦截 |
| `src/plugins/stats.rs` | `plugins/index.js:1369` | 按阶段上报统计，发出去就不管（fire-and-forget） |
| `sdk/whix-plugin.js` | `lib/plugins/load-plugin.js` | 零依赖的 JS/TS 插件 SDK（附 `.d.ts` 类型） |
| `src/proxy/restream.rs` | `lib/inspectors/data.js`（`parseFrameSep`） | 切成帧的 body：事件流（event stream）和 `x-whistle-custom-frame-separator` |
| `src/proxy/coding.rs` | `lib/util/index.js`（`getZipType`、各种 transform） | gzip / deflate / brotli / zstd：解码出来供查看，再编码回去转发 |
| `src/proxy/ciphers.rs` | `lib/rules/index.js`（`getTlsOptions`） | `cipher://`，以及规则可以钉死的 TLS 选项 |
| `src/proxy/timing.rs` | `lib/inspectors`（各阶段耗时） | 各阶段耗时，按控制台瀑布图读取的格式记录 |
| `src/proxy/bench.rs` | — | 进程内的压测工具，不放进常规测试集 |
| `src/explain.rs` | `biz/webui/cgi-bin/rules/test.js` | `whix explain`——不真的发请求，告诉你一个请求会命中哪些规则 |
| `src/proxy/body.rs` | — | 统一的 boxed 响应 body 类型 + 限速 body |
| `src/embed.rs` | — | 作为库使用时的门面：绑定端口 0、观察会话、替换规则、关闭 |
| `src/main.rs` | `bin/whistle.js` | 命令行解析、启动时把各部分组装起来 |
| `src/lib.rs` | — | 模块根，以及 crate 级文档 |

## 请求的生命周期

```
                       ┌──────────────────────── main port (TcpListener) ─────────────┐
client ── TCP ──▶ hyper http1 serve_connection ──▶ top_level(req)
                       │
   ┌───────────────────┼────────────────────────────────────────────┐
   │ CONNECT           │ absolute-form URI            │ origin-form:  │ origin-form:
   │                   │                              │ /-/, or a     │ Host is a
   │                   │                              │ Host that is  │ console name
   │                   │                              │ not a console │
   │                   │                              │ name          │
   ▼                   ▼                              ▼               ▼
handle_connect     serve(Forward)                serve(Forward)   local_ui
   ├─ relayed_unread ─ dial, then 200 (no reply if the dial fails) ──▶ relay_before_reply
   │ 200 + upgrade     │                              │            (status page,
   ▼                   │                              │             /rootCA.crt)
serve_tunnel           │                              │
   │ peek ClientHello  │                              │
   ├─ sni::decide ─ "do not intercept" ──▶ relay_recorded (opaque; one CONNECT session)
   │ TLS-accept        │                              │
   │ (leaf for the SNI,│                              │
   │  or a plugin's)   │                              │
   ▼                   ▼                              ▼
serve(Mitm) ──────────────────────────────────────────
        │
        ├─ build ReqInfo (scheme, host, port, path, full_url)
        ├─ RuleManager::resolve(&ReqInfo) → Resolved
        ├─ buffer request body?  ── only if a matched plugin's manifest asks
        ├─ plugin onRequest ── responded? ──▶ mock response
        │        │  else: merge injected rules, collect header rewrites
        ├─ apply::short_circuit? ── yes ──▶ 302 / mock status / file / template ─▶ response
        │        no
        ├─ apply::resolve_target (host:// override; keep SNI)
        ├─ apply::apply_request (headers, ua, method, …) + plugin header rewrites
        ├─ upstream::forward (own TCP/TLS conn) ──▶ Response<Incoming>
        ├─ apply::apply_response (status, headers, cors)
        ├─ plugin onResponse ── body-less plugins run here; response keeps streaming
        └─ buffer response body? ── only if a rule or a plugin needs it ──▶ response
```

两个入口（`Forward`、`Mitm`）汇入同一条 `serve()` 流水线，区别只在 scheme/host/port 是怎么得出来的。所以规则对普通 HTTP 和拦截（解密）后的 HTTPS 生效方式完全一样。

### 一个请求怎样恰好变成一条会话

`serve()` 接下的每个请求，不管怎么结束，都会变成一条会话。调用方是 `serve_recorded`：它交给`serve()` 一个 `Ledger`，也就是这条会话的草稿，随着请求往下走逐步填满（先是方法和 URL，然后是命中的规则，再然后是目标地址、发出去的头和这条连接的各项耗时）。草稿最后有三种落账方式：

- **负责应答的那条路径自己记账**，通过 `Ledger::record`：本地应答、插件应答、中止（abort），以及源站返回的响应头部。
- **从 `serve()` 里漏出来的错误**会落到 `guard`：它把草稿连同错误发生的阶段记下来，并回一个带`x-whix-error` 和 `x-whix-session` 头的 `502`。阶段不是从错误信息里猜的：`upstream` 在每个失败发生的地方就把它包进一个 `outcome::Stopped`（`dial` 把 DNS 和建连分开标，另外还有代理握手、TLS 握手、发送），`outcome::phase_of` 再穿过上层加的各种 `.context()`，找到最里层的那个标签。没打标签的错误算 `internal`——这说明标签漏打了，而不是一种错误类别。
- **future 被丢弃**——客户端关掉连接或重置流时，hyper 会丢掉 service future——`Ledger` 也跟着被丢弃，它的 `Drop` 把草稿记为 `client`。

三条路不会重复记账，靠的是 `settled`。转发出去的响应有一点不同：它那一行在收到响应头时就出现了，但要等 body 结束才算*完成*。`AppState::record_open` 先把它显示出来，`outcome::settle` 包住body，在 body 正常结束、出错（`response`）或者没收完就被丢弃（`client`）时，调用一次`AppState::complete`。只有 `complete` 会调用观察者（observer）、写入历史记录，所以两边看到的都是最终的会话。还有一种情况：只要写了 `content-length`，hyper 发完 body 后可能不再把它轮询到底，直接丢掉；`settle` 会自己数字节，这样就不会把它误当成客户端中途离开。

不读内容的隧道，里面没有请求来做这件事，所以 CONNECT 本身通过一个 `Tunnel` 记成会话：隧道被原样转发时（连上就显示，关闭时完成）；无法路由或连不上另一端时；以及客户端不接受证书时（`client-tls`）。

只看 CONNECT 就决定直接转发的隧道——拦截关闭，或者客户端请求的地址命中了`disable://intercept`——走 `relay_before_reply`：先去连对端，对端连上了才回 `200`，和 whistle的做法一样（`_original/lib/tunnel.js:637-695`）。对端连不上时，这个 CONNECT 不会得到应答，会话那一行停在状态码 0，于是客户端自己的 CONNECT 直接失败，而不是先成功、再被挂断。其他隧道都必须先应答，才能读到 ClientHello；在那一步才决定转发的（`serve_tunnel` → `relay_recorded`），会在`200` 之后才去连对端，whistle 在这条路径上也是这么做的。

### 为什么要自己建到源站的连接

whistle 的看家本领，是改掉请求**发往哪里**，却不改变**服务器看到的内容**。高层的、带连接池的HTTP 客户端按主机名区分连接，会按目标 IP 去发 SNI/Host。所以 `upstream::forward` 自己把 socket连到（可能已被改写的）目标地址，但 TLS SNI 和 `Host` 头用的是**原始**主机名。见`src/proxy/upstream.rs`。

### 复用源站连接

源站连接在请求结束后还能留着，但只留给打开它的那条**客户端连接**用：客户端连到代理的每条连接（keep-alive 的 HTTP 连接、CONNECT 隧道、h2 连接）都在其请求的 extensions 里带一个`ConnPool`，同一条连接上后来发往同一处的请求，会复用前面请求留下的连接（`src/proxy/pool.rs`）。不同客户端之间什么都不共享，所以绑在连接上、而不是请求上的凭据（NTLM、Negotiate）不会从一个客户端漏到另一个客户端——上游缓存 h2 session 时划的也是这条线。

池的键包含新建一条连接时会用到的全部信息：地址；请求的主机和端口；TLS 开没开，以及`cipher://` 指定的版本和密码套件；TLS 被剥离的标记；还有整条代理路由——类型、地址、`?host=`、`proxyTunnel`、出示的 `Proxy-Authorization`，以及 CONNECT 时带上的 `User-Agent`。`pool_tests::every_part_of_the_route_is_in_the_key` 逐项改动，检查键是否随之改变。

不进池的有：协议升级（upgrade）、CONNECT、响应没有干净结束的（hyper 会关掉这些连接），以及请求里写了 `Connection: close`、或者是不带 `keep-alive` 的 HTTP/1.0 的——hyper 判断这一点只看响应，所以由 `upstream::asks_to_close` 来看请求。空闲连接 15 秒后关闭；每个键最多留 16 条，每条客户端连接最多留 32 条，超出时先关最老的——不然一条 keep-alive 连接每次请求都换个新主机，就会给每个主机都占着一个 socket。复用只会多出一种失败：请求刚发出去，源站正好把这条连接关了。处理办法是：没有 body、方法幂等的请求，换一条新连接重发；其他请求只拿空闲不到 2 秒的连接，远在常见服务器最短的空闲超时（5 秒，Node 和 Apache）之内。

会话里记下了源站连接的编号（`timings.connection`、`timings.reused`；HAR 里是 `connection`），因为复用的连接没有 DNS、建连和 TLS 这几个阶段，不记编号的话，控制台只能把这几段显示成“未测量”。

**到源站用 HTTP/2。** 通过 h2 进来的请求——浏览器经由被拦截的 HTTPS 隧道发出的请求全都是——在和源站做 ALPN 协商时会提供 `h2`（`upstream::offers_h2`；和 whistle 一样，可以用`enable://h2`/`disable://h2` 覆盖）。h2 连接不是从池里取走的，而是共享的：这条客户端连接发往同一个键的所有请求，都在它上面并发（`ConnPool::session`）。一批请求同时到来时，第一个请求去建连，其他请求在 `ConnPool::opening` 上等，所以首次加载页面只握手一次，而不是在途的每个请求各握一次；源站如果选了 HTTP/1.1，就在它已经接受的那个 socket 上走 HTTP/1.1，并且这个选择会被记住，之后谁都不用再等它；建连失败时，等着的请求各自并行去连，而不是一个接一个地等连接超时。`upstream::for_h2`把 `Host` 换成 `:authority`，并去掉只对单条连接有意义的头，和 whistle 的 `formatH2Headers` 一样。

## 抓取的开销

每个经过代理的 body 都流经 `body::tee`：字节流过时，它把开头一段有上限的内容复制进会话的抓取记录（`src/proxy/body.rs`）。大 body、高并发下这笔开销扛不扛得住，是实测出来的，不是假设的；测试工具在 `src/proxy/bench.rs`，不放进常规测试集：

```bash
cargo test --release -- --ignored --nocapture bench::
```

下面的数字来自 Apple M4（10 核、16 GB、Darwin 25.3.0 arm64），rustc 1.96.1，默认的`--release` 配置。每行是 200 次迭代（微基准）或 150–800 个请求（端到端）。各配置**在同一个循环里轮流跑，每一轮都轮换顺序**。这样调度器卡一下、温度波动一下，会平均摊到所有配置上，而不是落在当时恰好在跑的那个上；此外，第一个位置是基准，其他各行都拿它来比，轮换顺序也是为了不让它悄悄吃掉每轮迭代的预热开销。

### tee 本身

和完全不走 tee 的同一个 body 对比，body 按每帧 16 KiB 送出（cap 是预览上限）：

| body（帧数） | 不走 tee | tee，cap 0 | tee，cap 16 KiB | tee，不设上限 |
|---|---|---|---|---|
| 4 KiB (1) | 192 ns | 529 ns | 793 ns | 795 ns |
| 64 KiB (4) | 222 ns | 688 ns | 1.7 µs | 9.0 µs |
| 1 MiB (64) | 942 ns | 2.3 µs | 3.2 µs | 57.6 µs |
| 16 MiB (1024) | 5.4 µs | 12.2 µs | 12.9 µs | 2.5 ms |

从中能看出两点。

**超过上限之后，开销就不再增长。** `cap 16 KiB` 和 `cap 0`（什么都不复制，只数字节）的差距，就是填满预览时那一次 16 KiB 的复制。body 从 1 MiB 涨到 16 MiB，涨了 16 倍，这两列的差距始终在0.7–0.9 µs。真正还会跟着涨的是帧数：body 固定 1 MiB、帧越切越小，16、64、256、2048 帧时每帧分别是 28.2、11.9、8.2、6.5 ns，收敛到**每帧约 6.5 ns**——也就是一次无竞争的 mutex 加锁和两次加法。每个 body 都有自己的抓取记录，所以并发请求之间从不争这把锁。

**关键全在上限。** 去掉上限，一个 16 MiB 的 body 要花 2.5 ms 而不是 12.9 µs，多了约 200 倍，因为这时预览会把整个 body 都复制一遍。

压缩过的 body 会先解码，好让预览能看懂。这是唯一值得单独说的固定开销：**每个 body 约 45 µs，与大小无关**（64 KiB 是 44.3 µs，1 MiB 是 45.4 µs，16 MiB 时的 55.7 µs 是这 45 µs 再加上每帧的开销）。之所以固定，是因为*解码后*的输出一凑够 16 KiB，解码就停了。

### 走真实 socket

起三个代理，每个用一种预览上限，挡在一个返回固定内容的源站前面；并发客户端和三个代理都保持keep-alive 连接，按请求轮流发给它们。下表是平均值，括号里是相对 `cap 0` 的差值（identity 即不压缩）：

| body | 连接数 | cap 0 | cap 16 KiB（默认） | cap 1 MiB |
|---|---|---|---|---|
| 4 KiB identity | 1 | 112.2 µs | 112.2 µs (−0.05 µs) | 112.4 µs (+0.2 µs) |
| 4 KiB identity | 32 | 807 µs | 816 µs (+8.6 µs) | 812 µs (+4.7 µs) |
| 1 MiB identity | 1 | 250 µs | 255 µs (+4.7 µs) | 355 µs (+105 µs) |
| 1 MiB identity | 32 | 6.1 ms | 6.2 ms (+41 µs) | 6.5 ms (+407 µs) |
| 1 MiB gzip | 1 | 779 µs | 811 µs (+32 µs) | 2.7 ms (+2.0 ms) |
| 1 MiB gzip | 32 | 6.0 ms | 6.1 ms (+85 µs) | 9.5 ms (+3.5 ms) |

**发布时的默认配置，和完全不抓取分不出差别。** 跑了两次，`cap 16 KiB` 的差值落在 −24 µs 到+85 µs 之间，正负都有；而同样这些行在两次运行之间本身就会漂移 6%（identity）到 50%（gzip）：差值完全在噪声范围内。连微基准里明确算到 gzip 解码头上的约 45 µs，在端到端耗时里也看不出来。只有 `cap 1 MiB` 这一列明显高出噪声，而且两次都是如此——真正会带来开销的，是去掉上限。

作为参照：测这些数据时还没有做源站连接复用（见上文），测试工具统计到**每个请求 1.00 条源站连接**。本机 TCP 握手要几十微秒，真实网络上要几毫秒，所以 tee 的开销比一个代理请求必须做的最便宜的那件事还低几个数量级。

**结论：吞吐量方面不需要做任何事。** 保持这一点靠的是预览上限——`--body-preview-limit`，默认 16 KiB；唯一会让抓取变贵的改动，就是放开这个上限。

### 剖析真正发现了什么

问题不在吞吐量，而在内存。`flate2` 的写端解压器会把它解压出的所有内容攒进一个内部 `Vec`，而`drain_decoder` 只会从中读开头有限的一段。预览有上限，它背后的解压器却没有；而且解压器在整个抓取期间都留在 `CaptureState` 里——抓取记录又存放在会话环形缓冲里，深度是 `MAX_SESSIONS`（500）。

一个 16 MiB、高度可压缩的响应，到达时只是单个 16 KiB 的帧。`write_all` 会先把它整个解压，然后才有人从开头取走 16 KiB 预览；于是整整 16 MiB 就留在会话里，直到又来了 500 个请求才把它挤出去。不需要什么恶意客户端：一个用 gzip 传输的大日志文件或 JSON 导出就够了。

现在，解压器一旦再也贡献不了什么就会被释放：预览填满时释放，tee 被丢弃时也释放，后者既包括body 正常结束，也包括客户端半路挂断。`bench::capture_retained_bytes` 报告一个已完成的抓取还占着多少内存，以前不为 0 的情况现在全都是 0 B。剩下的是瞬时峰值：一个帧仍会先被完整解压，再取它的开头，所以单个帧解压后的大小就是内存的最高水位。要给*这个*也设上限，就得改成用固定的输出缓冲区直接驱动 `flate2::Decompress`，而不是用写适配器——改动更大；而现在既然什么都不会留下，这里的风险也小得多。

## 依赖

| Crate | 用途 |
|-------|------|
| `tokio` | 异步运行时 |
| `hyper` 1.x + `hyper-util` | HTTP/1.1 服务端和客户端、连接升级 |
| `http-body-util`、`bytes` | body 类型 |
| `rustls`（ring provider）+ `tokio-rustls` | TLS 的接受端（中间人解密）和发起端（连源站） |
| `rcgen` | 生成根证书和站点证书 |
| `webpki-roots` | 校验源站服务器证书用的信任锚 |
| `regex` | 本项目自己生成的正则（通配符、端口匹配串），以及它内部的解析 |
| `regress` | 用户写的正则——ECMAScript 语法，所以一个 `/…/` 的含义和在 whistle 里一样（`src/rules/regexp.rs`） |
| `serde` / `serde_json` | 头类算子的 JSON 值 |
| `clap` | 命令行 |
| `tracing` / `tracing-subscriber` | 日志 |

加密后端固定用 `ring`（`default-features = false`），在 `main.rs` 里启动时安装。这并不能免掉它对本地编译工具的要求，也不保证在每个目标平台上都能产出完全静态的二进制；请使用对应平台的构建工具链。

## 扩展：新增一个规则算子

假设你想用 `delete://header-name` 删掉一个请求头。

1. **注册**——这个名字很可能已经在 `PROTOCOLS`（`src/rules/protocols.rs`）里了；没有就加上。如果它在一个请求上可以出现多次，再把它加进 `MULTI_MATCH`。
2. **应用**——在 `src/proxy/apply/` 下它所属那一类的文件里（具体是哪个，看 `apply.rs` 开头的表；请求头类在 `req_ops.rs`），从解析结果里读出它，然后执行：

   ```rust
   // 写在 apply_request(...) 里
   for op in resolved.all("delete") {
       parts.headers.remove(op.value.trim());
   }
   ```
3. **测试**——在 `src/rules/matcher.rs` 里加一个单元测试，证明这个算子能被解析出来；（可选）再像下面[测试](#测试)一节的冒烟测试那样端到端跑一遍。

`Resolved` 提供三个访问方法，对单次匹配和多次匹配的算子一律可用：`get(proto)` 返回胜出的那个`RuleOp`（多次匹配的算子返回列表里的第一个），`value(proto)` 返回它的值，`all(proto)` 按解析顺序返回所有匹配——important 行在前，同一轮内按书写顺序。单次匹配的算子，`all` 只有一个元素，所以写循环不用特殊处理。哪些算子会累积，看 `rules::protocols::MULTI_MATCH`；同一个算子的多个值怎么合并，每一类各不相同，写在 [`RULES.md`](RULES.md) 里。

## 上级代理是怎么接入的

规则里的 `proxy://`、`http-proxy://`、`https-proxy://`、`socks://`、`pac://` 等让请求经另一个代理转出去（写法和行为见[规则手册](RULES.md#上级代理)）。代码里分两步：

1. **选哪个代理**：`src/proxy/apply/route.rs` 的 `find_proxy`。几种写法都命中时，按规则行的先后取第一条；`pac://` 则运行 PAC 脚本的 `FindProxyForURL` 来决定。结果是一个 `upstream::ProxyConfig`。地址用不了、PAC 取不到或抛异常时，请求直接失败，不会悄悄改成直连源站——规则说了要走代理，直连恰恰是它排除的那条路。
2. **怎么连过去**：`src/proxy/upstream.rs`。设了代理就不直接连源站：HTTP 代理（`ProxyKind::Http`）对 http 源站发完整 URL 形式（absolute-form）的请求，对 https 源站先发 `CONNECT` 打通隧道再做 TLS；`ProxyKind::Https` 先和代理本身做一次 TLS；SOCKS5 走 `socks5_connect`。

## 测试

```bash
cargo test                  # 单元测试
cargo clippy --all-targets  # 应当没有任何输出；`[lints.clippy]` 把所有 lint 都设成了 deny
cargo build --release
```

“没有输出”只在 `rust-toolchain.toml` 钉住的工具链上成立；更新的 Clippy 可能会查出更多问题。完整的门禁和版本规则见 [DEVELOPMENT.md](DEVELOPMENT.md#工具链)。

抓取相关的基准测试标了 `#[ignore]`——它们是测量，不是断言，而且在 debug 构建下没有意义。单独跑：

```bash
cargo test --release -- --ignored --nocapture bench::
```

单元测试在 `src/rules/matcher.rs` 里，覆盖 hosts 简写、显式的 `host://`、正则和通配符匹配串、多次匹配的累积、`$` important 的优先级，以及以点开头的子域名匹配。

**端到端冒烟测试**（当初就是用它验证代理的）：

```bash
# 1. 一个本地源站
python3 -c "from http.server import *; import sys; \
  HTTPServer(('127.0.0.1',9099), type('H',(BaseHTTPRequestHandler,), {\
  'do_GET': lambda s: (s.send_response(200), s.end_headers(), s.wfile.write(b'origin'))[0],\
  'log_message': lambda *a: None})).serve_forever()" &

# 2. 规则 + 代理
echo "test.local 127.0.0.1:9099" > /tmp/r.txt
cargo run --release -- -p 8899 -r /tmp/r.txt &

# 3. 发请求试试
curl -x http://127.0.0.1:8899 http://test.local/       # host override → origin
curl -x http://127.0.0.1:8899 --cacert ~/.whix/certs/root.crt https://example.com/
```

## 项目目录结构

```
whix/
├── Cargo.toml
├── build.rs               # 把构建好的控制台内联进二进制
├── .cargo/config.toml     # Windows：把 C 运行时链接进二进制（不依赖 VCRUNTIME140.dll）
├── .github/workflows/     # ci.yml（每次 push/PR，五个平台），differential.yml（每周）
├── README.md              # 项目首页：是什么、能做什么、怎么上手
├── rules.txt              # 示例规则
├── docs/                  # docs/README.md 是文档索引
│   ├── INSTALL.md         # 安装包、校验和、数据目录、升级、卸载
│   ├── COOKBOOK.md        # 使用手册：按任务组织的用法示例
│   ├── RULES.md           # 规则语法参考
│   ├── CLI.md             # 命令行，逐个参数和 whistle 对照
│   ├── API.md             # 控制台的 HTTP API
│   ├── OPERATIONS.md      # 安全的默认值、存了什么、存多久
│   ├── TEMPLATES.md       # 本地文件 + 模板渲染
│   ├── PLUGINS.md         # 插件系统 + 通信协议
│   ├── LINE_PROPS.md      # 规则的行属性
│   ├── CERTIFICATES.md    # 根证书：安装、信任、移除
│   ├── DEVELOPMENT.md     # 工具链、检查、差分测试、CI
│   ├── UPSTREAM.md        # `_original/…` 引用指的是哪份 whistle 源码
│   ├── STATUS.md          # 按任务列出测了什么、没测什么
│   ├── ROADMAP.md         # 任务计划
│   └── ARCHITECTURE.md    # 本文件
├── scripts/
│   ├── smoke.mjs          # 像真人那样使用二进制，任何操作系统都能跑
│   ├── check-console.sh   # 查看二进制里嵌的是哪个控制台页面
│   ├── check-links.mjs    # 检查 Markdown 里的相对链接和锚点
│   └── third-party-licenses.mjs # 随发布包附带的许可证文本
├── sdk/                   # JS/TS 插件 SDK（零依赖）+ .d.ts 类型
├── examples/plugins/      # hello.js, body-rewrite.js, typed.ts
├── ui-src/                # 控制台：Vue 3 + Vite，构建成单个文件
│   ├── mock/api.ts        # mock 出来的代理 API，给 `npm run dev` 用
│   └── src/               # panes/, sidebar/, components/, editor/, filter/
├── tests/
│   ├── *_e2e.rs           # 端到端测试，走真实 socket，不需要 node
│   ├── data_compat.rs     # 旧版本写下的数据必须仍能加载
│   ├── data/<version>/    # ……就是那些数据，保持该版本留下时的原样
│   └── differential/      # 各项差分对比（bench）——见目录里自己的 README
└── src/
    ├── main.rs            # 命令行入口
    ├── lib.rs             # 模块根
    ├── config.rs
    ├── ca.rs
    ├── embed.rs           # 作为库使用时的门面
    ├── explain.rs         # `whix explain`
    ├── qr.rs              # 控制台的二维码编码器
    ├── private_fs.rs      # 只有属主能读写的文件，保存时整个替换
    ├── rules/
    │   ├── mod.rs
    │   ├── protocols.rs
    │   ├── matcher.rs
    │   ├── storage.rs     # 磁盘上的规则组和 Values
    │   ├── include.rs     # `@` 引入的来源，拉取并保持更新
    │   ├── wildcard.rs    # 主机名里的 `*`，以及其他地方的 `^…$`
    │   ├── url.rs         # joinUrl/setProtocol + (inline)/<verbatim> 两种写法
    │   └── replace.rs     # $0-$9 展开
    ├── plugins/           # 注册表、钩子、`pipe://`、ws 帧、auth、sni、ui
    └── proxy/
        ├── mod.rs         # 下面这些文件的总览
        ├── serve.rs       # `serve()`——每个请求都经过这里
        ├── tunnel.rs      # CONNECT、中间人解密，以及请求到来之前的那些事
        ├── response.rs    # 响应阶段和响应 body 类算子
        ├── apply.rs       # 解析出的规则 → 具体修改；apply/ 下一类算子一个文件
        ├── dest.rs        # 请求最终转发到的 URL
        ├── header_rules.rs # 请求在自己头里携带的规则
        ├── forwarded.rs   # 前置代理声称的信息，以及信不信
        ├── template.rs    # tpl/dust/jsonp 渲染 + ${var} 变量
        ├── persist.rs     # 会话持久化（JSONL）
        ├── search.rs      # 搜索框的 h:/b: 在这里处理
        ├── upstream.rs
        ├── sni.rs         # 预读 ClientHello，选证书，或者直接转发
        ├── socks.rs       # 入站 SOCKS5 服务
        ├── script.rs      # JS 引擎（resScript/frameScript/pac）
        ├── ws.rs          # WebSocket 帧编解码 + 会抓包的隧道
        ├── restream.rs    # 切成帧的 body（SSE、自定义分隔符）
        ├── coding.rs      # gzip/deflate/brotli/zstd
        ├── ciphers.rs     # `cipher://` 和 TLS 选项
        ├── timing.rs      # 各阶段耗时
        ├── webui.rs       # 控制台路由表；webui/ 下是 API，一个功能区一个文件
        ├── bench.rs
        └── body.rs
```

## 从哪里下手

| 我想…… | 从这里开始 |
|---|---|
| 新增一个规则算子 | `src/rules/protocols.rs`（注册），然后是 `src/proxy/apply/` 里它所属那一类的文件（执行） |
| 改规则的匹配方式 | `src/rules/matcher.rs` |
| 写一个插件 | [`PLUGINS.md`](PLUGINS.md)，然后看 `sdk/whix-plugin.d.ts` |
| 新增一个插件钩子 | `src/plugins/mod.rs`（manifest + trait），然后是调用处——不过先看看现有的分发机制是不是已经够用，`auth` 当初就是这样 |
| 改请求流水线 | `src/proxy/serve.rs` 里的 `serve()`——每个请求都经过的唯一入口 |
| 新增一个接口 | `src/proxy/webui.rs` 里 `handle` 的路由匹配，以及 `webui/` 下对应功能区文件里的处理函数 |
| 改控制台 | `ui-src/`——Vue 3 单文件组件；`npm run build` 生成 `dist/index.html`，然后 `cargo build` 把它内联进去 |
