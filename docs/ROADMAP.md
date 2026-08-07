# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 的对齐进度**：已完成的工作，以及仍
**有意简化 / 尚未移植 / 架构受限**的更大子系统与少数边缘算子。

> 现状快照：注册算子中只有 `G` 与 `style` **有意不产生流量效果**（二者都不是逐请求的
> 算子，见 Non-goals），其余全部已在运行时应用，加上**转发规则**（原版无名的
> `rule` 协议）、别名算子层、本地文件/模板家族（含两遍替换与 `${var}` 运行时变量）、
> `@`-includes、规则行级属性；**筛选器条件已全部可求值**；
> **pattern 层已按上游三种通配符语义重写，`$0`–`$9` 子匹配传值可用**；
> **算子取值可以指向文件或 URL**（`readRuleValue`），**反引号整值按请求渲染**（`renderTpl`）。
> **⚠️ 「已应用」不等于「与上游逐位一致」** —— 四路审计确认了 45 项行为差异，
> **失败开放已清空**；不再维护一个精确的「已修 N 项」整数，下一节的清单才是准的。
> 单元测试 **714** 项全绿；`cargo build --all-targets`、`cargo clippy --all-targets`
> 与 `cargo test --doc` 均 **0 警告 / 0 失败**（clippy 由 `Cargo.toml` 的
> `[lints.clippy]` 把住）。
> 已完整验证：HTTP 正向代理、HTTPS MITM、HTTP/2、WebSocket（含逐帧抓取、
> **逐方向扣留与放行**）、上游代理、自研插件体系 v2（Rust 进程内 + JS/TS SDK）、
> 流量检查（头 + Body 预览 + gzip/br/deflate 解码 + **二进制体的十六进制/图片/下载**）、
> HAR 导出（含二进制体的 base64 与**真实的耗时分解**）与**规则/取值的导入导出**、
> `cipher` 的 TLS 版本与**套件固定**、**请求耗时时间线**、
> 流量落盘持久化、请求重放、**Composer**、规则分组管理。
>
> **本轮（多路并行）清掉的是上一版「尚未修」的整张清单**，逐条见下一节：
> 事件流上的 body 算子、取值加载器、
> 反引号模板、隧道路径的 abort、控制台的六个缺口（含**时间线** —— 先把 Session 模型
> 加厚到能画），以及 `cipher://` 的**套件固定**：rustls 能表达的部分现已兑现，
> 不能表达的会明确报出来而不再静默丢弃。
> **真正不可达的只剩 OpenSSL cipher 字符串那门语言本身**（组别名、排除、排序指令）。

---

## 已完成（本轮：pattern 与 destination 层）

本轮审计的是**规则行怎么被切开**、以及**请求最终去哪**这两件事。四个缺口都属于
「解析了但语义不同」或「根本没解析」，其中两个是**失败开放**。

- [x] ~~**转发规则（原版的 `rule` 协议）根本不存在**~~ → 已实现（本轮）。原版把
      **任何未知协议的 matcher** 归入 `rules.rule`（`_original/lib/rules/rules.js:1313-1316`），
      其解析出的 URL 随后**整体替换请求 URL**（`util.rule.getUrl(req.rules.rule)` →
      `req.options`，`lib/inspectors/rules.js:40-44`）。这是原版**最常用**的一条规则
      —— 官方 getting-started 的第一个例子就是
      `www.example.com http://localhost:5173`。本移植此前把这一行的两个 token
      **都判成 pattern**，于是整行产生零个算子、**静默失效**。
      新增 `src/proxy/dest.rs`：`Destination` 决定 socket 目标、`Host` 头、请求行路径
      与 scheme；`host://` 仍在其之上覆盖 socket 地址而不动 `Host`（两者叠加的语义
      与上游一致）。实测转发、路径拼接、`< >` 固定值、以及与 `host://` 的对比。
      不覆盖：`http://` 用在 WebSocket 请求上不做 HTTP↔WS 协议转换，`tunnel://` 只
      当作地址（scheme 沿用请求自身）。
- [x] ~~**行切分算法与上游不同**~~ → 已按 `indexOfPattern`
      （`rules.js:1449-1466,:1767-1793`）重写。上游的规则是**按位置**：`patternIndex === 0`
      时第一个 token 是 pattern、**其余一律是算子**（无论长什么样）；只有算子在前的
      「位置调换」写法才允许多个 pattern。本移植此前按 token 形状 `partition`，
      因此 `example.com http://localhost:5173` 与 `a.com b.com host://x` 都被读错。
      顺带修正 `isHost`：上游是 `net.isIP`，所以 `localhost:8080` **不是** hosts 简写而是
      转发目标 —— 此前本移植把两者等同，等于悄悄保留了上游会改写的 `Host` 头。
      每一条判定都用上游的分类器逐行核对过。
- [x] ~~**命中后缀不拼到算子值上**~~ → 已实现 `joinUrl` / `joinQuery`
      （`rules.js:334-366`，新增 `src/rules/url.rs`）。这是原版文档里的「路径自动拼接」：
      `www.example.com file:///srv/static` 之下 `/js/app.js` 要落到
      `/srv/static/js/app.js`。此前本移植**从不拼接**，于是**一个 `file://` 目录规则
      对除根路径外的一切都 404**。拼接只作用于转发规则与 file 家族 —— 与上游一致
      （只有 `rule.url` 与 `rule.files` 参与 `joinUrl`，其余算子读的是 `rule.matcher`）。
      `|` 多路径按**每一条**分别拼接（上游先 split 再 map），否则第一条会丢掉路径。
      顺带补上 `decodePath`：file 路径要去掉 query/fragment 并做百分号解码。
- [x] ~~**通配符语义不同，且失败开放**~~ → 已按 `parseWildcard` / `isRegUrl` 重写
      （新增 `src/rules/wildcard.rs`）。此前任何含 `*` 的 pattern 都被编译成
      `^` + 把 `*` 换成 `.*` 的正则，**既没有 scheme 锚点、也不限制 `.` 与 `/`**：
      `*.example.com` 因此会命中 `http://evil.test/?next=a.example.com` ——
      一条只想作用于某站点的规则，作用到了任何**提到**该站点的请求上。**失败开放。**
      现按上游分三种：普通 pattern 的 `*` **只在域名部分**是通配符
      （`*`=`[^/?.]*`、`**`=`[^/?]*`，路径按字面前缀匹配）；`^` 前缀的 pattern 里
      路径与 query 的 `*`/`**`/`***` 才是通配符，`$` 收尾；filter 的 URL pattern 走
      `resolveFilterPattern`，**总是**按 `^` 解读（这也是 `includeFilter://*/cgi-*`
      能通配路径而同名 rule pattern 不能的原因）。编译出的正则已与上游逐字符比对。
- [x] ~~**`$0`–`$9` 子匹配传值不生效**~~ → 已实现。正则与通配符捕获的内容现在会代入
      **同一行所有算子**的值（`replaceSubMatcher`，`rules.js:945-953`）。复用已有的
      `replacePattern` 移植（提到 `src/rules/replace.rs` 共用），因此 `$$1` 的百分号
      编码、`\$1` 转义一并生效。无捕获的 pattern 不做替换，值里的 `$1` 保持字面。
- [x] ~~`proto://(inline)` 与 `proto://<verbatim>` 两种括号写法不认~~ → 已实现。
      `(text)` 是内联响应体（`file://({"status":"ok"})` 此前会去找一个同名文件并 404），
      `<path>` 是「就用这个值，不要拼路径」。**比上游窄**：上游对**每个**算子做这个判定，
      于是 `htmlAppend://<script>…</script>` 会被吃掉最后一个 `>`；本移植只在文档描述
      这两种写法的地方问这个问题（转发规则与 file 家族），注入的 HTML 不受影响。
- [x] ~~`//host/path` 型 pattern 落到路径里~~ → 已修：`//` 前缀按 `NO_SCHEMA_RE` 剥离，
      协议任意。此前 `//a.com/x` 会被解析成「任意 host + 路径前缀 `//a.com/x`」，
      即匹配不到任何真实请求。
- [x] ~~内建界面是「表格 + 两个 textarea」的堆叠~~ → 已重做为三栏控制台（本轮）。
      左侧来源列表 + 上方可排序表格 + 下方详情面板，形制取自 Surge：请求按客户端分组，
      详情的页签是 General / 请求头 / 响应头 / 请求体 / 响应体 / 帧，没有内容的页签置灰
      而不是显示空盒子。规则分组从「正表下面的一列 textarea」变成来源列表本身，
      Values 亦然。深色模式改为可持久化的主题而非仅跟随系统。
      HTML/CSS/JS 从 `format!` 字符串里搬到 `src/proxy/ui/`，编译期由 `include_str!`
      内联回单页 —— 仍是**一个请求就能打开**（控制台必须在它所检查的网络不通时也能加载）。
      表格新增 Up/Down 两列，取值是 body 字节数：头部字节本移植不在链路上计数，
      与其混入一个估计值，不如让这一列只报它真正量到的部分。
- [x] ~~规则编辑器是纯文本框，看不出一行会被怎么解析~~ → 已加 CodeMirror（MIT，
      vendored 到 `src/proxy/ui/vendor/`）与一个 **whistle 专用 mode**。
      通用高亮对 whistle 没用 —— 它的行语法是**按位置**的，而位置从行本身看不出来：
      `example.com http://localhost:5173` 是 pattern + 目标，`http://a.com/x host://1.2.3.4`
      也是 pattern + 算子，但那里的 pattern 恰恰是**长得像算子取值**的那个 token。
      写反是「规则静默不生效」最常见的成因，所以编辑器直接把答案画出来：被标成 pattern 的
      就是代理会拿去匹配的。mode 跑的是解析器同一套 `index_of_pattern`，
      并有测试（`proxy::webui::tests`，用本移植自带的 JS 引擎跑 mode）把两者钉住 ——
      高亮器与解析器不一致，比没有高亮更糟。
- [x] ~~控制台看不到运行时状态~~ → 新增 `GET /api/status` 与 Status 面板：端口、SOCKS、
      是否拦截 HTTPS、**是否关闭了源站证书校验**、根证书路径、抓包与帧计数、规则数、
      以及每个插件声明的钩子（从未应答过的远端插件没有 manifest，面板照实显示 ——
      那正说明代理从未连上它）。这些此前只在启动日志里出现，而有疑问时日志早已滚走。
- [x] ~~`lineProps://originUrl` 无物可接~~ → 已接线（拼接实现之后它才有意义）。
      域名型 pattern 命中时把拼过去的路径强制为 `/`，见 [`LINE_PROPS.md`](LINE_PROPS.md)。
- [x] ~~PAC 辅助函数测试依赖外部 DNS~~ → 已修。`dnsResolve('no-such-host.invalid') === null`
      在任何**劫持 NXDOMAIN** 的解析器下都会失败（本机答 198.18.0.57，这是桌面 VPN
      客户端 fake-ip 模式的常态）。改用一个根本到不了解析器的输入来验证同一条契约。

---

## 四路并行审计（本轮）：45 项差异，已修 12，其余在册

本轮对**请求侧算子、响应侧算子、规则解析层、控制台**做了四路并行审计，逐项以
上游源码行号 + 可复现输入核对。共确认 45 项差异。下面**如实**记录：已修的、
以及**尚未修的**（后者按严重度排序，不因未做而略去）。

### 已修（12）

| 项 | 类别 | 说明 |
|----|------|------|
| `whistle.<name>://` / `plugin.<name>://` 变成目的地重写 | **失败开放** | `PLUGIN_RE`（`rules.js:24`）把两者归入 `plugin`；本移植不识别该协议，于是整个 token 成了 URL 替换，`whistle.vase://x` 把流量发到名为 `x` 的主机。而 `whistle.<name>` 正是 npm 插件的标准写法 |
| `responseFor://` 发起未经请求的外连 | **失败开放 + 安全** | 上游 `setResponseFor`（`util/index.js:3214-3261`）**不发任何网络请求**，只把 `x-whistle-response-for` 写到**响应**头；本移植对每个命中请求 GET 一次规则里写的 URL，并把结果写到**出站请求**头上 |
| 裸 `$` / `!` 匹配一切 | **失败开放** | 无 host/path/scheme/port 的 token 落到 `Pattern::Any`；上游直接丢弃该规则（`rules.js:1247-1249`）。新增 `Pattern::Nothing` |
| `example.com/api` 命中 `example.com:8080/api` | **失败开放** | 带路径的 pattern 上游按 URL 文本（含端口）匹配，去端口回退只对纯域名 pattern 开放（`rule.isDomain`，`rules.js:1081-1083,:1343-1348`） |
| `ignore://` 只认一个词 | **失败开放** | 上游认 `*`/`All`/`allRules`/`allProtocols`、按 `&` 也分隔、支持 `-name`/`!name` 豁免与 `-*` 取消（`util/index.js:1891-1932`）。`ignore://*` 与 `ignore://host&ua` 此前什么都不丢 |
| `x-forwarded-for` 可被客户端伪造 | **失败开放 + 安全** | 上游默认**删除**客户端自带的 XFF（`res.js:690-710`）；本移植原样转发，等于代理为任意客户端自称的地址背书。另补上 `net.isIP` 门与 `disable://clientIp` |
| 3xx / 204 / HEAD 被注入 body | **失败开放** | 上游 `hasResBody`（`common.js:370-380`）把整个 body 层关掉；本移植给 302 加 body、去掉 `Content-Length`，并顺带写入 `no-store`、过期 `Expires`、剥掉 CSP |
| `reqSpeed`/`resSpeed` 快 8.192 倍 | 单位错误 | 上游单位是**千比特**（其文档明写「千比特/每秒」，实现 `parseInt(speed*1000/8)`），本移植按 KB/s |
| 速率/延迟带单位后缀被静默丢弃 | 失败静默 | 上游按 `parseFloat`/`parseInt` 读，`resSpeed://20kb`、`resDelay://500ms` 有效；本移植严格 `parse` 直接失败 |
| 上游连接无超时 | 健壮性 | 见上一节 |
| `--no-intercept-https` 无实现 | 死字段 | 见上一节 |
| `lineProps://originUrl` 无实现 | 死字段 | 见上一节 |

### 已修（45 条发现里约 38 条，另修掉 2 项不在其列的隐患）

**失败开放已清空**。剩余见下节，共 8 条，其中 2 条是某条发现修掉一半后剩下的另一半 ——
所以「已修多少条」这个数不精确，下一节的清单才是准的。

表中「强制编码可作用于未解开的体」与 `(inline)` 那一行里的 **panic** 都**不在那 45 项之内**
—— 它们不是与上游的差异，是本移植自己引入的隐患：前者靠一个非规范源站加一个 `enable://`
标志就能触发，后者只需要一个以中文开头的算子取值。

| 项 | 说明 |
|----|------|
| `formatShorthand` 缺失 | **最严重**。上游在切分行前展开每个 token（`rules.js:1766-1767`）；顺序承重 —— 没展开前路径没有协议，而**无协议的 token 正是切分器认定的 pattern**。`/Users/me/mock.json www.example.com api.example.com` 因此把路径当 pattern、把两个域名升格成目的地，且那条路径被过宽的正则判定接受、编译成**无锚点**的 `Users/me` |
| `is_regexp_token` 过宽 | 收紧到上游封闭 flag 集（`REG_EXP_RE`），这是把 `/regexp/` 与文件路径区分开的依据 |
| `filter://<name>` | `filter://` 是**两个算子共用一个名字**；只有 `/`(`i`) 结尾或 `*/` 开头的负载才是 URL 筛选器，其余命名的是要抑制的协议，上游折进 `ignore://` 同一集合 |
| `includeFilter://(cond)` | 括号未剥离（`INLINE_RE`），负载掉进 URL pattern 分支，规则静默不生效 |
| `disable://keepAlive` 作用错端 | 上游作用在**出站请求**（`res.js:446-448`），本移植作用在响应；注释里「自有扩展」的归属也是错的 |
| `enable://abort` 时机与取消 | 两道闸门都可被 `disable://abort` 取消；abort 现在销毁 socket 而非回 502 |
| `delete://query.x` 等整族 | `parseDelQuery`（`util/index.js:2669-2720`），含 `pathname[.N]` |
| `accept-encoding` 未收敛 | 按 `removeUnsupportsHeaders` 收敛到 `gzip, br` —— Chrome 带 `zstd` 时，上一轮修好的压缩体改写会从请求侧整体失效 |
| `reqReplace://` 对 form body 无效 | 上游归入 `FORM` 类（`req.js:434-438`） |
| `auth://` 只认 `user:pass` | 补 `{json}`（含 `proxy:true` → `Proxy-Authorization`）与 `username=…&password=…` |
| `reqHeaders://x=` 删头 | 上游发空值头；删除是 `delete://reqHeaders.x` |
| `resHeaders://set-cookie` 覆盖 | 改为按 cookie 名合并（`setCookies`，`res.js:89-122`） |
| trailers 四缺陷 | 源站 trailer、`disable://trailers`、非法 trailer 名过滤、trailers 分支吞掉 `resSpeed` |
| dump 算子三缺陷 | 已存在即跳过（`enable://forceReqWrite` 才覆盖）、非 200 加 `.<状态码>` 后缀、`reqWrite` 按有无请求体设门 |
| `disable://301` | 301→302 |
| `replaceStatus://` 无谓覆盖 | 状态未变时不再改写 `WWW-Authenticate` |
| `Location` 未重编码 | 补 `encodeNonLatin1Char`（比上游更宽，原因见代码注释） |
| `delete://` 与注入顺序 | 删除移到 CSP/no-store 剥离之后 |
| 方法名未大写 | 每个请求统一大写 |
| `reqDelay://` 跳过短路 | 上游在独立管线阶段延迟（`data.js:534`），先于 abort 与所有短路；本移植等到转发处才等，于是 `reqDelay://` + `file://` 完全不延迟 —— 而这正是两者唯一的搭配用法 |
| `urlReplace` / `params` 顺序颠倒 | 上游先写 query 再替换（`req.js:561,:569`） |
| `$` 展开把非 ASCII 打碎 | `bytes[i] as char` 把每个 UTF-8 字节当 Latin-1 标量，`/搜索` → `/æ\u{90}\u{9c}ç´¢`；影响**所有** `$` 展开，不只 header |
| **强制编码可作用于未解开的体** | **当日隐患**，非缺口：`restore == Identity` 同时表示「本来就明文」与「解不开、原样奉还」，`reencode` 分不出来，于是 `enable://gzip` 对 zstd 源站会**再压一层并标成 gzip** —— 客户端解一层后撞见原编码。现拆成 `Restore { coding, plain }`，非明文一律拒绝强制 |
| 合并规则优先级相反 | 上游 `mergeRule` 让**后并入的胜出**（`util/index.js:2147-2170`）：包含进来的文件覆盖包含它的文件。本移植是 `or_insert` + `extend`，于是「专门拉进来做覆盖的规则」输给了它要覆盖的东西 |
| `${key}` 值引用 | 只认整值 `{name}`；上游 `resolveVar` 还替换值**内部**的 `${name}`（`rules.js:39,:774-783`），`resHeaders://x-v=${myval}` 此前带着八个字面字符发给源站 |
| 内嵌值块 | ``` 围栏块声明命名值（`util/index.js:208-218`），此前围栏行被当成规则行、`{mock.json}` 解析为空。连带补上「值即内容」标记 —— 否则替换成功后 file 层会把 JSON 当**路径**去开 |
| `file`/`redirect`/`statusCode`/`tpl`/裸 URL 共用一个槽位 | 这五族在上游都不是协议名，`parseRule` 把它们归入同一个 `rule` 列表（`rules.js:1313-1316`），`getRule` 取**首个命中**（`:799-800`）—— 先写的胜出、其余完全不生效。本移植是固定协议优先级（redirect → statusCode → file）**且**允许目的地改写与 mock 并存，于是同一份文件在两边的行为按书写顺序往两个方向分歧 |
| `(inline)` 只对 file 族展开 | 上游 `getValue` 对**每个**算子展开（`rules.js:271-287`），`reqBody://(Hello)` 是它自己的文档示例，此前带括号原样发给源站。连带修掉一个**崩溃**：`fixed_value` 先按字节切括号再判断，值以多字节字符开头时 panic —— 这条路径现在每个算子都走 |
| 同名 header 只发一条 | `qs.parse("a=1&a=2")` 得到数组，Node 逐元素各发一行。已按上游重新取回核对（非推断）。相邻的「不 trim 键名」一条**刻意不对齐**：`qs.parse` 会留下带尾随空格的键名，那不是合法 token，hyper 会拒绝、上游 `setHeader` 也会抛 —— 照抄等于把算子变成静默空操作 |
| 控制台「Saved」是假的 | 默认组规则与整个 Values 只写内存；且即便存盘也读不回来（`load_groups` 用 `add_group` 恢复，而 "default" 永远已存在）。两者现已往返落盘，命令行优先 |
| 命中的规则被丢弃 | `Resolved` 里有每个命中算子的协议、值、原始 token 与解析顺序，然后被整个丢掉；控制台仅存的 `log://` 标签又挂在一行读起来像「命中的规则」的标题下。现随 `Session` 一并记录，按解析顺序（important 行在前，其后源码顺序）排出，控制台新增 Rules 页签 |
| 简写算子只认展开后的拼法（**记录在案的差异**） | 上游 `exactIgnore` 还会比对 `rawMatcher`，因此 `matcher=/local/path` 在上游能静默 `example.com /local/path`。本移植的 `format_shorthand` 在 `split_line` 判定谁是算子**之前**就跑完了整行，等 `RuleOp` 存在时它的 token 已是 `file:///local/path`，写法原文要穿透分割器传索引才能拿回 —— 为一个几乎没人会用的拼法改承重函数不值。已在 `docs/RULES.md` 写明 |
| `ignore://pattern=` / `matcher=` 静默不了任何东西 | 精确形式被当成协议名列表读，找不到叫 `pattern=example.com` 的协议，于是什么也不丢、也什么都不说。需要前置扫描：文本在解析后已丢失，且静默行可以写在被静默的规则**下方**。`has_exact_skip` 在解析期预计算，不用此特性的规则集不付这趟扫描的代价。连带恢复 `skip://` 与 `ignore://` 对**无键值**的不同读法 —— 本移植把两者折叠成一个协议，差别只能从原始 token 找回 |
| **事件流被缓冲到流结束** | **当日隐患**（`resReplace://` 一侧是既有缺陷，`enable://gzip` 一侧由上一行的改动**当天引入**）：缓冲一条 SSE 不是延迟而是扣留 —— 流何时结束由服务端说了算，对 SSE 通常是永不，客户端因而一个字节也收不到。实测两者对活的 SSE 源站三秒内零字节，而未加规则的同一主机立刻出事件。现按上游 `isSSE`（`util/index.js:3917-3921`）识别并放行 |
| mock 请求看不到客户端发了什么 | 短路（`file://`、`redirect://`、`statusCode://`、模板）与插件应答都不构建外发请求，两处记录点因而把 `req_headers`／`req_body` 留空 —— 控制台的请求头与请求体页签对**每一个** mock 请求都是空的。现按客户端**自己**的头记录：这条路径上没有转发那一跳，报出改写后的头等于命名一个从未发生的请求 |
| `enable://gzip` 单独出现时不生效 | `needs_body` 不把强制编码算在内，响应因而走流式路径，`reencode` 根本到不了 —— 只有当同一行上碰巧另有算子把 body 缓冲下来时它才像是生效。它是唯一一个「要整个 body 却一个字节都不改写」的算子，现把 `force_encoding` 挂在 `ResBodyOps` 上让 `needs_body` 看得见；无 body 的响应仍不被拖上缓冲路径。连带修掉一个更糟的（它此前藏在这条路径走不到的地方）：**解不开的体会被摘掉原编码头**。`reencode` 对非明文的体拒绝强制编码并回报 `Identity`，而照此调用 `set_content_encoding` 是把 `content-encoding: zstd` **删掉** —— 客户端收到 zstd 字节却被告知是明文。现在这种响应连头带体原样奉还 |
| 重放不带请求体 | `do_replay` 抄下每个抓到的请求头却发 `Empty::new()`：重放一个 POST 会声明 `content-length: 402` 而后面一个字节没有。现按抓到的**已解码**预览发送，`content-length` 按实发重算，`content-encoding` / `transfer-encoding` 随之去掉，截断与解不开两种情形逐条报给控制台 |

### 上一轮的「尚未修 6 条」：本轮的结果

上一版这里记着 6 条结构性缺口。**5 条已做完，1 条仍是架构限制**，另有 2 条
「非目标」因为前提改变而变成了功能。逐条如实记录，包括做完之后**剩下**的部分。

- [x] ~~**body 算子对 SSE 不生效**~~ → **已实现**（`src/proxy/restream.rs`）。
      上游的 body 层是流式的：替换变换只扣留一小段**尾巴**（刚好让跨块的匹配不会漏掉），
      对事件流再按最后一个空行冲刷，所以一条完整事件永远不被扣住
      （`replace-string-transform.js`、`replace-pattern-transform.js`）。本移植现在也是。
      `resReplace://` 随流生效；`resPrepend://`／`resAppend://`／`resBody://` 走另一条路
      —— 它们本来就不需要整个 body，一个在第一个字节之前、一个在最后一个字节之后、
      `resBody://` 则表示根本不必等源站（因此可以拿来 mock 一条永不结束的流）。
      实测：源站每 300ms 一跳，`resReplace://tick=TOCK` 之下**首字节 0.303s**、事件随写随到。
      **两处刻意偏离上游**，都写在模块里：索引按字节取字符边界而非 UTF-16 码元
      （只影响扣留多少，不影响结果）；**即将被事件冲刷冲出去的匹配会被替换** ——
      上游先判定哪些匹配「已定」再抬高冲刷点，两步在小事件上互相矛盾：匹配因为靠近末尾
      被跳过，随即又被原样冲出去。SSE 的一块通常就是一条短事件，所以上游的正则
      `resReplace://` 在事件流上**静默无效**，那正是本移植一路在清的失效类别。
      顺带把 `\r\n\r\n` 也认作事件边界（上游只找 `\n\n`）：不认的话，一个用 `\r\n`
      的源站会被扣到 5120 字节才放行，那是**这个功能自己引入的延迟**。
      **仍不覆盖**：`resMerge://`、`resScript://`，以及 `html*`/`js*`/`css*` 家族
      —— 后者由响应是 HTML/JS/CSS 选中，本就不会命中事件流。插件的 `responseBody`
      钩子同样跳过并打 `warn`，要流式请用 `pipe://`。
- [x] ~~**算子取值不支持从文件 / 远程 URL 读取**~~ → **已实现**（`readRuleValue`）。
      算子集合取自上游两个读取器的**全部调用点**而非猜测；URL 与路径按 `HTTP_RE` 区分；
      远程取值有 16s 硬期限与 256KB 上限，文件走已有的 mtime 缓存（改 mock 立刻生效）；
      `|` 多值按 CRLF 拼接。读取失败**不会**把路径当作 body 发给源站。
      实测：`reqHeaders:///…/hdrs.json` 之下源站收到 `x-from-file: yes`。
      刻意收窄两处（**裸相对路径**保持字面、含 `=` 的 JSON 取值永不当路径），已在
      `docs/RULES.md` 说明。**远程取值不缓存**，与上游一致。
- [x] ~~**反引号模板**~~ → **已实现**（`renderTpl` / `resolveTplVar`）。整值加反引号即按请求渲染，
      **复用** `template.rs` 已有的 `${var}` 词汇表（核对过是同一套，没有另建一份）；
      `${key}` 取回的内容在反引号值里也会再渲染一次（上游 `isTpl` 的那个交互）。
      顺带把此前恒为空的响应侧变量（`${statusCode}`、`${serverIp}`、`${resHeaders.*}` 等）
      接上了响应阶段。实测 `${method}` / `${query.a}` / `${{url}}` 三种写法。
- [x] ~~**响应 abort 仅覆盖 HTTP**~~ → **已实现**。CONNECT 隧道（含 MITM、
      `--no-intercept-https` 与 `sniCallback` 放弃拦截三条出口）、SOCKS（答
      `REP 0x02`「规则不允许」而不是先接受再重置）、以及 WebSocket 升级都过同一道闸门；
      `disable://tunnel` 一并实现，其布尔式与上游 `needAbortReq`/`needAbortRes` 逐项核对过。
      **两处刻意偏离**：hyper 要先答 CONNECT 才交出隧道字节，所以两道闸门在此合并为一道
      （客户端观感相同，差别是上游的 `abortRes` 会让源站先看到一次连接）；本移植对
      **被拦截的**隧道也过闸门，上游会跳过（拦截与否要等 ClientHello，而那在应答之后）。
      顺带补上：被 abort 的**普通 HTTP 请求**此前不记会话 —— 一条不出现的记录和一条
      从未命中的规则无法区分，而那正是写 `enable://abort` 的人唯一想知道的事。
- [x] ~~**控制台：无 Composer；二进制 body 做不了；无导入；Values 无逐键编辑；无多选/标记**~~
      → **五项全部实现**，逐项在浏览器里对着真实代理验证过。
      **Composer**：手写请求经代理自身端口发出，因此规则照常命中、照常抓取，
      `from:composer` 可匹配；可从任一抓到的请求「Edit & Resend」种子化。
      一行**不是 header 的 header** 会被拒绝并说明，而不是像上游那样静默丢弃 ——
      抓包是既成事实，丢掉一行是两害相权；手打的东西悄悄不发是最坏的答案。
      **二进制 body**：`GET /body.bin` 交付真实字节（**恒带 `Content-Disposition:
      attachment` 与 `nosniff`** —— 那是被检查站点的字节，从控制台自己的源提供，
      一个抓到的 `text/html` 若在此渲染就是它的脚本拿到了 `/api/rules` 的可达性），
      面板有 Text / Hex / Image 与下载；HAR 里按规范的 `content.encoding` 走 base64
      （此前把 `[binary, N bytes]` 写进了每个 HAR 阅读器都当作 body 的那个字段）。
      **导入/导出**：整包往返无损（组的文本、开关与**顺序**都保住，顺序即优先级）。
      **Values 逐键**：新增/改名/删除/编辑，与编辑同一把锁落盘。
      **多选与标记**：⌘/Ctrl 点选、Shift 范围与 Shift-方向键、`m` 标记，批量导出 HAR /
      重放 / 只清除选中。**标记只在客户端**，并且说明了原因：会话 id 每次重启从 1 开始，
      持久化会把标记贴到一个无关的请求上。
- [x] ~~**控制台无时间线（Session 模型太薄）**~~ → **已实现**。前提是对的：Session 只有
      `time_ms` 与 `duration_ms`，薄到画不出任何东西。所以先把模型加厚 —— 按 HAR 1.2 的
      阶段名测量 `dns` / `connect` / `ssl` / `wait` / `receive`，再在详情面板里画出来。
      顺带修掉一处**往标准字段里写不实数据**：HAR 导出此前恒填
      `{send: 0, wait: 全部, receive: 0}`，而每个 HAR 阅读器都拿这个字段画瀑布图，
      等于在导出一个从未发生过的请求。
      `dns` 是把 tokio 自己 `ToSocketAddrs` 做的事（先解析、再逐个连）中间加了块秒表，
      行为不变、只是报得更细；`connect` 到「与源站之间有了字节管道」为止，所以经代理时
      也涵盖代理自身的 TLS 与 CONNECT/SOCKS 协商 —— HAR 没有对应阶段，而连接在那之前
      并未建立。**`send` 不测量，报 `-1`**（HAR 自己的「不适用」写法）：hyper 交出请求后
      直接在响应头处返回，中间没有观测点，它的时间在 `wait` 里。报 `0` 会声称它不花时间，
      而那正是这次要替换掉的错误。
      像 `Capture` 一样共享回填，因为行是在**响应头**到达时记录的，而 `receive` 要等
      body 结束 —— 对事件流是永不，于是诚实地缺席。规则应答的请求根本没连过，
      因此**没有任何阶段**，面板直说「answered by the proxy and never opened a connection」，
      而不是画一排零。实测三种形态并在浏览器里逐一看过。
- [x] ~~**`cipher://` 的完整 OpenSSL 语义**（架构限制）~~ → **前提成立，结论不成立**。
      「rustls 不接受 cipher 字符串」是真的，但由此推出「语义不可移植」是错的：
      **cipher 字符串是一门语言，语言可以求值**。rustls 提供的只是一个更小的套件宇宙，
      而那正是一个没编译 3DES 的 OpenSSL 所处的位置 —— OpenSSL 在那里照样求值同样的字符串，
      不会抱怨。
      现已实现完整求值：别名（`HIGH`/`DEFAULT`/`ECDHE`/`AESGCM`/`aRSA`…）、
      中缀 `+`（逻辑与，`ECDHE+AESGCM`）、`!` 与 `-` 排除、前缀 `+` 降优先、`@STRENGTH` 排序。
      **与 Node 逐条比对，16 个字符串全部一致**（TLS 1.3 源站 8 条 + TLS 1.2 源站 8 条）。
      **顺带修掉本轮自己引入的一次降级。** OpenSSL 1.1.1+ 的 `ciphers` 只配置 TLS 1.2 及以下，
      TLS 1.3 有自己的列表。实测：TLS 1.2 的名字不影响 1.3，只有**显式的 1.3 套件名**才影响，
      别名（如 `CHACHA20`）也不行。上一次提交把 1.2 的选择套到了 1.3 上，于是
      `cipher://{"ciphers":"ECDHE-RSA-AES128-GCM-SHA256"}` 对着 TLS 1.3 源站
      **回落成 TLSv1.2**，而 Node 留在 TLSv1.3 —— 一条本意是「偏好这个套件」的规则
      在削弱连接。这条记录留在这里，因为它是本轮引入又本轮修掉的。
      选不中任何套件时**请求失败并点名**是哪些 token 落空 —— OpenSSL 自己就是在创建上下文时
      抛 `no cipher match`，而这是求值救不回来的唯一情形：算法根本没编译进来。
      **真正剩下的**：本构建没有的套件（`3DES`、`RC4`、kRSA、DH、PSK…）。那不是语义问题，
      是密码学实现问题。

以及两条因前提改变而不再是「非目标」的：

- [x] ~~**`enable://pauseSend` / `pauseReceive` 按非目标处理**~~ → **已实现，连 UI 控件一起**。
      此前的理由是「本移植的 Web UI 没有放行控件，照搬只会得到一个永远无人能解除的停顿」；
      控件做了，理由就不成立。放行是**每会话每方向、一次全放**，那是上游唯一的粒度
      （`changeStatus` → `setConnStatus`，其 UI 里没有「放行一帧」这种东西）。
      **暂停不豁免控制帧** —— 上游扣的是字节流而不是流里的帧，与 `ignore` 的类比不成立，
      这一条是读了 `handleFrame` 才纠正过来的。因此连接会静默，上游用一条自己的保活
      （每 22 秒）顶住对端的空闲超时，本移植照做。扣留有界（64 帧 / 4MiB），到界即背压。
      实测：`enable://pauseReceive` 之下 2 秒零字节（源站每 300ms 一帧），
      `/api/ws/status` 报 `receive: {held: 5, paused: true}`，
      `POST /api/ws/release` 答 `{"released": 5}`，随后 105 字节送达。
- [x] ~~**`disable://ping` / `disable://pong`「无物可禁」**~~ → **已实现**。那句话当时是对的
      —— 本移植不注入保活，两个标志确实没有可禁的东西。**上一条给了它一个**：
      扣留一个方向就会带来一条保活。于是两个标志在同一轮里从「无对应语义」变成了功能，
      并按上游拆开：`disable://pong` 禁掉握住 send 方向时发往**源站**的那条，
      `disable://ping` 禁掉握住 receive 方向时发往**客户端**的那条。

### 标志族的机械对照（本轮：不看自己的清单，看上游源码）

上一轮的结论是「清单清空」，但那份清单是我自己写的 —— 拿它当检查表是循环论证。
本轮改用上游源码本身：把 `lib/` 里每一处 `enable.X` / `disable.X` / `isEnable(req,'X')`
读取点抽出来（127 处，去重后 **99 个标志**），逐个在本移植的源码里对照。

机械对照报 44 个「未出现」，逐个查上游用途后的实情：

**真缺口，已实现（4）**

| 标志 | 后果 |
|------|------|
| `disable://intercept`（及 `https`/`capture` 两种拼法） | **最重要的一个**。「不要解密这台主机」——证书固定的 App 必须用它。本移植只有全局的 `--no-intercept-https`，无法逐规则说。已实现并实测：客户端看到的证书指纹与源站**完全一致**，而无规则时是伪造的 |
| `disable://autoCors` | 它要关掉的那个功能本身缺失 —— 见下方「自动 CORS」 |
| `disable://proxyUA` | 到上游代理的 CONNECT 无法去掉回显的 `User-Agent` |
| `disable://proxyConnection` | 同上，无法要求 `Proxy-Connection: close` |

**上游有、本移植无对应物（不是缺口，是没有那个机制）**

`clientId`/`clientID`/`clientid`/`keepClientId`/`multiClient`/`singleClient`/`userLogin`
/`proxifier`/`interceptConsole`/`additionalHeaders` —— whistle 自有的客户端标识、
多租户与 UI 基础设施，本移植没有 client-id 概念（这一点 ROADMAP 早已记过）。
`customParser`/`customFrames`/`forHttp`/`forHttps`/`useLocalHost`/`useSafePort` ——
上游插件加载器的机制，本移植的插件是讲自研协议的外部 HTTP server。
`requestWithMatchedRules`/`responseWithMatchedRules` —— 把命中规则回传给插件的开关，
本移植的插件协议里规则是**始终**随钩子送达的。
`keepH2Session`/`auto2http`/`lacalhostCompatible`（上游自己的拼写错误）—— 上游连接池与
兼容性开关，本移植不做上游连接池。
`clientCert`/`requestCert`/`secureOptions` —— 向**客户端**索要证书（mTLS 的服务端一侧），
本移植的 MITM 不做客户端证书请求。
`wsDecompress` —— 关掉 WebSocket 的 `permessage-deflate` 解压；本移植不做该扩展的解压，
无物可禁（与 `disable://ping`/`pong` 曾经的处境相同，若将来做了解压，这个标志就有了意义）。
`flushHeaders` —— Node 的 `res.flushHeaders()`；hyper 在响应头就绪时即写出，没有对应的推迟行为。
`rejectUnauthorized` —— 上游用它对**内部请求**关闭源站证书校验；本移植的默认姿态是
**校验**（唯一一处刻意不照抄上游默认值），逐规则放宽与该姿态冲突，保持不做。
`bigData`/`largeData`/`resMergeBigData`/`captureStream` 一族 —— 抓取上限的调节，
本移植用 `--body-preview-limit` 与新增的 `--body-rewrite-limit` 表达同一件事。
`captureIp`/`captureIP`/`captureSNI`/`captureNoSNI`/`captureHttp`/`captureHttps`/`inspect`
/`socket`/`http2`/`tunnelAuthHeader`/`tunnelHeadersFirst`/`logDoctype` —— 上游握手期与
日志注入的细分开关，各自依赖本移植没有的机制（client-info 头回灌、weinre 注入、
H2 会话复用）。

**对照器自己的假阳性**，一并记下来，因为它们说明这种机械对照要怎么读：
`reqPrepend`/`reqAppend` 报「未出现」是因为本移植用 `format!("{prefix}Prepend")` 动态拼名字；
`enable.length` 根本不是标志，是数组的 `.length`；而第一轮把 `intercept` 报成「已存在」，
是因为 `sniCallback` 返回的 JSON 里有个同名的键 —— 那是完全不同的东西，
真正的 `disable://intercept` 当时并不存在。

### 本轮顺带修掉的、不在上述清单里的

- **自动 CORS 缺失**（`isAutoCors`，`file-proxy.js:178-191`）。用 `file://` mock 一个
  API、而页面在另一个源上 —— whistle 的核心用法之一 —— 在本移植里被浏览器直接拒掉。
  上游对本地文件响应在请求带 `Origin` 时自动补 CORS 头，并且**对预检 `OPTIONS` 直接答
  200 而根本不打开文件**。后一半更要命：文件不存在就会 404 掉预检，真实请求永远不会发生。
  `docs/LINE_PROPS.md` 当时引用了准确的上游行号，却把结论写成「本移植没有可抑制的对象，
  为了能关掉它而先实现自动 CORS 是本末倒置」—— 自动 CORS 本身就是那个功能。
- **`resCors://` 的预检答错了头名**。写的是单数 `access-control-allow-method`，还附了一条
  「这是上游的笔误，照抄以保持一致」的注释。上游没有这个笔误（`setResCors` 两处分支都是
  复数），而单数那个名字浏览器根本不读 —— 预检因此缺了让真实请求得以继续的那个头，
  算子从代理侧看正常、从浏览器侧看完全不生效。
- **响应改写的缓冲无上限**。上游的响应改写是流式的，所以不需要上限；本移植是缓冲的，
  所以需要。实测一条最普通的 `resReplace://` 撞上 800MB 下载，RSS 从 9.9MB 涨到 **1.97GB**。
  现按 16MiB 设限（`--body-rewrite-limit`），过限即原样放行并打 WARN；同一下载峰值 **33MB**、
  字节完整。
- **两个偶发失败的测试，同一个成因**：进程级全局被并行测试反复写。`LISTEN`（自循环防护的
  端口表）与 `CONNECT_BUDGET`（连接超时预算）。前者的根因还是个真 bug —— `set_listen`
  是整体覆盖，而一个进程可以起多个 `embed::Proxy`，第二个启动会抹掉第一个的自循环防护。
  第三个同型窗口（`INSECURE_UPSTREAM` 与 `Lazy` 的 TLS 配置）没有观察到失败，也一并关掉了。

- **请求体的读取此前完全无上限**（两处：`b:` 筛选器的预读，以及 body 算子的缓冲）。
  一个代理只要照单全收客户端发来的东西，就离被操作系统杀掉只差一次上传，而触发它
  只需要一条提到 `b:` 或 `params://` 的规则。现按上游 `MAX_REQ_SIZE` 定为 2MB、
  `enable://reqMergeBigData` 抬到 16MB。**过界的处理照抄上游的 `interrupt`**：
  不失败、不截断，把已读的冲出去、其余原样流向源站，只是算子不再生效 ——
  对一个调试代理来说这是对的失败方式，被检查的流量不该被检查本身弄坏。
  并且**打一条 WARN 说出来**：这些算子每一种「悄悄不生效」的方式，最后都被证明是个 bug。
  实测 5MiB 上传经代理后 sha256 与源文件逐位相同。`b:` 那一处只能用 2MB
  ——「哪些规则命中」正是它读 body 要回答的问题，去问规则要上限是循环的。
- **`cargo test --doc` 在 HEAD 上是红的**：`lift_inline_values` 的文档注释里，
  一个 ``` 围栏嵌在 ```text 围栏内，rustdoc 提前闭合并把后面的散文当 Rust 编译。
  外层改用四个反引号。顺带把飘到它头上的 `parse_text` 文档注释放回原处。

---


## 已完成（上一轮）

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
| 插件直接应答的响应期算子 | ✅ 与短路出口共用 `finish_local_response`；短路出口顺带补上 body 算子 |
| 自产响应也跑插件响应钩子 | ✅ `POST /response` 与 `pipe://` 覆盖插件应答与短路两条出口 |
| 认证拦截不再被规则改写 | ✅ 按上游 `ignore://!…` 语义原样送出（`pin_refusal`），仍记会话 |
| `xhost://` 直连回退 | ✅ 与 `xproxy://` 同一约束：仅握手无法建立时重试一次 |
| `from:` 筛选条件 | ✅ `tunnel` / `sni` / `composer` 可判定，其余四个为已知 false；未知标记不满足任何筛选器 |
| tee 抓取开销剖析 | ✅ 每帧约 6.5 ns、过上限即常数、端到端不可测；见 [`ARCHITECTURE.md`](ARCHITECTURE.md#what-the-capture-costs) |
| 预览解码器内存修复 | ✅ 剖析查出：解压缓冲随 capture 滞留在 500 条 session 环里，现于预览填满 / tee drop 时释放 |
| clippy 零告警 + 门禁 | ✅ 54 → 0；`[lints.clippy] all = "deny"` 覆盖全部 target |
| `sniCallback` 证书钩子 | ✅ 握手期读 ClientHello 并回放；插件可自带证书或**拒绝拦截**；曾被误记为架构不可达 |
| 被放弃连接的路由 | ✅ `sniCallback` 说不拦截后，`host://` / `proxy://` 仍照常路由；代理不可兑现即关闭 |
| MITM 证书按 SNI 签发 | ✅ 修正：此前按 CONNECT 权威地址签，两者不同时握手直接失败 |

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
- [x] ~~**更多插件钩子**：`uiServer`/`statsServer`、`auth`~~ → 已完成，见
      [`PLUGINS.md`](PLUGINS.md)。
- [x] ~~**`sniCallback`**~~ → 已完成，见 [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback)。
      握手期由插件挑证书，四种答案（自签 / 自带 / 复用 / **不拦截**），
      规则按 `https://<ClientHello 里的名字>` 匹配。此前被记成「架构不可达」，
      那条记录是错的 —— 详见下方 [架构受限](#架构受限rustls--mitm-时序)。
- [x] ~~**「不拦截」之后的中继不走规则管线**~~ → 已修（本轮）。此前 `false` 之后是一条
      到「隧道开到的那个地址」的**直连**，`host://`、`proxy://` 一族全部失效 —— 而原版的
      `next(chunk)` 恰恰是汇入它自己的隧道处理（`rollBackTunnel` → `handleTunnel` →
      `rules.getProxy`，`_original/lib/tunnel.js:259-271,:436`），那里照常解析地址与代理。
      现在同一轮解析出的 `Resolved` 被保留下来（`Resolved` 是自有值，可越过读锁），
      交给 `apply::resolve_target` 得出目标，再由 `upstream::tunnel_stream` 建连。
      **三处刻意的约束**：源站那一段恒为明文（TLS 由客户端与源站自己谈，我们再包一层
      就等于把自签证书塞给一条已答应不拦截的连接 —— 原版的隧道路径同样只 CONNECT、
      从不自己包 TLS）；`xhost://` / `xproxy://` 的一次性回退保留（对应隧道路径的
      `retryXHost`，`tunnel.js:570-617`）；代理规则**无法兑现**时关闭连接而非改走直连
      （新增 `Decision::Unroutable`，与请求路径答 502 是同一判断）。
      **不覆盖**：中继到上游代理的 CONNECT 不带客户端 UA 与 `Proxy-Authorization` ——
      这条路径上没有请求可回显；代理 URL 自带的凭据照常使用。
      被放弃的连接依旧**不抓包、不跑任何请求/响应算子**：那些都需要读取内容。

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
      仍不覆盖：WebSocket / `CONNECT` 隧道没有响应阶段；自循环 302、`enable://abort`
      与认证拦截三条出口不应用任何响应期算子（前两条不产生自己的响应，第三条按上游的
      `ignore://!…` 原样钉死；顶层规则同理）。

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

> 未改动并记录：上游把根 CA 密钥复用为每张叶证书的密钥（`ca.js:203-260`），
> 本移植为每张叶证书新生成密钥 —— **严格更强**，故不对齐。

### 模式匹配（早期审计修复）

同一个根因的三处实例，都是**失败开放**（规则悄悄匹配了不该匹配的请求）：

- [x] ~~`:8080` 端口 pattern 匹配一切~~ → 已按上游编译为 `^[\w]+://[^/?]+:<port>/`。
- [x] ~~`example.test:8080` 忽略端口~~ → `Pattern::Prefix` 现在携带 `port`，匹配时校验。
- [x] ~~`!pattern` 取反~~ → 已支持，且与上游一致地**只作用于正则与端口 pattern**；
      上游对取反的字面量/通配 pattern 是在解析期直接丢弃的（`rules.js:1259-1268`），本移植照做。

第四处（通配符本身）见本轮的 [pattern 与 destination 层](#已完成本轮pattern-与-destination-层)：
`*` 此前被编译成不带锚点的 `.*`，是同一类问题里影响面最大的一个。

### 标志族 `enable://` / `disable://`（本轮审计发现）

- [x] ~~**请求侧的 `disable://` 全部不生效**~~ → 已修（本轮）。上游每个请求都跑
      `disableReqProps`（`_original/lib/util/index.js:2977-3009`，由 `req.js:580` 调用），
      本移植**根本没有这个函数** —— `disabled_flags` 只在响应侧被用过一次。
      因此 `disable://cookie`、`ua`、`referer`、`gzip`、`ajax`、`cache` 六类**逐字解析、
      静默失效**：**失败开放**，且 cookie 那条是隐私问题。实测（改前）写着
      `disable://cookie|ua|referer|gzip|ajax` 的请求，源站仍收到
      `cookie: sid=secret` / `user-agent: MyUA` / `referer` / `accept-encoding` /
      `x-requested-with` 一个不少；改后全部为空。
      照抄的细节：`cookie` 四种拼写（`cookie`/`cookies`/`reqCookie`/`reqCookies`）、
      `referer` 与 `referrer` 两种拼法、以及 `enable://captureStream` 也会去掉
      `accept-encoding`（`isEnable` 含 disable 抵消，故 `enable` 单独出现才算）。
      本层直读 `disable.x`，不走 `isDisable` 的转义机制 —— 与上游一致。

- [x] ~~**响应体算子命中时未禁用请求缓存**~~ → 已修（本轮），比上一条更严重。
      上游在请求发出前检查 `notAllowCache(resRules)`（`res.js:33-60,:1328`）：
      17 个响应体算子（`resBody`/`resReplace`/`resPrepend`/`resAppend`/`attachment`/
      `resMerge`/`resWrite`/`resWriteRaw` 及 html/js/css 家族）中任意一个命中，就顺带
      `disableReqCache` —— 否则源站回 `304 Not Modified`，**响应体是空的，改写无从下手**。
      本移植此前从不碰条件头。实测（改前）：同一条 `resBody://REWRITTEN` 规则，
      普通请求得到 `200 REWRITTEN`，带 `If-None-Match: "v1"` 的请求（**浏览器重载就是这么发的**）
      得到 `304` 空响应，改写静默消失 —— 表现为间歇性、极难归因的「规则有时不生效」。
      改后两种请求都是 `200 REWRITTEN`。

- [x] ~~**`enable://showHost` 不生效**~~ → 已修（本轮）。上游在响应头上写
      `x-host-ip: req.hostIp || 127.0.0.1`（`_original/lib/inspectors/res.js:1197-1199`），
      本移植此前完全不认这个标志。取值复用已有的 `known_server_ip` —— 也就是
      `serverIp:` 筛选器读的那个**已建立 socket 的对端地址**，因此标志与条件不可能
      互相矛盾；经上游代理时两者都是**代理的**地址。没有建立连接时按上游回退到
      `127.0.0.1`（而不是省略这个头 —— 规则要求了它）。
      顺序与上游一致：写在 `resHeaders://` **之后**，所以同一行的
      `resHeaders://x-host-ip=mine` 会被标志覆盖。
      本移植不认上游的 `_filters.showHost`（无 filters 概念），只认 `enable://`。

### 压缩响应体的改写（本轮审计发现，最严重）

- [x] ~~**对压缩响应的所有 body 改写静默失效**~~ → 已修（本轮）。`transform_res_body`
      一直在**原始字节**上做替换，从不解压。真实站点绝大多数启用压缩，所以
      `resBody`/`resReplace`/`resAppend`/注入/`resMerge` 等**在实践中大面积失效**。
      实测（改前）：`resReplace://ORIGINAL=REPLACED` 对一个 gzip 响应输出与直连源站
      一字不差；改后得到 `REPLACED` 且仍以 `content-encoding: gzip` 正确重压返回。
      上游从另一端到达同一结果：任何 body 变换置 `_needGunzip`，于是 `getDecoder`
      在前解压、`getEncoder` 在后重压（`_original/lib/inspectors/rules.js:60-140`、
      `data.js`）。新增 `src/proxy/coding.rs` 做整体解压/重压（gzip/deflate/br，
      deflate 兼容 zlib 包裹与裸流两种），接进上游响应与自产响应两条路径。
      刻意的取舍：**无法往返的编码**（`compress`、双层 `gzip, br`）保持原样不动 ——
      改写一个放不回去的体比不改更糟；此时算子照跑但匹配不到，即维持原来的「无效果」
      而非损坏响应。
- [x] ~~**`enable://gzip|br|deflate` 不生效**~~ → 已修（本轮，与上一条同一链路）。
      `getEnableEncoding`（`_original/lib/util/index.js:1534-1548`）强制响应的**出站**
      编码，优先级 `br` > `gzip` > `deflate`，是唯一「明文进、压缩出」的情形。实测
      `enable://gzip` 把明文源站的响应压缩返回，且同一行的改写照常生效。

### 请求体（本轮审计发现）

- [x] ~~**GET/HEAD 等无体方法仍被注入请求体**~~ → 已修（本轮）。上游
      `req.js:116-120` 在 `hasRequestBody(req.method)` 为假时丢弃
      `reqBody`/`reqPrepend`/`reqAppend` 并删掉 `content-length` —— 这四个方法
      （`GET`/`HEAD`/`OPTIONS`/`CONNECT`）按语义不带体。本移植的 `wants_req_body`
      不看方法，于是照注不误。实测（改前）：规则 `reqBody://INJECTED` 之下
      `GET` 到达源站是 `{"method":"GET","len":"8","body":"INJECTED"}`；
      改后 `len` 为 null、body 为空，`POST` 不受影响。
      给 GET 强加 body 会被部分源站与 CDN 判成 `400`。
      **判定用的是转发时的方法**（`method://` 改写之后），与上游 `handleReq`
      的顺序一致：`method://post` 会让注入重新生效。
      **只丢注入**：`reqReplace` 与 `delete://reqBody.x` 改写的是**已有**的体，
      这些方法上本就无体可改，任其自然成为空操作。
      顺带省掉一次缓冲 —— 无体方法不再为「注定要丢弃的注入」把 body 读进内存。

### WebSocket 帧层（本轮审计发现）

- [x] ~~**`enable://ignoreSend` / `enable://ignoreReceive` 不生效**~~ → 已修（本轮）。
      上游 `initStatus`（`_original/lib/socket-mgr.js:86-97`）据此把某一方向置为
      `IGNORE_STATUS`，丢弃该方向的全部数据帧。本移植此前两个标志逐字解析、静默失效。
      照抄的两处语义：
      **被丢的帧仍然抓取并带标记** —— 上游发给 UI 时带 `ignore: true`
      （`socket-mgr.js:401,:531`），而不是让它凭空消失；否则一个会话看起来会像
      对端什么都没发过。本移植为此给 `WsFrame` 加了 `ignored` 字段。
      **控制帧豁免** —— `close` 被丢会让两端对「连接是否结束」的认知永久分叉，
      `ping`/`pong` 被丢则破坏双方商定的保活；上游的 ignore 路径同样只扣留数据帧
      （`opts.data`，`socket-mgr.js:249-274`）。
      机制上复用了已有的逐帧裁决路径（原为插件帧钩子所建），只是新增了规则驱动的入口。
- [x] ~~**`enable://pauseSend` / `enable://pauseReceive`** 按非目标处理~~ → **已实现**。
      当时的理由是「本移植的 Web UI 没有放行控件，照搬只会得到一个永远无人能解除的停顿」，
      并且写明了出路：**要么连 UI 控件一起做，要么不做**。本轮做了前者。
      详情与实测见上方[「上一轮的『尚未修 6 条』」](#上一轮的尚未修-6-条本轮的结果)。
- [x] ~~**`disable://ping` / `disable://pong`「无物可禁」**~~ → **已实现**。
      那句话在写下时是对的：本移植不注入保活。上一条带来了一条 —— 扣住一个方向就必须
      顶住对端的空闲超时 —— 于是这两个标志在同一轮里有了可禁的东西。

### 多值算子（已完成）

- [x] ~~`headerReplace` 的 `$$` URL 编码形式与键的作用域继承未移植~~ → 均已实现（本轮）。
      **`$$` 形式**：`$$1` / `$$&` 插入的是**百分号编码后**的捕获组
      （`encode = $2[1] === '$'`，`_original/lib/util/replace-pattern-transform.js:78-88`）。
      这一条无法交给 `regex` crate 的替换语法表达（它没有变换捕获组的手段），因此本轮把
      上游的 `replacePattern` 整个移过来手工展开，顺带把反斜杠转义也对齐了：`\$1` 是字面
      `$1`，`\\$1` 留一个反斜杠再替换，`$b1` 指向本移植没有的值列表故原样保留。
      该展开对**所有** `*Replace` 算子生效，不只是 `headerReplace`。
      **作用域继承**：不带前缀的键会沿用**上一个键的作用域和 header 名**、只保留自己的
      pattern（上游 `name = name || …`，`index.js:2233`），因此
      `{"resH.location:/^http:/":"https:","x:/y/":"z"}` 两次替换都作用在 `location` 上。
      开头就不带前缀的键被丢弃（`else if (!prop) return`）。为此 JSON 改为**保序**解析
      —— `serde_json::Map` 会按键排序，而继承依赖书写顺序。
      顺带补上第三个作用域 `trailer.`，它作用于 `trailers://` 折叠后的结果
      （`hr.trailer`，`res.js:1281`）。

- [x] ~~`headerReplace` 的 `$$` URL 编码形式、以及无前缀键继承上一个键的作用域~~ → 均已实现（本轮）。
      **`$$` 形式**：`$$1` / `$$&` 插入的是**百分号编码后**的捕获组
      （`encode = $2[1] === '$'`，`_original/lib/util/replace-pattern-transform.js:78-88`）。
      此前整个 `$$` 被当成转义后的字面 `$`，规则要一个编码过的组、拿到的是字符 `$1`。
      顺带把 `replacePattern` 整个照抄了过来（不再借 `regex` crate 的替换语法 —— 它没有
      任何写法能把一个组变换一下）：`\$1` 转义引用、`\\$1` 留一个反斜杠再展开、
      `$b1` 指向的是流式 body 变换独有的取值表，本移植无对应物故**原样保留**（上游在不传
      该表时同解）。
      **作用域继承**：无前缀的键沿用上一个键的作用域**以及头名**，只保留自己的 pattern
      （上游 `name = name || …`，`index.js:2233`）—— 所以
      `{"resH.location:/^http:/":"https:","x:/y/":"z"}` 两条替换都打在 `location` 上，
      而不是打在 `x` 上；开头就无前缀的键被丢弃（`if (!prop) return`）。
      因此解析必须**保序**，而 `serde_json::Map` 会按键排序，改用保序解析。
      顺带接上了第三个作用域 `trailer.`（`res.js:1281`），此前只认 req/res 两个。

- [x] ~~cookie 的属性对象被序列化进值、`delete://resCookies.x` 不发过期 cookie、
      `delete://trailer.x` 不生效~~ → 均已修（本轮）。
      **属性对象**：`resCookies://{"sid":{"value":"x","httpOnly":true,"maxAge":600}}` 现在按
      `getCookieItem`（`_original/lib/util/index.js:3093-3117`）展开为 `Set-Cookie` 属性，
      顺序、大小写变体（`maxAge`/`Max-Age`/`max-age` 等）、JS 的真值语义、`parseInt` 的
      宽松解析都照抄；此前整个对象被 `to_string()` 塞进 cookie 值里，属性一个都不生效。
      **数组形式**：一个名字可带多条 `Set-Cookie`（`addMapArr`，`index.js:3119-3123`），
      规则替换的是该名字的**整组**而非其中一条。请求侧只取 `.value`，与上游同。
      **`delete://resCookies.x`**：响应无法删掉客户端已有的 cookie，只能回一条**已过期**的
      —— 每个名字发两条（plain 与 `Secure`，因为 `Secure` 不会被非 `Secure` 覆盖，
      而代理无从得知是哪种）；隧道请求再加两条按父域限定的（`getDomain`，`index.js:2758-2774`；
      上游的 `req._w2hostname` 只在隧道路径设置，`lib/https/index.js:707`，故普通正向代理
      请求只有两条）。删除**压过**同一请求上写同名 cookie 的 `resCookies://`
      （上游 `extend(cookies, delKeys)`）。
      **`delete://trailer.x`**：在 `trailers://` 折叠**之后**生效（`res.js:1275-1280`），
      且这个键**不带** `req`/`res` 作用域 —— `TRAILER_RE` 前端不锚定，照抄。

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

### 待跟进（上轮发现，本轮已闭环）

- [x] ~~**插件直接应答的出口不应用任何响应期算子**~~ → 已修。此前直接返回
      `plugin_response(resp)`，`resHeaders://`、`replaceStatus://`、`resType://`、
      `trailers://`、`resDelay://`、`resSpeed://`、`resScript://` 以及整个 body 家族
      对插件产生的响应**全部静默失效**；响应期二次解析也一并缺席，因此这条路径上
      `s:` / `resH.` 条件同样答不出来。上游对该路径照跑 `getResRules`——`plugin://`
      在上游就是一次到插件自有 server 的代理跳，插件的应答以普通响应身份走完
      `handleResponse`（`_original/lib/inspectors/res.js:825`）。
      本移植两条「自产响应」出口（插件应答、短路规则）现共用一个 `finish_local_response`：
      顺带补上了短路出口**此前只跑头部算子、不跑 body 算子**的缺口，并给插件应答
      补了会话 body 预览。没有任何算子命中的响应原样返回（含 `content-length`），
      流式路径不受影响。
- [x] ~~**插件自身的响应钩子在这条出口上不触发**~~ → 已修（本轮）。`POST /response`
      与 `pipe://` 现在覆盖两条自产响应出口，见
      [`PLUGINS.md`](PLUGINS.md#本地产生的响应也走响应阶段)。上游那边这是结构性的：
      `plugin://` 是一次到插件自有 server 的代理跳，应答以普通响应身份回到
      `handleResponse`（`res.js:825`），而 `pipe://` 从它自己那条规则解析、不看字节
      是谁产生的（`resolvePipePlugin`，`plugins/index.js:1173`）。
      三处需要留意：
      **(1)** `respond()` 终止的是请求阶段 —— 后续插件的 `onRequest` 不再执行，但
      **全部**命中插件的 `onResponse` 都会看到这个应答，包括应答者自己（上游亦然，
      它按全部命中插件建管道）。
      **(2)** body 已在内存，故 `pipe://` 在此是「装帧 → 过管道 → 收回」，
      钩子只有一套实现；管道改了长度即去掉 `content-length`。
      **(3)** **认证拦截是例外**，见下条。
- [x] ~~**认证拦截的响应会被其它规则改写**~~ → 已修（本轮，顺带发现）。`onAuth` 的拒绝
      此前也走 `finish_local_response`，于是 `resHeaders://`、`replaceStatus://`、
      `resAppend://` 都能改写它 —— `replaceStatus://200` 可以把一条 403 拦截变成 200。
      上游把拦截钉死为 `* ignore://!statusCode|!resBody|!resType|!resCharset …`
      （`plugins/index.js:936-959`），而 `ignore://!x` 是**反向白名单**：`ignoreRules`
      遍历全部已解析规则、除排除项外一律删除，**插件规则也删**
      （`util/index.js:2068-2092,:2008`）。也就是说拦截响应上**没有任何用户规则生效**。
      现按此对齐：拒绝走 `pin_refusal`，原样送出（仍然记会话）。区分「拒绝」与「应答」
      的是裁决来源而非状态码 —— 插件用 `respond()` 主动返回 403 仍是应答，照跑钩子。
- [x] ~~`xhost://` 的直连回退（`retryXHost`，`res.js:571-600`）~~ → 已实现。
      `xhost://` 是 `host://` 的**穿透版**：地址能连就用，连不上就忽略该规则走原始地址
      （`docs/docs/rules/xhost.md`），此前本移植两者等同，连不上即 502。
      约束与已落地的 `xproxy://` 回退一致：只有**握手无法建立**才重试，请求一旦写上
      socket 就无法重放。两者现由同一个 `Target::fallback_target` 给出，其中也编码了
      上游的 `else if`——有任何代理规则时永不走 host 回退（失败的是到代理的连接）。
      **刻意偏离**：只重试一次。上游 `if (retryXHost > 1)` 让**第一次**重试打同一个死地址、
      第二次才查 DNS（写成 `>= 1` 才对），照抄只会让每个失败的 `xhost://` 多一次无谓连接。

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
- [x] ~~`from:`（`tunnel`/`composer`/`sni` 等来源标记）~~ → 已实现，上游的整套标记
      （`_original/lib/rules/rules.js:1834-1859`）：
      `tunnel`（请求出自本代理拦截的隧道，CONNECT 或 SOCKS —— 上游是绕道达成的：
      解密后把自己的 client-info 头重新注入字节流再喂回自己的 HTTP server，
      `addClientInfo`，`lib/https/index.js:1203-1210`）、
      `sni`（被拦截的 ClientHello 带了 SNI；rustls 为选证书本就解析过，握手后读一次）、
      `composer`（Web UI 重放，回环跳上带 `x-whistle-composer`，到达即消费）；
      `test` / `httpserver` / `httpsserver` / `httpsport` 识别但恒为**已知的 false** ——
      本移植不认测试头、也不开代理端口之外的额外 HTTP/HTTPS 监听
      （`config.httpPort`/`httpsPort`，`lib/index.js:96-111`），与没开这两个端口的上游同解，
      因此 `from:!httpserver` 成立。
      **照抄的两处上游怪癖**：`from:internalPath` 永不命中（上游比较前先 `toLowerCase`，
      自己那条分支不可达）；不认识的标记**无论怎么写都不满足任何筛选器**（上游在读
      `filter.not` 之前就 `return false`），因此建模为「未知」——include 不满足、exclude 不生效。
      **开销**：composer 标记每请求一次 `HeaderMap::remove` 未命中，实测 30ns（对照
      500 条规则解析约 2.6µs）；来源标志的构造低于计时精度；500 条规则里有一条命中的
      `from:` 行是 2.56µs，没有是 2.62µs，即落在噪声内。

至此**每一个本移植会解析的筛选器条件都能求值**，`Deferred` 机制已无使用者，随之删除。

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
- 覆盖每一条会产生响应的出口，包括不走上游的两条：插件直接应答、短路规则
  （`file://` / `tpl://` / `redirect://` / `statusCode://`）。二者都按**产生时**的头解析，
  早于任何算子动手 —— 所以 `s:404` 看到的是插件自己的 404，而不是同一行
  `replaceStatus://200` 之后的值。
- 尚未覆盖：WebSocket 与 `CONNECT` 隧道没有响应阶段；自循环 302 与 `enable://abort`
  本就不产生自己的响应（顶层规则同理）。
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
- [x] ~~`{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 插件包变量~~ → **本移植无物可替，
      按非目标关闭**（理由见下方 Non-goals）。
- [x] ~~`lineProps`（whistle 规则行级属性系统）~~ → 见 [`LINE_PROPS.md`](LINE_PROPS.md)。
      解析层与原版完全对齐；`important`、`safeHtml`/`strictHtml` 注入门禁、
      `internal`/`internalOnly` 作用域、`proxyFirst`/`proxyHost`/`proxyHostOnly`、
      `weakRule` 均已端到端接线并验证。其余属性经核对**在本移植中无对应可接之处**
      （如本移植不发自动 CORS，`disableAutoCors` 无物可抑制），已在文档中逐条说明理由。

### 架构受限（rustls / MITM 时序）

- [x] ~~**`sniCallback`** —— 在 TLS SNI 阶段用插件选证书。我们的 MITM acceptor 在 SNI 阶段
      按域名构建，早于按请求的规则解析，且需插件运行时在该时点介入；当前架构下不可达。~~
      → **这条判断是错的，现已实现**，见 [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback)。
      本条不是「后来做到了」，而是**当初就不该这么记**：它描述的是当时的代码
      （`acceptor_for(host)` 从 CONNECT 权威地址**急切**构建），不是架构的约束。
      `tokio-rustls` 的 `LazyConfigAcceptor` 一直提供着 ClientHello 之后插入异步工作的接口。

      真正存在的障碍只有一个，而且比记的那个窄得多：`sniCallback` 的 `false` 意思是
      「这条连接原样中继出去」，那要求**已经被读走的 ClientHello 字节还能拿回来**，而
      `LazyConfigAcceptor` 接管 socket 之后不再交还。所以字节改由代理自己读、留着、再回放
      （拦截时回放给 rustls，不拦截时回放给源站），解析仍然用 `rustls::server::Acceptor`。
      原版从同一个约束走到同一个安排（`lib/https/index.js:1281-1308`）。

      代价量过：ClientHello 多解析一次，**p50 +0.6µs**，对着一个 170µs 的握手；没有
      `sniCallback://` 规则的连接一个 `bool` 就退出，与基线二进制逐字节相同。
- [x] ~~MITM 证书按 **CONNECT 权威地址**签发，而不是客户端 ClientHello 里的名字~~ →
      **已修**（与上一条同批）。两者不一致时旧行为是**握手直接失败**：客户端校验的是它
      自己要的名字。自己做 DNS 解析的 SOCKS5 客户端就会踩到 ——
      `curl --socks5`（区别于 `--socks5-hostname`）把隧道开到 `127.0.0.1`，ClientHello 里
      仍然要 `localhost`，于是拿到一张 `CN=127.0.0.1 / SAN=IP:127.0.0.1` 的证书。
      现在按 ClientHello 里的名字签，客户端没发 SNI 时才退回隧道地址 ——
      也就是上游的 `useSNI || socket.tunnelHostname`（`lib/https/index.js:1281-1296`）。
- [ ] **`cipher` 扩展** —— rustls 只暴露 TLS 1.2/1.3、不接受 OpenSSL cipher 字符串，故只支持
      版本固定（已实现），无法完整对齐 Node 的 TLS 选项。

### 非功能项

- [x] ~~性能剖析（大响应体、并发连接下 tee 抓取开销）~~ → 结论与数据见
      [`ARCHITECTURE.md` 的 “What the capture costs”](ARCHITECTURE.md#what-the-capture-costs)，
      测量代码在 `src/proxy/bench.rs`（`cargo test --release -- --ignored --nocapture bench::`）。
      **吞吐上无需处理**：每帧约 6.5 ns（一次无竞争加锁），过了预览上限即变为常数——
      16 MiB 与 1 MiB 相比只多 0.7–0.9 µs；每个 body 各持有自己的 capture，并发之间不存在锁竞争。
      端到端（1 / 32 并发，4 KiB 与 1 MiB，identity 与 gzip）下默认配置与「只计数不复制」
      无法区分，差值落在噪声内并会变号。唯一显著的是**去掉上限**：1 MiB gzip 从 6.0 ms 涨到 9.5 ms。
      对照物：本移植不做上游连接池，每请求 1.00 条上游连接，一次握手就比 tee 高出几个数量级。
      **但剖析查出一个内存问题并已修复**：预览解码器（`flate2` 写端）会把解压出的全部字节
      留在内部缓冲里，而它随 capture 一起活在 500 条的 session 环里 —— 一个 16 MiB 的高压缩比
      响应会因此长期占住 16 MiB。现已在预览填满、以及 tee 被 drop 时释放解码器。
- [x] ~~清理较新工具链带来的 clippy 风格提示（`collapsible_if` 等）~~ ——
      `cargo clippy --all-targets` 从 54 条告警清零：40 处 `collapsible_if` 全部借
      edition 2024 的 let-chain 合并（逐处核对过注释归属，无一处需要 `#[allow]`），
      另有 9 类零散提示。其中 `large_enum_variant` 确有实质：`RetryableError::Connect`
      内含整个待重试的 `Request`，使每次成功转发返回的 `Result` 都是 248 字节
      （载荷本身只有 184），已装箱。防回归的门禁放在 `Cargo.toml` 的 `[lints.clippy]`
      （`all = "deny"`，覆盖 lib/bin/tests 全部 target；`cargo build` 不受影响）。

---

## 不打算做的事（Non-goals）

- **现成 npm `whistle.*` 包的兼容运行** —— 原版插件 API 建立在对 Node `req`/`res` 对象的
  装饰之上（约 2600 行加载器、位置式 CSV 头协议、单端口多钩子分发）。与其被这套历史包袱
  绑定，whistle-rs 选择了一套显式、有类型、语言无关的自研协议，配 JS/TS SDK。
  见 [`PLUGINS.md`](PLUGINS.md)。

- **逐字节复刻 React 前端** —— 内建控制台已覆盖核心检查/编辑需求（三栏布局、可排序表格、
  逐请求详情、规则分组与 Values 编辑），且不引入构建步骤：`src/proxy/ui/` 就是普通的
  HTML/CSS/JS，编译期内联。除非有明确诉求，不重写 `biz/webui`。
- **硬绑定 Node.js 运行时** —— 项目目标是单一静态二进制。JS/TS 插件跑在子进程里，
  是**可选**特性：不写插件就完全不需要 Node。
- **`G` / `style` 算子的「流量效果」** —— `G` 是全局插件变量基础设施、`style` 是规则列表
  配色，二者都不是逐请求的流量算子；保持「解析但不产生效果」。

- **`{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 插件包变量** —— 上游把它们替换进
  **已安装 npm 包目录**里的 `rules.txt` / `_rules.txt` / `resRules.txt` / `_values.txt`，
  取值源是该包自己的 `package.json`（`renderPluginRules`，
  `_original/lib/util/index.js:3533-3542`；`lib/plugins/get-plugins-sync.js:184-206`）。
  本移植的插件是讲自研协议的外部 HTTP server：没有包目录、没有 `package.json`、
  也没有静态规则文件 —— 插件是从请求钩子**返回**规则文本的，而它本来就知道自己的名字。
  **没有可替换的来源**，因此这不是「待补的缺口」而是非目标。若硬要在插件返回的规则文本上
  做替换，等于凭空发明一个包概念，还会让代理去改写插件刻意产出的文本。

---

## 参与

**本轮把上一版「尚未修」的整张清单清完了**，包括当时判为架构限制的那两条 ——
它们的前提都成立，但都不是全部：控制台时间线的前提是「Session 模型太薄」，
那就把模型加厚；`cipher://` 的前提是「rustls 不接受 cipher 字符串」，那也是真的，
可由此推出「语义不可移植」是错的 —— 字符串是一门语言，语言可以求值，
rustls 给的只是一个更小的套件宇宙。
做完之后**剩下**的部分没有被略去：事件流上仍不生效的是 `resMerge://`、`resScript://`
与 typed 家族，后者本就不会命中事件流；标记只存在于客户端；`b:` 筛选器的预读只能用
未抬高的那个上限；`cipher://` 给不出本构建没有的密码算法，`send` 阶段不可测量。

这一轮里有两条记录被自己的实现推翻，都留在原处并注明：
`enable://pauseSend`/`pauseReceive` 曾按**非目标**处理，理由是「没有放行控件」——
控件做了，理由就不成立；`disable://ping`/`pong` 曾记作**无物可禁**，那句话当时是对的，
而扣留一个方向恰好带来了一条保活，于是同一轮里它从「没有对应语义」变成了功能。
第三条是别人的：上游的正则 `resReplace://` 在事件流上静默无效（先判定哪些匹配已定、
再抬高冲刷点，两步在一条短事件上互相矛盾），本移植**没有照抄这个 bug**，理由写在代码里。

规则/筛选/上游层的对齐清单同样清空：**每一个会解析的筛选器条件都能求值**，
每一条会产生响应的出口都跑响应期算子。**`sniCallback` 也不再是缺口** —— 它曾被记成
「架构不可达」，而那条记录经核查是错的：障碍不在架构，在于当时的 acceptor 构建得太早。
现在 ClientHello 由代理先读、保留、再回放，插件因而能在握手期挑证书，甚至拒绝拦截。

被架构真正挡住的只剩**本构建没有的密码算法**（`3DES`、`RC4`、静态 RSA 密钥交换、DH、PSK）。
cipher 字符串那门语言本身已经被完整求值了 —— 挡住的从来不是语法，是密码学实现。
**插件的响应钩子不再有缺口** —— `POST /response` 与 `pipe://` 已覆盖两条自产响应出口，
认证拦截则按上游的 `ignore://!…` 语义原样钉死。**被放弃的连接也不再是缺口** ——
`sniCallback` 说「不拦截」之后，`host://` 与 `proxy://` 照常路由；它拿不到的只是那些
需要读取内容才成立的东西。

算子层此前清掉四条**静默失效**（都是「解析了但不产生效果」，最坏情况是用户以为写了却没写）：
cookie 的属性对象与数组形式、`delete://resCookies.x` 的过期 cookie、`delete://trailer.x`、
`headerReplace` 的 `$$` 编码引用与无前缀键的作用域继承。仍然刻意保留的是四条有意的取舍
（注入文本按 UTF-8、`params://` 缓冲改写、非 UTF-8 请求体不处理、`resScript` 里的
`resRules://` 条目无处安放），理由都写在 [`RULES.md`](RULES.md) 的对应条目里。

**上一轮把审计范围往前挪到了算子之前** —— 规则行怎么被切开、以及请求最终去哪。这一层
在那之前没有被系统看过，结果是四个缺口里有两个**失败开放**，另有一个是原版**最常用**的
那条规则从来不生效：

- 转发规则（`example.com http://localhost:5173`）**整行被读成两个 pattern**，产生零个算子；
- `*` 通配符被编译成不带锚点的 `.*`，于是 `*.example.com` 命中任何**提到**该域名的 URL；
- 命中后缀从不拼接，于是 `file://` 指向目录的规则对根路径以外的一切都 404；
- `$0`–`$9` 子匹配传值逐字发给源站。

这一层的判定全部与上游的分类器/编译器**逐条比对**过（`indexOfPattern` 的分支、
`parseWildcard` 与 `isRegUrl` 编译出的正则源码），而不是照着文档重写。

模块地图见 [`ARCHITECTURE.md`](ARCHITECTURE.md)，算子覆盖见 [`RULES.md`](RULES.md)，
插件编写见 [`PLUGINS.md`](PLUGINS.md)，模板见 [`TEMPLATES.md`](TEMPLATES.md)，
规则行级属性见 [`LINE_PROPS.md`](LINE_PROPS.md)。
