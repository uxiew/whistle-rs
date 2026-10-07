# 自有 HTTP API

基线：`702486d` / 2026-09-25，2026-09-28 按 S1 更新访问规则，2026-09-29 按 O1 补上失败会话、按 O2 补上检索、游标、body 与出错的约定。接口来自 `src/proxy/webui.rs`（路由表 `handle`）和 `src/proxy/webui/` 下按领域分开的文件，现有调用与类型见 `ui-src/src/api.ts`。

这是 whix 的控制接口，**不是官方 `/cgi-bin/*` 或 Node Local Agent API 的兼容层**。以下是现有路由与主要参数，不代表已承诺独立稳定的版本化 API。本文和路由表由测试双向核对（`api_doc_tests`）：加了路由没写进来、或者这里写了路由表里没有，测试都会失败。

## 地址与认证

默认与代理共用端口，只监听 `127.0.0.1`；`-P/--uiport` 另开一个只服务控制台的端口。按 [OPERATIONS.md](OPERATIONS.md) 限制访问。配置账户时使用 HTTP Basic；访客账户只读。不要把 CORS 白名单当身份认证，也不要把 UI 认证当代理转发认证。

每个请求先过两道检查，再验登录：

| 检查 | 不通过时 |
| --- | --- |
| `Host` 必须是 IP 地址、`localhost` 或控制台主机名（内置的和 `-l` 加的） | 代理端口上：当普通请求转发给那个域名，解析回本机则 `302` 到控制台地址；`-P` 端口上：`403`，正文说明原因。都是为了防 DNS rebinding |
| POST/DELETE 若带 `Origin`，须是控制台自己或 `--allow-origin` 名单上的来源；`Origin: null` 一律不行 | `403 cross-site request refused`；不带 `Origin` 的脚本和 curl 不受影响 |
| 请求体不超过 16 MiB | `413` |

根证书和 PAC 不受前两道检查限制。

直连接口不要经过调试代理本身，例如：

```sh
curl --noproxy '*' http://127.0.0.1:8899/api/status
curl --noproxy '*' http://127.0.0.1:8899/sessions.json
curl --noproxy '*' 'http://127.0.0.1:8899/session.json?id=1'
```

这些示例假定本机实例未设置口令；有认证的实例须提供对应凭据。不要把真实凭据写进文档或命令日志。

## 出错时

控制台前面那几道检查（Host、Origin、登录）拒绝时回纯文本；过了这几道之后，**接口的每一种拒绝都是同一个样子**：4xx 状态码、`Content-Type: application/json`、正文 `{"ok": false, "error": "原因"}`。

```sh
curl -s --noproxy '*' -X POST http://127.0.0.1:8899/api/replay -d '{"id": 999999}'
# 404 {"ok":false,"error":"no session with that id is held; it may have left the list or been cleared"}
```

判断成功看状态码，不要只看能不能解析出 JSON。没有的路径也是这个样子的 404。例外只有一个：`/session.json?id=N` 查不到时回 `200` 和 `null`（控制台每次轮询都会问选中的那一行，刚被挤出列表不算错误）。

## 读取流量

| 方法 / 路径 | 含义 |
| --- | --- |
| `GET /api/status` | 状态、配置摘要与插件信息；不同调用来源可能得到受限字段，不应假定总有本地路径等字段 |
| `GET /sessions.json` | 会话摘要列表，新的在前，不带请求头和 body。可带 `after`、`ids` 当游标用，见下文 |
| `GET /session.json?id=N` | 单个会话详情，含请求/响应头和 body 预览；查不到是 `null` |
| `GET /api/sessions/search?c=h:…&c=b:…` | 在代理手里的全部会话里查请求/响应头（`h:`）和 body（`b:`），见下文 |
| `GET /body.bin?id=N&side=req` / `side=res` | 已捕获体的字节；按附件返回，截断时文件名带 `partial-` |
| `GET /frames.json?id=N` | 对应会话捕获的帧 |
| `GET /sessions.har` / `?ids=1,2` | HAR 导出；来源是有界捕获，不等于完整原始报文归档，没存全的 body 会标出来 |

这几条读接口其实不看方法，用 GET 就行。

**列表行上有什么：** `id`、`time_ms`、`method`、`url`、`status`、`client_ip`、`target`、`duration_ms`、`log`、`rules`、`up`/`down`（body 字节数，不含头）、`has_req_body`/`has_res_body`/`has_frames`、`type`（响应的 `content-type`）。另外四个字段只在成立时出现：`error`（没完成，见下文）、`composer: true`（Composer 或 Replay 发的）、`open: true`（响应还在传，见下文）、`unapplied`（有命中的规则没生效，见[没生效的规则](#没生效的规则)）。

**当游标轮询：** 列表永远是整个内存里的会话（上限 `-R`，最少 600 条）。程序要持续跟踪时：

1. 记下见过的最大 `id`，下次请求 `/sessions.json?after=那个id`，只拿新来的（id 只增不减，不复用）。
2. 带 `open: true` 的行还没结束：body 预览还在长，`down` 会变，还可能补上 `error`。用 `/sessions.json?ids=12,15` 反复拿这几行，直到 `open` 消失。

`after` 不是数字时回 400。一直不结束的流（长连着的 SSE）会一直是 `open`。

**body 预览的字段：** `/session.json` 里的 `req_body`/`res_body` 形如 `{len, truncated, text, binary, undecodable}`：

| 字段 | 含义 |
| --- | --- |
| `len` | body 在线上的原始字节数（压缩过的就是压缩后的大小），不是预览的长度 |
| `truncated` | 预览没存全：到了 `--body-preview-limit`，或者解压到一半坏了。为 `true` 时 `text` 只是开头一段 |
| `text` | 解码后的预览文本；`binary` 为 `true` 时是 `[binary, N bytes]` 这句标记，不是 body |
| `binary` | 按 `content-type` 判断不是文本。字节从 `/body.bin` 取 |
| `undecodable` | `content-encoding`（gzip/deflate/br）解到一半失败，`text` 是失败前解出来的部分；这时 `truncated` 也是 `true` |

这些标记写盘时原样保存，重启后读回来不变；二进制和不是 UTF-8 的文本连字节一起存（base64），所以重启后 `/body.bin` 拿到的还是原来的字节。

**导出和重放怎么说明"不完整"：**

- HAR：没存全的 body 在 `content`（或请求的 `postData`）上多两个键：HAR 1.2 标准的 `comment`（如 `whix kept 10 of 100 bytes; the rest was not captured`），以及 `_truncated: true`。二进制和不是 UTF-8 的文本按 base64 导出（`encoding: "base64"`）。
- Replay：返回里每个会话的 `body` 是 `whole`/`partial`/`empty`/`undecodable`；`partial` 只发存下的那段，`undecodable` 不发 body。
- 控制台的"Copy as cURL"遇到没存全、二进制或解不开的请求体时不带 body，行尾用 shell 注释写明原因；"Edit & Resend"不把二进制标记当 body 填进去。

## 检索：`h:` 和 `b:`

列表行不带头和 body，所以这两个条件由代理来查：

```sh
curl -s --noproxy '*' 'http://127.0.0.1:8899/api/sessions/search?c=b%3A%22success%22%3Afalse&c=h%3Acookie'
# {"scanned":812,"results":[{"condition":"b:\"success\":false","ids":[3,9],"partly_kept":[5]},
#                           {"condition":"h:cookie","ids":[1,3]}]}
```

- 每个 `c` 一个条件，写法和控制台检索框一样：关键字是不分大小写的子串；`/…/flags` 是正则，按浏览器 `RegExp` 的语法（引擎是 regress，支持后行断言）。
- `h:` 查请求头和响应头。一个头的名字、值、或者 `名字: 值` 这一行，任何一个匹配就算。
- `b:` 查请求 body 和响应 body 的**已存预览**，按 UTF-8 读。`partly_kept` 列出没匹配上、但 body 没存全的会话：匹配可能在没存下的那部分里，这些是"不知道"，不是"没有"。控制台把这种行数显示在请求计数旁边。
- 只接受 `h:` 和 `b:`；别的前缀、空条件、写错的正则或标志都回 400，`error` 里写明是哪个条件、错在哪。
- `scanned` 是代理当时手里的会话数，也就是控制台列表的全部。

控制台检索框的其他前缀（`m:`、`s:`、`H:`、`fc:` 等）在浏览器里用列表行就能答，不经过这个接口。`app:` 不支持：上游是在浏览器里按 User-Agent 猜的，把猜测当成流量的事实展示不如不答。

## 采集和显示是两回事

| 做法 | 代理还记不记 | 接口、HAR、磁盘里有没有 |
| --- | --- | --- |
| 规则 `enable://hide` | **不记** | 都没有：列表、详情、检索、HAR、嵌入 API 的 `on_session`、磁盘历史里都查不到。失败时的 502 仍带 `x-whix-error`，但不带会话号 |
| `--no-persist` | 记在内存里 | 接口和 HAR 里有，磁盘上不写历史（根证书和规则照常写） |
| 控制台检索框、Capture filter、按客户端筛选、只看标记 | 记 | 都有；只是控制台这一页不显示 |

Capture filter 在浏览器里、对新到的行生效，存在浏览器的 `localStorage`，代理完全不知道它。要让某类请求不进记录，用 `enable://hide`。上面两条"不记"都有端到端测试核实（`tests/hide_e2e.rs`）。

## 失败的请求

**每个经过代理的请求记一条会话，只记一次，失败的也记。** 没完成的请求多一个字段：

```json
{ "id": 12, "status": 502, "target": "127.0.0.1:9",
  "error": { "phase": "connect", "message": "connecting to 127.0.0.1:9: Connection refused (os error 61)" } }
```

`phase` 是请求停在哪一步，取值和各自的意思见 [Cookbook 的排查一节](COOKBOOK.md#规则不生效时)；`message` 是完整的错误链，和客户端收到的 502 正文是同一段。`error` 出现在 `/sessions.json` 的行上（没有失败的行不带这个字段）、`/session.json` 详情里、磁盘历史里；HAR 导出写成 Chrome 导出用的 `_error` 字符串，形如 `"connect: connecting to …"`。

本代理替失败的请求生成的响应是 `502`，带两个头：

| 头 | 值 |
| --- | --- |
| `x-whix-error` | 停在哪一步，同 `error.phase` |
| `x-whix-session` | 记成的会话号，拿它查 `/session.json?id=N` |

**判断一个 502 是谁回的，看有没有 `x-whix-error`**：没有就是源站自己回的，那条会话也没有 `error`。`x-server: whix` 分不出来 —— `statusCode://502` 这类规则回的也带它。规则主动丢弃的请求（`enable://abort` 等）不回任何响应，会话的 `phase` 是 `abort`、`status` 是 `0`。

**一条会话什么时候出现、什么时候算完成：**

- 响应头一到就出现在列表里，这时 body 可能还在传。本地应答的、失败的，出现时就已完成。
- body 传完、出错或客户端中途离开，才算完成。**完成时才写进磁盘历史，嵌入 API 的 `on_session` 也在这时调用**，每条只调一次。所以历史里存的是完整的 body 预览和全部耗时阶段；中途断掉的会在这时补上 `response` 或 `client`。
- 一直不结束的流（长连着的 SSE）结束前不会写盘；代理进程被直接杀掉时，这类还开着的会话不会进历史。
- WebSocket 握手完成就算完成，之后的帧另外记（`/frames.json`），不属于会话本身。

**各入口的范围：**

| 入口 | 记什么 |
| --- | --- |
| 普通 HTTP 代理请求 | 每个请求一条，失败的也有 |
| 解密的 HTTPS（MITM） | 隧道里每个请求各一条，和普通请求一样。隧道本身没有自己的一条 —— 除非 TLS 握手就失败了：客户端不接受本代理的证书时，记一条 `CONNECT`，`phase` 是 `client-tls` |
| 不解密转发的隧道（`disable://intercept`、`--no-intercept-https`、非 HTTP 流量） | 一条 `CONNECT`，Policy（`target`）末尾带 `(tunnel)`，状态 `200`；连不上远端时按 `dns`/`connect`/`proxy` 记失败。隧道里的内容不读。`--no-intercept-https` 和命中 CONNECT 地址的 `disable://intercept` 是先连远端、连上了才回 `200`（和 whistle 一样），所以连不上时 CONNECT 没有任何回复，这一条的状态是 `0` |
| SOCKS5 入口 | 和 CONNECT 隧道走同一段代码，记法相同 |
| WebSocket | 握手一条；握手转发失败按普通请求记失败 |
| Composer / Replay | 请求从代理自己的端口发出，按普通请求记会话，失败的也记。接口接下任务就回答（Composer 回 `ok`，Replay 回 `replayed`），不等请求结果，也不返回会话号：去列表里找最新的那条 |

不记的只有三种：控制台自己的请求、`enable://hide` 命中的请求、客户端开了隧道一个字节没发就关掉的（什么都没请求）。第三种有个例外：上面说的"先连远端再回 `200`"的隧道，连上就记一条，不管客户端后来发没发数据。

## 没生效的规则

`rules` 列的是**命中**的算子，不等于**生效**的算子。代理有意不执行某些算子时（body 太大、是事件流、解不开压缩……），会在会话上记一个 `unapplied` 列表，列表行和 `/session.json` 里都有，也写进磁盘历史；全部生效时没有这个字段：

```json
{ "rules": [ {"protocol": "resReplace", "value": "a=b", "raw": "resReplace://a=b"},
             {"protocol": "resHeaders", "value": "x=1", "raw": "resHeaders://x=1"} ],
  "unapplied": [ { "kind": "body-over-limit",
                   "ops": ["resReplace://a=b"],
                   "reason": "the response body is over 16777216 bytes, the rewrite limit, so it was forwarded as it arrived. --body-rewrite-limit raises it" } ] }
```

`ops` 里每一项就是 `rules` 里某一条的 `raw`，拿它对上是哪条；`reason` 是给人看的原因，带上当时的数字；`kind` 给程序判断用：

| `kind` | 什么情况 | 怎么处理的 |
| --- | --- | --- |
| `body-over-limit` | 响应 body 超过 `--body-rewrite-limit`（默认 16 MiB） | 原样转发，响应 body 算子都不执行 |
| `request-body-over-limit` | 请求 body 超过 2 MB（`enable://reqMergeBigData` 等可提到 16 MB） | 原样发给源站 |
| `event-stream` | 响应是事件流（SSE），不会被整个收下来 | 边到边转发；`resReplace`/`resBody`/`resPrepend`/`resAppend` 照常执行（压缩的流上 `resReplace` 不执行），其余需要完整 body 的不执行 |
| `decoded-over-limit` | 压缩的 body 解开后会超过改写上限 | 不解压，原样转发 |
| `undecodable` | `content-encoding` 解不开（字节和头说的不一致） | 原样转发，不在压缩字节上跑算子 |
| `unsupported-coding` | 本代理不支持的编码（`zstd`、叠加编码） | 原样转发 |
| `plugin-failed` | 插件的 request/response 钩子连不上、回了错误状态码、或 30 秒没回答 | 请求照常继续，当作钩子什么都没说 |
| `no-weinre-server` | `weinre://id` 只写了 id，而启动时没用 `--weinre` 指明 weinre 服务在哪（本代理不自带 weinre） | 不注入任何东西，页面原样返回，CSP 和缓存头也不动 |
| `cipher-unusable` | `cipher://` 选不出可用的套件，或套件和允许的 TLS 版本对不上；或 `tlsOptions://` 里有本代理的 TLS 库做不了的选项（`dhparam`、`secureOptions` 等） | 不带那一部分建连（版本限制和其余选项保留） |
| `missing-value` | 改 body 的算子（`resBody`、`resPrepend`、`htmlAppend`、`reqBody` 等）整个值是 `{名字}`，而规则文本的 ``` 块和 Values 里都没有这个名字 | 不执行，body 和缓存头都不动；`reason` 里写着是哪个名字 |
| `script-failed` | 规则跑的脚本（`reqScript`、`rulesFile`、`resScript` 等）抛了错，或 1 秒还没跑完；`reason` 写明是哪种，抛错时带上错误信息 | 脚本推的规则、对响应的改动都不算数，请求照常继续 |

这些都是**降级**：请求照常完成，只是这些算子没执行。只有插件的认证网关（auth）失败时会拦截请求，那是请求失败，记在 `error` 里（阶段 `plugin`），不在这里。控制台的 Rules 标签页会把这些算子划掉并标 "not applied"。

还没覆盖的情况（算子会命中但实际不起作用，而 `unapplied` 里不会有）：按内容类型跳过的（如 `resMerge` 对非 JSON/JS/HTML、`html*` 对非 HTML 响应）、隧道和 WebSocket 升级上的响应阶段算子、写不进去的非法头、`statusCode://abc` 这类无效值。

## 规则与 Values

除特别注明外，写接口的请求体是 JSON。服务端不检查 `Content-Type`；防跨站靠的是上面的 `Origin` 检查，不是内容类型。

| 方法 / 路径 | 输入或用途 |
| --- | --- |
| `GET /api/rules` | 规则文本；不是 JSON |
| `POST /api/rules` | **原始规则文本**，更新 Default 组；不是 `{rules: ...}` 包装 |
| `GET /api/rule-groups` | 组名、开关与解析规则数 |
| `GET /api/rule-group?name=NAME` | 单组详情；名称需 URL 编码 |
| `POST /api/rule-groups` | `{ "name": "dev", "text": "...", "enabled": true }` |
| `POST /api/rule-group/update` | `{ "name": "dev", "text": "..." }` |
| `POST /api/rule-group/toggle` | `{ "name": "dev" }`；切换而非显式设置，重试前注意当前状态 |
| `DELETE /api/rule-group` | JSON `{ "name": "dev" }` |
| `GET /api/values` | 字符串键值对象 |
| `POST /api/values` | 整份 Values JSON 文本；会整体更新，单键编辑优先下列接口 |
| `POST /api/value` | `{ "name": "key", "value": "text" }` |
| `POST /api/value/rename` | `{ "name": "key", "to": "new-key" }` |
| `DELETE /api/value` | JSON `{ "name": "key" }` |
| `GET /api/export` | 导出本项目格式的配置包，可能包含敏感 Values |
| `POST /api/import` | 原样传入导出的配置包；带格式标记，不接受任意 JSON 冒充配置 |

调用方同时检查 HTTP 状态与响应 `ok/error`，不要因为成功解析出 JSON 就认为写入成功。导入、删除及覆盖规则前应保存自己的备份。

## 开关：HTTPS、全部规则、插件

控制台 Status 页的「Switches」和左侧栏的勾选框用的就是这三个接口。对应上游菜单里的 "Enable HTTPS"、"Disable all rules"、"Disable all plugins" 和每个插件前的勾。

```sh
# 先关掉全部规则看看问题还在不在，再打开
curl -s -X POST http://127.0.0.1:8899/api/switches -d '{"rules":false}'
curl -s -X POST http://127.0.0.1:8899/api/switches -d '{"rules":true}'
```

| 方法 / 路径 | 输入 / 返回 |
| --- | --- |
| `GET /api/switches` | 返回 `{ "ok": true, "intercept_https": true, "intercept_https_locked": false, "rules": true, "rules_locked": false, "plugins": true, "plugins_locked": false, "plugins_off": ["audit"] }` |
| `POST /api/switches` | 设 `intercept_https`、`rules`、`plugins` 里的任意几个（`true` 是开）；没写的不动。返回同上 |
| `POST /api/plugin/switch` | `{ "name": "audit", "on": false }` 单独关一个插件。返回同上 |

- **`rules: false`**：所有规则组一起不生效，请求原样转发；每个组自己的开关不变，打开后各回各的状态（一个个手动关，再打开时就不记得原来哪些是开的了）。请求头里带的规则（`-M multiEnv`）和插件返回的规则不受影响。
- **`plugins: false` 或单个插件关掉**：对规则来说，这个插件就当不存在——`plugin://名字` 什么也不做，它的钩子都不跑，**包括认证钩子 `onAuth`**，所以关掉一个认证插件就等于放开它守的门。插件自己的页面 `/plugin/名字/` 照常能打开。关掉之后各次请求的 `rules` 里还会列出 `plugin://名字`（规则确实命中了），只是没有插件去执行它。
- **`intercept_https`**：只影响之后新建的连接，已经开着的隧道不变。**只管这次运行**，重启后回到命令行的设置（默认开，`--no-intercept-https` 是关）。全部规则和插件开关会存进数据目录的 `switches.json`，重启后还在；规则全关时启动日志会有一行 WARN 提醒。
- **被模式锁住**：`-M multiEnv` / `-M notAllowedEnableHTTPS` 锁 HTTPS 开关，`-M notAllowedDisableRules` 锁规则总开关，`-M notAllowedDisablePlugins`（`-M admin` 也带它）锁插件开关。对应的 `*_locked` 是 `true`，想动它会得到 **409** 和原因；一次请求里只要有一项动不了，**整个请求都不生效**，不会只改一半。参数写错（比如 `"rules": "no"`）是 400，插件名不存在是 404。

`GET /api/status` 的 `plugins` 列表里每项多一个 `on`，就是上面算下来这个插件此刻开没开。

## 诊断与执行

| 方法 / 路径 | 输入 / 注意 |
| --- | --- |
| `POST /api/explain` | `{ "rules": "...", "url": "http://example.com/", "method": "GET" }`；可选 headers/body/response；只解释，不发请求 |
| `POST /api/composer` | `{ "method": "GET", "url": "http://example.com/", "headers": "", "body": "" }`；headers 是逐行原始头文本 |
| `POST /api/replay` | `{ "ids": [1, 2] }`；使用捕获数据，检查结果中的 body 状态 `whole/partial/empty/undecodable` |
| `POST /api/sessions/clear` | `{ "ids": [1, 2] }` 清除指定会话；`{}` 清空列表。**只清内存**，已落盘的历史重启后会回来 |
| `POST /api/sessions/purge` | 清空内存并删除全部会话文件；返回 `{ "ok": true, "files_deleted": N }` |
| `GET /api/ws/status?id=N` | 当前连接的扣留/放行状态 |
| `POST /api/ws/release` | `{ "id": 1, "dir": "send" }`；方向为 send/receive，按该方向批量放行 |
| `POST /api/ws/send` | `{ "id": 1, "dir": "send", "data": "hello" }`；确实向活动连接发送数据 |

## 页面日志

`log://id` 规则会往命中的页面里注入一段脚本，把页面的 `console.log`、未捕获的异常等发回代理（怎么用见 [RULES 的 log 一节](RULES.md#log--a-pages-console-in-this-one)）。这两个接口读和清这些日志。

| 方法 / 路径 | 含义 |
| --- | --- |
| `GET /api/logs` | 返回 `{ "ok": true, "logs": [...], "ids": [...], "last": N }`，旧的在前。可带 `?after=N`（只要序号大于 N 的）和 `?id=名字`（只要这一组的） |
| `POST /api/logs/clear` | `{}` 清空全部；`{ "id": "名字" }` 只清这一组。返回 `{ "ok": true, "cleared": N }` |

每条日志：`seq`（只增不减的序号）、`time_ms`（页面那边的时间）、`level`（`log`/`info`/`warn`/`error`/`debug`）、`id`（规则里写的组名）、`args`（每个参数一段文本：字符串原样，其它是 JSON）、`page`（哪个页面）、`client_ip`。

要持续跟着看：记下上次返回的 `last`，下次请求 `/api/logs?after=那个数`。`ids` 永远是当前所有有日志的组，不受 `id` 参数影响。

只存在内存里：最多 2000 条、总共 8 MiB，超了丢最旧的；重启就没了。

页面是往自己域名下的 `/.whix/log` 发 POST 的，代理拦下来直接回 `204`，不转给源站，也不产生会话。这个路径不是给人调的。

Composer/Replay 的调用会产生网络请求并经过代理规则；不能当作只读查询。Composer 接受任务的响应不是源站已经成功完成的证明：结果看它在列表里的那条会话，失败时那条会话的 `error` 说明原因。重复调用执行接口可能重复产生业务副作用，当前不要假定提供幂等键。

## 启动辅助与插件页面

`GET /` 和 `GET /index.html` 是控制台页面本身；`GET /plugin` 跳到 `/plugin/`。`GET /rootCA.crt`（另有 `/rootca.crt`）下载公钥证书；`GET /proxy.pac`（另有 `/pac`）读取 PAC。它们有免登录配置用途，不能返回 CA 私钥。`GET /api/qr?text=...&scale=...` 返回 SVG。`/plugin/<name>/...` 交给本项目插件处理，经过控制台入口的全部检查；转交给插件时去掉 `Authorization` 和 `Proxy-Authorization`，插件拿不到控制台的登录凭据。

这些端点的可用性还受 `headless` 等启动模式影响；不要靠一个首页状态推断所有读写能力均已开放。
