# 自有 HTTP API

基线：`702486d` / 2026-09-25，2026-09-28 按 S1 更新访问规则，2026-09-29 按 O1 补上失败会话、按 O2 补上检索、游标、body 与出错的约定。接口来自 `src/proxy/webui.rs`，现有调用与类型见 `ui-src/src/api.ts`。

这是 whistle-rs 的控制接口，**不是官方 `/cgi-bin/*` 或 Node Local Agent API 的兼容层**。以下是现有路由与主要参数，不代表已承诺独立稳定的版本化 API。本文和路由表由测试双向核对（`api_doc_tests`）：加了路由没写进来、或者这里写了路由表里没有，测试都会失败。

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

**列表行上有什么：** `id`、`time_ms`、`method`、`url`、`status`、`client_ip`、`target`、`duration_ms`、`log`、`rules`、`up`/`down`（body 字节数，不含头）、`has_req_body`/`has_res_body`/`has_frames`、`type`（响应的 `content-type`）。另外三个字段只在成立时出现：`error`（没完成，见下文）、`composer: true`（Composer 或 Replay 发的）、`open: true`（响应还在传，见下文）。

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

- HAR：没存全的 body 在 `content`（或请求的 `postData`）上多两个键：HAR 1.2 标准的 `comment`（如 `whistle-rs kept 10 of 100 bytes; the rest was not captured`），以及 `_truncated: true`。二进制和不是 UTF-8 的文本按 base64 导出（`encoding: "base64"`）。
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
| 规则 `enable://hide` | **不记** | 都没有：列表、详情、检索、HAR、嵌入 API 的 `on_session`、磁盘历史里都查不到。失败时的 502 仍带 `x-whistle-rs-error`，但不带会话号 |
| `--no-persist` | 记在内存里 | 接口和 HAR 里有，磁盘上不写历史（根证书和规则照常写） |
| 控制台检索框、Capture filter、按客户端筛选、只看标记 | 记 | 都有；只是控制台这一页不显示 |

Capture filter 在浏览器里、对新到的行生效，存在浏览器的 `localStorage`，代理完全不知道它。要让某类请求不进记录，用 `enable://hide`。上面两条"不记"都有端到端测试核实（`tests/hide_e2e.rs`）。

## 失败的请求

**每个经过代理的请求记一条会话，只记一次，失败的也记。** 没完成的请求多一个字段：

```json
{ "id": 12, "status": 502, "target": "127.0.0.1:9",
  "error": { "phase": "connect", "message": "connecting to 127.0.0.1:9: Connection refused (os error 61)" } }
```

`phase` 是请求停在哪一步，取值和各自的意思见 [Cookbook 的排查一节](COOKBOOK.zh-CN.md#规则不生效时)；`message` 是完整的错误链，和客户端收到的 502 正文是同一段。`error` 出现在 `/sessions.json` 的行上（没有失败的行不带这个字段）、`/session.json` 详情里、磁盘历史里；HAR 导出写成 Chrome 导出用的 `_error` 字符串，形如 `"connect: connecting to …"`。

本代理替失败的请求生成的响应是 `502`，带两个头：

| 头 | 值 |
| --- | --- |
| `x-whistle-rs-error` | 停在哪一步，同 `error.phase` |
| `x-whistle-rs-session` | 记成的会话号，拿它查 `/session.json?id=N` |

**判断一个 502 是谁回的，看有没有 `x-whistle-rs-error`**：没有就是源站自己回的，那条会话也没有 `error`。`x-server: whistle-rs` 分不出来 —— `statusCode://502` 这类规则回的也带它。规则主动丢弃的请求（`enable://abort` 等）不回任何响应，会话的 `phase` 是 `abort`、`status` 是 `0`。

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
| 不解密转发的隧道（`disable://intercept`、`--no-intercept-https`、非 HTTP 流量） | 一条 `CONNECT`，Policy（`target`）末尾带 `(tunnel)`，状态 `200`；连不上远端时按 `dns`/`connect`/`proxy` 记失败。隧道里的内容不读 |
| SOCKS5 入口 | 和 CONNECT 隧道走同一段代码，记法相同 |
| WebSocket | 握手一条；握手转发失败按普通请求记失败 |
| Composer / Replay | 请求从代理自己的端口发出，按普通请求记会话，失败的也记。接口接下任务就回答（Composer 回 `ok`，Replay 回 `replayed`），不等请求结果，也不返回会话号：去列表里找最新的那条 |

不记的只有三种：控制台自己的请求、`enable://hide` 命中的请求、客户端开了隧道一个字节没发就关掉的（什么都没请求）。

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

Composer/Replay 的调用会产生网络请求并经过代理规则；不能当作只读查询。Composer 接受任务的响应不是源站已经成功完成的证明：结果看它在列表里的那条会话，失败时那条会话的 `error` 说明原因。重复调用执行接口可能重复产生业务副作用，当前不要假定提供幂等键。

## 启动辅助与插件页面

`GET /` 和 `GET /index.html` 是控制台页面本身；`GET /plugin` 跳到 `/plugin/`。`GET /rootCA.crt`（另有 `/rootca.crt`）下载公钥证书；`GET /proxy.pac`（另有 `/pac`）读取 PAC。它们有免登录配置用途，不能返回 CA 私钥。`GET /api/qr?text=...&scale=...` 返回 SVG。`/plugin/<name>/...` 交给本项目插件处理，经过控制台入口的全部检查；转交给插件时去掉 `Authorization` 和 `Proxy-Authorization`，插件拿不到控制台的登录凭据。

这些端点的可用性还受 `headless` 等启动模式影响；不要靠一个首页状态推断所有读写能力均已开放。
