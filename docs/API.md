# 自有 HTTP API

基线：`702486d` / 2026-09-25，2026-09-28 按 S1 更新访问规则，2026-09-29 按 O1 补上失败会话。接口来自 `src/proxy/webui.rs`，现有调用与类型见 `ui-src/src/api.ts`。

这是 whistle-rs 的控制接口，**不是官方 `/cgi-bin/*` 或 Node Local Agent API 的兼容层**。以下是现有路由与主要参数，不代表已承诺独立稳定的版本化 API；分页、检索字段等补强见 [ROADMAP.md](ROADMAP.md) 的 O2。

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

## 读取流量

| 方法 / 路径 | 含义 |
| --- | --- |
| `GET /api/status` | 状态、配置摘要与插件信息；不同调用来源可能得到受限字段，不应假定总有本地路径等字段 |
| `GET /sessions.json` | 会话摘要列表，不带完整请求头或 body |
| `GET /session.json?id=N` | 单个会话详情；不存在时调用方应处理空结果 |
| `GET /body.bin?id=N&side=req` / `side=res` | 已捕获体的字节；按附件返回，截断时文件名可带 `partial-` |
| `GET /frames.json?id=N` | 对应会话捕获的帧 |
| `GET /sessions.har` / `?ids=1,2` | HAR 导出；来源仍是有界捕获，不等于完整原始报文归档 |

Body 详情包含 `len`、`truncated`、`text`、`binary`。`len` 不是可下载预览的保证长度；二进制内容取 `/body.bin`，不要把 `text` 中的标记当原始字节。

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

`GET /rootCA.crt`（另有 `/rootca.crt`）下载公钥证书；`GET /proxy.pac`（另有 `/pac`）读取 PAC。它们有免登录配置用途，不能返回 CA 私钥。`GET /api/qr?text=...&scale=...` 返回 SVG。`/plugin/<name>/...` 交给本项目插件处理，经过控制台入口的全部检查；转交给插件时去掉 `Authorization` 和 `Proxy-Authorization`，插件拿不到控制台的登录凭据。

这些端点的可用性还受 `headless` 等启动模式影响；不要靠一个首页状态推断所有读写能力均已开放。
