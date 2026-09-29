# 自有 HTTP API

基线：`702486d` / 2026-09-25，2026-09-28 按 S1 更新访问规则。接口来自 `src/proxy/webui.rs`，现有调用与类型见 `ui-src/src/api.ts`。

这是 whistle-rs 的控制接口，**不是官方 `/cgi-bin/*` 或 Node Local Agent API 的兼容层**。以下是现有路由与主要参数，不代表已承诺独立稳定的版本化 API；错误模型、分页和诊断补强见 [ROADMAP.md](ROADMAP.md) 的 O1/O2。

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

Composer/Replay 的调用会产生网络请求并经过代理规则；不能当作只读查询。Composer 接受任务的响应不是源站已经成功完成的证明，应结合流量结果和日志判断。重复调用执行接口可能重复产生业务副作用，当前不要假定提供幂等键。

## 启动辅助与插件页面

`GET /rootCA.crt`（另有 `/rootca.crt`）下载公钥证书；`GET /proxy.pac`（另有 `/pac`）读取 PAC。它们有免登录配置用途，不能返回 CA 私钥。`GET /api/qr?text=...&scale=...` 返回 SVG。`/plugin/<name>/...` 交给本项目插件处理，经过控制台入口的全部检查；转交给插件时去掉 `Authorization` 和 `Proxy-Authorization`，插件拿不到控制台的登录凭据。

这些端点的可用性还受 `headless` 等启动模式影响；不要靠一个首页状态推断所有读写能力均已开放。
