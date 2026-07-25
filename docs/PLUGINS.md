# 插件系统 / Plugins

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [架构](ARCHITECTURE.md) · [规则](RULES.md)

whistle-rs 的插件是**按请求生效的中间件**。一个插件可以：

- **注入规则** —— 动态产生 whistle 规则，合并进本次请求的规则集
- **直接应答** —— 短路上游，返回一个 mock 响应
- **改写请求头** —— 在规则算子之后生效，因此可以覆盖规则的结果
- **改写响应** —— 状态码、响应头、响应体

两种运行时实现同一套契约：

| 运行时 | 说明 |
|--------|------|
| **JS / TS 插件** | 独立进程，通过 HTTP + JSON 协议通信。用 [`sdk/`](../sdk/) 的零依赖 SDK 编写，协议细节完全被封装 |
| **Rust 插件** | 进程内原生插件，实现 `RustPlugin` trait，零 IPC。见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) |

两者都由 `plugin://<name>[/<param>]`（或 `pipe://…`）规则触发。

> 这是 whistle-rs **自研**的插件体系，不是原版 whistle 插件 API 的复刻。现成的
> `npm i whistle.xxx` 包无法直接运行 —— 原版 API 建立在对 Node `req`/`res` 对象的
> 装饰之上（约 2600 行加载器、位置式 CSV 头协议、单端口多钩子分发）。这里换成了一套
> 显式、有类型、语言无关的协议。

---

## 快速开始（JavaScript）

```js
// my-plugin.js
const { start } = require('whistle-rs/sdk/whistle-rs-plugin');

start({
  name: 'my-plugin',

  onRequest(ctx) {
    if (ctx.param === 'mock') {
      return ctx.respond({ statusCode: 200, body: { hello: 'world' } });
    }
    ctx.setHeader('x-traced', '1');
    ctx.setRules('* resHeaders://x-from-plugin=1');
  },

  onResponse(ctx) {
    ctx.setHeader('x-powered-by', 'whistle-rs');
  },
});
```

启动：

```bash
whistle-rs --node-plugin my-plugin=./my-plugin.js
```

规则里引用：

```
example.com        plugin://my-plugin
example.com/mock   plugin://my-plugin/mock
```

---

## TypeScript

SDK 自带 `.d.ts`，钩子、上下文、能力开关全部有类型。推荐 `satisfies Plugin` —— 既校验形状，又保留精确的类型：

```ts
import { start, type Plugin, type RequestCtx, type ResponseCtx } from 'whistle-rs/sdk/whistle-rs-plugin';

const plugin = {
  name: 'typed',
  requestBody: true,

  async onRequest(ctx: RequestCtx) {
    const payload = ctx.json<{ userId?: number }>();
    if (payload?.userId != null) ctx.setHeader('x-user-id', String(payload.userId));
  },

  async onResponse(ctx: ResponseCtx) {
    if (ctx.statusCode >= 500) ctx.setStatus(503).setBody({ error: 'upstream unavailable' });
  },
} satisfies Plugin;

start(plugin);
```

编译后运行，或用 TS 加载器直接运行：

```bash
npx tsc my-plugin.ts --outDir dist --module commonjs --target es2020
whistle-rs --node-plugin typed=dist/my-plugin.js
```

完整示例见 [`examples/plugins/typed.ts`](../examples/plugins/typed.ts)。

---

## 能力声明与性能（重要）

whistle-rs **默认不缓冲任何 body**：请求体和响应体都是流式穿过代理的，SSE、大文件下载、长轮询都不受影响。

只有当插件**显式声明**需要 body 时，代理才会缓冲：

```js
start({
  name: 'p',
  requestBody: true,    // ctx.body 才会有请求体
  responseBody: true,   // ctx.body 才会有响应体
  onRequest(ctx) { ctx.json(); },
  onResponse(ctx) { ctx.setBody(ctx.text().toUpperCase()); },
});
```

**声明你不读的 body，就是白白牺牲流式。** 两个开关都默认 `false`。

这一点是实测过的：同一个 SSE 源，挂上未声明 body 的插件时三个 chunk 按 0.40s 间隔到达；换成声明了 `responseBody` 的插件后，三个 chunk 在同一时刻到达（即被缓冲）。

> 想**替换**响应体则不需要 `responseBody` —— 替换不需要知道原内容。只有**读取**才需要声明。

---

## 上下文 API

### 通用（两个钩子都有）

| 成员 | 说明 |
|------|------|
| `ctx.id` | 关联 id，同一请求的 `onRequest` 与 `onResponse` 拿到的值相同 |
| `ctx.method` / `ctx.url` | 方法与完整 URL |
| `ctx.param` | `plugin://name/PARAM` 中 name 之后的部分，用于插件内路由 |
| `ctx.headers` | `[名, 值]` 数组，保持线序与大小写 |
| `ctx.body` | `Buffer`，**仅在声明了对应 body 开关时非 null** |
| `ctx.header(name)` | 大小写不敏感地取头 |
| `ctx.setHeader(n, v)` / `ctx.removeHeader(n)` | 改写头 |
| `ctx.text()` / `ctx.json<T>()` | body 解码；无 body 时分别返回 `''` / `undefined` |
| `ctx.parsedUrl` / `ctx.query(name)` | URL 解析与查询参数 |

### `onRequest` 专有

| 成员 | 说明 |
|------|------|
| `ctx.clientIp` | 客户端 IP（已知时） |
| `ctx.setRules(rules)` | 注入 whistle 规则；可多次调用，以换行拼接 |
| `ctx.respond({statusCode, headers, body})` | 直接应答，**不触达上游** |

### `onResponse` 专有

| 成员 | 说明 |
|------|------|
| `ctx.statusCode` | 上游返回的状态码 |
| `ctx.setStatus(code)` | 改写状态码 |
| `ctx.setBody(body)` | 替换响应体（字符串 / Buffer / 可 JSON 序列化的值） |

`setHeader` / `setRules` / `setStatus` / `setBody` 都返回 `ctx`，可以链式调用。

---

## 执行顺序

一次请求里发生的事，按顺序：

1. 规则解析 → 得到本次请求的规则集
2. **若有插件声明 `requestBody`** → 缓冲请求体
3. **`onRequest`**（按规则中出现的顺序遍历所有匹配插件）
   - `setRules` 注入的规则合并进规则集
   - `respond()` 一旦调用，立即返回，**后续插件不再执行**
4. 规则算子应用到请求上（`reqHeaders` 等）
5. 插件的 `setHeaders` / `removeHeaders` 应用 —— **在算子之后**，所以插件可以覆盖规则
6. 请求发往上游
7. 规则算子应用到响应上（`resHeaders` 等）
8. **`onResponse`**
   - 未声明 `responseBody` 的插件先跑，响应**保持流式**
   - 声明了的插件在 body 就绪后跑
9. 响应返回客户端

---

## 错误处理

SDK 做了隔离：钩子抛异常会被记录到插件自己的 stderr，并按「无操作」处理 —— **插件挂掉不会拖垮代理**。

代理侧同样是优雅降级：插件无响应、超时、返回非 200，都视为无操作，只在 `debug` 级别记一行日志。分发失败会重试两次（新拉起的插件进程可能还在绑定端口）。

---

## 内置 Rust 插件

无需任何配置即可使用，同时也是编写原生插件的参考（[`src/plugins/builtin.rs`](../src/plugins/builtin.rs)）：

| 规则 | 作用 |
|------|------|
| `plugin://echo` | 把请求本身以 JSON 返回，演示「直接应答」 |
| `plugin://tag[/<值>]` | 注入给请求和响应打标签的规则，演示「规则注入」 |
| `plugin://stamp[/<值>]` | 给响应加 `x-stamped-by` 头，演示**响应钩子**且不索取 body |

写一个 Rust 插件只需实现 `name` 与 `on_request`，其余方法都有默认实现 —— 以后给协议加钩子不会破坏已有插件。

---

## 线上协议

自己实现协议（非 JS/TS 语言）时的完整规格。SDK 用户不需要关心这一节。

插件是一个 HTTP 服务，实现以下端点。

### `GET /manifest` —— 能力声明

首次使用时拉取一次并缓存。

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "hooks": ["request", "response"],
  "requestBody": false,
  "responseBody": true
}
```

`hooks` 决定哪些端点会被调用；两个 body 开关决定是否缓冲并投递 body。

**不提供 `/manifest` 的插件按 v1 协议处理**：只有请求钩子，无 body，分发到 `POST /`。老插件因此无需改动即可继续工作。

### `POST /request`

```json
{ "id": 42, "method": "GET", "url": "http://…", "headers": [["k","v"]],
  "clientIp": "1.2.3.4", "param": "extra/after/name", "bodyBase64": "…" }
```

`bodyBase64` 仅在声明 `requestBody` 时出现。应答（各字段均可选）：

```json
{ "rules": "example.com resHeaders://x=1",
  "setHeaders": { "x-foo": "bar" },
  "removeHeaders": ["cookie"],
  "response": { "statusCode": 200, "headers": {}, "body": "…" } }
```

### `POST /response`

```json
{ "id": 42, "method": "GET", "url": "http://…", "statusCode": 200,
  "headers": [["k","v"]], "param": "…", "bodyBase64": "…" }
```

应答（各字段均可选，全空表示不改动）：

```json
{ "statusCode": 201, "setHeaders": {}, "removeHeaders": [], "body": "…" }
```

### 约定

- 二进制 body 用 `bodyBase64`，文本用 `body`
- `headers` 请求方向是 `[名,值]` 数组（保序、保大小写）；应答方向对象和数组都接受
- `removeHeaders` 接受数组，也接受单个字符串
- 应答 `204` / `304` 等价于「无操作」
- 解析是宽松的：无法识别的字段忽略，畸形字段跳过而非报错
- `body` 字段**存在但为空字符串**表示「清空 body」，与**完全不带该字段**（不改动）是两种语义

---

## 注册插件

```bash
# 由 whistle-rs 拉起 Node 进程（自动分配端口）
whistle-rs --node-plugin name=./path/to/plugin.js

# 指向一个已在运行的插件服务
whistle-rs --plugin name=127.0.0.1:9000
```

`--node-plugin` 会以环境变量 `WHISTLE_RS_PLUGIN_PORT` 和 `WHISTLE_RS_PLUGIN_NAME` 启动 `node <path>`，并等待端口就绪（最多 5 秒）后才开始服务。

---

## 尚未支持

诚实记录当前边界：

- **流式 body 钩子**（原版的 `reqRead`/`resRead`）—— 现在的 body 投递是「缓冲后整体传递」。真正的流式需要基于 CONNECT 的插件传输、长度前缀分帧（原版 `lib/util/transproto.js` 的 `'\n' + 长度 + '\n' + 负载`，EOF 为 `'\n0\n'`）、单字节握手确认，以及边收边转的 body 路径。当前的单次 JSON POST 传输无法表达这一契约。
- **`pipe://`** —— 目前是 `plugin://` 的别名，并非真正的流式管道（同上）。
- **WebSocket 帧级钩子** —— 帧已被抓取并展示，但插件还不能拦改。
- **插件自带 UI / 统计页**（原版的 `uiServer` / `statsServer`）。
- **`sniCallback`** —— 需要在 TLS SNI 阶段介入选证书，早于按请求的规则解析，当前 MITM 架构不可达。
- **npm `whistle.*` 包兼容** —— 明确的非目标，见本文开头。
