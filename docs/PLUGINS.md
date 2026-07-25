# 插件系统 / Plugins

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [架构](ARCHITECTURE.md) · [规则](RULES.md)

whistle-rs 的插件是**按请求生效的中间件**。一个插件可以：

- **注入规则** —— 动态产生 whistle 规则，合并进本次请求的规则集
- **直接应答** —— 短路上游，返回一个 mock 响应
- **改写请求头** —— 在规则算子之后生效，因此可以覆盖规则的结果
- **改写响应** —— 状态码、响应头、响应体
- **流式改写 body** —— 边收边改，全程不落内存（`pipe://`）

两种运行时实现同一套契约：

| 运行时 | 说明 |
|--------|------|
| **JS / TS 插件** | 独立进程，通过 HTTP 协议通信。用 [`sdk/`](../sdk/) 的零依赖 SDK 编写，协议细节完全被封装 |
| **Rust 插件** | 进程内原生插件，实现 `RustPlugin` trait，零 IPC。见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) |

钩子分两族，**由规则的协议名决定跑哪一族**：

| 规则 | 钩子 | body |
|------|------|------|
| `plugin://<name>[/<param>]` | `onRequest` / `onResponse` | 整体缓冲，需显式声明 |
| `pipe://<name>[(<value>)]` | `pipeRequest` / `pipeResponse` | **流式，永不缓冲** |

`pipe://` 指向一个没有声明任何流式钩子的插件时，退化为 `plugin://` —— 与流式钩子出现之前的语义一致，老规则不会失效。

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

**要读、又不想缓冲，就用下面的流式钩子。**

---

## 流式钩子 / `pipe://`

`onResponse` 想看 body 就得等它收完。流式钩子不用等：body 的每一片到达时就交给插件，插件吐出来的字节直接继续往下走，**代理和插件两端都不缓冲**。

```js
const { start, transform } = require('whistle-rs/sdk/whistle-rs-plugin');

start({
  name: 'events',

  // req 是 body 字节的 Readable，res 是变换后字节的 Writable。
  // 返回一个 Transform，SDK 负责 req → transform → res 的接线。
  pipeResponse(req, res, ctx) {
    return transform((chunk) => chunk.toString().toUpperCase());
  },
});
```

```
127.0.0.1:18081/sse   pipe://events
127.0.0.1:18081/sse   pipe://events(SHOUT)     # ctx.pipeValue === 'SHOUT'
```

完整示例见 [`examples/plugins/stream-events.js`](../examples/plugins/stream-events.js)（逐事件改写 SSE，同时演示请求方向）。

### 上下文

流式钩子拿到的 `ctx` 就是缓冲钩子那套元信息，**减去 body** —— body 就是那个流本身：

| 成员 | 说明 |
|------|------|
| `ctx.id` | 关联 id，与本请求的缓冲钩子一致 |
| `ctx.method` / `ctx.url` / `ctx.clientIp` | 同缓冲钩子 |
| `ctx.param` | 插件名之后的 `/…` 部分 |
| `ctx.pipeValue` | `pipe://name(value)` 里的 `value` |
| `ctx.headers` / `ctx.header(n)` | 请求方向是请求头，响应方向是响应头 |
| `ctx.statusCode` | 上游状态码（**仅** `pipeResponse`） |
| `ctx.direction` | `'request'` / `'response'`，方便两个方向共用一个实现 |

### 三条纪律

1. **别攒 body。** 攒起来就等于把流式钩子写成了缓冲钩子，只是绕了远路。
2. **二进制别当文本。** `chunk.toString('utf8')` 再 `Buffer.from` 会把每个非法序列替换成 U+FFFD —— 实测 8MB 随机数据会被撑成 15MB。文本变换请先看 `content-type`，不匹配就 `req.pipe(res)` 直通。
3. **要么返回一个 Transform，要么自己接线。** 两样都没做，body 就吊在那儿了。

### 出错了会怎样

**在插件应答 `200` 之前，代理一个 body 字节都不会读。** 所以插件没起来、连不上、超时、或者返回了非 200 —— 代价只有一次连接尝试，body 原封不动继续走，日志里留一行 `WARN`：

```
WARN pipeResponse events: Connection refused (os error 61); body forwarded unchanged
```

握手成功之后就交接了：此后插件挂掉会让 body 出错，和上游服务器中途挂掉是同一种失败。这是流式变换绕不开的代价 —— 已经发出去的字节收不回来。

### Rust 插件

`RustPlugin` 的 `pipe` 方法默认是恒等变换，覆盖它即可：

```rust
fn pipe(&self, _dir: Dir, _meta: &PipeMeta, body: DynBody) -> DynBody {
    body.map_frame(|f| f.map_data(|d| Bytes::from(d.to_ascii_uppercase()))).boxed()
}
```

内置的 `pipe://upper` 就是这么实现的，见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs)。

### 实测数据

同一个 SSE 源（5 个事件，间隔 400ms），三种挂法，记录每个 chunk 到达客户端的时刻：

```
$ node timestamped-get.js http://127.0.0.1:18081/plain 127.0.0.1:18913     # 不挂插件
+  408ms  HEAD 200
+  409ms  14B "data: tick 1\n\n"
+  808ms  14B "data: tick 2\n\n"
+ 1208ms  14B "data: tick 3\n\n"
+ 1611ms  14B "data: tick 4\n\n"
+ 2012ms  14B "data: tick 5\n\n"

$ node timestamped-get.js http://127.0.0.1:18081/sse 127.0.0.1:18913       # pipe://events(SHOUT)
+  411ms  HEAD 200
+  413ms  25B "data: [SHOUT #1] tick 1\n\n"
+  811ms  25B "data: [SHOUT #2] tick 2\n\n"
+ 1213ms  25B "data: [SHOUT #3] tick 3\n\n"
+ 1615ms  25B "data: [SHOUT #4] tick 4\n\n"
+ 2017ms  25B "data: [SHOUT #5] tick 5\n\n"

$ node timestamped-get.js http://127.0.0.1:18081/buffered 127.0.0.1:18913  # plugin:// + responseBody
+ 2019ms  HEAD 200
+ 2020ms  125B "data: [BUFFERED] tick 1\n\ndata: ... tick 5\n\n"
```

流式钩子逐事件到达、逐事件变换；缓冲钩子在 2019ms 一次性吐出全部 125 字节。**不挂插件的那条基线一字未变** —— 这是硬要求。

内存也验过：200MB 的 body 经过 `pipeRequest` + `pipeResponse` 往返，sha256 完全一致，代理进程 RSS 峰值 22.9MB（基线 12.4MB）。

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
6. **`pipeRequest`** 接入请求体（多个 `pipe://` 按规则顺序串联，后一个吃前一个的输出）
7. 请求发往上游
8. 规则算子应用到响应上（`resHeaders` 等）
9. **`onResponse`**
   - 未声明 `responseBody` 的插件先跑，响应**保持流式**
   - 声明了的插件在 body 就绪后跑
10. **`pipeResponse`** 接入响应体 —— 在「是否缓冲」的判断**之前**，所以接了管道的响应仍然走流式分支
11. 响应返回客户端

一旦有 `pipe://` 插件真的接管了 body，该方向的 `content-length` 会被去掉（变换可以改变长度），后续按 chunked 传输。

---

## 错误处理

SDK 做了隔离：钩子抛异常会被记录到插件自己的 stderr，并按「无操作」处理 —— **插件挂掉不会拖垮代理**。

代理侧同样是优雅降级：插件无响应、超时、返回非 200，都视为无操作，只在 `debug` 级别记一行日志。分发失败会重试两次（新拉起的插件进程可能还在绑定端口）。

流式钩子的降级规则不同，见 [流式钩子 · 出错了会怎样](#出错了会怎样)：**握手成功之前**任何失败都零代价（body 原样放行，记一行 `WARN`）；**握手成功之后**插件挂掉会让 body 出错。

---

## 内置 Rust 插件

无需任何配置即可使用，同时也是编写原生插件的参考（[`src/plugins/builtin.rs`](../src/plugins/builtin.rs)）：

| 规则 | 作用 |
|------|------|
| `plugin://echo` | 把请求本身以 JSON 返回，演示「直接应答」 |
| `plugin://tag[/<值>]` | 注入给请求和响应打标签的规则，演示「规则注入」 |
| `plugin://stamp[/<值>]` | 给响应加 `x-stamped-by` 头，演示**响应钩子**且不索取 body |
| `pipe://upper` | 把 body 逐帧转大写，演示**流式钩子**（请求、响应两个方向都接） |

写一个 Rust 插件只需实现 `name` 与 `on_request`，其余方法都有默认实现 —— 以后给协议加钩子不会破坏已有插件。`pipe` 的默认实现是恒等变换。

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
  "hooks": ["request", "response", "pipeRequest", "pipeResponse"],
  "requestBody": false,
  "responseBody": true
}
```

`hooks` 决定哪些端点会被调用；两个 body 开关决定是否缓冲并投递 body（只对 `request` / `response` 有意义 —— 流式钩子从不缓冲，也就无需声明）。

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

### `POST /pipe/request`、`POST /pipe/response` —— 流式钩子

**请求体就是被代理的 body 本身，应答体就是替换它的内容**，两个方向都是 chunked，两端都不缓冲。元信息放在一个头里，base64 编码的 JSON：

```
POST /pipe/response HTTP/1.1
x-whistle-rs-pipe: eyJpZCI6NDIsIm1ldGhvZCI6IkdFVCIsInVybCI6Imh0dHA6Ly8uLi4ifQ==
transfer-encoding: chunked

<body 字节，边到边发>
```

解码后：

```json
{ "id": 42, "method": "GET", "url": "http://…", "param": "…",
  "pipeValue": "SHOUT", "clientIp": "1.2.3.4",
  "headers": [["k","v"]], "statusCode": 200 }
```

`pipeValue` / `clientIp` / `statusCode` 缺省时不出现（`statusCode` 仅响应方向）。

应答：

- **`200`** —— 接管。应答体流式回传，替换原 body。
- **其它任何状态码 / 连不上 / 5 秒内不应答** —— 代理放弃这次变换，原 body 原样放行。

**握手先于字节**：代理在收到应答头之前不会读 body 的任何一个字节，所以上面那些失败都是零代价的。因此插件**必须在进入处理函数时立刻发出 `200` 头**（SDK 已经这么做了，包括 `flushHeaders()`），不要等第一个 chunk 到了再发。

### 为什么是 HTTP，而不是原版的 CONNECT + transproto

原版 whistle 建立管道的方式是：向插件端口发 `CONNECT`，等 `200 Connection Established`，再写一个 `'1'` 字节做确认，然后用自定义的长度前缀分帧收发 body（`'\n' + 长度 + '\n' + 负载`，EOF 是 `'\n0\n'`，见 `lib/util/transproto.js`）。

whistle-rs **有意不复刻这一套**：

- 本项目的插件协议本来就是自研的（JSON over HTTP + `/manifest` 能力声明），插件是照着**我们的** SDK 写的，与原版的线上兼容换不来任何东西；
- HTTP/1.1 的 chunked 编码**就是** transproto 重新发明的那种长度前缀分帧，而且 hyper 和 Node 两端都已经实现好了 —— 不用自己写分帧层，就没有自己写错分帧层的机会；
- 元信息直接当 header 走，不用挤进字节流；
- 插件作者拿到的是 Node 原生的 `(req, res)` —— 一个可读流加一个可写流。这恰好就是原版 `reqRead`/`resRead` 钩子最终拿到的形状，只是不用那 2000 多行加载器。

**代价说清楚**：为原版 `pipe://` 写的插件在这里跑不了，反之亦然。这与本文开头「不复刻原版插件 API」的取舍是同一个。

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

### 流式钩子的边界

- **上游插件不兼容** —— 为原版 `pipe://` 写的插件（CONNECT + transproto）在这里跑不了。理由见上一节，这是取舍不是遗漏。
- **握手之后不再有兜底** —— 插件应答 `200` 之前失败是零代价的；应答之后失败会让 body 出错（客户端看到截断的响应）。字节已经交出去了就收不回来，这是流式变换的固有代价，不是可以修的 bug。
- **不覆盖 WebSocket / 协议升级** —— `pipe://` 只作用于普通 HTTP body。升级请求在流式钩子接线之前就走掉了，WS 帧另有一套抓取路径。
- **不覆盖短路响应** —— `file://`、`tpl://`、`redirect://` 这类不走上游的响应，以及插件 `respond()` 产生的响应，都在流式钩子之前返回，不经过管道。
- **插件端点必须是明文 HTTP** —— 插件是本机进程；`https://` 的插件地址会被拒绝并降级（日志里有 `WARN`），而不是悄悄走错路。
- **不搬运 trailer** —— 管道中途的 trailer 帧会被丢弃，最终的分帧由插件的输出决定。
- **每次调用一条新连接** —— 没有连接池。本机连接的开销可以忽略，但这是实现现状而不是承诺。
- **`(value)` 的语法只对 `pipe://` 生效** —— `plugin://` 的取值解析与之前逐字节一致，不受影响。

### 其它

- **WebSocket 帧级钩子** —— 帧已被抓取并展示，但插件还不能拦改。
- **插件自带 UI / 统计页**（原版的 `uiServer` / `statsServer`）。
- **`sniCallback`** —— 需要在 TLS SNI 阶段介入选证书，早于按请求的规则解析，当前 MITM 架构不可达。
- **npm `whistle.*` 包兼容** —— 明确的非目标，见本文开头。
