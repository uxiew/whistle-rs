# 插件系统 / Plugins

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [架构](ARCHITECTURE.md) · [规则](RULES.md)

whistle-rs 的插件是**按请求生效的中间件**。一个插件可以：

- **注入规则** —— 动态产生 whistle 规则，合并进本次请求的规则集
- **直接应答** —— 短路上游，返回一个 mock 响应
- **改写请求头** —— 在规则算子之后生效，因此可以覆盖规则的结果
- **改写响应** —— 状态码、响应头、响应体
- **流式改写 body** —— 边收边改，全程不落内存（`pipe://`）
- **拦改 WebSocket 帧** —— 逐帧、双向，可改写也可丢弃

两种运行时实现同一套契约：

| 运行时 | 说明 |
|--------|------|
| **JS / TS 插件** | 独立进程，通过 HTTP 协议通信。用 [`sdk/`](../sdk/) 的零依赖 SDK 编写，协议细节完全被封装 |
| **Rust 插件** | 进程内原生插件，实现 `RustPlugin` trait，零 IPC。见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) |

钩子分三族，**由规则的协议名决定跑哪一族**：

| 规则 | 钩子 | body |
|------|------|------|
| `plugin://<name>[/<param>]` | `onRequest` / `onResponse` | 整体缓冲，需显式声明 |
| `pipe://<name>[(<value>)]` | `pipeRequest` / `pipeResponse` | **流式，永不缓冲** |
| 两者皆可，命中 WebSocket 时 | `onWsFrame` | 逐帧，一次一帧 |

`pipe://` 指向一个没有声明任何流式钩子的插件时，退化为 `plugin://` —— 与流式钩子出现之前的语义一致，老规则不会失效。

WebSocket 帧钩子**两种协议名都能触发**：一个 WebSocket 没有「缓冲 / 流式」之分可供协议名表达，
让其中一个悄悄不生效只会变成陷阱。协议名依然决定**握手请求**（它就是个普通 HTTP 请求）跑哪一族。

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

## WebSocket 帧钩子 / `onWsFrame`

WebSocket 的单位既不是「一个请求」也不是「一条字节流」，而是**一帧**，所以它有自己的钩子：

```js
const { start } = require('whistle-rs/sdk/whistle-rs-plugin');

start({
  name: 'wschat',

  onWsFrame(frame, ctx) {
    if (!frame.isText) return;                      // 二进制/分片原样放行
    if (frame.text.includes('SECRET')) return null; // 丢弃这一帧
    return `${frame.text} [${ctx.direction}]`;      // 改写
  },
});
```

```
127.0.0.1:19010   pipe://wschat
127.0.0.1:19010   pipe://wschat(demo)     # ctx.pipeValue === 'demo'
127.0.0.1:19010   plugin://wschat/demo    # ctx.param === 'demo'
```

完整示例见 [`examples/plugins/ws-frames.js`](../examples/plugins/ws-frames.js)；
Rust 版本见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) 里的 `pipe://ws-upper`。

### 钩子能做什么、不能做什么

| 返回值 | 结果 |
|--------|------|
| 不返回 / `undefined` / `true` / `frame` 本身 | 原样放行（也支持直接改 `frame.payload`） |
| 字符串 | 按 UTF-8 编码后替换负载 |
| `Buffer` | 逐字节替换负载 |
| 其它对象 | JSON 序列化后替换负载 |
| `null` / `false` | **丢弃这一帧** |

**不能改的是帧的类型和分片结构**：返回值里的 opcode 与 FIN 位会被代理忽略。让插件把一个
continuation 改成 text，或者把一条分片消息拆散，是稳定的自毁方式，而真正需要它的场景并不存在。

### 帧对象

| 成员 | 说明 |
|------|------|
| `frame.payload` | **`Buffer`**，永远是字节；可直接赋值改写 |
| `frame.opcode` | `0x0` continuation / `0x1` text / `0x2` binary |
| `frame.fin` | 是否是所属消息的最后一帧 |
| `frame.direction` | `'send'`（客户端→服务端）/ `'receive'`（服务端→客户端） |
| `frame.isText` / `isBinary` | **一整条**消息（`fin` 为真且 opcode 对应）时才为真 |
| `frame.isFragment` | 分片：`!fin` 或 opcode 为 continuation |
| `frame.text` | 按 UTF-8 解码 —— **显式索取**，见下 |
| `frame.setText(s)` | 用 UTF-8 编码替换负载 |

`ctx` 是**会话级**的（每个方向一个实例，活到会话结束，可以往上挂状态）：
`ctx.id`（就是 `/frames.json` 里的会话 id）、`ctx.url` / `ctx.method`、`ctx.param`、
`ctx.pipeValue`、`ctx.clientIp`、`ctx.headers`（握手请求头）、`ctx.direction`、`ctx.header(n)`、`ctx.query(n)`。

### 二进制纪律（同一条老规矩）

`frame.payload` 是 `Buffer` 而且必须一直是。`Buffer.from(buf.toString())` 会把每个非法 UTF-8
序列换成 U+FFFD —— 8MB 的二进制帧回来会变成 15MB 的乱码。所以：

- 帧交到手里就是 `Buffer`，**没有**自动解码；`frame.text` 要自己开口要；
- `isText` 只在**完整**文本消息上为真。分片的第一帧 opcode 也是 `0x1`，但一个多字节字符可能
  正好被切在两片之间 —— 要处理分片，就跨 `isFragment` 帧自己攒。

### 哪些帧不会交给插件

- **控制帧（close / ping / pong）永不交付**。它们是协议机件不是应用数据：丢一个 ping 会打断
  保活，改一个 close 会打断关闭握手，而没有哪个正当的钩子需要这么做。它们照常被抓取展示。
- 保留 opcode（`0x3`–`0x7`、`0xb`–`0xf`）同样不交付。

**分片是交付的**（continuation 也交），带着 `fin` 和 opcode。对分片调用「丢弃」时，代理不会
真的把这一帧删掉，而是**把它变成空负载放行** —— 删掉一片会让消息永远收不完或让后续 continuation
变成孤儿，那是协议错误，不是「少了一条消息」。字节没了，结构还在。

### 传输：一条长连接，不是一帧一次 HTTP

钩子必须先给出裁决，帧才能转发（它可以改写、可以丢弃），所以**每帧一次本机往返是任何正确
设计的下限**。能选的只是往返之外还要花什么。

一帧一次 `POST` 要额外付 TCP 连接 + 请求头 + 响应头，而 WebSocket 恰恰是「很多条小消息」。
所以每个会话**每个方向开一条长连接**（`POST /ws/frames`），活到隧道结束：每帧只多六字节记录头，
顺序天然由流保证，插件也能在连接上挂会话级状态。

代价说清楚（实测，debug 构建，Node 插件在同机 loopback，500 次串行 echo 往返 —— 每次往返
经过两帧钩子）：

```
不挂插件            mean 0.089ms  p50 0.084ms  p95 0.124ms
插件在跑但规则没命中  mean 0.091ms  p50 0.084ms  p95 0.131ms
挂上帧钩子           mean 0.164ms  p50 0.129ms  p95 0.276ms
```

即**每帧约 20µs（p50）/ 37µs（mean）/ 75µs（p95）**。帧不做流水线：第 n+1 帧要等第 n 帧的
裁决回来才交出去 —— 一个会让 WebSocket 乱序的钩子比一个慢的钩子糟糕得多。

### 出错了会怎样

和流式钩子不同，帧钩子**任何时候都能被放弃**：帧流始终在代理手里。插件没起来、拒绝会话、
中途挂掉、5 秒不给裁决 —— 结果都一样：这个钩子被摘掉，之后的帧原样放行，日志里留一行 `WARN`。
**插件永远不会弄断一条 WebSocket。**

被摘掉时正在飞的那一帧会原样放行；已经交出去还没回裁决的帧则可能丢失。超时后不重试也不复用
连接：迟到的裁决会被当成下一帧的裁决，一个错位的钩子比没有钩子更糟。

### 和 `frameScript` 的关系

两个都命中时，**`frameScript` 先跑，插件后跑**：`frameScript` 是规则算子，而这个代理里规则
算子一律先于插件。于是

- 插件看到的是脚本改写后的负载；
- 插件最后返回的字节既是上线的字节，也是 Network 面板记录的字节；
- 被丢弃的帧不会出现在 `/frames.json` —— 对端根本没见过它。

多个插件命中时按规则顺序串联，后一个吃前一个的输出；第一个说「丢弃」的插件终止这条链
（与第一个 `respond()` 终止请求钩子链同理）。

### Rust 插件

`RustPlugin::on_ws_frame` 默认是恒等，覆盖它即可：

```rust
fn on_ws_frame(&self, _meta: &FrameMeta, frame: &HookFrame<'_>) -> Verdict {
    if frame.opcode != 0x1 || !frame.fin {
        return Verdict::Keep;
    }
    Verdict::Replace(Bytes::from(frame.payload.to_ascii_uppercase()))
}
```

内置的 `pipe://ws-upper` 就是这么实现的。注意它同样不解码成 `String` —— `to_ascii_uppercase`
在字节上工作，多字节 UTF-8 因此原样穿过。

### 实测

一条真的 WebSocket（握手 + 掩码 + 分片都是真的）穿过代理，插件双向改写：

```
$ ./run.sh hooked
CLIENT  handshake: HTTP/1.1 101 Switching Protocols
CLIENT  send text "hello"
CLIENT  got  text "echo:hello [demo → server] [demo → client]"
CLIENT  send text "this is SECRET" (the plugin drops this one)
CLIENT  send text "after"
CLIENT  got  text "echo:after [demo → server] [demo → client]"
CLIENT  SECRET reached the client: false
CLIENT  send binary 8388608B sha=7d212b9c884f5c77
CLIENT  got  binary 8388608B sha=7d212b9c884f5c77
CLIENT  binary round-trip: IDENTICAL
--- 源站看到的 ---
SERVER  saw text   fin=true  "hello [demo → server]"
SERVER  saw text   fin=true  "after [demo → server]"
SERVER  saw binary fin=true  8388608B sha=7d212b9c884f5c77
SERVER  saw text   fin=false "frag"          <- 分片原样放行
SERVER  saw cont   fin=true  "ment"
```

`SECRET` 那一帧既没到源站也没回客户端；8MB 二进制两个方向都**长度和 sha 分毫不差**（不是
15MB 的乱码）；分片按示例插件的选择原样穿过。不挂插件跑同一个脚本，输出与不经过代理时一致。

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

**WebSocket 升级请求走的是另一条路**：它在第 6 步之前就分岔了（升级没有 body，也就没有管道可接）。
顺序变成：规则解析 → `onRequest`（握手请求也是普通请求，插件可以改握手头、注入规则、甚至直接
应答挡掉升级）→ 转发握手 → 上游回 `101` → **隧道建立，帧钩子这时才去连插件**（因此插件的连接
不会拖慢握手）→ 每帧 `frameScript` → 每帧 `onWsFrame`。上游没回 `101` 就不会有任何插件被连接。

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
| `pipe://ws-upper` | 把 WebSocket 文本帧转大写，演示**帧钩子**（双向；二进制与分片不碰） |

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
  "hooks": ["request", "response", "pipeRequest", "pipeResponse", "wsFrame"],
  "requestBody": false,
  "responseBody": true
}
```

`hooks` 决定哪些端点会被调用；两个 body 开关决定是否缓冲并投递 body（只对 `request` / `response` 有意义 —— 流式钩子和帧钩子从不缓冲，也就无需声明）。

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

### `POST /ws/frames` —— WebSocket 帧钩子

每个被隧道化的 WebSocket 会话、**每个方向**一条长连接，活到隧道结束。元信息同样是一个头，
base64 编码的 JSON：

```
POST /ws/frames HTTP/1.1
x-whistle-rs-ws: eyJpZCI6NDIsImRpcmVjdGlvbiI6InNlbmQiLCJ1cmwiOiJ3czovLy4uLiJ9
transfer-encoding: chunked
```

解码后：

```json
{ "id": 42, "method": "GET", "url": "ws://…/chat", "param": "…",
  "direction": "send", "pipeValue": "demo", "clientIp": "1.2.3.4",
  "headers": [["origin","http://a"]] }
```

`direction` 是 `send`（客户端→服务端）或 `receive`。`pipeValue` / `clientIp` 缺省时不出现。

应答 `200` 表示接管，其它任何状态码 / 连不上 / 5 秒不应答 —— 这个方向就不挂钩子，帧原样穿过。

此后请求体与应答体各是一串**记录**，一帧一条，一进一出、严格有序：

```
flags:u8  opcode:u8  length:u32be  payload:length
flags: 0x01 FIN，0x02 DROP（仅插件→代理）
```

代理**忽略**回传记录里的 opcode 与 FIN 位（见上文「不能改的是帧的类型和分片结构」），
只取 DROP 与负载。

**为什么这里要自己分帧**，而 `pipe://` 一节刚说过不该重新发明分帧？因为两者的单位不同：
一条 body 是**一**串字节配**一**份元信息，chunked 就够了；而帧钩子要搬运**很多条消息**，
每条都有自己的边界、opcode 和 FIN 位，而 chunk 边界不是消息边界（HTTP、hyper、Node 都不
承诺一次写入对应一个 `'data'` 事件）。六字节、长度前缀、二进制 —— 负载逐字节穿过；换成
JSON/base64 信封则每个二进制帧要涨三分之一，还得走一遍它最不该走的文本往返。

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
- **不覆盖 WebSocket / 协议升级** —— `pipe://` 只作用于普通 HTTP body。升级请求在流式钩子接线之前就走掉了；WebSocket 走的是 [帧钩子](#websocket-帧钩子--onwsframe)。
- **不覆盖短路响应** —— `file://`、`tpl://`、`redirect://` 这类不走上游的响应，以及插件 `respond()` 产生的响应，都在流式钩子之前返回，不经过管道。
- **插件端点必须是明文 HTTP** —— 插件是本机进程；`https://` 的插件地址会被拒绝并降级（日志里有 `WARN`），而不是悄悄走错路。
- **不搬运 trailer** —— 管道中途的 trailer 帧会被丢弃，最终的分帧由插件的输出决定。
- **每次调用一条新连接** —— 没有连接池。本机连接的开销可以忽略，但这是实现现状而不是承诺。
- **`(value)` 的语法只对 `pipe://` 生效** —— `plugin://` 的取值解析与之前逐字节一致，不受影响。

### 帧钩子的边界

- **控制帧不交付** —— close / ping / pong 与保留 opcode 只被抓取，不交给插件。理由见
  [哪些帧不会交给插件](#哪些帧不会交给插件)，这是取舍不是遗漏。
- **不能改帧类型与分片结构** —— 只能改负载、丢整条消息；丢一个分片会退化成「空负载放行」。
- **不流水线** —— 一个方向上同时最多一帧在插件手里。吞吐因此受限于插件的往返延迟，
  这是为了保住顺序而付的钱。
- **不能凭空插入帧，也不能往另一个方向发帧** —— 钩子是「一帧进、一帧出」，不是一个 socket。
- **不覆盖 `wss://` 的未解密流量** —— 只有被 MITM 解密的 WebSocket 才有帧可拦；纯隧道过去的
  连接对代理是一团密文。
- **原版插件不兼容** —— 原版的 `wsReqRead` / `wsReqWrite` / `wsResRead` / `wsResWrite`
  建立在 CONNECT + 装饰过的 socket 上，与这里的协议无关。语义搬了，线上格式没搬。

### 其它

- **插件自带 UI / 统计页**（原版的 `uiServer` / `statsServer`）。
- **`sniCallback`** —— 需要在 TLS SNI 阶段介入选证书，早于按请求的规则解析，当前 MITM 架构不可达。
- **npm `whistle.*` 包兼容** —— 明确的非目标，见本文开头。
