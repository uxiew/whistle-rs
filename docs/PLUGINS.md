# 插件系统 / Plugins

[项目说明](../README.md) · [架构](ARCHITECTURE.md) · [规则](RULES.md)

whix 的插件是**按请求生效的中间件**。一个插件可以：

- **注入规则** —— 动态产生 whistle 规则，合并进本次请求的规则集
- **直接应答** —— 短路上游，返回一个 mock 响应
- **改写请求头** —— 在规则算子之后生效，因此可以覆盖规则的结果
- **改写响应** —— 状态码、响应头、响应体
- **流式改写 body** —— 边收边改，全程不落内存（`pipe://`）
- **拦改 WebSocket 帧** —— 逐帧、双向，可改写也可丢弃
- **决定放不放行** —— 认证钩子，**唯一一个失败即拦截**的钩子
- **挑 TLS 证书** —— 在握手期决定这条连接用哪张证书，**甚至可以决定不拦截**
- **上报统计** —— 请求/响应两个阶段各一次，发完不管
- **自带页面** —— 在 `/plugin/<name>/` 下服务插件自己的 UI

两种运行时实现同一套契约：

| 运行时 | 说明 |
|--------|------|
| **JS / TS 插件** | 独立进程，通过 HTTP 协议通信。用 [`sdk/`](../sdk/) 的零依赖 SDK 编写，协议细节完全被封装 |
| **Rust 插件** | 进程内原生插件，实现 `RustPlugin` trait，零 IPC。见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) |

改写流量的钩子分三族，**由规则的协议名决定跑哪一族**：

| 规则 | 钩子 | body |
|------|------|------|
| `plugin://<name>[/<param>]`，也可写成上游的 `whistle.<name>://<param>` 或 `<name>://<param>`（见 [RULES 的 Plugins](RULES.md#plugins)） | `onRequest` / `onResponse` | 整体缓冲，需显式声明 |
| `pipe://<name>[(<value>)]` | `pipeRequest` / `pipeResponse` | **流式，永不缓冲** |
| 两者皆可，命中 WebSocket 时 | `onWsFrame` | 逐帧，一次一帧 |

另有四个**不改写流量**的钩子：

| 钩子 | 由什么触发 | 说明 |
|------|-----------|------|
| [`onAuth`](#认证钩子--onauth) | 同上两种规则，跑在所有请求钩子**之前** | 决定这个请求放不放行 |
| [`sniCallback`](#证书钩子--snicallback) | `sniCallback://<name>` 规则，在 **TLS 握手期** | 决定这条连接用哪张证书，或者干脆不拦截 |
| [`onReqStats` / `onResStats`](#统计钩子--onreqstats--onresstats) | 同上，两个阶段各一次 | 只上报，不等回应 |
| [`onUi`](#插件页面--onui) | 浏览器访问 `/plugin/<name>/…` | 插件自己的页面，与代理流量无关 |

`sniCallback` 是这一族里唯一**不作用在请求上**的钩子 —— 它跑的时候还没有请求。

`pipe://` 指向一个没有声明任何流式钩子的插件时，退化为 `plugin://` —— 与流式钩子出现之前的语义一致，老规则不会失效。

WebSocket 帧钩子**两种协议名都能触发**：一个 WebSocket 没有「缓冲 / 流式」之分可供协议名表达，
让其中一个悄悄不生效只会变成陷阱。协议名依然决定**握手请求**（它就是个普通 HTTP 请求）跑哪一族。

> 这是 whix **自研**的插件体系，不是原版 whistle 插件 API 的复刻。现成的
> `npm i whistle.xxx` 包无法直接运行 —— 原版 API 建立在对 Node `req`/`res` 对象的
> 装饰之上（约 2600 行加载器、位置式 CSV 头协议、单端口多钩子分发）。这里换成了一套
> 显式、有类型、语言无关的协议。

---

## 快速开始（JavaScript）

```js
// my-plugin.js
const { start } = require('whix/sdk/whix-plugin');

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
    ctx.setHeader('x-powered-by', 'whix');
  },
});
```

启动：

```bash
whix --node-plugin my-plugin=./my-plugin.js
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
import { start, type Plugin, type RequestCtx, type ResponseCtx } from 'whix/sdk/whix-plugin';

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
whix --node-plugin typed=dist/my-plugin.js
```

完整示例见 [`examples/plugins/typed.ts`](../examples/plugins/typed.ts)。

---

## 能力声明与性能（重要）

whix **默认不缓冲任何 body**：请求体和响应体都是流式穿过代理的，SSE、大文件下载、长轮询都不受影响。

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
const { start, transform } = require('whix/sdk/whix-plugin');

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
const { start } = require('whix/sdk/whix-plugin');

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
不挂插件             mean 0.092ms  p50 0.091ms  p95 0.134ms
插件在跑但规则没命中  mean 0.093ms  p50 0.090ms  p95 0.135ms
挂上帧钩子            mean 0.178ms  p50 0.166ms  p95 0.245ms
```

即**每帧约 38µs（p50）/ 42µs（mean）/ 56µs（p95）**。注意第二行：插件进程在跑、只是规则没
命中这条 WebSocket —— 与不挂插件在噪声内无法区分，这是硬要求。

帧不做流水线：第 n+1 帧要等第 n 帧的裁决回来才交出去 —— 一个会让 WebSocket 乱序的钩子比
一个慢的钩子糟糕得多。

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
fn on_ws_frame(&self, _meta: &FrameMeta, frame: &HookFrame) -> Verdict {
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

## 认证钩子 / `onAuth`

一个插件决定这个请求**放不放行**。返回 `false` 就是拦下来。

```js
const { start } = require('whix/sdk/whix-plugin');

start({
  name: 'gate',

  onAuth(ctx) {
    const token = ctx.header('x-gate-token');
    if (!token) {
      ctx.setLogin(true);              // 401 + www-authenticate，浏览器弹登录框
      return false;
    }
    if (token !== ctx.param) {
      ctx.setHtml('<h1>403</h1>');     // 自定义拦截页
      return false;
    }
    ctx.setHeader('x-whistle-user', token);   // 放行，并给下游带上身份
  },
});
```

```
example.com   plugin://gate/s3cret
```

完整示例见 [`examples/plugins/token-gate.js`](../examples/plugins/token-gate.js)（认证 + 统计 + 页面三个钩子）；
Rust 版本见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) 里的 `plugin://gate`。

### 拦截的四种形态

| 调用 | 客户端看到 |
|------|-----------|
| 什么都不调，`return false` | `403` + `Forbidden` |
| `ctx.setHtml(html)` | `403` + 这段 HTML |
| `ctx.setRedirect(url)` | `302` + `location: url` |
| `ctx.setUrl(url)` / `setFile(path)` | `403` + **该 URL / 文件的内容**（代理去 GET / 读盘） |
| `ctx.setLogin(true)` | `401` + `www-authenticate: Basic`（`setStatus(407)` 则是 `proxy-authenticate`） |
| `ctx.setStatus(code)` | 换掉状态码，**仅接受 3xx–5xx** |

对应原版的 `req.setHtml` / `setRedirect` / `setUrl` / `setFile` / `setLogin`。原版把拦截翻译成
三条合成规则（`lib/plugins/index.js:936-959`：`method://get <url>`、`redirect://<url>`、
`status:// + resBody://`），whix 直接渲染成响应 —— 合成规则在原版存在，是因为拦截结果必须
重新汇入一条只认规则的管线，所以每条都用 `ignore://` 钉死；这里少一层机器就到同一个地方，而且
**直接应答会终止插件链**，那才是关键的部分。

几个刻意的选择：

- **拦截永远不是 2xx。** `setStatus(200)` 会被忽略，退回 `403`。
- **`setHeader` 只认 `x-whistle-*` 和 `proxy-authorization`**，且只在**放行**时生效。
  与原版同一组限制（`load-plugin.js:1757-1768`、`index.js:878-895`），并且在代理侧**再过滤一次** ——
  插件不是安全边界。认证钩子是用来**标识**一个请求的，不是用来改写它的。
- **没有 body。** 认证钩子拿不到请求体：为了鉴权而缓冲每一个上传，代价不成比例；原版也不给。

### 失败即拦截（fail closed）

这套插件系统里所有其它钩子失败都降级成「什么都不做」：管道接不上就原样放行，帧钩子挂了就摘掉，
请求钩子超时就当无操作。那些都是**装饰性**的属性，请求继续走反而更好。

**认证不是装饰性的。** 一个坏掉就放行的门不是门，所以这里**每一种失败都拦截**：

| 情况 | 结果 |
|------|------|
| 插件连不上 / 中途死了 | `502`，正文写明原因 |
| 5 秒内没给裁决 | `502` |
| 应答非 200/204 | `502` |
| 应答 200 但不是能看懂的 JSON | `502` |
| 应答 200/204 且**正文为空** | **放行** —— 这是本协议里一致的「无话可说」 |
| 声明了 `auth` 却不提供 `/auth` 端点 | `502`（清单说了有，那就得有） |
| **`/manifest` 取不到**（连不上、5 秒没回、`5xx`、不是 JSON 对象） | `502`，正文 `Plugin unavailable: manifest unavailable: …`。插件有没有认证钩子恰恰是这时不知道的事，所以不猜 |

最后一行是 2026-09-30 加的。之前 `/manifest` 第一次失败会被**永久**记成"老协议、没有认证钩子"：
插件启动慢了半秒、第一次回了 `503`，从此命中它的请求全部直达源站，`/auth` 再也不会被调用，插件
恢复正常也没用，要重启 whix 才行。现在失败不记成任何结论，最多每秒重新问一次，问到为止。

原版从另一个方向落到同一处：它的 `authReq` 把传输错误和主动拒绝一视同仁（`if (err || body)` →
forbidden，`lib/plugins/index.js:836`），并且给错误 `502`、给主动拒绝 `403`
（`index.js:951`）。**状态码就是这两者的区分方式**，这里保留了它。

实测（杀掉插件进程之后，同一条原本 200 的请求）：

```
$ curl -i -x 127.0.0.1:19181 -H 'x-gate-token: s3cret' http://127.0.0.1:19180/open
HTTP/1.1 502 Bad Gateway
x-whix-auth: tokengate
content-type: text/html; charset=utf-8

Plugin auth failed: connecting to 127.0.0.1:61043: Connection refused (os error 61)
```

日志里同时留一行 `WARN auth tokengate: … ; request blocked`。**没有命中这个门的请求不受影响**
（同一时刻 `/plain` 依然 200）。

### 代价

认证跑在请求路径上，所以它的开销落在**每一个命中的请求**上。同一台机器、debug 构建、
Node 插件在本机 loopback，四种配置交替发送（每轮各发一次，让负载波动平摊到所有配置上），
每种 400 次串行请求：

```
基线二进制（f21b92a）  /bare            mean 0.234ms  p50 0.226ms  p95 0.299ms
本分支                 /bare            mean 0.226ms  p50 0.223ms  p95 0.267ms
基线二进制（f21b92a）  /plain (stamp)   mean 0.245ms  p50 0.241ms  p95 0.290ms
本分支                 /plain (stamp)   mean 0.247ms  p50 0.242ms  p95 0.292ms
插件在跑但规则没命中                     mean 0.212ms  p50 0.208ms  p95 0.248ms
命中门（Node，走 HTTP）                  mean 0.419ms  p50 0.402ms  p95 0.489ms
命中门（Rust，进程内）                   mean 0.258ms  p50 0.255ms  p95 0.296ms
```

三件事：

1. **前两组是硬要求**：没有认证插件的请求，与加这个钩子之前**一模一样** —— `/bare`（无规则）
   和 `/plain`（命中一个没有认证钩子的插件）两条路径都在噪声内。字节也一样：同一请求分别打到
   基线二进制和本分支，响应头（除 `date`）与响应体逐字节相同。
2. **Node 的门约 +0.18ms（p50）** —— 就是一次本机 HTTP 往返，和其它远程钩子同价。
3. **Rust 的门约 +0.03ms** —— 没有 IPC，剩下的只是判断和一个额外的头。

### Rust 插件

```rust
fn auth(&self, req: &PluginReq) -> AuthVerdict {
    if req.headers.iter().any(|(k, v)| k == "x-gate-token" && v == "s3cret") {
        return AuthVerdict::Allow(vec![("x-whistle-user".into(), "bob".into())]);
    }
    AuthVerdict::Deny(Denial {
        page: DenyPage::Html(b"<h1>no</h1>".to_vec()),
        ..Denial::forbidden()
    })
}
```

内置的 `plugin://gate` 就是这么实现的。

---

## 证书钩子 / `sniCallback`

在一条被拦截的 TLS 连接的**握手期**，由插件决定这条连接用哪张证书 —— 或者**根本不拦它**。

```js
const { start } = require('whix/sdk/whix-plugin');

start({
  name: 'certs',

  sniCallback(ctx) {
    if (ctx.value === 'skip') return false;        // 不拦截，原样透传
    if (ctx.hasCachedCert) return ctx.reuse();     // 你手上那张还能用
    return { key: keyPem, cert: certPem, mtime: issuedAt };
  },
});
```

```
api.example.com      sniCallback://certs(staging)
pinned.example.com   sniCallback://no-mitm        # 内置，永远返回 false
```

完整示例见 [`examples/plugins/sni-certs.js`](../examples/plugins/sni-certs.js)；
Rust 版本见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs) 里的 `sniCallback://no-mitm`。

### 它和别的钩子不一样在哪

**它跑的时候还没有请求。** 握手还没做完，所以没有 method、没有 URL、没有头、没有 body，
以后也不会有。`ctx` 就是握手能知道的那点东西：

| 成员 | 说明 |
|------|------|
| `ctx.servername` | 客户端 ClientHello 里要的名字；客户端没发 SNI 时退回隧道的主机名 |
| `ctx.value` | `sniCallback://name(value)` 里的 `value`，没有就是 `''` |
| `ctx.tunnelHost` / `ctx.port` | 隧道**开到**的地址。与 `servername` 可能不同 |
| `ctx.clientIp` | 客户端地址 |
| `ctx.certCacheName` | 代理手上这个名字的证书是**你**给的时，等于你自己的插件名；否则 undefined |
| `ctx.certCacheTime` | 那张证书带的 `mtime`（没带就是 `0`） |
| `ctx.hasCachedCert` | 上面那条的布尔简写 |

规则匹配的是 `https://<ctx.servername>[:<port>]` —— 那是握手期唯一存在的 URL。所以：
**端口是 pattern 的一部分**（ClientHello 里没有端口，但隧道的端口是知道的），而任何问
method / 路径 / 头 / body 的筛选器都不会命中一条 `sniCallback` 行。

### 四种返回值

| 返回 | 结果 |
|------|------|
| `false` | **不拦截。** 连接原样中继出去，客户端和源站自己协商 TLS，代理看不见里面。去哪仍由 `host://` / `proxy://` 决定 |
| `true` | 拦截，用 whix 自己签的证书（和没有这条规则时一样）；并**作废**你之前给的那张 |
| `{key, cert, mtime?}` | 拦截，用这张证书。两个字段都必须是非空字符串（PEM） |
| `ctx.reuse()` | 拦截，用**你上次给的那张**。代理没有缓存时退回自签的那张 |
| 不返回 / 返回别的 | 等同于 `true` |

`false` 是这一整套插件系统里**唯一**能关掉拦截的开关 —— 别的钩子都跑在拦截之后，那时
已经太晚了。

> 与原版的对应：原版的 `true` 是「保留缓存的那张」，也就是这里的 `ctx.reuse()`；原版的
> 空 body 是「删掉缓存、用自签的」，也就是这里的 `true`。原版把「保留」和「作废」分别绑在
> `true` 和「什么都不返回」上（`lib/https/load-cert.js:31-53`），于是**出错**和**明确表态**
> 走进了同一个分支。这里把两件事拆开命名，语义一一对应，但拼法不同。

### 证书缓存

代理会记住每个 `servername` 上**哪个插件**给过哪张证书，下次握手时把 `certCacheName` /
`certCacheTime` 告诉那个插件 —— 这就是 `ctx.reuse()` 存在的理由：证书是几 KB 的 PEM，
而握手期客户端正等着。

缓存是**按插件隔离**的：另一个插件的规则命中同一个名字时，既看不到 `certCacheName`，
`reuse()` 也拿不到别人的证书。

什么时候变：

- 插件给出**能用**的证书 → 写入；
- 插件说 `ctx.reuse()` → 读取；
- 插件说 `true`（或没话说）→ **作废** —— 这是插件主动收回它给过的证书；
- 插件**问不到**（连不上 / 超时 / 非 200）→ 不动，而且这次握手就用缓存里那张。一个本地
  进程重启不该改变一个活着的客户端正在看到的证书。

### 出错了会怎样 —— 以及为什么这是一次**政策选择**

**结论先说：任何失败都退回「whix 自签的那张证书」**，也就是和没有这条规则时一模一样，
日志里留一行 `WARN` 写清是哪个插件、哪个名字。畸形的证书材料（PEM 解析不了、key 和 cert
不配对）同样如此 —— rustls 在**采用之前**就会拒绝它，所以一个乱答的插件弄不垮监听器。

这一条与本项目其它安全相关路径的取向**不一致**，所以要把理由摆出来：坏掉的认证门是拦截，
失败的 PAC 是 502，源站 TLS 默认校验 —— 都是 fail closed。这里没有照做，是因为「closed」
在这个位置有**两个方向相反**的读法：

- *不要拿出运维没有批准的证书* → 失败就该**停止拦截**（等同于插件说了 `false`）；
- *不要悄悄停止抓取运维要求抓的流量* → 失败就该**照常拦截**，用本来就会用的那张证书。

whix 选了后者，理由有两条：退回去的那张证书是**它自己的**、由用户亲手装进信任库的
根签的 —— 它不是第三方的身份，而且给每一个别的主机拿出来的正是这张；另一条是，选前者会让
一次插件重启在抓包里凿出一个**看起来完全正常**的洞。原版落在同一处
（`loadCert` 的错误分支保留缓存、否则落到自签，`lib/plugins/index.js:245-247`）。

**如果你的部署需要另一种读法**（插件挂了就不拦截、让流量原样过去），今天做不到 —— 这不是
可配置项。这一条记在[边界](#证书钩子的边界)里，而不是假装它不存在。

注意这与认证钩子并不矛盾：认证钩子是一道**门**，坏掉的门必须关上；证书钩子不是门，它退回去
的是一个**默认值**，没有任何检查因此被放过。

### 代价

握手在**每一条 HTTPS 连接**的关键路径上，所以这里的开销分两笔算：**重构本身**的，和
**插件往返**的。

重构的部分是：ClientHello 现在由代理先读一遍（用 rustls 自己的解析器），再把原样的字节
交还给真正的握手。也就是说 rustls 会解析两次 ClientHello。这一次解析单独量出来是
**1.6–2.0µs**（244 字节的 hello，release 构建）：

```
$ cargo test --release -- --ignored --nocapture bench::client_hello_peek_cost
ClientHello: 244 bytes
Reading one ClientHello  (5000 samples per row)
  configuration                mean        p50        p95    vs. first
  copy the bytes only      358.0ns   375.0ns   500.0ns       +0.0ns
  peek (parse + copy)        2.0µs     2.1µs     2.8µs       +1.6µs
```

放回一次真实握手里（四种配置在同一个循环里轮转，客户端和代理都在本机）：

```
$ cargo test --release -- --ignored --nocapture bench::tls_handshake_latency
TLS handshake through the SNI stage  (400 samples per row)
  configuration                mean        p50        p95    vs. first
  eager (pre-change)       173.1µs   170.3µs   188.1µs       +0.0ns
  read + replay, no parse  173.0µs   170.1µs   187.4µs      -53.0ns
  peek + replay            173.7µs   170.7µs   190.5µs     +612.0ns
  peek + rule miss         174.1µs   171.6µs   189.2µs     +994.0ns
  peek + rust plugin       175.3µs   172.0µs   190.2µs       +2.2µs
```

三件事：

1. **第一行是硬要求。** 没有 `sniCallback://` 规则的连接与加这个钩子之前**一模一样** ——
   规则文件里有没有这个协议名，是每个规则组一个**解析期就算好的 `bool`**，答案是「没有」时
   连插件注册表都不会碰。第二行（只读不解析）说明「读一次 + 回放」这层管道本身在噪声里。
2. **解析那一次约 +0.6µs（p50）**，对着一个 170µs 的握手 —— 密钥交换和签名才是这里的钱。
3. **进程内 Rust 插件约 +2.2µs**；换成 Node 插件要再加一次本机 HTTP 往返（约 +0.2ms，与
   本文其它远程钩子同价），**每条连接一次**，不是每请求、更不是每帧。

端到端对着**基线二进制**（`fcda35b`）复核过同一件事：同一个根 CA、同一个源站，一条没有规则
的连接在两个二进制上拿到的证书 subject / issuer / SAN / 有效期完全相同，响应逐字节相同，
握手延迟 p50 0.445ms vs 0.447ms。

### 实测

三条连接穿过**真的二进制**（`--node-plugin certs=examples/plugins/sni-certs.js`），
源站是一个自己有证书的 Node HTTPS server，规则按端口区分三种情形：

```
--- rules ---
localhost:19443   sniCallback://certs(mine)
localhost:19444   sniCallback://certs

--- the three connections ---
[1] sniCallback://certs(mine)   the plugin supplies a certificate
   SNI sent    localhost
   subject     CN=localhost,O=whix sniCallback example
   issuer      CN=localhost,O=whix sniCallback example
   response    HTTP/1.1 200 OK  {"origin":true,"port":19443,"url":"/hello",…}

[2] sniCallback://certs         the plugin declines interception
   SNI sent    localhost
   subject     CN=localhost,O=THE REAL ORIGIN
   issuer      CN=localhost,O=THE REAL ORIGIN
   response    HTTP/1.1 200 OK  {"origin":true,"port":19444,"url":"/hello",…}

[3] no rule                     control, untouched
   SNI sent    localhost
   subject     CN=localhost
   issuer      CN=whix Root CA,O=whix
   response    HTTP/1.1 200 OK  {"origin":true,"port":19445,"url":"/hello",…}

--- what the proxy captured ---
   200 GET https://localhost:19445/hello
   200 GET https://localhost:19443/hello
```

三张证书各不相同，而且**第二条拿到的是源站自己的那张** —— 那正是「没被拦截」长什么样。
抓取列表里也只有 19443 和 19445 两条：被放弃的那条连接对代理自始至终是一团密文。
三条请求都是 `200`，也就是说「不拦截」不是「断开」。

### 传输：一次 JSON 往返

和缓冲钩子同一条线：`POST /sni`，JSON 进 JSON 出。理由很直接 —— 这个钩子搬的是**几个标量
和一小份文档**，没有流、没有分帧问题要解决，`pipe://` 和帧钩子各自发明传输是因为它们有；
这个没有。它与别的钩子的差别在**什么时候跑**，不在搬多少东西。

单位是**一条连接**，不是一个请求，也不是一帧 —— 这一族里最便宜的成本模型。应答上限 72 KB
（与原版 `MAX_CERT_SIZE` 同值），超过就当没答；超时 5 秒，与认证钩子同一个预算。

### 为什么这曾被记成「架构不可达」

路线图里长期写着：MITM acceptor 在 SNI 阶段按域名构建、早于按请求的规则解析，因此不可达。
**描述属实，结论不成立** —— 那描述的是当时的代码，不是架构。真正的障碍只有一个：
`sniCallback` 的 `false` 意味着「把这条连接原样中继出去」，而那要求**已经被读走的
ClientHello 字节还能拿回来**。

`tokio-rustls` 的 `LazyConfigAcceptor` 能在 ClientHello 之后插入任意异步工作，四种返回值里
它能满足三种；唯独 `false` 不行 —— 它接管 socket 之后不再交还，也没有任何 rustls API 能
复现它吃掉的字节，被插件拒绝的连接就只能被丢掉，而那不是「拒绝」的意思。

所以字节由代理自己读、留着、再回放：拦截时回放给 rustls，不拦截时回放给源站。解析仍然是
rustls 的（`rustls::server::Acceptor` 当成纯解析器用完就扔），这里没有一个字节的 TLS 是由
自己写的代码解释的。原版从同一个约束走到同一个安排（自己 peek 第一个 chunk、自己解析 SNI、
拒绝时 `next(chunk)` 放回去，`lib/https/index.js:1281-1308`）。

代价就是上面那 0.6µs。

### Rust 插件

```rust
fn manifest(&self) -> PluginManifest {
    PluginManifest { sni: true, ..PluginManifest::none(self.name()) }
}

fn sni(&self, _req: &SniReq) -> SniVerdict {
    SniVerdict::Bypass
}
```

内置的 `sniCallback://no-mitm` 就是这么实现的 —— 那张不需要证书的答案，也是别处给不出的
那一个。

---

## 统计钩子 / `onReqStats` / `onResStats`

告诉插件「有什么东西过去了」。**发完不管**：应答被丢弃，请求路径上没有任何东西等它。

```js
start({
  name: 'gate',
  onReqStats(ctx) { seen.push(ctx.url); },
  onResStats(ctx) { byStatus[ctx.statusCode] = (byStatus[ctx.statusCode] || 0) + 1; },
});
```

这正是它敢挂在热路径上的原因：一个卡住、崩掉、返回 500 的统计插件，代价是一次
`tokio::spawn` 和一个 socket，**不是一毫秒的延迟**。原版也是这么做的 —— 开一个请求，
`response.on('data', util.noop)`，错误吞掉，从不回调（`lib/plugins/index.js:1369-1408`）。

反过来说：**统计钩子不是做决定的地方**。想改请求就用认证钩子或请求钩子，那两个之所以被等待，
正是因为它们说了算。

`ctx` 是缓冲钩子那套元信息（`id` / `method` / `url` / `headers` / `param` / `clientIp`），
外加 `ctx.phase`（`'request'` / `'response'`）和 `ctx.statusCode`（仅响应阶段）。

每个阶段每个插件恰好一次：代理本来就按阶段遍历命中的插件一遍，所以不需要原版那种
`req._postResStats` 去重标记。

---

## 插件页面 / `onUi`

浏览器访问 `http://<代理端口>/plugin/<name>/…`，请求就交给这个插件。

```js
start({
  name: 'gate',
  onUi(req, res) {
    if (req.url === '/stats.json') return seen;         // 非字符串 → JSON
    return `<h1>admitted ${seen.admitted}</h1>`;        // 字符串 → HTML
    // 什么都不返回，就自己写 res —— 拿到的是 Node 原生的 (req, res)
  },
});
```

```
http://127.0.0.1:8899/plugin/          # 所有带 UI 的插件的索引
http://127.0.0.1:8899/plugin/gate/     # 插件自己的首页
```

### 为什么是「再转发一次 HTTP」

UI 请求本来就是一个 HTTP 请求配一个 HTTP 应答，所以这个钩子整个复用 HTTP：浏览器的方法、路径、
查询串、头、body 原样发给插件的 `/ui…`，插件的状态码、头、body 流式回来。没有 JSON 信封，
因为没有东西需要被信封装 —— 与 `pipe://` 选择 chunked 而不是自造分帧是同一条理由的下一步。
插件作者写的就是一个普通的 Node handler，可以用自己的路径、content-type、缓存头和流式输出，
这些没有一样能塞进 JSON 协议里。

代理会把 `/plugin/<name>` 从路径上摘掉，再补上 `/ui` 前缀 —— 这就是插件的**页面**和它的**钩子**
互不打架的原因：`/ui` 下面是浏览器的地盘，旁边的 `/manifest`、`/request`、`/auth` 是代理的地盘。
原版用另一种方式隔开（同一个端口，靠一个内部的 hook-name 头分发，`load-plugin.js:2006-2024`），
但它有一个独立的 `uiServer` 对象可以分发过去；这里只有一个 server 和一个路由表，所以这条边界
必须画在路径上。

### UI 请求拿不到什么

**拿不到被代理的那个请求。** 原版在这一点上很明确：HTTP 钩子拿的是 `initReq(req, res, true)`
（带规则、会话信息、原始请求/响应的完整装饰对象），而 UI 钩子只拿 `setContext(req)` ——
挂上存储，以及调用方传了会话头时的客户端地址（`load-plugin.js:160-200`、`:2019-2024`）。

whix 照做：插件收到的就是**浏览器自己那个请求**，别的没有。理由不是省事 —— UI 请求是
浏览器在向插件要一张页面，它不属于任何人的代理流量，硬塞一个请求上下文进去等于凭空发明一段
根本不存在的关联。想展示抓到的流量，就在**真的看得见流量**的钩子里（`onRequest`、`onResStats`）
攒起来，再从自己的状态里渲染 —— 原版插件也正是这么写的。

### 失败与限制

- 插件连不上 / 10 秒不应答 → 浏览器看到 `502`，日志里一行 `debug`。**代理流量不受影响**。
- 页面里请用**相对链接**。绝对路径（`/style.css`）会打到代理的 web UI 上，不会到插件。
  访问 `/plugin/<name>`（无尾斜杠）会被 `302` 到带斜杠的形式，否则相对链接全断 —— 原版同理
  （`biz/webui/lib/index.js:489-491`）。
- **这个路由和控制台用同一个登录**：设了 `-n/-w` 就要先登录（`-N/-W` 的只读账户只能 `GET`），
  跨站写入和陌生 Host 的拒绝同样适用。插件收不到控制台的 `Authorization`/`Proxy-Authorization`，
  转交前就去掉了。原版要插件自己声明 `inheritAuth` 才继承登录态；这里一律继承，没有开关。
- 不支持从 UI 路由升级 WebSocket。

### Rust 插件

```rust
fn ui(&self, req: &UiReq) -> UiResp {
    match req.path.as_str() {
        "/" => UiResp::html("<h1>hi</h1>"),
        "/stats.json" => UiResp::json(&serde_json::json!({ "ok": true })),
        _ => UiResp::not_found(),
    }
}
```

`UiReq` 只有 `method` / `path` / `query` / `headers` / `body`（外加 `req.param("k")`），
与上面那条「UI 请求拿不到被代理的请求」是同一件事。往页面里插流量里来的字符串时用
`plugins::ui::escape_html`。

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
| `ctx.setValues({ name: value })` | 给 `setRules` 注入的规则里的 `{name}` / `${name}` 提供值。只有这个插件的规则看得到，和控制台 Values 重名时**插件的优先**；不是字符串的值按 JSON 发送。可多次调用，同名后者覆盖前者 |
| `ctx.respond({statusCode, headers, body})` | 直接应答，**不触达上游** |

### `onResponse` 专有

| 成员 | 说明 |
|------|------|
| `ctx.statusCode` | 上游返回的状态码 |
| `ctx.setStatus(code)` | 改写状态码 |
| `ctx.setBody(body)` | 替换响应体（字符串 / Buffer / 可 JSON 序列化的值） |

`setHeader` / `setRules` / `setValues` / `setStatus` / `setBody` 都返回 `ctx`，可以链式调用。

`setValues` 的典型用法是让插件自带 mock 内容，不用让用户先去 Values 里建一项：

```js
onRequest(ctx) {
  ctx.setRules('* resBody://{page} resHeaders://x-mocked-by=${who}')
     .setValues({ page: { ok: true, items: [] }, who: 'mocks' });
}
```

注意 `{name}` 只在**整个值**就是它时才替换（`resBody://{page}`），值的中间要写 `${name}`（`x-mocked-by=${who}`）——写成 `x-mocked-by={who}`，响应头里就是字面的 `{who}`。这条规则和上游一样，见 [RULES 的 values 一节](RULES.md#flags-includes--values)。

---

## 插件自带的规则

插件可以带一段规则，只要插件开着就对**每个请求**生效，用户不用写任何一行去点它的名字。这就是上游插件包里的 `rules.txt`。

```js
start({
  name: 'cors-everywhere',
  rules: '* resCors://enable',
});
```

不写任何钩子、只有 `rules` 也行。Rust 插件在 `manifest()` 里设 `rules`，自己实现协议的在 `/manifest` 里多一个 `"rules": "…"` 字段（见[线上协议](#get-manifest--能力声明)）。

**优先级和上游一样：排在控制台的规则后面。** 同一个 URL 上，用户写了 `file://` 而插件也写了 `file://`，用用户的；插件里标了 `lineProps://important` 的行例外，它照样压过用户没标 important 的行，就像这两行写在同一个规则文件里。多个插件之间按插件名排序。

**什么时候生效：**

- 内置插件和 Rust 插件：启动就生效。
- 远程插件（`--plugin`、`--node-plugin`）：代理拿到它的 `/manifest` 之后。启动时会在后台去要，插件还没起来就每秒再要一次，一分钟后改成每 30 秒一次。在拿到之前，它的规则**不生效**，请求也不会为此等它。不这么做的话，一个连不上的插件会拖慢所有请求，而现在只拖慢点名它的那些。
- 规则是随 manifest 一起拿到并缓存的，插件改了规则要**重启代理**才会生效。
- 插件被关掉（见[被关掉的插件](#被关掉的插件)）时，它的规则也一起失效。

**管不到的地方**（这几处只看控制台的规则）：决定 HTTPS 隧道拦不拦的那一步（`disable://intercept`、`sniCallback://` 写在插件规则里不起作用）、控制台的 Test Rules 和 `whix explain`。

### 上游的 `resRulesServer`，在这里怎么做

上游插件可以在**响应阶段**再返回一次规则。这里没有单独的钩子，下面两种写法能覆盖它的用途：

- **规则要看响应才决定生效的**：照样在 `onRequest` 里 `setRules`，用响应条件过滤。插件返回的规则在响应到达后会再解析一次，所以 `* resHeaders://x-not-found=1 includeFilter://s:404` 只在 404 时生效。
- **要直接改响应的**：用 `onResponse` 改状态码、响应头和 body，见[上下文 API](#上下文-api)。

---

## 执行顺序

HTTPS 的话，第 0 步发生在**连接**上而不是请求上：CONNECT（或 SOCKS）之后、任何请求存在之前，
代理读 ClientHello，按 `https://<其中的名字>` 解析 `sniCallback://` 规则，握手才开始。
这一步说「不拦截」，下面这一整张表就都不会发生 —— 那条连接对代理是一团密文。
不过它**去哪**仍然由同一轮解析出的 `host://` / `proxy://` 决定，见
[证书钩子的边界](#证书钩子的边界)。

一次请求里发生的事，按顺序：

1. 规则解析 → 得到本次请求的规则集
2. **若有插件声明 `requestBody`** → 缓冲请求体
3. **请求阶段**（按规则中出现的顺序遍历所有匹配插件，每个插件内部依次是）
   - **`onAuth`** —— 拦下就立即返回，**后续插件一律不执行**（连同它自己的 `onRequest`）
   - **`onReqStats`** —— 发出去就不管
   - **`onRequest`**
     - `setRules` 注入的规则合并进规则集
     - `respond()` 一旦调用，立即返回，**后续插件不再执行**
4. 规则算子应用到请求上（`reqHeaders` 等）
5. 插件的 `setHeaders` / `removeHeaders` 应用 —— **在算子之后**，所以插件可以覆盖规则
6. **`pipeRequest`** 接入请求体（多个 `pipe://` 按规则顺序串联，后一个吃前一个的输出）
7. 请求发往上游
8. 规则算子应用到响应上（`resHeaders` 等）
9. **响应阶段** —— **`onResStats`**（发出去就不管），然后 **`onResponse`**
   - 未声明 `responseBody` 的插件先跑，响应**保持流式**
   - 声明了的插件在 body 就绪后跑
10. **`pipeResponse`** 接入响应体 —— 在「是否缓冲」的判断**之前**，所以接了管道的响应仍然走流式分支
11. 响应返回客户端

一旦有 `pipe://` 插件真的接管了 body，该方向的 `content-length` 会被去掉（变换可以改变长度），后续按 chunked 传输。

### 本地产生的响应也走响应阶段

第 8–10 步不只发生在「上游回来的响应」上。有两条出口的响应是代理**自己**产生的：

- **插件的 `respond()`** —— `plugin://` 直接应答
- **短路规则** —— `file://` / `tpl://` / `redirect://` / `statusCode://`

这两条出口同样跑完响应期算子、`onResStats`、`onResponse` 与 `pipeResponse`。原版那边这是结构性的：
原版的 `plugin://` 是一次到插件自有 server 的**代理跳**，插件的应答以普通响应的身份回到
`handleResponse`（`_original/lib/inspectors/res.js:825`），而 `pipe://` 是从它自己那条规则解析出来
的，不看字节是谁产生的（`resolvePipePlugin`，`_original/lib/plugins/index.js:1173`）。

两处需要注意：

- **`respond()` 终止的是请求阶段，不是响应阶段。** 后续插件的 `onRequest` 确实不再执行，但
  **所有**命中插件的 `onResponse` 都会看到这个应答 —— 包括 `onRequest` 从未跑过的那些。
- **应答的插件本身也在观众里。** 一个既 `respond()` 又实现 `onResponse` 的插件会看到自己的应答。
  原版同样如此（响应管道按全部命中插件建立），要区分请在 `respond()` 里带个自己的标记头。

body 已经在内存里（这两条出口都不涉及等待上游），因此 `pipeResponse` 在这里是「装帧 → 过管道 →
收回」而不是真的边收边发 —— 同样的工作，换个顺序，好处是钩子只有一套实现。管道改了长度时
`content-length` 会被去掉，与流式路径一致。

**一个例外：认证拦截。** `onAuth` 的拒绝也是一个「代理自己产生的响应」，但它**不跑任何响应钩子**
（连响应期算子也不跑）。理由不是实现方便：一个能被别的插件改写的门不是门。原版把拦截钉死在
`* ignore://!statusCode|!resBody|!resType|!resCharset …`（`_original/lib/plugins/index.js:936-959`），
也就是**忽略该请求上其余全部规则**，方向与这里一致。区分「拒绝」与「应答」的是裁决来源，不是状态码 ——
插件用 `respond()` 主动返回 403 仍然是应答，照跑钩子。

**WebSocket 升级请求走的是另一条路**：它在第 6 步之前就分岔了（升级没有 body，也就没有管道可接）。
顺序变成：规则解析 → `onRequest`（握手请求也是普通请求，插件可以改握手头、注入规则、甚至直接
应答挡掉升级）→ 转发握手 → 上游回 `101` → **隧道建立，帧钩子这时才去连插件**（因此插件的连接
不会拖慢握手）→ 每帧 `frameScript` → 每帧 `onWsFrame`。上游没回 `101` 就不会有任何插件被连接。

---

## 错误处理

SDK 做了隔离：钩子抛异常会被记录到插件自己的 stderr，并按「无操作」处理 —— **插件挂掉不会拖垮代理**。整个进程退出了也一样，`--node-plugin` 拉起的会在下一个请求时重新拉起，见[注册插件](#注册插件)。

代理侧同样是优雅降级：插件连不上、回了 `200`/`204`/`304` 以外的状态码、或者 **30 秒**内没回答（`HOOK_TIMEOUT`），请求都照常继续，当作钩子什么都没说。连不上时会重试两次（新拉起的插件进程可能还在绑定端口）。

降级不再是悄无声息的：这条请求的会话会多一条 `unapplied`，`kind` 是 `plugin-failed`，写明是哪个插件的哪个钩子、为什么失败（见 [API 的「没生效的规则」](API.md#没生效的规则)），控制台的 Rules 标签页会把对应的 `plugin://` 标成 "not applied"。日志里仍只有 `debug` 一行。`204`/`304` 是"没什么要做"，不算失败。

以前没有这个 30 秒：插件接下调用却一直不回，命中它的请求就一直挂着。

流式钩子的降级规则不同，见 [流式钩子 · 出错了会怎样](#出错了会怎样)：**握手成功之前**任何失败都零代价（body 原样放行，记一行 `WARN`）；**握手成功之后**插件挂掉会让 body 出错。

**还没取到 `/manifest` 的插件不算"钩子失败"**：代理不知道它有哪些钩子，命中它的请求直接 `502`，
见 [失败即拦截](#失败即拦截fail-closed) 表里最后一行。用 `--plugin name=host:port` 指向一个还没
启动的服务时就是这个表现——先启动插件，或者等它起来（代理每秒重新问一次）。

**认证钩子是唯一的例外**：它失败就拦截，见 [失败即拦截](#失败即拦截fail-closed)。SDK 里的
`onAuth` 抛异常会返回 `500`（而不是像其它钩子那样返回 `200 {}`），代理据此给出 `502`。

**证书钩子的降级方向是一次政策选择**，不是实现细节：它失败时连接**照常被拦截**，用代理本来
就会生成的那张证书。为什么不像认证钩子那样 fail closed，见
[出错了会怎样](#出错了会怎样--以及为什么这是一次政策选择)。

### 被关掉的插件

控制台可以把插件关掉：Status 页左侧栏双击插件名关一个，或者取消勾选 "All plugins on" 全关（接口见 [API 的「开关」](API.md#开关https全部规则插件)）。关掉的插件**不是失败，是不存在**：

- 所有钩子都不再被调用，包括 `onAuth`。认证插件关掉，它守的请求就直接放行。所以如果别人不该能关掉它，用 `-M notAllowedDisablePlugins` 启动。
- 证书钩子也不调用了，连接用代理自己生成的证书。之前缓存的、插件提供的证书**不会**再用。
- 会话里不会出现 `plugin-failed`，因为根本没去调用它。
- 插件进程照常运行，`/plugin/名字/` 页面也照常能打开。插件的设置页往往就在这里，关掉插件后还得能去改它。

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
| `plugin://gate[/<令牌>]` | 校验 `x-gate-token`，演示**认证 + 统计 + 页面**三个钩子 |
| `sniCallback://no-mitm` | 对命中的主机**放弃拦截**，演示**证书钩子**（不需要任何证书材料） |

> `plugin://gate` **默认拦截** —— 没有 `x-gate-token` 就是 `401`。同名的自定义插件
> （`--node-plugin gate=…`）会覆盖内置的这一个，覆盖方向是「用户的赢」。

写一个 Rust 插件只需实现 `name` 与 `on_request`，其余方法都有默认实现 —— 以后给协议加钩子不会破坏已有插件。`pipe` 的默认实现是恒等变换，`auth` 的默认实现是放行。

---

## 线上协议

自己实现协议（非 JS/TS 语言）时的完整规格。SDK 用户不需要关心这一节。

插件是一个 HTTP 服务，实现以下端点。

### `GET /manifest` —— 能力声明

首次使用时拉取，**取到了才缓存**。三种回答：

| `/manifest` 回了什么 | 代理怎么办 |
|------|------|
| `200` + 一个 JSON 对象 | 这就是清单，缓存到进程退出 |
| `404` | 这个插件没有这个路由，按 v1 协议处理（见下），同样缓存 |
| 其它任何情况：连不上、5 秒没回、`5xx`、`200` 但不是 JSON 对象 | **什么都不缓存**。命中这个插件的请求 `502`；最多每秒重新问一次 |

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "hooks": ["request", "response", "pipeRequest", "pipeResponse", "wsFrame",
            "auth", "sni", "reqStats", "resStats", "ui"],
  "requestBody": false,
  "responseBody": true,
  "rules": "* resHeaders://x-via=my-plugin"
}
```

`rules` 可选，见[插件自带的规则](#插件自带的规则)。

`hooks` 决定哪些端点会被调用；两个 body 开关决定是否缓冲并投递 body（只对 `request` / `response` 有意义 —— 流式钩子、帧钩子、认证钩子和统计钩子都不缓冲，也就无需声明）。

**声明 `auth` 是一个承诺**：从此这个插件命中的请求必须拿到它的裁决才能继续，拿不到就是拦截。不打算做认证就别声明。

**不提供 `/manifest` 的插件按 v1 协议处理**：只有请求钩子，无 body，分发到 `POST /`。老插件因此无需改动即可继续工作。"不提供"指的是对 `GET /manifest` 回 `404`；回 `500`、回一张 HTML 错误页、或者干脆不回，都不是 v1，是"还不知道"。

### `POST /request`

```json
{ "id": 42, "method": "GET", "url": "http://…", "headers": [["k","v"]],
  "clientIp": "1.2.3.4", "param": "extra/after/name", "bodyBase64": "…" }
```

`bodyBase64` 仅在声明 `requestBody` 时出现。应答（各字段均可选）：

```json
{ "rules": "example.com resHeaders://x=1",
  "values": { "page": "<h1>mock</h1>" },
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

### `POST /auth` —— 认证

请求体与 `POST /request` 相同，**减去 body**：

```json
{ "id": 42, "method": "GET", "url": "http://…", "headers": [["k","v"]],
  "clientIp": "1.2.3.4", "param": "extra/after/name" }
```

应答 `200`：

```json
{ "allow": false, "statusCode": 403, "login": false,
  "html": "<h1>no</h1>", "redirect": "http://…", "url": "http://…",
  "setHeaders": { "x-whistle-user": "bob" } }
```

- `allow` 缺省视为 `true`（没有意见 = 放行）；`setHeaders` 只在放行时生效，且只保留
  `x-whistle-*` 与 `proxy-authorization`。
- 拦截时 `redirect` > `url` > `html`（与原版读取顺序一致），`statusCode` 只接受 `300`–`599`。
- **`200` 且正文为空、或 `204`/`304`** —— 放行。
- **其它任何情况（连不上、超时 5 秒、非 200、正文不是 JSON 对象）—— 拦截**，`502`。

### `POST /sni` —— 挑证书

在一条被拦截的 TLS 连接的握手期发出，**每条连接一次**。请求体里没有任何请求上下文，
因为那时还没有请求：

```json
{ "servername": "api.example.com", "value": "staging",
  "tunnelHost": "api.example.com", "port": 443, "clientIp": "127.0.0.1",
  "certCacheName": "certs", "certCacheTime": 1737849600 }
```

`certCacheName` / `certCacheTime` 只在代理手上有**这个插件**给过的证书时出现。

应答 `200`，四种形状：

```json
{"intercept": true}                        // 用 whix 自签的那张
{"intercept": false}                       // 不拦截，原样中继
{"key": "…", "cert": "…", "mtime": 0}      // 用这张（PEM，两个字段都必须非空）
{"reuse": true}                            // 用这个插件上次给的那张
```

裸的 JSON `true` / `false` 等价于前两种（原版就是这么写在线上的）。

- **`204`/`304`/空 body/认不出的字段** —— 「没话说」，等同于 `{"intercept": true}`。
- **连不上、超时 5 秒、非 200、正文超过 72 KB、PEM 不合法或 key 与 cert 不配对** ——
  一律退回自签的那张（有缓存时用缓存的），并留一行 `WARN`。理由见
  [出错了会怎样](#出错了会怎样--以及为什么这是一次政策选择)。

### `POST /stats` —— 统计（发完不管）

```json
{ "phase": "response", "id": 42, "method": "GET", "url": "http://…",
  "statusCode": 200, "headers": [["k","v"]], "param": "…" }
```

`phase` 是 `request` 或 `response`（`statusCode` 仅响应阶段）。**应答会被直接丢弃**，
返回什么都行，代理不会等。

### `GET|POST|… /ui/<path>` —— 插件页面

不是 JSON 协议：浏览器的请求原样转发，`/plugin/<name>` 被摘掉、`/ui` 被补上，
逐跳头（`connection`、`transfer-encoding`、`content-length`、`host` 等）由代理重建。
应答的状态码、头、body 流式回传给浏览器。

### `POST /pipe/request`、`POST /pipe/response` —— 流式钩子

**请求体就是被代理的 body 本身，应答体就是替换它的内容**，两个方向都是 chunked，两端都不缓冲。元信息放在一个头里，base64 编码的 JSON：

```
POST /pipe/response HTTP/1.1
x-whix-pipe: eyJpZCI6NDIsIm1ldGhvZCI6IkdFVCIsInVybCI6Imh0dHA6Ly8uLi4ifQ==
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
x-whix-ws: eyJpZCI6NDIsImRpcmVjdGlvbiI6InNlbmQiLCJ1cmwiOiJ3czovLy4uLiJ9
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

whix **有意不复刻这一套**：

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
# 由 whix 拉起 Node 进程（自动分配端口）
whix --node-plugin name=./path/to/plugin.js

# 指向一个已在运行的插件服务
whix --plugin name=127.0.0.1:9000
```

`--node-plugin` 会以环境变量 `WHIX_PLUGIN_PORT` 和 `WHIX_PLUGIN_NAME` 启动 `node <path>`，并等插件开始监听后才开始服务，几个插件一起最多等 5 秒。插件进程在监听之前就退出了（比如加载时抛异常），就不再等它，日志写 `WARN node plugin 'name' not ready (exited (exit status: 1) before it was listening); continuing`，代理照常启动。以前这种插件也要等满 5 秒（2026-10-07 修，R6-02）。`node` 须在 `PATH` 上，找不到时 whix 直接报错退出。

**插件进程随 whix 一起退出：**

| whix 怎么停的 | 插件 |
| --- | --- |
| Ctrl+C、`kill`（SIGTERM）；Windows 上 Ctrl+C、Ctrl+Break、关控制台窗口（Windows 这几种没有实测：CI 只能从外面强杀进程） | whix 先把已完成的会话写完盘，再结束插件进程，自己以退出码 0 退出 |
| `kill -9`、`taskkill /F`、崩溃（whix 自己的代码一行都跑不到） | 用 SDK 写的插件自己退出：whix 给插件的 stdin 是一根只有它握着的管道，它一没，操作系统就关掉管道，SDK 读到结尾就退出（环境变量 `WHIX_PLUGIN_STDIN=lifeline` 表示 stdin 是这根管道） |

不用 SDK 的插件要自己照做：`WHIX_PLUGIN_STDIN` 为 `lifeline` 时读 stdin，读到结尾就退出。不这么做，whix 被强杀后插件还会一直占着端口，下次启动分到的新端口不受影响，但旧进程要手动结束。以前（2026-09-29 之前）连 `kill` 也会留下插件进程，只有终端里的 Ctrl+C 能带走它们，因为 Ctrl+C 发给整个进程组。

**插件进程自己退出了（崩溃、被杀、`process.exit`）：** 下一个要用它的请求会重新拉起它，并等它起来再发过去，和上游一样。日志里先有一条 `WARN node plugin 'name' exited (exit status: 1)…`，再有一条 `started again`。具体是：

- 没有请求要用它时不拉起。一个一启动就崩的插件，没人用就不花任何代价；启动时后台预取 `/manifest`、控制台的状态页和插件页面目录都只看已知的清单，不会去拉它，也不等它。以前状态页每打开一次就拉起它一次（2026-10-07 修）。
- 同一个插件最多每秒拉起一次。
- 请求最多等 5 秒。等不到就按[错误处理](#错误处理)里"插件连不上"算：钩子跳过、会话记 `plugin-failed`，还没取到 `/manifest` 的插件和认证插件则 `502`。
- 拉起的进程在监听之前就退出了，等它的请求立刻按"插件连不上"处理，原因写明退出码，比如 `the plugin's process is not running: it exited (exit status: 1) before it was listening`；之后 1 秒内来的请求直接拿到这个原因，不再拉起。一个加载就抛异常的插件，复核时每 200 ms 一个请求、持续 12 秒，最长 68 ms 就拿到 502；以前中位 5 秒（2026-10-07 修，R6-02）。
- 每次拉起都换一个当时空着的端口，`WHIX_PLUGIN_PORT` 跟着变，日志的 `started again on 127.0.0.1:<端口>` 写明是哪个。SDK 每次启动都读这个变量，不用改什么。为什么换：进程没了以后，旧端口谁都能占；以前沿用旧端口时，新进程绑不上、马上退出，可"端口能连上"已经成立，请求连同 URL 和 `Authorization` 被发给了占端口的那个程序，然后照常去了源站（2026-10-07 修，R6-01）。插件不在的时候，代理也不会再往旧端口发任何东西，统计钩子的调用那段时间直接丢掉。
- 只管 `--node-plugin`。`--plugin name=host:port` 指向的进程不归 whix 管，它退出了就是连不上。

以前（2026-10-06 之前）插件进程一退出就再也不回来，钩子一直失败，请求不经过插件照常转发。一个自己应答请求的插件崩掉之后，所有请求都直接到了真实源站。

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

### 认证钩子的边界

- **不覆盖未被解密的 CONNECT 隧道** —— 认证跑在请求上，隧道里没有请求可看。被 MITM 解密的
  HTTPS 请求（包括 WebSocket 握手）会正常过门；按规则直通的隧道不会。原版可以对隧道整体
  返回 `407`，这里不行。
- **升级请求能被拦，但拿不到注入的头** —— WebSocket 握手会正常过门（拦下就是一个普通的
  `401`/`403` 响应，`101` 不会发生），只是升级分支在插件头被应用到出站请求之前就分岔了，
  所以放行时 `setHeader` 的头不会出现在转发出去的握手里。这是升级路径既有的性质。
- **拿不到请求体** —— 见上文，这是取舍不是遗漏。
- **多个门是串行的** —— 命中 N 个带认证的插件就是 N 次串行往返，第一个说拦的终止其余。
  原版是并发发起、任一拒绝即拦截。顺序换来的是「谁拦的」是确定的，代价是延迟叠加。
- **超时固定 5 秒**，不可配置。
- **放行时注入的头，后面的插件看不到** —— 它们在规则算子之后才被应用到出站请求上，而同一轮里
  后续插件拿到的是这一轮开始时的请求头快照。上游服务器看到的是最终结果，插件之间看不到。

### 插件页面的边界

- **与控制台同一个登录** —— 见上文「失败与限制」；插件拿不到控制台的凭据。
- **只有相对链接可用**，且必须带尾斜杠访问（无尾斜杠会被 302）。
- **没有 `/whistle.<name>/` 别名**，也没有把插件页面嵌进 Network 面板的菜单/检查器扩展点
  （原版的 `MENU_URL` / `INSPECTOR_URL`）。
- **不能从 UI 路由升级 WebSocket。**

### 证书钩子的边界

- **失败的方向不可配置** —— 插件挂了就是「用自签的证书照常拦截」。想要相反的读法
  （插件挂了就不拦截）今天没有开关。理由见
  [出错了会怎样](#出错了会怎样--以及为什么这是一次政策选择)，但**这是一次政策选择，
  不是一条物理定律** —— 换一种部署可能需要另一个答案。
- **被放弃的连接仍然按规则路由，但不再被读取** —— `false` 之后，`host://` 与 `proxy://`
  一族**照常生效**：拒绝*读*一条连接不等于拒绝*安排它去哪*。原版的 `next(chunk)` 正是
  汇入它自己的隧道处理（`rollBackTunnel` → `handleTunnel` → `rules.getProxy`，
  `_original/lib/tunnel.js:259-271,:436`），本移植同样如此。
  拿不到的是所有需要读取内容才成立的东西：**不抓包、不应用请求/响应算子、没有响应阶段**——
  这里没有请求，只有我们答应不看的字节。
  两处细节：源站那一段**恒为明文转发**（TLS 由客户端自己和源站谈，我们再包一层就等于
  把自签证书塞给一条已经答应不拦截的连接）；`xhost://` / `xproxy://` 的一次性回退依旧
  有效（与原版隧道路径的 `retryXHost` 同源）。
  代理规则**无法兑现**时连接直接关闭，不会悄悄改成直连 —— 否则字节就走上了那条规则
  明确要绕开的线路。
- **中继到上游代理的 CONNECT 不带客户端的 UA 与 `Proxy-Authorization`** —— 这条路径上
  没有请求可供回显（原版在隧道路径上手里还有 CONNECT 的头）。代理 URL 自带的凭据
  （`proxy://user:pass@host`）照常使用，那也是代理规则携带凭据的常规写法。
- **拿不到 ClientHello 的其余部分** —— 钩子只被告知 servername。ALPN 提议、cipher 列表、
  扩展列表都不在 `ctx` 里。加进去很容易，但至今没有哪个用例需要它。
- **不能换 ALPN，也不能要求客户端证书** —— 插件给的是一张证书，不是一份 `ServerConfig`。
  代理用同一套条件把它端出去（`h2` + `http/1.1`），因为「挑一张证书」不该悄悄改变这条连接
  上每个请求怎么被代理。
- **一个 servername 一次决定** —— 判决作用于整条连接。同一条连接上后续请求的 `Host` 头
  再怎么变，证书都已经定了。
- **没有并发去重** —— 同一个名字上同时来 N 条连接就是 N 次插件调用。原版会把它们合并到
  一个回调列表里（`certCallbacks`，`lib/https/load-cert.js:26-29,:60-67`）；这里靠证书
  缓存把稳态摊平，但第一波并发不会被合并。
- **被放弃的连接不会出现在抓取列表里** —— 它对代理是密文，没有请求、没有帧可记。
  只有日志里那一行 `INFO sniCallback <plugin>: not intercepting <name>`。
- **只作用于被拦截的 TLS** —— 明文隧道没有 ClientHello，转发代理请求没有握手。

### 统计钩子的边界

- **不保证送达，也不保证顺序** —— 这是「发完不管」的定义，不是缺陷。
- **只有元信息** —— 没有耗时、没有字节数、没有 body。响应阶段在**响应头**就绪时触发，
  那时 body 还没走完。
- **没走到那一步就不会上报** —— 被拦截、被 `abort`、被规则短路的请求没有响应阶段。

### 其它

- **npm `whistle.*` 包兼容** —— 明确的非目标，见本文开头。
