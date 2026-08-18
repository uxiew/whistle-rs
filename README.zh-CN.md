# whistle-rs

[English](README.md) · **简体中文** · [路线图 / Roadmap](docs/ROADMAP.md)

[whistle](https://wproxy.org)（HTTP / HTTPS / WebSocket 调试代理）**核心**的 Rust 移植版。
它实现了 whistle 最核心、最吃重的部分：**规则 DSL 引擎**、**代理服务器**（HTTP 正向代理 +
CONNECT 隧道 + HTTPS 中间人）以及**动态 CA 证书生成**。

原始 JavaScript 源码**不随本仓库分发** —— 取回方式与对应提交见
[`docs/UPSTREAM.md`](docs/UPSTREAM.md)。本移植逐模块对应到它
（见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)）。

## 目录

- [功能特性](#功能特性)
- [安装与构建](#安装与构建)
- [快速开始](#快速开始)
- [配置客户端](#配置客户端)
- [拦截 HTTPS](#拦截-https)
- [编写规则](#编写规则)
- [使用手册 / Cookbook](docs/COOKBOOK.zh-CN.md) —— 大家真正会做的那些事的配方
- [作为库使用](#作为库使用)
- [命令行参数](#命令行参数)
- [文档](#文档)
- [移植范围：已实现 vs. 简化](#移植范围已实现-vs-简化)
- [故障排查](#故障排查)
- [开发](#开发)
- [路线图](#路线图)
- [许可证](#许可证)

## 功能特性

- **HTTP 正向代理** —— 标准的 absolute-form 代理转发。
- **HTTPS 中间人（MITM）** —— 拦截 `CONNECT`，用本地生成并持久化的根 CA
  为每个域名即时签发证书。
- **HTTP/2** —— 被拦截的 TLS 连接通过 ALPN 协商 `h2` 并以 HTTP/2 提供服务
  （上游仍走 HTTP/1.1，由 hyper 转换），无法协商时回退到 HTTP/1.1。
- **WebSocket** —— `ws://` 及（经 MITM 的）`wss://` 升级端到端隧道转发，
  并逐帧抓取，在网络面板中呈现每一帧。
- **上游代理** —— 可经由另一个 HTTP/HTTPS 代理或 SOCKS5 代理转发。
- **内建 SOCKS5 服务** —— 接受 SOCKS5 客户端（`--socks-port`）进入同一套拦截管线，
  自动识别 TLS 与明文 HTTP。
- **规则引擎** —— whistle 规则语法：域名/前缀、前导点子域、域名通配符、`^` 前缀的
  路径/查询通配符（含 `$1`…`$9` 子匹配传值）与正则模式；`lineProps://important` 高优先级；多命中累加。
- **转发** —— 一个裸 URL 就把站点指向本地开发服务
  （`www.example.com http://localhost:5173`），未命中的路径会自动拼接过去。
- **目标改写**（`host://`）—— 改写目标 IP/端口，同时保留原始 `Host` 头与 TLS SNI ——
  这正是调试代理的核心行为。
- **请求/响应改写** —— 头、Cookie、Body（替换/前插/追加/正则）、URL/查询串、
  User-Agent、方法、Content-Type、CORS、鉴权、延迟、状态码替换、重定向、本地文件服务。
- **流量检查** —— 每条事务记录请求/响应头与有界的 Body 预览（通过流式 tee 抓取，
  因此分块 / SSE 响应也可查看且不破坏流式传输；`gzip`/`deflate`/`br` 压缩体会被解码后
  预览）。可在控制台里过滤/排序，或访问 `/sessions.json`、`/session.json?id=`，也可导出为
  HAR 文件（`/sessions.har`）。
- **控制台** —— 自包含单页（浏览器直接访问代理地址即可打开）：左侧来源列表、上方可排序的
  请求表格、下方详情面板（General / 请求头 / 响应头 / 请求体 / 响应体 / WebSocket 帧）。
  方向键遍历抓包，`Copy as cURL` 按**源站实际收到**的形态复现请求，JSON 响应体可就地格式化。
  Status 面板报告端口、TLS 姿态、根证书路径与已注册插件。**Test Rules** 面板回答规则
  文件最常见的那个问题 —— 这条请求会命中哪些算子 —— 一个字节都不发出去；和命令行的
  `whistle-rs explain`、上游控制台的 Test Rules 是同一个答案。Frames 标签页可以往
  **还开着**的连接里发帧，两个方向都行。
- **带语法高亮的规则编辑器** —— CodeMirror 6，配一个 whistle 专用 mode：它标出**代理将用哪个
  token 去匹配**，而这正是规则文件唯一会「静默写错」的地方。该 mode 跑的是解析器同一套行切分
  算法，并有测试把两者钉在一起。控制台本身是 Vue 3 应用，构建为**单个自包含文件** ——
  见 [`ui-src/`](ui-src/)。
- **流量持久化** —— 捕获的请求/响应以 JSONL 格式写入磁盘，每日自动轮转；重启后自动恢复
  历史流量。通过 `--no-persist` 关闭，`--persist-days` 控制保留天数。
- **请求重放** —— 通过 `POST /api/replay` 或控制台的 Replay 按钮重发已捕获的请求，
  走完整规则管线。
- **规则分组** —— 多个命名规则集与默认组并列显示在控制台的来源列表里，每组可独立
  启用/禁用（双击切换）。分组持久化到 `storage_dir/rules/`。
- **单一静态二进制**，构建无需 C 工具链（固定使用 `ring` TLS provider）。

## 安装与构建

需要较新的稳定版 Rust 工具链。

```bash
cargo build --release
# 二进制位于 ./target/release/whistle-rs
```

代理本身不需要别的东西。**Web 控制台**是一份单独的 Vite 产物，只生成不入库；
想要它就先构建，Rust 编译期会把它内联进来。没有构建时 `/` 会返回一个占位页，
并在编译时打一条 warning 说清缺了什么：

```bash
cd ui-src && npm install && npm run build && cd ..
cargo build --release
```

## 快速开始

```bash
# 在 whistle 默认端口 8899 启动，并加载规则文件
./target/release/whistle-rs -p 8899 -r rules.txt

# 或使用内联规则并开启详细日志
./target/release/whistle-rs --rule "test.local 127.0.0.1:9099" -v
```

仓库内自带一个可直接使用的 [`rules.txt`](rules.txt)。启动时会打印监听地址与根 CA 位置。

## 配置客户端

将客户端的 **HTTP 与 HTTPS** 代理都指向 `HOST:PORT`（默认 `127.0.0.1:8899`）。

```bash
# curl
curl -x http://127.0.0.1:8899 http://example.com/

# 整个 shell 会话
export http_proxy=http://127.0.0.1:8899 https_proxy=http://127.0.0.1:8899
```

**浏览器 / 系统：** 将系统或浏览器的 HTTP+HTTPS 代理设为同一 host/port。

**手机或另一台机器**要用的是本机在局域网里的地址，不是 `127.0.0.1`。whistle-rs 启动时
就会打印出来：

```
INFO on this network: http://192.168.2.203:8899 — set one as the proxy on a phone
     (try each if unsure), then open http://rootca.pro/ to install the certificate
```

`GET /api/status` 里的 `lan_addresses` 是同一份列表。另外确认端口可达——十有八九是本机
防火墙拦了。

### 打开控制台

两条路，第二条是 whistle 官方文档教的那条：

```
http://127.0.0.1:8899/        # 直接访问，不经过代理
http://local.whistlejs.com/   # 经过代理 —— 这个域名本身就是控制台
```

`local.whistlejs.com`、`local.wproxy.org` 和 **`rootca.pro`** 由代理自己应答、不转发出去，
跟 whistle 一样。前两个开控制台；`rootca.pro` **在任何路径下**都直接给出根证书 —— 这就是
手机那套流程：设好代理、打开 `rootca.pro`、装它给你的东西。用 `-l/--local-ui-host`
可以再加域名，用 `-M pureProxy` 可以让它们变回普通域名照常转发。

`GET /sessions.json` 返回抓包数据（JSON），`GET /proxy.pac` 提供可自动配置客户端的 PAC 文件。

### 在一堆请求里找东西

控制台的搜索框用的是 whistle 那套筛选语法：不带前缀就是匹配 URL，带前缀则问别的东西，
多个条件之间是「与」。

| | | | |
|---|---|---|---|
| `m:` 方法 | `s:` 状态码 | `t:` Content-Type | `H:` Host |
| `i:` 客户端或服务端 IP | `e:` 出错的 | `style:` `style://` 的值 | `mark:` 手工标记的 |

每个都吃**关键字或 `/正则/flags`** —— `m:POST s:/^5/ H:api.example.com` 就是「某个域名下
失败的 POST」。`e:` 和 `mark:` 单独写表示那个集合本身。还有四个这里答不了的
（`h:`、`b:` —— 列表行不带头和 body；`app:`、`fc:`），会在输入框下方说明原因，
而不是给你一个空列表。

## 拦截 HTTPS

HTTPS 流量是加密的，要读取/改写它，whistle-rs 会出示一份自己签发的证书。
客户端必须先信任根 CA：

1. 启动 whistle-rs，从 <http://127.0.0.1:8899/rootCA.crt> 下载 CA
   （或复制 `~/.whistle-rs/certs/root.crt`）。**手机或另一台机器**上更省事：先把代理设好，
   然后打开 <http://rootca.pro/> —— 这个域名由代理应答并直接下发证书，不用记地址。
2. 在操作系统/浏览器中安装并信任它 —— **各平台分步说明见
   [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md)**。
3. 验证：

   ```bash
   curl -x http://127.0.0.1:8899 \
        --cacert ~/.whistle-rs/certs/root.crt \
        https://example.com/ -D - -o /dev/null   # → HTTP/1.1 200 OK
   ```

## 编写规则

每行形如 `pattern operator1 operator2 …`。几个例子：

```
# 把站点交给本地开发服务（剩余路径会跟着走）
www.example.com       http://localhost:5173

# 改写目标地址、保留 Host 头（hosts 简写）
test.local            127.0.0.1:9099

# 显式目标改写（同时作用于 http + https）
.cdn.example.com      host://10.0.0.9

# 正则模式 → 设置响应 Content-Type
/\.js(\?|$)/          resType://application/javascript

# 域名通配符 → 重定向（短路上游）
*.old.example.com     redirect://https://new.example.com/

# `^` 让每个 `*` 都成为通配符，$1… 就是它们匹配到的内容
^http://*.example.com/v0/users/**   file:///mock/$1/$2

# 注入头（同名规则跨行累加）
example.com           reqHeaders://x-token=abc
example.com           resHeaders://x-mitm=intercepted

# $ 前缀 = 高优先级；胜过普通规则
$example.com          host://2.2.2.2
```

写规则文件之前，这套语法里有三件事值得先知道，因为每一件都会产出「静默不生效」的规则：

- **位置决定一切，形状不决定。** 第一个 token 是 pattern，其后**全部**是算子 ——
  `example.com http://localhost:5173` 是一条转发规则，不是两个 pattern。
- **算子取值里不能有空格。** `reqHeaders://authorization=Bearer secret` 会设成
  `authorization: Bearer`，然后把请求发到一台叫 `secret` 的主机上。请用命名 value 加 `${name}`。
- **`file`、`redirect`、`statusCode`、模板家族与裸目标 URL 共用一个槽位**，先写的赢 ——
  所以写在转发**下面**的 mock 永远不会执行。

**大家真正会做的那些事的配方 —— 把站点交给开发服务、mock 接口、限速、调手机、导出 HAR ——
见 [`docs/COOKBOOK.zh-CN.md`](docs/COOKBOOK.zh-CN.md)。完整语法 —— 每种模式与算子、
优先级规则、算子覆盖 —— 见 [`docs/RULES.md`](docs/RULES.md)。**

## 作为库使用

whistle-rs 是「一个库 + 一个跑在它上面的二进制」，而不是反过来。如果你要做的东西**自己内部**
需要流量拦截或接口调试 —— 你自己的代理程序、测试夹具、桌面应用 —— 直接嵌进去：

```toml
[dependencies]
whistle-rs = { path = "…" }   # 或 git / crates.io 依赖
tokio = { version = "1", features = ["full"] }
```

```rust
use whistle_rs::embed::Proxy;

let proxy = Proxy::builder()
    .port(0)                        // 0：由系统挑端口，addr() 告诉你挑了哪个
    .host("127.0.0.1".parse()?)     // 不暴露到网络上
    .rules("api.example.com  http://127.0.0.1:3000")
    .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
    .start()
    .await?;

println!("把客户端指向 {}", proxy.addr());
proxy.set_rules("api.example.com  statusCode://503");   // 运行中热更新
proxy.shutdown().await;
```

要**改**流量而不只是看，就注册一个进程内钩子。它就是内建插件用的那个 `RustPlugin` trait，
因此可以改写请求头、注入规则、直接应答请求、做鉴权拦截、变换响应，或在握手期挑证书：

```rust
struct MockApi;

impl RustPlugin for MockApi {
    fn name(&self) -> &str { "mock-api" }
    fn on_request(&self, req: &PluginReq) -> PluginResult {
        PluginResult {
            response: Some(PluginResp { status: 200, headers: vec![], body: b"{}".to_vec() }),
            ..Default::default()
        }
    }
}

Proxy::builder().plugin(MockApi).rules("api.test  plugin://mock-api")
```

`cargo run --example embedded` 会把上面这些端到端跑一遍。builder 还覆盖 SOCKS5 端口、
存储目录（两个 embedder 共用同一目录即共用一份 CA）、values、Body 抓取上限，以及
`intercept_https(false)` —— 只路由 TLS 而不解密。facade 之外的东西都可以从 `proxy.state()`
拿到：会话环、规则管理器、插件注册表、CA。

## 命令行参数

| 参数 | 含义 | 默认值 |
|------|------|--------|
| `-p, --port <PORT>` | 代理端口 | `8899` |
| `-H, --host <IP>` | 绑定地址 | 所有网卡（`0.0.0.0`） |
| `-P, --uiport <PORT>` | 把控制台单独放到一个端口（上游的 `-P`）。不设则跟上游一样，控制台就在代理端口上 | 代理端口 |
| `-n, --username <NAME>` / `-w, --password <PASS>` | 控制台登录（上游的 `-n`/`-w`）。都不设则控制台不设防 | 不设防 |
| `-N, --guest-name <NAME>` / `-W, --guest-password <PASS>` | 只读账号（上游的 `-N`/`-W`）：只放行 `GET`，能看抓包、改不了任何东西 | —— |
| `-M, --mode <LIST>` | 启动模式（上游的 `-M`），用 `\|`/`,`/`&` 分隔。已生效：`pureProxy`（不再应答控制台域名）、`headless`（关掉控制台，只留证书与 PAC）、`capture`/`disableCapture`（HTTPS 解密开关）、`keepXFF`（放行客户端自带的 `x-forwarded-for`）。其余上游认识的 token 会在启动时报「此处无对应行为」 | — |
| `-l, --local-ui-host <HOSTS>` | 追加能打开控制台的域名（上游的 `-l`），用 `\|`、`,` 或 `&` 分隔。不设时 `local.whistlejs.com`、`local.wproxy.org`、`rootca.pro` 也已生效 | 内建三个 |
| `--socks-port <PORT>` | 额外启动内建 SOCKS5 服务（上游拼作 `--socksPort`，同样接受） | 关闭 |
| `--plugin <NAME=HOST:PORT>` | 注册一个远程（Node/HTTP）插件（可重复） | —— |
| `--node-plugin <NAME=PATH>` | 从脚本拉起一个 Node 插件（可重复） | —— |
| `--value <NAME=CONTENT>` | 定义命名 value（可重复），规则中以 `{name}` 引用 | —— |
| `-r, --rules <FILE>` | 启动时加载的规则文件 | —— |
| `--rule <TEXT>` | 内联规则，在 `--rules` 之后应用 | —— |
| `--dir <DIR>` | 存储目录（根 CA 等） | `~/.whistle-rs` |
| `--body-preview-limit <BYTES>` | 每条事务保留的 Body 预览上限字节数 | `16384` |
| `--no-persist` | 关闭流量落盘（仅存内存） | 开启落盘 |
| `--persist-days <N>` | 磁盘上保留多少天的历史 | `7` |
| `-R, --req-cache-size <N>` | 内存里保留多少条抓包（上游的 `-R`）。小于默认值的会被忽略，上游也是这么做的 | `600` |
| `-F, --frame-cache-size <N>` | 内存里保留多少个 WebSocket 帧（上游的 `-F`）。上游那道下限是拿 720 去比、落回 600，中间这一段等于没设 | `600` |
| `--insecure-upstream` | **不**校验源站 TLS 证书。与上游不同，whistle-rs 默认校验 —— 见 [源站证书校验](docs/RULES.md#origin-certificate-verification) | 校验开启 |
| `--no-intercept-https` | 不解密 HTTPS：每条 TLS 连接原样中继，但仍按规则路由（上游写作 `-M pureProxy`） | 拦截开启 |
| `-t, --timeout <MS>` | 到源站 / 上游代理的连接**建立**超时。已建立的连接不会被切断，流式响应不受影响。它只会**收紧**：底下还有 16 秒硬上限，所以默认值实际是 16 秒，只有设到它以下才起作用 | `360000` |
| `-v, --verbose` | 调试日志 —— 失败的**原因**，这是光看 `502` 得不到的 | 关闭 |
| `-h, --help` / `-V, --version` | 帮助 / 版本 | —— |

### `whistle-rs explain` —— 这个请求会命中哪些规则？

原版控制台里的 *Test Rules*，这里是一个子命令，而且**什么都不启动** —— 不开服务、
不建存储目录、不生成 CA。它回答的是规则文件最常见的那个问题：**一条不命中的规则什么
也不报**，命中和落空在客户端那边长得一模一样。

```console
$ whistle-rs explain --rules rules.txt -X POST -H 'x-env: staging' \
    'http://www.example.com/api/list?id=2'
http://www.example.com/api/list?id=2
  rule        http://localhost:5173/api/list?id=2   [slot]
      on: www.example.com http://localhost:5173
  reqHeaders  x-env=staging
      on: www.example.com/api reqHeaders://x-env=staging
```

`[slot]` 标出赢下[共享槽位](docs/RULES.md#short-circuit-no-upstream-request-is-made)
的那个算子 —— 输的那些**根本不在输出里**，这就是「我的 mock 为什么被忽略」的答案。
另有 `--body`（喂 `b:` 条件）、`--client-ip`（喂 `clientIp:`）、
`--value NAME=CONTENT`（取值）、`--json`，以及 `--batch`（stdin 一行一个 JSON 问题）。
最后这个就是 `tests/differential/rules-oracle.js` 的接口：同样一万七千个问题，一边问
本移植、一边问 whistle 自己的解析器，逐条比对。

## 文档
- [`docs/UPSTREAM.md`](docs/UPSTREAM.md) —— 原版 whistle 的取回方式与提交号；源码里 513 处 `_original/…` 引用都指向它


| 文档 | 内容 |
|------|------|
| [`docs/COOKBOOK.zh-CN.md`](docs/COOKBOOK.zh-CN.md) | 按任务组织的实操手册：开发服务、mock、改写、限速、手机、HAR、嵌入 —— 从这里开始 |
| [`docs/RULES.md`](docs/RULES.md) | 完整规则语法：模式、算子、优先级、速查、兼容性、算子覆盖表 |
| [`docs/CLI.md`](docs/CLI.md) | 命令行逐项对照：每个上游参数在这里是什么行为、`-M/--mode` 认哪些、以及 `w2 start` 这类子命令该怎么替代 |
| [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md) | 在各平台下载、安装并信任根 CA |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 模块地图、请求生命周期、如何扩展代理 |
| [`docs/PLUGINS.md`](docs/PLUGINS.md) | 编写插件（Rust 进程内 + Node 子进程）与 JSON 协议 |
| [`docs/TEMPLATES.md`](docs/TEMPLATES.md) | 本地文件与模板：两遍替换、`${var}` 变量表、jsonp、Content-Type 推断 |
| [`docs/LINE_PROPS.md`](docs/LINE_PROPS.md) | 规则行级属性 `lineProps://`：语法、属性表与各自的接线状态 |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | 未来计划与仍简化/未对齐的子系统 |

## 移植范围：已实现 vs. 简化

> whistle 是一个成熟的约 3.2 万行核心，外加 245 个文件的 web-UI/插件层与一个 React 前端。
> 本项目**不是**对这一切的 1:1 移植 —— 而是对「代理 + 规则」核心的忠实、可运行实现，
> 并按可增量补齐其余部分的方式组织代码。

**完整可用（均已端到端验证）：**

- HTTP 正向代理；CONNECT 隧道 + HTTPS MITM + 动态逐域名证书
- HTTP/2 拦截（ALPN h2），失败回退 HTTP/1.1
- WebSocket（`ws://`/`wss://`）升级隧道**并逐帧抓取**
- 根 CA 生成、持久化与 `/rootCA.crt` 下载
- 规则引擎：注释、hosts 简写、正则/通配/前缀/点模式、`lineProps://important` 高优先级、多命中累加、
  `ignore://`、`filter`/`includeFilter`/`excludeFilter` 条件（方法/域名/头/客户端 IP/URL）
- 上游路由：`proxy`/`http-proxy`/`https-proxy`/`internal-proxy`（HTTP 代理）与
  `socks`（SOCKS5）；`pac`（求值 PAC 选择代理）
- 运行时应用的算子：**whistle 73 个注册算子中的 70 个** —— 头、Cookie、`delete`、charset、
  Body 改写（通用 + `css`/`html`/`js` + `resMerge`）、`trailers`、`headerReplace`、
  URL/查询、`ua`/`referer`/`method`/`auth`/`forwardedFor`、延迟/限速、`cache`、`attachment`、
  `redirect`/`file`/`statusCode`、`enable`/`disable` 标志、`reqWrite`/`resWrite`(`Raw`)、
  `responseFor`、`log`、`cipher`（上游 TLS 版本固定）、`resScript`/`frameScript`、
  `plugin`/`pipe`、`weinre`、`rule`/`rulesFile` 引入、以及 `{name}` value 引用。
  另外还有**本地文件 / 模板家族**（`file`/`rawfile`/`tpl`/`jsonp`/`dust` 及其 `x`/`xs`
  回退变体）与 whistle 的**别名算子**（`hosts`、`html`、`css`、`js`、`download`、`status`、
  `skip`、`tlsOptions`、`pathReplace`、`reqMerge` 等），均归一化到规范名。
  完整映射见 [`docs/RULES.md#operator-coverage`](docs/RULES.md#operator-coverage)。
- 流量检查：逐事务的请求/响应头 + Body 预览
- 三栏控制台：请求按客户端分组、表格可按任意列排序与过滤，详情面板含头、解码后的
  Body 预览与逐连接的 WebSocket 帧；规则分组与 Values 在同一外壳内编辑。
  `/sessions.json`、`/session.json?id=`、`/frames.json`、`/sessions.har`（HAR 导出）、
  `/proxy.pac`
- `@`-includes（从 URL/文件引入规则）与 `${port}`/`${version}` 配置变量

仅剩 **2** 个算子未实现 —— `G`（全局规则标记）与 `style`（界面里的规则颜色）——
每个都在覆盖表中注明了原因。`sniCallback` 曾是第三个：它现在已实现，而那条
「架构不可达」的记录本身是错的，不只是过时。

**插件**是 whistle-rs 自研的体系，两种运行时共用同一套契约（`plugin://name`）：
**Rust** 进程内插件（`RustPlugin` trait）与 **JS/TS** 插件（`sdk/` 提供零依赖运行时
与 `.d.ts` 类型）—— whistle-rs 可拉起 Node 进程（`--node-plugin`）或指向已运行的
进程（`--plugin`）。插件可以注入规则、直接应答、改写请求头，以及改写响应的状态码/头/体；
是否投递 body 由插件的能力清单决定，未声明的插件保持流式零开销。还有一个钩子根本不作用在
请求上：`sniCallback://name` 在 TLS 握手期决定被拦截的连接拿到哪张证书 —— 或者干脆不拦。
详见 [`docs/PLUGINS.md`](docs/PLUGINS.md)。

这不是原版插件 API 的复刻，现成的 `npm i whistle.xxx` 包无法直接运行 —— 这是有意的取舍，
理由见[路线图的 Non-goals](docs/ROADMAP.md)。

**相对原版的其他简化**（可用，但非逐字节移植）：whistle 的 React web UI（`biz/`）由一个
轻量内建控制台替代；weinre 仅做脚本注入（inspector 服务在外部）；流量抓取（含头、Body 与
WebSocket 帧）保留在内存的环形缓冲中，可选落盘（`--no-persist` 关闭），Body 预览上限
默认 16 KB（`--body-preview-limit` 可调），gzip/deflate/brotli 会为查看而解码。

算子级别的细节见 [`docs/RULES.md#operator-coverage`](docs/RULES.md#operator-coverage)，
未来计划见 [`docs/ROADMAP.md`](docs/ROADMAP.md)。

## 故障排查

**先问抓包命中了哪些规则。** 每条会话都记录了为它解析出来的算子，含「原文」与「结果」两栏 ——
不在表里的算子就是根本没匹配上，在表里但 `value` 不对的则是替换问题而非匹配问题：

```bash
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
s = json.load(sys.stdin)[0]
print(s["url"])
for r in s["rules"]: print(" ", r["raw"], "->", r["value"])'
```

**然后看日志。** 每个请求都会打印它解析出的目标，其余的答案通常就在这一行里：

```
INFO GET http://seg.test/path/to/x  -> 127.0.0.1:5173 (http)   # 规则命中
INFO GET http://seg.test/path/toxxx -> seg.test:80    (http)   # 没命中
INFO OPTIONS http://api.test/users  -> short-circuit           # 本地应答
```

这几行是 `INFO`，不加任何参数就有。`-v` 补上失败的**原因** —— 光看一个 `502` 是得不到的：

```
DEBUG request failed: connecting to 127.0.0.1:9: Connection refused (os error 61)
DEBUG request failed: upstream TLS handshake: invalid peer certificate: …
```

### 什么都没被拦到

| 现象 | 原因 / 解决 |
|------|------------|
| **直连**请求返回带 `Proxy-Connection` 头的 `502` | shell 设了 `http_proxy`，于是连 `http://127.0.0.1:8899/` 都走了*另一个*代理。curl 加 `--noproxy '*'`，或取消该环境变量。 |
| 控制台只有一行行 `CONNECT`，里面什么都没有 | HTTPS 被隧道转发而没有被解密 —— 客户端不信任根 CA。见 [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md)。Firefox 要装进*它自己*的证书库；iOS 还需要单独的第二步「启用完全信任」，大多数人在这一步之前就停了。 |
| 浏览器提示证书不受信任 | 同一个原因，早一步。 |
| 局域网设备连不上代理 | whistle-rs 默认绑定所有网卡，所以检查防火墙，以及你给设备的是不是**局域网**地址而不是 `127.0.0.1`。在设备上打开 `http://<局域网IP>:8899/proxy.pac` 既能测连通性，又能一次拿到正确的 PAC。 |
| 端口被占用 | 换一个端口：`-p`。 |

### 规则不生效

| 现象 | 原因 / 解决 |
|------|------------|
| 命中了你以为不该命中的 URL，或反过来 | 路径前缀只在 `/`、`\`、`?` 边界上匹配：`example.com/path/to` 命中 `/path/to/x`，但**不**命中 `/path/toxxx`。 |
| 路径里的 `*` 什么都匹配不到 | `*` **只在域名部分**是通配符；在路径里它是字面量，因为 `*` 是合法的 URL 字符。要路径通配请写 `^http://example.com/old/**`。筛选器是例外 —— 它的 pattern 总按 `^` 解读。 |
| mock / 重定向 / 转发被静默忽略 | `file`、`redirect`、`statusCode`、模板家族与裸目标 URL **共用一个槽位**，第一条填进去的完全获胜。写在转发下面的 mock 永远不会执行 —— 把它往上挪，或标 `lineProps://important`。 |
| 算子取值被截断 | 里面有空格，而行是按空白切分的。`reqHeaders://authorization=Bearer secret` 设成 `Bearer`，然后把请求路由到一台叫 `secret` 的主机。百分号编码救不了；用命名 value 加 `${name}`。 |
| 整行只对一部分请求生效 | 筛选器的作用域是**整行**，包括目标。`host://` 旁边写了 `includeFilter://from:composer`，这个改写就只对重放生效。 |
| 两行设了同一个头，少了一个 | 同名争用由**首行**获胜，important 行在前。 |
| 赢的是一条你没料到的规则 | `lineProps://important` 的行先于其余一切解析，与行序无关。行首的 `$` **不是**它 —— 那是原版的精确匹配 pattern。 |

### 生效了，但结果不对

| 现象 | 原因 / 解决 |
|------|------------|
| 自签名 / 私有 CA 源站返回 `502` | whistle-rs **校验**源站证书，上游不校验（那边 `rejectUnauthorized` 默认为 `false`，仅 `--safe` 打开）。这是本移植唯一刻意不照抄上游默认值的地方 —— 一个对任何源站证书照单全收的调试代理，无法告诉你它正在检查的连接自己也被劫持了。用 `--insecure-upstream` 关掉。 |
| 转发到被拦截主机时报 `502` | 上游连接或其 TLS 失败 —— `-v` 会给出目标与错误。`host://` 若把 TLS 指向非 TLS 端口会握手失败。 |
| 请求挂一分多钟才失败 | 目标是**丢包**而不是拒绝连接，于是这段等待就是操作系统的 TCP 超时。`-t 3000` 给连接**建立**封顶（不影响已建立的连接，流式响应是安全的）。 |
| `resDelay://1s` 瞬间就过去了 | 延迟单位是**毫秒**，单位后缀会被解析掉然后丢弃而不是换算，所以 `1s` 是 1 毫秒。写 `1000`。 |
| 限速比预期快 8 倍 | `reqSpeed://` / `resSpeed://` 的单位是**千比特**每秒，不是千字节。本移植此前按千字节读，按旧行为写的数值乘以 8。 |
| SSE / chunked 响应不再流式 | 不该发生：`resReplace://` 随流生效、只扣住一小段尾巴，prepend/append/`resBody` 一族根本不需要缓冲 —— 实测一个每 200 毫秒发一条事件的 SSE 源站，带规则首字节 204 毫秒、不带 206 毫秒。**确实**要等最后一个字节的是那些天然需要整段 body 的算子（`resMerge://`、往标记语言里注入）。 |
| `statusCode://` 返回了空 body | 它就是这么设计的 —— 它**造**一个响应。要改一个本来就有 body 的响应的状态码，用 `replaceStatus://`。 |
| 给了路径的算子发出来的东西不是你写的那串字 | 这正是它的语义：算子取值若命名了一个**位置**，会在算子生效前被**读出来**（上游的 `readRuleValue`），所以 `resBody:///tmp/mock.json` 发的是文件内容，`resBody://https://cdn.test/mock.json` 每请求抓一次。要发那串字本身就包起来：`resBody://(/tmp/mock.json)`。 |
| 证书绑定的 App 一拦就崩 | 只放过这一个域名：`pinned.example.com sniCallback://no-mitm` 会逐字节中继它，同时仍按规则路由。`--no-intercept-https` 是对所有连接这么做。 |

### 抓包里没有它

| 现象 | 原因 / 解决 |
|------|------------|
| 失败的请求在控制台里根本找不到 | **没有拿到响应**的请求 —— 连接被拒、DNS 失败、TLS 握手失败 —— 不会被记为会话。它只出现在日志里。 |
| 详情面板里 body 被截断 | 预览上限默认 16 KB，用 `--body-preview-limit` 调高。 |
| 二进制 body 显示为 `[binary, N bytes]` | 二进制 body 在序列化时即被替换，因此图片与十六进制视图还做不了 —— 见 [`docs/ROADMAP.md`](docs/ROADMAP.md)。 |
| 重启之后抓包是空的 | 要么开了 `--no-persist`，要么 `--persist-days` 已经让 `<存储目录>/sessions/` 下的文件过期了。 |

上面每一条都有配套的实操配方（含对应的坑），见
[`docs/COOKBOOK.zh-CN.md`](docs/COOKBOOK.zh-CN.md)。

## 开发

```bash
cargo test                 # 规则引擎单元测试
cargo build --release
cargo run -- -p 8899 -r rules.txt -v
```

架构、请求生命周期图、以及新增算子或上游代理的示例见
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 路线图

仍处于简化/未对齐状态的子系统，以及按优先级排列的后续计划，见
**[`docs/ROADMAP.md`](docs/ROADMAP.md)**。

## 许可证

MIT（与上游 whistle 一致）。
