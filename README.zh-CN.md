# whistle-rs

[English](README.md) · **简体中文** · [路线图 / Roadmap](docs/ROADMAP.md)

[whistle](https://wproxy.org)（HTTP / HTTPS / WebSocket 调试代理）**核心**的 Rust 移植版。
它实现了 whistle 最核心、最吃重的部分：**规则 DSL 引擎**、**代理服务器**（HTTP 正向代理 +
CONNECT 隧道 + HTTPS 中间人）以及**动态 CA 证书生成**。

原始 JavaScript 源码位于 [`../_original`](../_original)；本移植逐模块对应到它
（见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)）。

## 目录

- [功能特性](#功能特性)
- [安装与构建](#安装与构建)
- [快速开始](#快速开始)
- [配置客户端](#配置客户端)
- [拦截 HTTPS](#拦截-https)
- [编写规则](#编写规则)
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
  路径/查询通配符（含 `$1`…`$9` 子匹配传值）与正则模式；`$` 高优先级；多命中累加。
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
  规则分组与 Values 在同一套外壳里编辑，规则改动即时生效。
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
cd whistle-rs
cargo build --release
# 二进制位于 ./target/release/whistle-rs
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
局域网内的设备请改用本机 IP（而非 `127.0.0.1`），并确保端口可达。

直接访问 <http://127.0.0.1:8899/>（**不经过**代理）可查看状态页，列出近期抓取的流量。
`GET /sessions.json` 返回同样的数据（JSON），`GET /proxy.pac` 提供可自动配置客户端的 PAC 文件。

## 拦截 HTTPS

HTTPS 流量是加密的，要读取/改写它，whistle-rs 会出示一份自己签发的证书。
客户端必须先信任根 CA：

1. 启动 whistle-rs，从 <http://127.0.0.1:8899/rootCA.crt> 下载 CA
   （或复制 `~/.whistle-rs/certs/root.crt`）。
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

**完整语法 —— 每种模式与算子、优先级规则、以及速查手册 —— 见
[`docs/RULES.md`](docs/RULES.md)。**

## 命令行参数

| 参数 | 含义 | 默认值 |
|------|------|--------|
| `-p, --port <PORT>` | 代理端口 | `8899` |
| `-H, --host <IP>` | 绑定地址 | 所有网卡（`0.0.0.0`） |
| `--socks-port <PORT>` | 额外启动内建 SOCKS5 服务 | 关闭 |
| `--plugin <NAME=HOST:PORT>` | 注册一个远程（Node/HTTP）插件（可重复） | —— |
| `--node-plugin <NAME=PATH>` | 从脚本拉起一个 Node 插件（可重复） | —— |
| `--value <NAME=CONTENT>` | 定义命名 value（可重复），规则中以 `{name}` 引用 | —— |
| `-r, --rules <FILE>` | 启动时加载的规则文件 | —— |
| `--rule <TEXT>` | 内联规则，在 `--rules` 之后应用 | —— |
| `--dir <DIR>` | 存储目录（根 CA 等） | `~/.whistle-rs` |
| `--body-preview-limit <BYTES>` | 每条事务保留的 Body 预览上限字节数 | `16384` |
| `-v, --verbose` | 调试日志（逐请求决策） | 关闭 |
| `-h, --help` / `-V, --version` | 帮助 / 版本 | —— |

## 文档

| 文档 | 内容 |
|------|------|
| [`docs/RULES.md`](docs/RULES.md) | 完整规则语法：模式、算子、优先级、速查、兼容性、算子覆盖表 |
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
- 规则引擎：注释、hosts 简写、正则/通配/前缀/点模式、`$` 高优先级、多命中累加、
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

| 现象 | 原因 / 解决 |
|------|------------|
| **直连**请求返回带 `Proxy-Connection` 头的 `502 Bad Gateway` | 你的 shell 设置了 `http_proxy`，请求走了*另一个*代理。curl 加 `--noproxy '*'`，或取消该环境变量。 |
| HTTPS 时浏览器提示证书不受信任 | 根 CA 尚未安装/信任 —— 见 [`docs/CERTIFICATES.md`](docs/CERTIFICATES.md)。Firefox 需装入它*自己*的证书库。 |
| 转发到被拦截主机时报 `502` | 上游连接/TLS 失败。用 `-v` 查看目标与错误。`host://` 若把 TLS 指向非 TLS 端口会握手失败。 |
| 某条规则似乎被忽略 | 检查优先级（`$` 与文件顺序），并确认该算子确实被**应用**（见范围表）。`-v` 会打印每个请求解析出的目标或短路决策。 |
| 端口被占用 | 换一个端口：`-p`。 |

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
