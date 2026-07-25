# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 的对齐进度**：已完成的工作，以及仍
**有意简化 / 尚未移植 / 架构受限**的更大子系统与少数边缘算子。

> 现状快照：73 个注册算子中 **70 个**已在运行时应用，另有别名算子层、本地文件/模板家族
> （含两遍替换与 `${var}` 运行时变量）、`@`-includes、规则行级属性；
> 单元测试 **181** 项全绿、构建 0 警告。
> 已完整验证：HTTP 正向代理、HTTPS MITM、HTTP/2、WebSocket（含逐帧抓取）、上游代理、
> 自研插件体系 v2（Rust 进程内 + JS/TS SDK）、流量检查（头 + Body 预览 + gzip/br/deflate 解码）、
> HAR 导出、`cipher` TLS 版本固定、流量落盘持久化、请求重放、规则分组管理。

---

## 已完成（本轮）

| 领域 | 状态 |
|------|------|
| 插件运行时（Rust 进程内 + 子进程 + 远程） | ✅ 二进制响应体、就绪等待、失败重试 |
| `@`-includes（从 URL / 文件引入规则） | ✅ 加载时解析 |
| `${port}` / `${version}` 配置变量 | ✅ |
| 响应体解码（gzip / deflate / brotli）用于查看 | ✅ 流式解码，界限 16 KB，不影响转发 |
| HAR 1.2 导出（`/sessions.har` + UI 下载） | ✅ |
| Web UI 过滤/搜索 | ✅ 按 URL/方法/状态/目标 |
| Body 预览上限可配置（`--body-preview-limit`） | ✅ |
| `internal-http-proxy` / `internal-https-proxy` | ✅ |
| `x`/`xs` 前缀代理变体 | ✅ 以基础代理近似 |
| `locationHref` 算子 | ✅ HTML 注入跳转脚本 |
| 流量落盘持久化 | ✅ JSONL 追加写入 + 每日轮转 + 启动恢复 (`--no-persist` / `--persist-days`) |
| 请求重放 | ✅ `POST /api/replay` self-loopback + UI ↻ 按钮 |
| 规则分组管理 | ✅ 多组 CRUD + toggle + 持久化到 `storage_dir/rules/` |
| 自研插件体系 v2 | ✅ 能力清单 (`GET /manifest`)、请求/响应双钩子、请求头改写、按需 body 投递 |
| JS / TS 插件 SDK | ✅ 零依赖运行时 + `.d.ts` 类型定义（`sdk/`），`satisfies Plugin` 可用 |

---

## 仍未对齐 / 后续计划

### 大型子系统（多天工作量）

- [x] ~~**向插件传递请求体**~~ → 已完成，见 [`PLUGINS.md`](PLUGINS.md)。请求体与响应体
      都可投递给插件，但**由插件的能力清单决定是否缓冲** —— 未声明的插件保持流式零开销
      （已用 SSE 实测双向验证）。
- [x] ~~**流式 body 钩子**（原版 `reqRead`/`resRead`）~~ → 已完成，见
      [`PLUGINS.md`](PLUGINS.md#流式钩子--pipe)。传输选了 HTTP/1.1 chunked 而非原版的
      CONNECT + `transproto` 分帧 —— 后者重新发明的正是 chunked，而 hyper 与 Node 两端都
      已实现好；代价是与原版 `pipe://` 插件不互通，理由与「不复刻原版插件 API」一致。
      握手先于字节：插件应答 200 之前的任何失败都零代价（body 原样放行）。
- [x] ~~**`pipe://` 真正的流式管道**~~ → 已完成。`pipe://` 现在选中流式钩子、支持
      `pipe://name(value)` 取值语法；指向没有流式钩子的插件时退化为 `plugin://`。
- [ ] **更多插件钩子**：`uiServer`/`statsServer`（插件自带 UI/统计页）、`auth`、
      `sniCallback`、WebSocket 帧级拦改。

### 规则解析（本轮审计修复）

- [x] ~~一行多个 pattern~~ → 已修。此前只取第一个 pattern，`host://x a.com b.com` 对 b.com 静默失效。
- [x] ~~行内 `#` 注释~~ → 已修。此前只处理行首 `#`。
- [x] ~~多行 `` line` `` 块~~ → 已实现。

### 模式匹配（本轮审计修复）

同一个根因的三处实例，都是**失败开放**（规则悄悄匹配了不该匹配的请求）：

- [x] ~~`:8080` 端口 pattern 匹配一切~~ → 已按上游编译为 `^[\w]+://[^/?]+:<port>/`。
- [x] ~~`example.test:8080` 忽略端口~~ → `Pattern::Prefix` 现在携带 `port`，匹配时校验。
- [x] ~~`!pattern` 取反~~ → 已支持，且与上游一致地**只作用于正则与端口 pattern**；
      上游对取反的字面量/通配 pattern 是在解析期直接丢弃的（`rules.js:1259-1268`），本移植照做。

### 筛选器（本轮审计发现）

原版文档的条件语法见 `_original/docs/docs/rules/filters.md`；以下差异均已用运行中的代理实测：

- [ ] **`reqH.<key>:<pattern>` 头筛选语法** —— 本移植用的是 `h:<key>=<value>`，上游写法会落到
      URL 正则回退上**静默永不匹配**。这是「为 whistle 写的规则文件在这里不工作」的最主要一处。
- [ ] `chance:<概率>` 随机采样、`b:` 请求体、`s:` 响应状态、`resH.` 响应头、`serverIp:`。
- [ ] `i:` 上游同时匹配客户端**与服务端** IP，本移植只匹配客户端。
- [ ] 条件值的 `/regexp/[i]` 形式（当前只支持精确匹配）。

未知条件会落到 URL 正则回退，因此不支持的筛选器让规则**惰性失效**而非错误命中 ——
失败是保守的，但静默。

### 观测与持久化

- [x] ~~**流量落盘持久化**~~ → 已完成（JSONL + 每日轮转 + 启动回加载）
- [x] ~~**请求重放**~~ → 已完成（self-loopback 通过代理自身端口）
- [x] ~~规则的导入/导出与分组管理~~ → 已完成（多组 CRUD + UI toggle/edit/delete）

### 模板与变量（原版本身很窄）

- [x] ~~`tpl`/`dust`/`jsonp` 升级为完整 dust.js / handlebars 语义~~ → **前提有误，已按上游实情完成**，
      见 [`TEMPLATES.md`](TEMPLATES.md)。原版**根本没有模板引擎**：`tpl`/`dust`/`jsonp`
      字节级等价，没有 section/循环/嵌套。真正缺失的是第二遍 `${var}` 运行时变量替换，
      现已实现（封闭白名单 + `.key` 子路径 + `${{var}}` URI 编码）。同时修正了三个缺陷：
      未知占位符曾被置空（上游是原样保留）、`jsonp://` 的 callback 包装是本移植凭空发明的
      （已移除）、第一遍正则曾每请求重新编译。
- [ ] `{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 插件包变量（与插件运行时耦合）。
- [x] ~~`lineProps`（whistle 规则行级属性系统）~~ → 见 [`LINE_PROPS.md`](LINE_PROPS.md)。
      解析层与原版完全对齐；`important`、`safeHtml`/`strictHtml` 注入门禁、
      `internal`/`internalOnly` 作用域、`proxyFirst`/`proxyHost`/`proxyHostOnly`、
      `weakRule` 均已端到端接线并验证。其余属性经核对**在本移植中无对应可接之处**
      （如本移植不发自动 CORS，`disableAutoCors` 无物可抑制），已在文档中逐条说明理由。

### 架构受限（rustls / MITM 时序）

- [ ] **`sniCallback`** —— 在 TLS SNI 阶段用插件选证书。我们的 MITM acceptor 在 SNI 阶段
      按域名构建，早于按请求的规则解析，且需插件运行时在该时点介入；当前架构下不可达。
- [ ] **`cipher` 扩展** —— rustls 只暴露 TLS 1.2/1.3、不接受 OpenSSL cipher 字符串，故只支持
      版本固定（已实现），无法完整对齐 Node 的 TLS 选项。

### 非功能项

- [ ] 性能剖析（大响应体、并发连接下 tee 抓取开销）。
- [ ] 清理较新工具链带来的 clippy 风格提示（`collapsible_if` 等）。

---

## 不打算做的事（Non-goals）

- **现成 npm `whistle.*` 包的兼容运行** —— 原版插件 API 建立在对 Node `req`/`res` 对象的
  装饰之上（约 2600 行加载器、位置式 CSV 头协议、单端口多钩子分发）。与其被这套历史包袱
  绑定，whistle-rs 选择了一套显式、有类型、语言无关的自研协议，配 JS/TS SDK。
  见 [`PLUGINS.md`](PLUGINS.md)。

- **逐字节复刻 React 前端** —— 内建轻量 UI 已覆盖核心检查/编辑需求；除非有明确诉求，
  不重写 `biz/webui`。
- **硬绑定 Node.js 运行时** —— 项目目标是单一静态二进制。JS/TS 插件跑在子进程里，
  是**可选**特性：不写插件就完全不需要 Node。
- **`G` / `style` 算子的「流量效果」** —— `G` 是全局插件变量基础设施、`style` 是规则列表
  配色，二者都不是逐请求的流量算子；保持「解析但不产生效果」。

---

## 参与

剩下的多为增量工作。最接近「架构挡住的能力」的一项是 **WebSocket 帧级拦改** ——
帧已经抓到并展示了，但插件还够不着；流式钩子的传输层可以复用，缺的是帧级的接线。

模块地图见 [`ARCHITECTURE.md`](ARCHITECTURE.md)，算子覆盖见 [`RULES.md`](RULES.md)，
插件编写见 [`PLUGINS.md`](PLUGINS.md)，模板见 [`TEMPLATES.md`](TEMPLATES.md)，
规则行级属性见 [`LINE_PROPS.md`](LINE_PROPS.md)。
