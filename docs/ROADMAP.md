# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 的对齐进度**：已完成的工作，以及仍
**有意简化 / 尚未移植 / 架构受限**的更大子系统与少数边缘算子。

> 现状快照：73 个注册算子中 **70 个**已在运行时应用，另有别名算子层、本地文件/模板家族、
> `@`-includes、`${port}/${version}` 配置变量；单元测试 **60** 项全绿、构建 0 警告。
> 已完整验证：HTTP 正向代理、HTTPS MITM、HTTP/2、WebSocket（含逐帧抓取）、上游代理、
> 统一插件系统（Rust + Node）、流量检查（头 + Body 预览 + gzip/br/deflate 解码）、
> HAR 导出、`cipher` TLS 版本固定、流量落盘持久化、请求重放、规则分组管理。

---

## 已完成（本轮）

| 领域 | 状态 |
|------|------|
| 统一插件系统（Rust 进程内 + Node 子进程 + 远程） | ✅ `server`/`rulesServer` 钩子、二进制响应体、就绪等待 |
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

---

## 仍未对齐 / 后续计划

### 大型子系统（多天工作量）

- [ ] **现成 npm `whistle.*` 插件兼容加载器** —— 原版插件 API 基于对 Node `req`/`res`
      对象的装饰（`setRules`/`request`/`writeHead` 等约 2000 行加载器），并非简单的 HTTP
      头协议。要原样运行现有 npm 插件需移植这层加载器。当前的统一插件系统覆盖了最常用的
      `server`/`rulesServer` 能力（用 Rust 或按约定的 Node 协议编写），但不直接兼容任意
      `npm i whistle.xxx`。**这是投入产出比最高的下一块大工作。**
- [ ] **更多插件钩子**：`reqRead`/`resRead`（请求/响应体流式读写）、`uiServer`/
      `statsServer`（插件自带 UI/统计页）、`auth`、`sniCallback`。
- [ ] **`pipe://` 真正的流式管道** —— 当前与 `plugin://` 同为整体分发；真正的 pipe 需要
      把 Body 边流边过插件（依赖 `reqRead`/`resRead`）。
- [ ] **向插件传递请求体** —— 需要在插件分发前缓冲请求体并重构下游 Body 类型（对核心
      serve 管线是侵入式改动）；当前只传 方法/URL/头/客户端 IP/param。

### 观测与持久化

- [x] ~~**流量落盘持久化**~~ → 已完成（JSONL + 每日轮转 + 启动回加载）
- [x] ~~**请求重放**~~ → 已完成（self-loopback 通过代理自身端口）
- [x] ~~规则的导入/导出与分组管理~~ → 已完成（多组 CRUD + UI toggle/edit/delete）

### 模板与变量（原版本身很窄）

- [ ] `tpl`/`dust`/`jsonp` 升级为完整 dust.js / handlebars 语义（当前为 `{name}` 简单替换）。
- [ ] `{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 插件包变量（与插件运行时耦合）。
- [x] ~~`lineProps`（whistle 规则行级属性系统）~~ → **部分完成**，见
      [`LINE_PROPS.md`](LINE_PROPS.md)。解析层与原版完全对齐（`[|&]` 分隔、无转义、多令牌合并、
      未知属性保留）；`important` 已端到端生效；`internal`/`internalOnly` 的匹配门禁
      （`resolve_refs_scoped`）已实现并测试，但**尚无调用方传入内部请求标记**；
      `safeHtml`/`strictHtml` 的判定函数已就绪，等待 `apply.rs` 注入路径调用。
      其余 12 个属性已解析并可经 `Resolved::props(protocol)` 读取，暂无运行时效果。

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

- **逐字节复刻 React 前端** —— 内建轻量 UI 已覆盖核心检查/编辑需求；除非有明确诉求，
  不重写 `biz/webui`。
- **硬绑定 Node.js 运行时** —— 项目目标是单一静态二进制；Node 子进程插件加载器（含未来的
  npm 兼容层）将是可选特性，而非硬依赖。
- **`G` / `style` 算子的「流量效果」** —— `G` 是全局插件变量基础设施、`style` 是规则列表
  配色，二者都不是逐请求的流量算子；保持「解析但不产生效果」。

---

## 参与

若要优先某一项，**npm `whistle.*` 插件兼容加载器** 是解锁现有 whistle 生态、投入产出比
最高的下一块大工作。模块地图见 [`ARCHITECTURE.md`](ARCHITECTURE.md)，算子覆盖细节见
[`RULES.md`](RULES.md)，插件编写见 [`PLUGINS.md`](PLUGINS.md)。
