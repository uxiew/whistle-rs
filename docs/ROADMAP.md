# 路线图 / Roadmap

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本文件诚实记录 **whistle-rs 相对原版 whistle 仍未对齐的部分**，以及后续计划。
核心的「代理服务器 + 规则 DSL 引擎」已完整实现并端到端验证；下面列出的都是原版中
**有意简化或尚未移植**的更大子系统与少数边缘算子。

> 现状快照：73 个注册算子中 **70 个**已在运行时应用，另有别名算子层与本地文件/模板家族；
> 单元测试 38 项全绿、构建 0 警告。已完整验证：HTTP 正向代理、HTTPS MITM、HTTP/2、
> WebSocket（含逐帧抓取）、上游代理、流量检查（头 + Body 预览）、`cipher` TLS 版本固定。

---

## 已知差距一览

| 领域 | 当前状态 | 影响 | 优先级 |
|------|----------|------|--------|
| Node 插件运行时 | 插件是外部 HTTP 服务，仅有 `x-whistle-*` 上下文头 | 高 —— 生态多数插件跑不起来 | ⭐⭐⭐ |
| 插件/模板变量（`${…}`、`%name`、`G`/`@`） | 未实现 | 中 | ⭐⭐ |
| dust / handlebars 模板引擎 | 以 `{name}` 简单替换近似 | 低-中 | ⭐⭐ |
| 流量持久化 | 仅内存（有界环形缓冲） | 中 | ⭐⭐ |
| 响应体解码（gzip/br）用于查看 | 压缩 Body 以二进制展示 | 中 | ⭐⭐ |
| weinre 完整支持 | 仅脚本注入，inspector 在外部 | 低 | ⭐ |
| `sniCallback` 算子 | 未实现（SNI 阶段 + 依赖插件） | 低 | ⭐ |
| 其余代理变体 | `internal-http-proxy`/`internal-https-proxy`、`x`/`xs` 前缀代理 | 低 | ⭐ |
| `locationHref` 算子 | 未实现（客户端注入式跳转） | 低 | ⭐ |
| `style` / `G` 算子 | 解析但不产生流量效果 | 无 | —— |
| React Web 前端（`biz/`） | 由轻量内建 UI 替代 | 视需求 | ⭐ |

---

## 分阶段计划

### 第一阶段：Node 插件运行时（最高价值）

原版 whistle 的插件通过 Node 子进程加载，实现一组约定的钩子：
`server`、`rulesServer`、`resRules`、`reqRead`、`resRead`、`auth`、`statsServer` 等。
当前移植只把 `plugin://name` 路由到一个外部 HTTP 服务并附带 `x-whistle-*` 头，
覆盖不了真正的插件协议。

- [ ] 实现插件的 HTTP 协议契约（请求/响应规则服务、读写钩子的头约定）。
- [ ] 支持插件返回**规则**（rulesServer），并合并进解析结果。
- [ ] 支持 `pipe://` 的真正流式管道（当前近似为整体路由）。
- [ ] （可选）Node 子进程加载器，以便直接运行现有 npm 插件包。

### 第二阶段：变量与模板系统

- [ ] 插件变量与模板变量：`${expr}`、`%name`、`@`/`G` 全局值解析。
- [ ] 将 `tpl`/`dust`/`jsonp` 从「简单 `{name}` 替换」升级为对齐 whistle 的模板语义
      （dust.js / handlebars 行为，或明确记录取舍）。
- [ ] `lineProps` 系统（whistle 规则行级属性）。

### 第三阶段：观测与持久化

- [ ] 流量抓取持久化到磁盘（可回放、可导出 HAR）。
- [ ] 查看时解码响应体（gzip / brotli / deflate），文本正确呈现。
- [ ] Body 预览上限可配置（当前固定 16 KB）。
- [ ] 更丰富的 Web UI：按域名/状态过滤、搜索、请求重放、导入/导出规则。

### 第四阶段：TLS 与代理补全

- [ ] `sniCallback`：在 SNI 阶段用插件选择 MITM 证书（需第一阶段的插件运行时）。
- [ ] `cipher` 扩展：在 rustls 能力范围内支持更多 TLS 选项（目前仅版本固定）。
- [ ] 代理变体：`internal-http-proxy`/`internal-https-proxy` 与 `x`/`xs` 前缀代理。
- [ ] `locationHref`（HTML 响应中注入跳转脚本）。

### 持续项

- [ ] 补齐单元/集成测试，尤其是插件协议与模板系统。
- [ ] 性能剖析（大响应体、并发连接下的 tee 抓取开销）。
- [ ] 清理既有 clippy 风格提示（`collapsible_if` 等，来自较新版工具链）。

---

## 不打算做的事（Non-goals）

- **逐字节复刻 React 前端** —— 内建轻量 UI 已覆盖核心检查/编辑需求；除非有明确诉求，
  不重写 `biz/webui`。
- **绑定 Node.js 运行时** —— 项目目标是单一静态二进制；Node 子进程插件加载器（若做）
  将是可选特性，而非硬依赖。

---

## 参与

任何一个阶段都可以独立推进。若要优先某一项，**Node 插件运行时（第一阶段）** 是解锁
whistle 生态、投入产出比最高的一块。相关模块地图见
[`ARCHITECTURE.md`](ARCHITECTURE.md)，算子覆盖细节见 [`RULES.md`](RULES.md)。
