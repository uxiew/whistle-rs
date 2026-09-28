# 对齐与完善程度审查

日期：**2026-09-25**。代码基线：`702486d4f0e5dbc70ae20055ff89fcac46084650`，`main`，`whistle-rs 0.1.0`。

本轮修改限于文档；没有为通过检查而改动 Rust、前端、依赖声明或锁文件。初始工作区已有未跟踪的 `_original/`，未纳入提交、删除或覆盖。

## 结论

**方向与 Whistle 的代理/规则核心对齐，已有较完整的可用实现和较强的测试基础；不等于原项目全量兼容，也尚未达到可宣称稳定发布的交付状态。**

不能用「70/73 个算子」或一个百分比表示完善程度：名字被解析、运行时被调用、特定用例一致、与官方全部工作流兼容，是四种不同的证据。当前更准确的定位是：**可用于受控开发调试、可嵌入的 Rust 调试代理，兼容范围有边界，发布门禁仍待补齐**。

### 对照对象

| 对象 | 本轮确认 |
| --- | --- |
| 可执行差分基线 | `tests/differential/package.json` 固定 `whistle: 2.10.8`；本机实际加载的包也为 **2.10.8** |
| 在线上游 | 2026-09-25 读取官方 `master/package.json` 为 **2.10.10**，更新日志已有 2.10.9、2.10.10；这是本次在线观察，不等于完成该版本验收 |
| 官网文档 | 动态更新的当前文档，不是 2.10.8 的冻结规范 |
| 原始源码行号 | 既有文档记录提交 `1df0805f09fd979e0e31fd6eab99ca97239ac1ec`；本轮未独立验证该提交与标签/发布包的逐文件对应关系 |

来源：[官方安装与文档](https://wproxy.org/docs/)、[官方 package.json](https://github.com/avwo/whistle/blob/master/package.json)、[官方更新日志](https://github.com/avwo/whistle/blob/master/CHANGELOG.md)。复现约束见 [UPSTREAM.md](UPSTREAM.md)。

## 能力对齐矩阵

「已实现」以代码入口及已有测试为依据，不表示本轮跑过该能力的每一种端到端组合。

| 维度 | 当前实现与边界 | 核验入口 |
| --- | --- | --- |
| 代理核心 | HTTP 正向代理、CONNECT、HTTPS MITM、入站 SOCKS5、HTTP/HTTPS/SOCKS 上游代理与 PAC 已有实现 | `src/proxy/{mod,upstream,socks,sni}.rs` |
| HTTP/2 | 客户端到 MITM 侧支持 h2；向源站的主要请求路径仍使用 HTTP/1.1，不是端到端 h2 等价 | `src/proxy/mod.rs`、`upstream.rs` 的 `http1::handshake` |
| CA / TLS | 动态 CA、自备证书和 SNI 插件钩子已实现；默认验证源站证书是有意的安全差异。证书安装仍由用户完成 | `src/ca.rs`、`src/proxy/sni.rs`、`src/main.rs` |
| 规则语义 | 模式、优先级、Values、includes、改写与响应阶段等有广泛实现；特定语料的差分通过，不代表所有输入和上游版本一致 | `src/rules/`、`src/proxy/apply.rs`、`tests/differential/` |
| WebSocket / 流 | 有 ws/wss 帧抓取、发送、扣留/放行及自有插件钩子；不代表复刻上游全部 TCP/帧工作流 | `src/proxy/ws.rs`、`src/plugins/wsframe.rs` |
| 控制台 | Vue 3 + CodeMirror；已有规则/Values、Composer/重放、时间线、二进制预览/下载、HAR 与配置导入导出，**不是缺失项** | `ui-src/src/panes/`；`src/proxy/webui.rs` 路由表 |
| 检索与错误观测 | `h:`、`b:`、`app:`、`fc:` 搜索仍明确不支持；请求早期失败的兜底 `guard` 没有会话写入，因此不是完整失败时间线 | `ui-src/src/filter/session-filter.js`；`src/proxy/mod.rs` 的 `guard` |
| 持久化 | JSONL 会话历史与按天保留；内存/体预览有界。UI 隐藏不等于后端未采集，预览/HAR/重放不能保证任意大报文完整 | `src/proxy/{persist,body,webui}.rs`、`src/config.rs` |
| 插件生态 | 自有 Rust/HTTP/Node 插件协议与 SDK；**不直接运行现成 `whistle.*` npm 插件** | `src/plugins/`、`sdk/`、[PLUGINS.md](PLUGINS.md) |
| CLI / Agent 接口 | `explain`、`qr` 及自有 HTTP API；没有 `w2 start/stop` 兼容层，`-r` 是可编辑的 Default 规则组而不是上游隐藏 shadowRules | `src/main.rs`；`src/proxy/webui.rs` |
| 工程与发布 | 单元/集成测试可跑，前端能构建；当前 Clippy/格式门禁未通过，未找到受版本控制的 CI、根 LICENSE 或差分依赖锁文件 | 本文验证记录；`git ls-files` |

上游插件契约见[官方插件开发](https://wproxy.org/docs/extensions/dev.html)；上游 Local Agent API 见[官方接口文档](https://wproxy.org/docs/extensions/api.html)。同名能力不意味着 URL、数据模型或插件对象兼容。

### 已实现但旧文档误报的内容

二进制体通过 `/body.bin` 提供，UI 支持十六进制/图片/下载；Composer、时间线和配置导入导出已有实际入口。`style` 元数据参与控制台搜索，不能笼统说成完全未实现；它与 `G` 的上游全局插件基础设施也不是同一类能力。

`src/proxy/ciphers.rs` 已实现针对当前后端可用套件的 OpenSSL 风格选择表达式求值，不能再计划「从零实现 cipher 字符串」。真实边界是 rustls 可用算法与 TLS 版本；当前选不到套件时会记录日志并放弃该 pin，**不能把这条规则当成强制安全策略**。该行为应进入可见诊断与明确的降级契约。

## 本轮实际验证

环境：macOS / ARM64，Node.js **v24.9.0**，实际 Vite **8.2.0**。Clippy 输出指向 Rust **1.98.0** lint 文档；`rustc -vV` 被工具命令白名单阻止，未据此声称已完整采集 Rust 工具链元数据。前端使用现有 `node_modules`；本轮没有做全新机器安装试验。

| 命令 | 结果 | 覆盖范围 / 限制 |
| --- | --- | --- |
| `cargo test --locked --all-targets` | **通过：939 单元 + 20 集成，8 ignored** | 集成为 console 6、forwarded 7、header-rules 7；ignored 未执行 |
| `cargo test --locked --doc` | **通过：2** | 文档示例编译测试 |
| `npm run typecheck --prefix ui-src` | **通过** | `vue-tsc --noEmit`；不是浏览器交互测试 |
| `npm run build --prefix ui-src` | **通过** | 输出单文件控制台 `ui-src/dist/index.html` |
| `cargo build --locked`（前端构建之后） | **通过** | 重新编译 debug 二进制；本轮没有生成 release 分发制品 |
| `cd tests/differential && node rules-oracle.js --values` | **通过：17,462 问题；算子/取值差异均 0** | 4,730 个问题命中规则；51 次 host 大小写归一化；没有打开代理端口 |
| `cargo clippy --locked --all-targets -- -D warnings` | **失败，退出 101：两类错误** | `src/proxy/ciphers.rs:270` 的 `question_mark`；`src/proxy/webui.rs:1436` 的 `result_large_err` |
| `cargo fmt --all -- --check` | **失败，退出 1** | 存在多处既有格式差异；本轮未改写源码 |

首次离线 Cargo 测试因缺少 `json5 1.3.1` 缓存而失败；随后允许下载锁定依赖后测试通过。这是安装环境问题，不计为已确认的产品缺陷，锁文件没有因此升级。

本轮**未重新执行**全套真代理网络差分、性能基准、长时间稳定性、浏览器自动化、Linux/Windows 真机及 2.10.10 兼容矩阵。历史文档的 2,297 条网络差分、21,752 个解析问题等记录仍保留在历史档案，不能合并进本轮结果。

### 差分证据的强弱

`rules-oracle.js` 比较解析结果并做显式归一化，不能证明转发后的字节、响应阶段、动态 include 或插件行为。网络 `harness.js` 同时看客户端和源站，但含 `IGNORE`、`EXPECTED` 归一化与例外。因此必须同时报告有效命中、`inert`、具名偏离和未知差异；**退出 0 不等于未归一化的全量字节一致**。

## 真实缺口与风险

| 优先级 | 发现 | 后续任务 |
| --- | --- | --- |
| P0 | 质量状态漂移：Clippy 两处错误、格式未统一，历史“全绿”已不适用；未固定工具链/最低支持版本 | Q1 |
| P0 | 可复现交付不足：无跟踪中的 CI，差分依赖仅固定顶层版本、没有跟踪锁文件，缺少统一网络差分入口 | Q2 |
| P0 | 发布许可不完整：根 LICENSE 缺失，Cargo 包元数据缺少 license 等字段；旧 README 的 MIT 声明不足以完成分发准备 | Q3 |
| P0 | 默认全接口、无 UI 口令、会话落盘；UI 认证不保护代理转发，分 UI 端口不是自动的网络隔离 | S1 |
| P1 | 早期请求失败缺少统一会话结果；依赖日志/502，影响定位 DNS/连接/TLS 失败 | O1 |
| P1 | UI 检索字段、采集/显示过滤、二进制与截断状态需要更明确的契约；不能把过滤后的画面当作隐私保证 | O2 |
| P1 | 缓冲改写超限、流式算子边界和 cipher 降级应被用户/Agent 看见，而不只藏在日志或长文档里 | R1 |
| P1 | 当前上游 2.10.9/2.10.10 变化尚未做版本矩阵复验；优先核查带 charset 的 SSE、pipe 阻塞/内存、DNS 顺序 | U1 |
| P2 | 上游连接池、源站 h2、长连接资源与跨平台分发需要专项验证，不能仅因 Rust 实现就承诺性能更高 | PERF1 / D1 |
| P2 | `apply.rs`、`mod.rs`、`webui.rs` 体积较大；测试完善后沿责任边界拆分，避免先做无收益重写 | M1 |

Q/S/O/R/U/P/D/M 编号均指 [ROADMAP.md](ROADMAP.md)。这是一份审查快照，不是新功能已经完成的报告。

## 不应混入必做清单的事情

直接兼容 npm 插件、逐像素复刻官方 React UI、复刻 `/cgi-bin/*` 数据模型、强制随代理捆绑 Node，都不是本项目当前交付目标。没有新的产品决策，不应把它们作为“全面对齐”的隐含承诺。确有迁移客户时，单独设计薄适配层与契约测试，不污染核心协议。
