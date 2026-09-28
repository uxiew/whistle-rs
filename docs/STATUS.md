# 对齐与完善程度审查

日期：**2026-09-25**。代码基线：`702486d4f0e5dbc70ae20055ff89fcac46084650`，`main`，`whistle-rs 0.1.0`。

本轮修改限于文档；没有为通过检查而改动 Rust、前端、依赖声明或锁文件。初始工作区已有未跟踪的 `_original/`，未纳入提交、删除或覆盖。

**2026-09-28 更新：** Q1 已完成，质量门禁在钉住的工具链上全部通过，见 [Q1 门禁复验](#2026-09-28-q1-门禁复验)。Q2 的本地部分完成，CI 待首次在 GitHub 上运行，见 [Q2 记录](#2026-09-28-q2-可复现构建与差分门禁)。Q3 完成，见 [Q3 记录](#2026-09-28-q3-许可来源与包元数据)。下文「2026-09-25 审查时的验证」保留为当时的记录，其中 Clippy/格式失败已不是现状。

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
| 工程与发布 | 格式、Clippy、单元/集成/doc 测试和前端构建在钉住的工具链（Rust 1.98.1）上全部通过，MSRV 1.95 实测；差分依赖有审阅过的锁文件，`run.js` 一条命令跑全量差分并归档；CI workflow 已写好但**尚未在 GitHub 上运行过**；MIT 许可、来源说明、Cargo 元数据齐备，发布构件附带第三方许可原文 | 本文 Q1、Q2 记录；`.github/workflows/`；`tests/differential/` |

上游插件契约见[官方插件开发](https://wproxy.org/docs/extensions/dev.html)；上游 Local Agent API 见[官方接口文档](https://wproxy.org/docs/extensions/api.html)。同名能力不意味着 URL、数据模型或插件对象兼容。

### 已实现但旧文档误报的内容

二进制体通过 `/body.bin` 提供，UI 支持十六进制/图片/下载；Composer、时间线和配置导入导出已有实际入口。`style` 元数据参与控制台搜索，不能笼统说成完全未实现；它与 `G` 的上游全局插件基础设施也不是同一类能力。

`src/proxy/ciphers.rs` 已实现针对当前后端可用套件的 OpenSSL 风格选择表达式求值，不能再计划「从零实现 cipher 字符串」。真实边界是 rustls 可用算法与 TLS 版本；当前选不到套件时会记录日志并放弃该 pin，**不能把这条规则当成强制安全策略**。该行为应进入可见诊断与明确的降级契约。

## 2026-09-25 审查时的验证

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

## 2026-09-28 Q1 门禁复验

代码提交：`b2211dc941f6360c54c59ccd76909a8a412d3d66`（Q1 最后一个代码提交；此后只有文档提交）。环境：macOS / Apple M4 / Darwin 25.3.0 arm64；门禁工具链 `rustc 1.98.1 (48a229cea 2026-09-01)`、LLVM 22.1.8；MSRV 验证用 `rustc 1.95.0`；Node.js **v26.4.0**、npm 11.17.0、Vite 8.2.0。

Q1 做了什么（每项一个提交，可单独回退）：

| 提交 | 内容 |
| --- | --- |
| `a9e3b84` | `ciphers.rs` 的 `question_mark`：改用 `?`，语义不变 |
| `140d743` | `webui.rs` 的 `result_large_err`：`read_json_body` 的错误返回改为 `Box<Response>`，400 响应字节不变 |
| `05c4186` | 全树 rustfmt，纯格式；1.96.1 与 1.98.1 结果一致。`d0aa96a` 把它记入 `.git-blame-ignore-revs` |
| `ba5ab71` | 控制台声明 Node `engines` 并开 `engine-strict` |
| `8b1caed` | 修掉一个不稳定测试（见下） |
| `86e3670` | `rust-toolchain.toml` 钉住 1.98.1 |
| `b2211dc` | `Cargo.toml` 声明 `rust-version = "1.95"` |

没有用全局 `allow`、没有降低 lint 级别，`Cargo.lock` 未变。

| 命令 | 结果 | 说明 |
| --- | --- | --- |
| `cargo fmt --all -- --check` | **通过** | |
| `cargo clippy --locked --all-targets -- -D warnings` | **通过** | 1.98.1；1.96.1 也通过 |
| `cargo test --locked --all-targets` | **通过：939 单元 + 20 集成，8 ignored** | 集成为 console 6、forwarded 7、header-rules 7；ignored 是基准，未执行 |
| `cargo test --locked --doc` | **通过：2** | |
| `cargo +1.95.0 test --locked --all-targets` 与 `--doc` | **通过**，计数同上 | MSRV 实测 |
| `cargo +1.94.0 check --locked` | **按预期拒绝** | `whistle-rs@0.1.0 requires rustc 1.95`；去掉 `rust-version` 时报 E0658（`if let` 守卫） |
| 全新目录 `npm ci` → `typecheck` → `build` | **通过** | 在不含 `node_modules`/`dist` 的副本里；`dist/index.html` sha256 `6d02b4be…c47c516`，与仓库内现有依赖构建的字节一致 |
| `engine-strict` 反向验证 | **生效** | 把 `engines` 改成不可能满足：`npm ci` 以 `EBADENGINE` 退出 1；去掉 `.npmrc` 同一安装退出 0、只有警告 |
| 前端构建后 `cargo build --locked` | **通过** | 嵌入的 `console.html` 哈希同上，二进制中不含占位页文案 |
| `cd tests/differential && node rules-oracle.js --values` | **通过：17,462 问题，4,730 命中，差异 0，取值差异 0** | host 大小写归一 51 次；与 09-25 结果完全一致；本机 whistle 2.10.8 |
| `git diff --check 702486d HEAD` | **通过** | |

**不稳定测试。** `proxy::console_port_tests::the_console_answers_on_its_own_port` 在 1.95 和 1.98 上都会偶发失败：修复前连续跑 60 次全量 lib 测试挂 3 次。给测试加诊断后确认原因是测试先绑 0 端口、释放、再让服务重新绑这个端口号，中间被并行测试占走，服务任务以 `EADDRINUSE` 退出，而这个错误被丢弃的 `JoinHandle` 吞掉，只剩一句 "the console never came up"。改为把已绑定的 listener 直接交给服务后，连续 100 次 0 失败。

**没有执行：** 真代理网络差分（`harness.js` 及各 `*-bench.js`）、`#[ignore]` 基准、`--release` 构建、浏览器交互、`npm run dev`、Linux/Windows、任何 CI（仓库仍没有，属 Q2）。差分依赖仍没有锁文件，本次读到的 2.10.8 是本机现有安装。

**剩余风险：**

- `rust-toolchain.toml` 只对 rustup 用户生效；CI 必须经 rustup 安装，否则会用别的版本跑 Clippy（Q2 落实）。
- MSRV 1.95 与 Node 版本只在 macOS arm64 上实测；Node 下限 20.19 是按依赖声明推出的，未真机验证。
- `src/proxy/bench.rs:454` 有同样的"释放再重绑"写法。它在 `#[ignore]` 基准里，普通门禁不跑，但单独跑基准时可能偶发同类失败。

## 2026-09-28 Q2 可复现构建与差分门禁

环境同 Q1：macOS / Apple M4 / Darwin 25.3.0 arm64，Rust 1.98.1，Node.js **v26.4.0**，npm 11.17.0；对照组 whistle **2.10.8**，锁文件 SHA-256 `45b91b6c…6fdec`。每条测量后面写了它对应的提交。

**结论：** 本地部分完成并实测——锁文件、统一入口、逐条声明、未知差异非零退出、inert 必须有解释、预设回归必被抓住、全新 clone 可重建。**CI 两个 workflow 写好了，但从没在 GitHub 上跑过**，所以 ROADMAP 里 CI 两项不勾；Linux 上的任何结果都还没有测过。

### 做了什么

| 提交 | 内容 |
| --- | --- |
| `a33369e` | 差分依赖锁文件：196 个包钉在历次测量用的那棵树上；`resolved`/`integrity` 取自 registry.npmjs.org，并与 npmmirror 逐个核对一致 |
| `bdd07b0` | `rules-oracle` 的取值差异计入退出码（原来只算匹配差异）；借此发现一个藏着的取值差异（`file://D:\dir\` 的分隔符），核实后声明 |
| `f55fddb` | oracle 与三个自起代理的 bench 可由外部指定状态目录、监听地址和二进制；https-bench 的证书超过一天就重建 |
| `223915a` | `declared.js`：82 条已知差异逐条写明用例、字段、上游版本、理由；`EXPECTED` 每条限定字段和范围，两条收窄；`IGNORE` 每个头写明理由；未声明差异和过期声明都让 harness 退出 1 |
| `624669e` | auth/frames/https/timing/mode 五个 bench 按未声明差异数决定退出码（原来永远 0） |
| `3c09405` | cases-paths 三个本就不该命中的用例标 `inert: true`（此前从未过 inert 分诊） |
| `9a9832f` | `run.js`：fast / network / all 三个套件，临时目录、回环监听、端口预检、进程组清理、归档 |
| `f3bdd69` `ea45090` `3608371` `77c2bc9` | `mutations.js` 预设回归检查；修 `require.cache` 桩按真实路径做键；修中断处理；换掉一个等价变异 |
| `c4255ac` `02663b8` | Markdown 相对链接与锚点检查；修一处审查时改名留下的坏链接 |
| `66df8e2` `f1bae57` | 控制台检查脚本；CI（`ci.yml` 每个 PR，`differential.yml` 手动+每周） |

### 实测

| 命令 | 结果 | 说明 |
| --- | --- | --- |
| 全新目录按锁文件 `npm ci` | **通过** | 装出的 `node_modules` 与原树逐文件一致（`diff -rq` 无输出） |
| `node run.js all` | **27 步全过，851 秒** | 归档 `second-all`：whistle-rs SHA-256 `7101639b…`；跑完无残留进程、无残留临时目录（代码 ≈ `9a9832f`，差别见该提交说明） |
| 同上，在写 `declared.js` 之前 | **按预期失败** | 恰好是有已知差异的 10 个语料，加 cases-paths 的 inert 分诊 |
| `node mutations.js` | **5/5 被抓住**，5 个基线先通过 | `3608371`（4 条）与 `77c2bc9`（改过的 1 条）；见下表 |
| 全新 `git clone` → `npm ci` → `cargo build` → `run.js fast` | **通过** | `77c2bc9`；clone 里除 `node_modules` 外没有多出任何文件，包括被忽略的 |
| `scripts/check-console.sh` 四种组合 | **符合预期** | 真控制台构建：built 0、placeholder 1；无前端产物构建：placeholder 0、built 1 |
| `node scripts/check-links.mjs` | **通过：21 个文件** | 修复前报 1 处；合成仓库里 5 个坏链接全报、8 个好链接不误报 |
| 两个 workflow | **只验证了 YAML 能解析** | 没有在 GitHub 上运行；本机 Docker 未启动，容器 job 也没在本地跑 |

预设回归（每条都必须让对应门禁失败，且未注入时门禁先通过）：

| 回归 | 由谁抓到 | 备注 |
| --- | --- | --- |
| 重要规则失去优先级 | `oracle-cases` | **文档语料 `oracle-docs` 抓不到**，只有手写语料能 |
| `{name}` 取值多一个空格 | `oracle-cases`，157 处取值差异 | 用 `bdd07b0` 之前的脚本复测同一变异：158 处取值差异，**退出码 0** |
| `$1` 取错捕获组 | 网络：`cases` 4 例、`cases-patterns` 8 例 | 文档语料的解析差分看不到 |
| `statusCode://404` 回 405 | 网络：`cases` 3 例 | 解析差分只看"匹配到什么"，看不到执行效果——网络差分存在的理由 |
| QR 第 6 种掩码取反 | `qr`，17 个码不一致 | |

### 顺带发现的问题

- `rules-oracle` 取值差异不影响退出码，`--values` 印出错值照样退出 0；审查时也只跑了文档语料，`--from-cases` 从没进过验证记录。
- `harness.js` 与 6 个专项 bench 无论多少差异都退出 0，"已知差异数"靠人对照 README——而 README 的数字有两处和语料对不上（compose 写 7 实为 9；paths 列了两个语料里已不存在的用例、漏了实际有差异的两个）。
- `require.cache` 桩按拼写路径做键，经符号链接的 `node_modules` 必崩；`mutations.js` 用 `spawnSync` 导致中断后留下已注册的 worktree——两者都已修并实测。
- 本机设了 `http_proxy` 且无 `no_proxy`，curl 访问 127.0.0.1 也走代理，控制台检查会一直卡住；脚本已加 `--noproxy '*'`。
- `short_circuit` 里对 `statusCode` 的解析结果总被 `apply_response_for` 覆盖，是死代码（第一版变异因此"存活"）。未改，留给 M1。

### 没有执行 / 剩余风险

- **CI 从未运行。** 以下都只有在 GitHub 上跑一次才算证实：Linux 上的差分结果（全部声明都是在 macOS + Node 26.4 上测的）、`rust:1.98.1-trixie` 容器里的纯代理构建、Node 20.19.0 下的前端构建、缓存恢复的 `target/` 与 `run.js` 的"二进制比源码旧"检查是否相容。
- `run.js` 用进程组清理子进程，不支持 Windows。
- 网络套件里 auth/https/mode 会查询 `local.whistlejs.com`、`rootca.pro` 等名字，依赖 DNS；timing 按时间容差判定，在 CI 上是否稳定未知。
- 语料仍把夹具写到固定的 `/tmp/wrs-*`（测试文件，不含密钥），不在临时目录里、也不删除。
- auth/https/mode/forwarded 各自的内联声明表已按用例限定，但没有迁进 `declared.js`、也没有写上游版本字段。
- `tests/differential/` 下此前手动运行留下的 `.data-*`、`.mode-*` 等目录（已被 git 忽略）没有动。
- 对照组结果随 Node 版本变化；换 Node 需重新测量。

## 2026-09-28 Q3 许可、来源与包元数据

许可由维护者选定为 **MIT**。提交：`865debb` LICENSE、`9bc9713` 第三方许可生成脚本、`2905f2d` NOTICE.md、`b9b75f8` Cargo 元数据、`a9941ea` crate 包内容与忽略 `_original/`、`8722f32` SDK 的 LICENSE、`7379280` CI 发布构件附带许可、`8e9ac50` 上游对应关系。

| 事项 | 结果 | 怎么核实的 |
| --- | --- | --- |
| 根 `LICENSE` | MIT，版权人写"whistle-rs contributors"，不虚构个人作者 | 许可正文与上游 LICENSE 逐字相同 |
| `NOTICE.md` | 写明来自上游的内容（规则语言与设计、按上游翻译的逻辑——`src/` 下 866 处 `_original/…:行号` 注释、测试语料里逐字取自上游文档的规则行）和不来自上游的内容；附上游 MIT 原文 | 上游 LICENSE 在 v2.10.4、v2.10.8 与 npm 包里完全相同 |
| 上游 tag / 提交 / npm 包 | `v2.10.8` 是指向 `1df0805` 的轻量 tag；npm 包 228 个文件中 227 个与该提交逐字节相同，唯一多出的是上游控制台的构建产物 | `git ls-remote`；部分克隆上游后逐文件比对 |
| Cargo 元数据 | `description`、`license = "MIT"`、`repository`；不写 `authors` | `cargo metadata` |
| crate 包内容 | 原先会打包 1,119 个文件，其中 940 个是本地 `_original/` 里的上游源码；现在按白名单只有 62 个，能从包内容独立编译 | `cargo package --list`；`cargo package` |
| 第三方许可 | 生成脚本在 x86_64-linux 上列出 223 个 crate、36 个 npm 包、164 段不同的许可原文；12 个 crate 声明了许可但包里没带原文，按 SPDX 标识列出 | 本地对 aarch64-darwin 与 x86_64-linux 两个目标各生成一次 |
| SDK | 补 `sdk/LICENSE`，`npm pack --dry-run` 显示随包发出 | npm pack 清单 |
| 发布构件 | CI release job 把 LICENSE、NOTICE.md、THIRD-PARTY-LICENSES.md 与二进制放在一起并算校验和 | 本地按同样步骤手动走过一遍；**CI 本身未运行** |

**剩余风险：** `Cargo.lock` 里的 `num-bigint 0.4.7` 已在 crates.io 被撤回（`cargo package` 报出），未处理；crate 包不含 `ui-src/dist`，从 crates.io 构建得到的是占位控制台；许可判断基于各包声明的 SPDX 标识与自带的许可文件，没有逐个核对声明是否与源码实际许可一致。

## 真实缺口与风险

| 优先级 | 发现 | 后续任务 |
| --- | --- | --- |
| ~~P0~~ | ~~质量状态漂移：Clippy 两处错误、格式未统一；未固定工具链/最低支持版本~~ 2026-09-28 已解决，见 Q1 复验 | Q1 ✓ |
| P0 | ~~差分依赖无锁文件、无统一网络差分入口~~ 2026-09-28 已解决；**CI 已写未跑**：两个 workflow 从未在 GitHub 上执行，Linux 上的结果没有测过 | Q2（剩 CI 首跑） |
| ~~P0~~ | ~~发布许可不完整~~ 2026-09-28 已补齐（MIT、NOTICE、Cargo 元数据、第三方许可生成）；发布构件随 CI 首跑确认 | Q3 ✓ |
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
