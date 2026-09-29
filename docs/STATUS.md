# 对齐与完善程度审查

日期：**2026-09-25**。代码基线：`702486d4f0e5dbc70ae20055ff89fcac46084650`，`main`，`whistle-rs 0.1.0`。

本轮修改限于文档；没有为通过检查而改动 Rust、前端、依赖声明或锁文件。初始工作区已有未跟踪的 `_original/`，未纳入提交、删除或覆盖。

**2026-09-28 更新：** Q1 已完成，质量门禁在钉住的工具链上全部通过，见 [Q1 门禁复验](#2026-09-28-q1-门禁复验)。Q2 完成，CI 首跑全部通过，见 [Q2 记录](#2026-09-28-q2-可复现构建与差分门禁)。Q3 完成，见 [Q3 记录](#2026-09-28-q3-许可来源与包元数据)。S1 完成，见 [S1 记录](#2026-09-28-s1-安全运行契约)。**2026-09-29：** 上游自带测试成为门禁（U0），途中修了 11 个缺陷，见 [U0 记录](#2026-09-29-u0-上游自带测试)；S1、U0 的改动推送后 GitHub CI 8 个 job 全过（`502c153`）。失败的请求也留下会话（O1），见 [O1 记录](#2026-09-29-o1-失败会话与生命周期)。检索、采集与接口契约（O2），见 [O2 记录](#2026-09-29-o2-检索采集和自有-api-契约)。下文「2026-09-25 审查时的验证」保留为当时的记录，其中 Clippy/格式失败已不是现状。

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
| 检索与错误观测 | 检索框支持 `h:`、`b:`（由代理查，`b:` 只查已存的预览）、`fc:`；`app:` 明确不支持。失败的请求各有一条会话，带失败阶段和原因，本代理生成的 502 带阶段和会话号；插件钩子失败时放行请求，会话不标失败 | `ui-src/src/filter/session-filter.js`；`src/proxy/search.rs`；`src/proxy/outcome.rs`、`src/proxy/mod.rs` 的 `Ledger`/`guard` |
| 持久化 | JSONL 会话历史与按天保留；内存/体预览有界，没存全的 body 在接口、HAR、重放里都有标记，写盘读回不变。控制台隐藏不等于没采集，只有 `enable://hide` 不记录 | `src/proxy/{persist,body,webui}.rs`、`src/config.rs` |
| 插件生态 | 自有 Rust/HTTP/Node 插件协议与 SDK；**不直接运行现成 `whistle.*` npm 插件** | `src/plugins/`、`sdk/`、[PLUGINS.md](PLUGINS.md) |
| CLI / Agent 接口 | `explain`、`qr` 及自有 HTTP API；没有 `w2 start/stop` 兼容层，`-r` 是可编辑的 Default 规则组而不是上游隐藏 shadowRules | `src/main.rs`；`src/proxy/webui.rs` |
| 工程与发布 | 格式、Clippy、单元/集成/doc 测试和前端构建在钉住的工具链（Rust 1.98.1）上全部通过，MSRV 1.95 实测；差分依赖有审阅过的锁文件，`run.js` 一条命令跑全量差分并归档；CI 首跑 8 个 job 全部通过，全量差分在 Linux 容器里通过；MIT 许可、来源说明、Cargo 元数据齐备，发布构件附带第三方许可原文；上游自带测试已成为门禁（可评判的 180 条中 154 条通过、26 条逐条声明） | 本文 Q1、Q2、U0 记录；`.github/workflows/`；`tests/differential/` |

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

**结论：** 完成。本地实测了锁文件、统一入口、逐条声明、未知差异非零退出、inert 必须有解释、预设回归必被抓住、全新 clone 可重建；CI 首跑（`6e28a23`）8 个 job 全部通过；全量差分在 Linux 容器里 27 步全过，没有冒出新差异。全量差分 workflow 本身还没在 GitHub 上触发过。

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
| `ci.yml` 首跑 | **8 个 job 全部通过，3 分 19 秒** | GitHub Actions run `36438710319`，提交 `6e28a23`（推到 main 触发）；详见下文 |
| `run.js all`，Linux | **27 步全过，854 秒** | 本机 OrbStack 里的 `node:26-trixie` 容器，arm64，Node 26.10.0，代码 `6e28a23` |
| actionlint 1.7.12 | **两个 workflow 0 条问题** | 它会对 `run:` 块跑 shellcheck |

预设回归（每条都必须让对应门禁失败，且未注入时门禁先通过）：

| 回归 | 由谁抓到 | 备注 |
| --- | --- | --- |
| 重要规则失去优先级 | `oracle-cases` | **文档语料 `oracle-docs` 抓不到**，只有手写语料能 |
| `{name}` 取值多一个空格 | `oracle-cases`，157 处取值差异 | 用 `bdd07b0` 之前的脚本复测同一变异：158 处取值差异，**退出码 0** |
| `$1` 取错捕获组 | 网络：`cases` 4 例、`cases-patterns` 8 例 | 文档语料的解析差分看不到 |
| `statusCode://404` 回 405 | 网络：`cases` 3 例 | 解析差分只看"匹配到什么"，看不到执行效果——网络差分存在的理由 |
| QR 第 6 种掩码取反 | `qr`，17 个码不一致 | |

### CI 首跑（2026-09-28）

推到 main 触发，run `36438710319`，提交 `6e28a23`，8 个 job 全部通过：

| Job | 用时 | 证明了什么 |
| --- | --- | --- |
| Rust — fmt, clippy, tests | 2 分 28 秒 | Linux x86_64 上门禁与全部测试通过；`rust-toolchain.toml` 被 rustup 采用 |
| Rust — the oldest supported version | 1 分 45 秒 | MSRV 1.95 在 Linux 上成立 |
| Proxy-only build | 1 分 36 秒 | 不含 Node 的 `rust:1.98.1-trixie` 容器里能编译，二进制给出占位页 |
| Console — Node 20.19.0 / 24 | 16 秒 / 13 秒 | **Node 下限 20.19.0 第一次真跑通过**（之前只是按依赖声明推出来的） |
| Release binary with the real console | 3 分 15 秒 | 全新检出先建控制台再编 release，嵌入的就是这一版控制台；构件含二进制、`LICENSE`、`NOTICE.md`、`THIRD-PARTY-LICENSES.md` 与校验和（10.9 MB） |
| Docs — relative links and anchors | 11 秒 | |
| Differential — rules oracle and QR encoder | 1 分 52 秒 | Linux + Node 26 上 fast 差分通过；运行归档作为构件上传 |

缓存恢复的 `target/` 与 `run.js` 的"二进制比源码旧"检查相容（CI 里 fast 差分通过即证明）。构件内容需要登录才能下载，这里没有逐字节核对，核对的是生成它们的步骤全部成功。

### 顺带发现的问题

- `rules-oracle` 取值差异不影响退出码，`--values` 印出错值照样退出 0；审查时也只跑了文档语料，`--from-cases` 从没进过验证记录。
- `harness.js` 与 6 个专项 bench 无论多少差异都退出 0，"已知差异数"靠人对照 README——而 README 的数字有两处和语料对不上（compose 写 7 实为 9；paths 列了两个语料里已不存在的用例、漏了实际有差异的两个）。
- `require.cache` 桩按拼写路径做键，经符号链接的 `node_modules` 必崩；`mutations.js` 用 `spawnSync` 导致中断后留下已注册的 worktree——两者都已修并实测。
- 本机设了 `http_proxy` 且无 `no_proxy`，curl 访问 127.0.0.1 也走代理，控制台检查会一直卡住；脚本已加 `--noproxy '*'`。
- `short_circuit` 里对 `statusCode` 的解析结果总被 `apply_response_for` 覆盖，是死代码（第一版变异因此"存活"）。未改，留给 M1。

### 没有执行 / 剩余风险

- **全量差分 workflow（`differential.yml`）还没在 GitHub 上跑过**，要在 Actions 页面手动触发，之后每周一自动跑。它的内容（`run.js all`）已在 Linux 容器里通过，但那是 arm64，GitHub 是 x86_64。
- 容器里用 `git archive` 导出的代码没有 `.git`，归档清单的提交号为空；在正常检出里（包括 CI）会记录。
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

## 2026-09-28 S1 安全运行契约

先派只读 agent 做了一次安全现状盘点（监听、控制台认证与跨站、请求头规则、请求体上限、持久化、凭据外泄、插件），再逐项修。每项都有测试，行为变化都用真实二进制实测过。

| 问题（修之前） | 现在 | 提交 | 怎么验证的 |
| --- | --- | --- | --- |
| 任何网页都能用一个 `text/plain` 的 POST 改规则（不触发预检）；规则能读写任意文件 | 带 `Origin` 的 POST/DELETE 须同源或在 `--allow-origin` 上，否则 `403` | `4f191ff` | 端到端：跨站 POST 得 403 且规则未变；去掉检查后测试失败 |
| Host 不校验，DNS rebinding 可读写一切 | Host 须是 IP、`localhost` 或控制台主机名（`-l` 可加） | `4f191ff` | 端到端：`Host: evil.example` 得 403 |
| 默认监听 `0.0.0.0`，控制台无口令即对整个网络开放 | 默认 `127.0.0.1`；启动日志提示怎么开放，非回环且无口令时 WARN；状态页只在可达时显示手机二维码 | `7ca4a1d` `c508bdc` | lsof：无 `-H` 监听 127.0.0.1，`-H 0.0.0.0` 监听 `*` |
| CA 私钥 `0644`，会话、规则、Values 同样任何账户可读 | 文件 `0600`、自有目录 `0700`；旧的 `0644` 私钥在下次启动时收紧 | `8fd3785` | 启动后逐个查看磁盘权限；单元测试含"旧文件被收紧" |
| 控制台请求体没有上限 | 16 MiB，超过 `413`；插件页面同样 | `65a8f0e` | 端到端：16 MiB+1 的 POST 得 413 且规则未变 |
| "保留 7 天"只在进程跨过 UTC 午夜时生效；加载会读任意年份的旧文件 | 启动时和加载前就删除超期文件 | `b0d232c` | 放一个 2000 年的会话文件，启动后被删 |
| "清空"只清内存，重启后回来，且没有真正删除的办法 | 清空保持只清内存（界面明说）；新增"删除历史"（`/api/sessions/purge`）连磁盘一起删 | `b0d232c` `c34c19b` | 3 个会话：清空后重启回来 3 个；删除历史后重启为 0 |
| 客户端给本代理的 `Proxy-Authorization` 原样发给源站（上游 2.10.8 也这样，实测） | 进来时取下，只交给上游代理；规则主动设置的照常发送 | `d3d731e` `311fd9a` | 端到端三种情况；差分新增用例并声明为偏离 |
| 只给 `-N/-W` 不给 `-n/-w` 时控制台完全敞开 | 拒绝启动并说明原因 | `a79bf07` | 直接启动看报错 |
| 插件页面收到控制台的 `Authorization` | 转交前去掉 | `4d0b746` | 端到端：回显头的插件看不到凭据；去掉过滤后测试失败 |
| `-P` 的帮助说它让控制台离开代理端口（实际没有） | 帮助文字改正 | `174f9eb` | 实测两个端口都返回控制台 |

`--no-persist` 实测只写 CA 和规则，不写会话。文档（OPERATIONS、CLI、API、CERTIFICATES、两份 Cookbook、README）已按新契约更新（`712c4b5` 等）。

**与上游的有意偏离**（新增）：默认只监听回环；拒绝跨站写入和陌生 Host；不把客户端的 `Proxy-Authorization` 发给源站；`-N/-W` 缺 `-n/-w` 时拒绝启动。

**实测：** 本地 `cargo test` 956 单元 + 25 集成 + 2 doc 全过；差分 `run.js all` 27 步全过（852 秒，代码 `51595c5`，未提交的只有 STATUS/ROADMAP 两份文档），上游对照结果除新增的那条已声明偏离外没有变化。

**剩余风险（没有做的）：**

- **没有代理本身的访问控制**：局域网里能连上端口的设备都能用它转发；只能靠防火墙。
- **能改规则就能读写本机任意文件**，这是 whistle 规则语言的能力，不是漏洞；控制台写权限等同于该账户的文件权限。开启请求头规则模式后，这个能力延伸到所有代理客户端。
- 抓到的会话原样保存 `Authorization`、`Cookie`，只读账户和 HAR 导出都能看到；没有脱敏。
- INFO 日志记录完整 URL（含查询参数，可能带令牌）。
- 口令只能从命令行给，出现在进程列表里；Basic 认证在局域网上是明文。
- ~~S1 这批改动还没在 GitHub CI 上跑过~~ 2026-09-29 推送后 CI 8 个 job 全过（`502c153`）。

## 2026-09-29 U0 上游自带测试

用上游 v2.10.8 提交（`1df0805`）自己的 `test/` 测 whistle-rs：82 个单元文件、280 条带断言的调用，断言一行不改，只换了驱动（`tests/differential/upstream-suite.js`，用法见[差分 README](../tests/differential/README.md#upstreams-own-test-suite)）。

**先确认驱动没把测试改坏：** 上游装上自己的插件跑这套测试，280/280 全过（`--control`）。

**为什么只评判 180 条：** 206 条依赖测试自带的 8 个 Node 插件（规则写在插件的 `rules.txt`/`_rules.txt` 里，不少响应是插件服务器回的）。不装插件，上游自己也只过 74 条；而跑上游 npm 插件是写明的非目标。所以把插件自带的规则翻译成普通规则，同时交给两边，只评判上游在"联网"和"所有 DNS 查询都失败"两种情况下都能过的调用，共 180 条。剩下 100 条需要插件代码本身或外网，不评判。

**结果：** whistle-rs 通过 154 条；26 条逐条写进 `DECLARED` 并注明原因：上游嵌入 API（mock/service/shadow 规则）18 条，`/cgi-bin` 控制台接口 6 条，非法/中间状态码 2 条（有意偏离）。没有未声明的失败。门禁接进 `run.js network`，每周的 `Differential` workflow 会跑。

**途中修掉的缺陷**（每个有自己的测试，删掉修复测试就失败）：

| 上游单元 | 修之前 | 提交 |
| --- | --- | --- |
| `keys` | 控制台/embed 存的 Values 压过规则里同名的 ```` ``` ```` 块（上游是块优先）；`--value` 仍然压过块 | `562db0f` |
| `keys` | 请求头带来的规则（`x-whistle-rule-value`）里的块被丢掉 | `87e4ef0` |
| `script` | `reqScript` 写进 `values` 的值不能解析它推出的规则里的 `{name}`（源码注释说"实测如此"，那次探针本身测偏了）；`rulesFile` 引入的文本看不到自己的块 | `437246d` |
| `tps` | `resScript` 的内容是规则文本时被当 JS 执行，什么都没发生；现在只有提到 `ctx` 的才算本项目的钩子 | `ebb2857` |
| `ws` | 发到代理端口、只带路径、Host 是别的域名的请求得到 403（S1 的 Host 检查），上游是照常转发；现在转发，解析回本机则 302，另有标记兜底防循环（508） | `ed62f9e` |
| `connect` | 两端协商了 permessage-deflate 时，中继丢了帧的"已压缩"位，客户端收到乱码；现在不让两端协商压缩（有意偏离，上游是保留压缩、另解一份给界面看） | `4f722be` |
| `script` | `reqScriptData` 不能从请求脚本带到响应脚本 | `fa6117b` |
| `insertFile` | 6 个二进制操作符（`reqBody`/`resBody`/`*Prepend`/`*Append`）从文件读的内容先按 UTF-8 有损解码，GBK 页面、跨文件拆开的汉字都坏掉 | `8a4a018` |
| `plugin` | `headerReplace` 改多个 `set-cookie` 时只剩一个 | `cec00d5` |
| `params` | multipart 里对象形式的参数变成空文本字段，而不是文件 | `0ad9c2c` |
| `ws` | `statusCode://101` 回的 101 缺握手头，客户端拒绝 | `598c0c9` |

S1 记录里"`Host: evil.example` 得 403"指的是控制台本身，仍然成立；在代理端口上，这类请求现在按上游转发，被重绑到本机的域名拿到的是跳到 IP 地址的 302，读不到控制台数据（端到端测试 `a_rebound_hostname_cannot_read_the_console`）。`-P` 单独的控制台端口仍回 403。

**测试夹具上的三处改动**（断言没动，都写在驱动里）：上游测试客户端和上游代理同进程，证书校验被全局关掉，测 whistle-rs 时照做；两个 SOCKS 夹具与客户端存在竞态（先报成功、后接管道，未等请求就回响应），改成等待；所有夹具只监听 `127.0.0.1`。

**实测：** 本地 `cargo fmt --check`、Clippy `-D warnings` 通过；`cargo test` 966 单元 + 28 集成 + 2 doc 全过；差分 `run.js all` 28 步全过（1093 秒，代码 `870bed5`，其后只改了文档），原有语料没有新差异、没有过期声明，新的 `upstream-suite` 一步 239 秒。

**剩余风险 / 没做的：**

- 100 条调用需要上游插件代码或外网，没有评判；它们测的规则行为只部分被差分语料覆盖。
- `jsAppend` 这类操作符的 `{name}` 查不到时，上游什么都不追加，whistle-rs 追加字面量 `{name}`（顺带发现，未修）。
- 上游 2.10.8 不认 `rule://名字` 这种引入写法（报 Unsupported protocol），whistle-rs 认，属于既有差异，未处理。
- 驱动在上游一侧有一条 WebSocket 调用偶发超时（`proxy` 单元 `ws3.w2.org`，本地 3 次里出现 1 次）；门禁取两次上游都通过的调用，这类偶发只会让那一次少评判一条，不会误报。
- ~~这批改动还没在 GitHub CI 上跑过~~ 2026-09-29 推送后 CI 8 个 job 全过（`502c153`）；每周的 `Differential` workflow 仍未在 GitHub 上触发过。

## 2026-09-29 O1 失败会话与生命周期

**修之前：** 名字解析不了、连接被拒、源站 TLS 握手失败、客户端等不及走了——这些请求给客户端一个 502、日志里一行 `debug`，控制台里什么都没有。排查时要找的恰恰是这一条。

**现在：** 每个经过代理的请求落成一条会话，只落一次，失败的也落。没完成的带 `error: {phase, message}`，`phase` 说停在哪一步（`client-tls`、`request`、`rules`、`plugin`、`dns`、`connect`、`proxy`、`tls`、`response`、`client`、`abort`）。本代理生成的 502 带 `x-whistle-rs-error`（阶段）和 `x-whistle-rs-session`（会话号），源站自己回的 502 两个都没有。字段、各入口的范围写在 [API 的「失败的请求」](API.md#失败的请求)，排查顺序写在 [Cookbook](COOKBOOK.zh-CN.md#规则不生效时)。

| 改动 | 提交 | 怎么验证的 |
| --- | --- | --- |
| 失败的请求也成会话；阶段在出错的地方打标签，不靠猜错误文本；本代理的 502 带两个头 | `155e049` | `src/proxy/failure_tests.rs` 用本地夹具逐个复现 dns、connect、tls、response、proxy、rules、abort、client，外加 WebSocket 握手连不上；对照组是源站自己回 502，会话不标失败、502 不带头 |
| 会话在 body 结束时才算完成，这时才写盘、才调嵌入 API 的 `on_session`，只调一次；body 中途断开补记 `response`，客户端中途离开补记 `client` | `ec97bb2` | `outcome.rs` 4 条结算测试（含"写了 `content-length`、hyper 读够就丢 body"不能误判成客户端离开）；夹具测试 3 条 |
| 客户端不接受本代理证书，记一条 `CONNECT`，阶段 `client-tls`；不解密转发的隧道记一条 `CONNECT`，连不上按 `dns`/`connect`/`proxy` 失败；SOCKS 同 | `82bbc56` | 夹具测试 4 条 + SOCKS 1 条；开隧道一个字节不发就关的，确认什么都不记 |
| 认证插件自己坏了（连不上、回 500）时，502 也带两个头 | `fc5d413` | 夹具测试；去掉修复就失败 |
| 控制台：失败行标阶段、圆点变红；详情页先给"没完成"卡片；状态徽标分清"没完成""源站回了错误码""旧历史里没记原因"；`e:` 能搜阶段和原因（`e:dns`） | `fa64630` `669061a` | typecheck/build；HAR 导出的 `_error` 有测试（`b31ebdf`） |
| 失败的日志行以会话号开头，和控制台、502 的头对得上 | `7c92c45` | — |
| 差分：两个新头是本项目独有的，在 `EXPECTED` 里整体豁免一次，不逐条声明 | `799d527` | `run.js all` |

**端到端：** `tests/failure_e2e.rs` 拿一个被拒的连接，核对客户端收到的 502、会话列表、会话详情、`on_session` 回调、磁盘历史、重启后重新加载，六处阶段和原因一致，且只有一条。

**顺带修掉的**（都是这次的测试撞出来的）：

- `proxy://alice:s3cret@:8080` 这种用不了的代理规则，错误信息原样带出密码——而它就是 502 的正文和会话的原因。现在显示成 `***@`（`1fc0775`）。
- 嵌入 API 的 `persist_sessions(true)` 什么都不写盘：只有二进制的 `main()` 装了历史存储，端到端测试发现的（`42f135d`）。
- 选中的失败行在鼠标悬停时是白字配浅粉底，看不清（`669061a`）。

**实测：** `cargo fmt --check`、Clippy `-D warnings` 通过；`cargo test` 998 单元 + 29 集成 + 2 doc 全过（`fc5d413`）；前端 typecheck/build 通过。差分 `run.js all` 28 步全过（1087 秒，代码 `bcda843`，未提交的只有 README/ROADMAP/STATUS），上游自带测试仍是评判 180、通过 154、声明 26、未声明 0。`fc5d413` 只改了认证插件失败这一条路径，差分不覆盖它，没有重跑。这次差分的最后一步（上游自带测试）跑到一半时，本机按同一提交重新构建过一次二进制（控制台重新嵌入），所以那一步用的二进制和归档里记的哈希不是同一个文件，代码相同。

**剩余风险 / 没做的：**

- 插件的请求/响应钩子失败时，请求照常放行，会话**不标**失败；只有认证网关失败算 `plugin` 阶段。归 R1。
- 一直不结束的流（长连着的 SSE）结束前不写盘；进程被直接杀掉时，还开着的会话不进历史。
- Composer/Replay 接口接下任务就回答，不返回会话号，要去列表里找最新那条。
- 客户端开了隧道一个字节没发就关掉的，不记（什么都没请求）。
- 这批改动还没在 GitHub CI 上跑过（需要推送）。

## 2026-09-29 O2 检索、采集和自有 API 契约

**结论：** 控制台检索框能答 `h:`、`b:`、`fc:` 了，`app:` 仍明确不支持；"只是没显示"和"没有记录"分开了，后者有测试核实；body 没存全时，接口、HAR、重放、复制 cURL 都会说；接口的拒绝统一成一种 JSON，会话列表能当游标轮询；API.md 和路由表由测试双向核对。接口细节只写在 [API.md](API.md)。

| 修之前 | 现在 | 提交 | 怎么验证的 |
| --- | --- | --- | --- |
| 会话写盘再读回，body 的信息是重新推算的，每种都有算错的：完整的 body 重启后全显示"没存全"；截断的读回成完整，重放会把前缀当整个 body 发；PNG 读回成一段写着 `[binary, N bytes]` 的文本，`/body.bin` 把这句话当图片发；GBK 页面变成 U+FFFD | 标记原样写盘，字节在文本装不下时（二进制、非 UTF-8）存 base64；读回按写下的标记恢复。旧历史里只有标记的二进制 body 读回为"一个字节都没存" | `724ecf7` | 6 种 body 的往返测试；把读回换回旧写法，测试失败。真二进制重启后实测 `len`、`truncated` 不变 |
| body 解压到一半失败，只有 Replay 知道 | 预览多一个 `undecodable`，并算作截断；控制台写明 | `724ecf7` | 同上 |
| HAR 里截断的 body 只有前缀、`size` 却是全长，没有任何标记 | `comment`（HAR 1.2 标准字段）写明存了多少，外加 `_truncated: true`；非 UTF-8 文本按 base64 导出 | `9521e55` | 2 条测试 |
| Copy as cURL 悄悄丢掉截断的 body，二进制 body 把标记当 `--data-raw` 发；Edit & Resend 把标记填进 Composer；批量重放只报条数 | cURL 不带 body，行尾用 shell 注释写原因；Composer 不填标记并说明；批量重放报出几条被截断 | `9e6d416` | 用 Node 直接跑 `asCurl` 四种情况；typecheck |
| `fc:` 没有字段可读，只能报不支持 | 会话记 `composer`，写盘，行上带出（失败的也记） | `5bc7c43` | 端到端（含一条失败的 Composer 请求）；往返测试 |
| `h:`、`b:` 只能报不支持 | 代理在手里的全部会话里查（`/api/sessions/search`），正则用 regress，和浏览器 `RegExp` 语法一致；`b:` 列出"没匹配但 body 没存全"的会话，控制台在计数旁写明几条没法排除 | `9dfc33b` `ac79c4c` | 检索模块 4 条测试、端到端 1 条、JS 用例表；浏览器里实测 6 种查询 |
| Capture filter 框里写 `h:` 会被悄悄丢掉，框里只剩它时等于全部放行；按钮说它决定"保留还是丢弃" | 框下明确列出被忽略的条件和原因；按钮、提示、注释都改成"只影响列表显示，代理照记"，要不记用 `enable://hide` | `6b3409a` | 浏览器实测 |
| `enable://hide` 的请求失败时，502 带着一个指向不存在会话的会话号 | 不带会话号，日志写 `(hidden)`；"不记录"有端到端测试：接口、详情、检索、HAR、嵌入回调、磁盘历史里都查不到；`persist_sessions(false)` 时磁盘上没有流量 | `ca76801` `aeb47cc` | 2 条端到端测试；修之前第一条在会话号那一行失败 |
| 接口拒绝有四种样子：纯文本、不带类型的 JSON、`{ok:false}`，还有一种用 `format!` 拼、遇到引号就坏的 JSON | 全部 `4xx` + `application/json` + `{ok:false, error}` | `d37777c` | 10 种拒绝的端到端测试 |
| `/sessions.json` 每次返回全部，看不出哪条还在传 | `after`、`ids` 两个参数；响应还在传的行带 `open: true`，结束后消失 | `7b84753` | 端到端：body 发一半停住的源站 |
| API.md 和代码没有任何核对 | `api_doc_tests` 从路由表和 API.md 双向核对，curl 示例也核对 | `ad4c1a9` `8e15cf3` | 一上来就查出 4 个没写的路由；文档里加一条假路由，测试失败 |

文档：API.md 重写了读取、出错、检索、采集与显示几节；两份 Cookbook 和 OPERATIONS 同步，排查表里"被抓包筛选挡在外面"改成"只是从列表里藏起来"（`d343757`）。

**检索的开销**（release 构建，本机 M4，每条响应 31 KB、存 16 KB）：

| 手里的会话 | 关键字，扫完全部没命中 | 正则，扫完全部没命中 | 命中在前面 |
| --- | --- | --- | --- |
| 600（默认 `-R`） | 5 ms | 35 ms | 5–12 ms |
| 5000（`-R 5000`） | 38 ms | 约 300 ms | — |

控制台只在检索框里有 `h:`/`b:`、开着自动刷新、停在 Requests 页时，每 2 秒问一次。

**与上游的有意偏离：** `h:` 名字、值或 `名字: 值` 整行任一匹配就算（上游代码只测名字和值，它文档的例子却需要整行）；Capture filter 不接受 `h:`/`b:`（上游接受请求头和请求体），因为它按到达时的列表行判断；`app:` 不支持（上游在浏览器里按 User-Agent 猜）。

**实测：** `cargo fmt --check`、Clippy `-D warnings` 通过；`cargo test` 1009 单元 + 34 集成 + 2 doc 全过；前端 typecheck/build、链接检查、`run.js fast` 通过（代码 `6065250`）。差分 `run.js all`（代码 `8e15cf3`）27 步通过，上游自带测试一步失败，原因是**多过了**：`/cgi-bin/values` 的 `add`/`rename` 6 条调用原本声明为失败，现在通过了——它们没有自己的断言，只检查返回能解析成 JSON，而本项目的 404 现在是 JSON。`/cgi-bin` 仍未实现；删掉过期声明、写明原因（`6065250`）后单跑这一步通过：评判 180、通过 160、声明 20、未声明失败 0、过期声明 0。其他 27 步的上游对照结果没有新差异。

**剩余风险 / 没做的：**

- `b:` 只查存下的预览（默认 16 KiB）。没存全的会列出来，但真正的匹配若在后面，查不到。
- 控制台仍然每 2 秒整表拉取，没用新游标；`-R` 很大时这本身是开销。
- 被 `enable://hide` 的 Composer/Replay 请求也不记（上游只受 `hideComposer` 控制），属于既有差异，未改。
- 超过预览上限的 body，上游整个不存，本项目存前缀并标记，属于既有差异。
- Composer/Replay 接口仍不返回会话号。
- 旧格式历史里的二进制 body 只有标记，读回为"一个字节都没存"，无法恢复。
- 历史文件会变大：二进制和非 UTF-8 的 body 现在连字节写盘（base64），每个最多约 1.33 × 预览上限（默认约 21 KB）；以前只写一句标记。按天保留（`--persist-days`）不变。
- 这批改动还没在 GitHub CI 上跑过（需要推送）。

## 真实缺口与风险

| 优先级 | 发现 | 后续任务 |
| --- | --- | --- |
| ~~P0~~ | ~~质量状态漂移：Clippy 两处错误、格式未统一；未固定工具链/最低支持版本~~ 2026-09-28 已解决，见 Q1 复验 | Q1 ✓ |
| ~~P0~~ | ~~可复现交付不足~~ 2026-09-28 已解决：锁文件、统一入口、CI 首跑通过；全量差分 workflow 尚待在 GitHub 上首次触发 | Q2 ✓ |
| ~~P0~~ | ~~发布许可不完整~~ 2026-09-28 已补齐（MIT、NOTICE、Cargo 元数据、第三方许可生成）；发布构件已由 CI 首跑生成 | Q3 ✓ |
| ~~P0~~ | ~~默认全接口、无 UI 口令、跨站可写~~ 2026-09-28 已收紧（回环默认、跨站/Host 检查、文件权限、保留期与删除）；仍无代理本身的访问控制 | S1 ✓ |
| ~~P1~~ | ~~早期请求失败缺少统一会话结果；依赖日志/502，影响定位 DNS/连接/TLS 失败~~ 2026-09-29 已解决：失败请求各有一条带阶段和原因的会话，见 O1 记录 | O1 ✓ |
| ~~P1~~ | ~~UI 检索字段、采集/显示过滤、二进制与截断状态需要更明确的契约；不能把过滤后的画面当作隐私保证~~ 2026-09-29 已解决，见 O2 记录；`b:` 只能查已存的预览 | O2 ✓ |
| P1 | 缓冲改写超限、流式算子边界和 cipher 降级应被用户/Agent 看见，而不只藏在日志或长文档里 | R1 |
| P1 | 当前上游 2.10.9/2.10.10 变化尚未做版本矩阵复验；优先核查带 charset 的 SSE、pipe 阻塞/内存、DNS 顺序 | U1 |
| P2 | 上游连接池、源站 h2、长连接资源与跨平台分发需要专项验证，不能仅因 Rust 实现就承诺性能更高 | PERF1 / D1 |
| P2 | `apply.rs`、`mod.rs`、`webui.rs` 体积较大；测试完善后沿责任边界拆分，避免先做无收益重写 | M1 |

Q/S/O/R/U/P/D/M 编号均指 [ROADMAP.md](ROADMAP.md)。这是一份审查快照，不是新功能已经完成的报告。

## 不应混入必做清单的事情

直接兼容 npm 插件、逐像素复刻官方 React UI、复刻 `/cgi-bin/*` 数据模型、强制随代理捆绑 Node，都不是本项目当前交付目标。没有新的产品决策，不应把它们作为“全面对齐”的隐含承诺。确有迁移客户时，单独设计薄适配层与契约测试，不污染核心协议。
