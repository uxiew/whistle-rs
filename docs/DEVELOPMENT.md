# 开发、构建与验证

[文档导航](README.md) · [架构](ARCHITECTURE.md) · [上游基线](UPSTREAM.md) · [本轮结果](STATUS.md)

## 构建顺序

本项目使用 Rust edition 2024；目前尚未提交固定工具链与明确 MSRV。前端为 Vue 3/Vite，Vite 8.2.0 的 Node 要求是 `^20.19.0 || >=22.12.0`，本轮使用 Node 24.9.0。需要平台正常的编译工具；`ring` 不意味着“无需 C 工具链”或任意平台的全静态制品。

仓库根目录执行：

```sh
npm ci --prefix ui-src
npm run typecheck --prefix ui-src
npm run build --prefix ui-src
cargo build --locked --release
```

`build.rs` 将 `ui-src/dist/index.html` 复制到 Cargo 的 `OUT_DIR`，再由 Rust 嵌入。更新 UI 后必须再次构建 Rust。没有前端产物时编译仍可成功，但首页仅为占位页；“Cargo 成功”不等于“可交付完整控制台”。不要将生成的 dist、target 或测试 CA 提交到仓库。

开发前端可运行 `npm run dev --prefix ui-src`；嵌入式调用例子在 `examples/embedded.rs`。前端独立开发说明见 [ui-src/README.md](../ui-src/README.md)。本项目没有 `w2 start/stop` 守护进程管理兼容层。

## 快速质量检查

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
npm run typecheck --prefix ui-src
npm run build --prefix ui-src
git diff --check
```

这些是应通过的门禁，**不是当前都已通过的声明**。2026-09-25 的 Clippy/格式问题及实测数字集中记录在 STATUS，不在每份手册重复维护计数。普通测试不会执行 `#[ignore]` 基准；`--all-targets` 也不能替代单独的 doc tests。

首次安装允许 Cargo 下载 Cargo.lock 固定依赖，缓存齐备后才考虑 `--offline`。不要把离线缓存不完整当成源码错误，也不要为通过测试擅自更新锁文件。

## 解析差分

```sh
# 在根目录生成 oracle 固定读取的 debug 二进制
cargo build --locked
cd tests/differential
# 此目录当前没有受版本控制的锁文件；不能假定 npm ci 可用
npm install
node rules-oracle.js --values
```

`package.json` 固定直接依赖 Whistle 2.10.8，但未锁定全部传递依赖。Q2 要把安装改成锁文件驱动；在该任务完成前，报告需记录实际安装版本，不能写成完全可复现的依赖树。

`rules-oracle.js` 直接调用上游解析器，并询问 `target/debug/whistle-rs explain --batch`。它不打开代理端口，适合语法/匹配/取值回归；不覆盖真实网络、响应阶段、动态 includes 或插件。报告同时保存 questions、answered、differing、value differences 和归一化信息，不能只抄退出码。

## 真代理、流和专项差分

`harness.js` 比较客户端与源站两端结果，语料由 `CASES` 选择、端口基址由 `PORT_BASE` 指定。`https-bench.js`、`timing-bench.js`、`write-bench.js`、`frames-bench.js`、`header-rules-bench.js` 等覆盖不同边界，启动/清理安排须先读各脚本；当前没有一个经本轮验证的“跑一条命令即全套验收”入口。

只在专用临时目录、回环地址和自有夹具上跑网络差分；不要把官网所有示例直接当网络用例执行，其中的真实 URL 或文件路径可能产生外部请求和副作用。测试 CA 只供测试客户端信任，不自动导入系统。

`IGNORE`/`EXPECTED` 是有限的归一化与已知偏离，而不是掩盖回归的工具。每项新增例外要绑定用例、字段、上游版本和理由；无法区分“实现了”和“根本没实现”的 `inert` 用例须解释或加强。

性能基准与长连接稳定性另行记录配置、硬件、制品和资源曲线。macOS 测试不能代替 Linux/Windows 真机，编译成功不能替代证书、网络和 UI 工作流测试。

## 变更交接

先记录 git 状态和既有未提交内容；不要覆盖用户的 `_original/` 或其他工作。规则变更同时更新最小反例、差分语料和对应手册；行为变化写入 STATUS 的下一次快照。每次验收关联具体提交/制品与命令，标明 skipped/未运行项，禁止从历史路线图复制“全绿”。

文档分层保持稳定：根 README 是入口，操作细节放本文/OPERATIONS/参考手册，当前状态放 STATUS，活动任务放 ROADMAP，过程证据放历史记录。
