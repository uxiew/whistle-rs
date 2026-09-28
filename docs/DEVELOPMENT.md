# 开发、构建与验证

[文档导航](README.md) · [架构](ARCHITECTURE.md) · [上游基线](UPSTREAM.md) · [本轮结果](STATUS.md)

## 工具链

| 用途 | 版本 | 定义在 | 版本不对会怎样 |
| --- | --- | --- | --- |
| Rust，跑门禁和日常开发 | **1.98.1**，含 clippy、rustfmt | `rust-toolchain.toml` | 装了 rustup 的机器，在仓库里第一次执行 `cargo` 时自动下载，无需手动切换 |
| Rust 最低可编译版本（MSRV） | **1.95** | `Cargo.toml` 的 `rust-version` | 1.94 及更早立刻报 `rustc 1.94.0 is not supported by the following packages: whistle-rs@0.1.0 requires rustc 1.95`，不会先编译一堆依赖 |
| Node.js，只在构建控制台时需要 | **`^20.19.0 \|\| >=22.12.0`** | `ui-src/package.json` 的 `engines`，由 `ui-src/.npmrc` 的 `engine-strict` 强制 | `npm ci` 直接以 `EBADENGINE` 失败。运行代理本身不需要 Node |

两个 Rust 版本是两件事：`rust-toolchain.toml` 决定**用哪个版本做检查**，`rust-version` 声明**最老能用哪个版本编译**。门禁版本必须钉死，因为 Clippy 每个版本都会加新检查：同一份代码在 1.96.1 上 `clippy -D warnings` 通过，在 1.98.1 上报两处错误。不钉版本，"门禁通过"就取决于谁的电脑跑的。升级门禁版本要单独提交，并在同一提交里修掉新 lint。

- 用发行版自带、不经 rustup 的 Rust 时，`rust-toolchain.toml` 不生效，Clippy 结果可能和门禁不一致；以 1.98.1 的结果为准。
- 1.95 的来历：1.94 不认识 `src/proxy/apply.rs` 里的 `if let` 匹配守卫（E0658），锁定的依赖本身只要求 1.88。验证 MSRV 需要显式指定版本，因为 `+版本` 会覆盖 `rust-toolchain.toml`：

  ```sh
  rustup toolchain install 1.95.0 --profile minimal
  cargo +1.95.0 test --locked --all-targets
  cargo +1.95.0 test --locked --doc
  ```

- Node 下限来自 Vite 8.2.0、rolldown 和 `@vitejs/plugin-vue` 三者的 `engines`，锁文件里没有更严的要求。实测过 24.9.0 和 26.4.0；20.19 这个下限是按依赖声明推出来的，没有真机跑过。
- npm 11 的 `npm ci` 会对 `fsevents`（macOS 文件监听的可选依赖）打印 `allow-scripts` 警告。已实测 `typecheck`、`build` 不受影响；`npm run dev` 的热更新监听没有验证。

还需要平台正常的编译工具；`ring` 不意味着“无需 C 工具链”或任意平台的全静态制品。

## 构建顺序

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

在 `rust-toolchain.toml` 钉住的工具链上，这些命令都应通过；任何一条失败都算门禁失败，不要用全局 `allow` 或降低 lint 级别绕过。最近一次实测的提交、环境和计数只记在 [STATUS](STATUS.md)，手册里不抄数字。普通测试不会执行 `#[ignore]` 基准；`--all-targets` 也不能替代单独的 doc tests。

格式化只用 rustfmt 默认配置（仓库里没有 `rustfmt.toml`）。整树重排这类纯格式提交要记进 `.git-blame-ignore-revs`，本地执行一次 `git config blame.ignoreRevsFile .git-blame-ignore-revs`，`git blame` 就会跳过它们。

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
