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
node scripts/check-links.mjs
node tests/differential/run.js fast   # 需先在 tests/differential 里 npm ci
git diff --check
```

在 `rust-toolchain.toml` 钉住的工具链上，这些命令都应通过；任何一条失败都算门禁失败，不要用全局 `allow` 或降低 lint 级别绕过。最近一次实测的提交、环境和计数只记在 [STATUS](STATUS.md)，手册里不抄数字。普通测试不会执行 `#[ignore]` 基准；`--all-targets` 也不能替代单独的 doc tests。

格式化只用 rustfmt 默认配置（仓库里没有 `rustfmt.toml`）。整树重排这类纯格式提交要记进 `.git-blame-ignore-revs`，本地执行一次 `git config blame.ignoreRevsFile .git-blame-ignore-revs`，`git blame` 就会跳过它们。

首次安装允许 Cargo 下载 Cargo.lock 固定依赖，缓存齐备后才考虑 `--offline`。不要把离线缓存不完整当成源码错误，也不要为通过测试擅自更新锁文件。

## 文档链接与控制台检查

```sh
node scripts/check-links.mjs                                  # 所有受版本控制的 Markdown 的相对链接和 #锚点
scripts/check-console.sh target/release/whistle-rs built      # 二进制嵌入的就是 ui-src/dist 这一版控制台
scripts/check-console.sh target/debug/whistle-rs placeholder  # 没有前端产物时，二进制能跑且给出占位页
```

链接检查只认 git 跟踪的文件：`_original/` 在本机存在，但在 GitHub 上是 404，指向它的链接会被报出来。外链不联网检查。`check-console.sh` 只用 sh 和 curl，所以也能在没装 Node 的环境里跑；它对 curl 加了 `--noproxy '*'`——本机设了 `http_proxy` 又没设 `no_proxy` 时，curl 连 127.0.0.1 也会走代理，检查会一直卡住。

## 与上游的差分

```sh
cargo build --locked              # 仓库根目录；比源码旧的二进制会被拒绝
cd tests/differential
npm ci                            # 按锁文件装 whistle 2.10.8 全套依赖；不要用 npm install
node run.js fast                  # 约 5 秒：规则解析差分（文档语料 + 手写语料）和二维码，不开端口代理
node run.js network               # 约 18 分钟（2026-09-29 本机 `all` 实测 1093 秒）：两边代理都起来，所有语料、专项 bench 和上游自带测试
node run.js network --only cases-delete,https   # 只跑几步；--list 列出全部步骤
```

**对照第二个上游版本（2.10.10）：** 它有自己的目录和锁文件，不会动到 2.10.8 基线。

```sh
(cd versions/2.10.10 && npm ci)                      # 一次
node run.js all --whistle 2.10.10                    # 对 2.10.10 的门禁
node matrix.js ../../target/differential/<基线那次> ../../target/differential/<2.10.10 那次>   # 两版之间谁变了
```

两次要用同一个二进制（先复制一份，用 `RS_BIN=` 指过去），否则 `matrix.js` 会拒绝比较（退出码 2）：它分不清一个变化是上游的还是本项目的。`--assume-baseline`、加新版本的步骤只写在[差分 README](../tests/differential/README.md#which-whistle-though)，两版的实测差别见 [STATUS 的 U1 记录](STATUS.md#2026-09-29-u1-上游版本矩阵)。

`run.js` 自己起停需要的代理，数据目录、根证书和会话都放在用完即删的临时目录里，只监听 127.0.0.1；开跑前逐个检查要用的端口，被占用就直接退出并报端口号和占用者；每个子进程单独一个进程组，结束或 Ctrl-C 时整组杀掉，不会留下还在监听的代理。退出码：0 全部通过，1 有步骤失败，2 没法开始（端口被占、二进制缺失或比源码旧、没跑 `npm ci`）。归档在 `target/differential/<时间>-<套件>/`：`manifest.json` 记录提交与未提交文件、whistle-rs 版本和 SHA-256、whistle 版本和锁文件哈希、每个脚本和语料的哈希、Node 版本、每一步的命令和结果，外加每一步的输出和每个代理的日志。

判定规则只有一条：**没人解释过的差异就失败。** 已知且接受的差异逐条写在 `tests/differential/declared.js`（用例、字段、在哪些上游版本上测过、理由；只对列出的版本生效）；跨语料反复出现的模式在 `harness.js` 的 `EXPECTED`，每条都限定了能豁免的字段和用例范围。声明了却不再出现的差异同样算失败——留着它，以后这个字段在这个用例上出什么问题都会被放过。每个语料跑完还会跑 `triage-inert.js`：规则一条都没命中、又没说明原因的用例算失败。

新增例外时照这个格式写进 `declared.js`，别加宽 `EXPECTED` 的匹配范围，也别往 `IGNORE` 里加头。门禁到底能不能抓到回归，用 `node mutations.js` 验证：它在 HEAD 的临时 worktree 里逐条注入几个预设的语义回归，每条都必须让对应门禁失败（所以跑之前先提交）。

**上游自带的测试**也是 `network` 里的一步（`upstream-suite`，约 4 分钟）：拿所测上游版本那个 tag 的 `test/` 原样跑 whistle-rs（2.10.8 与 2.10.10 的 `test/` 完全相同），第一次运行会从 GitHub 按提交号取到 `target/upstream-suite/`。它用上游固定的端口（6666、18080、5566、1080 等），跟 `--port-base` 无关，端口被占会直接报出来。单独跑：`node upstream-suite.js`；某个单元挂了，用 `node upstream-suite.js --target rs --only <单元名> --verbose` 看每条调用的状态和错误页。它评判哪些调用、怎么声明例外，只写在[差分 README](../tests/differential/README.md#upstreams-own-test-suite)。

**性能对比**不是门禁，`run.js` 不跑它，要手动跑。它测的是 release 二进制，改了连接或数据通路之后跑一次，和 [STATUS 的 PERF1 记录](STATUS.md#2026-09-29-perf1-源站连接复用与源站-h2)里的数字比较：

```sh
cargo build --release
node perf-bench.js                   # 在 tests/differential 里；回环，约 2 分钟
RTT_MS=20 node perf-bench.js         # 源站前面加 20 ms 往返时延
```

每个场景报告源站连接数、TLS 握手数、延迟、吞吐、峰值内存和取消后的释放时间；参数和它模拟不了什么，只写在[差分 README](../tests/differential/README.md#what-a-request-costs-the-network)。

**Node 版本会影响结果。** 对照组是跑在 Node 上的 whistle，有些答案随 Node 版本变（`cases-compose.js` 记录过 gzip 头的一个字节）。当前声明是在 Node 26 上测的，CI 的差分任务也用 26；换版本要重新测量。

几条不要做的事：不要把官网示例直接当网络用例跑（真实 URL 会产生外部请求）；测试 CA 只给测试客户端信任，不导入系统；`npm audit fix` 会悄悄换掉对照组，别跑（原因见差分 README）。各语料、专项 bench 和锁文件审阅的细节只写在 [tests/differential/README.md](../tests/differential/README.md)。

## CI

`.github/workflows/ci.yml` 在每个 PR 和推到 main 时运行：钉住工具链上的 fmt/Clippy/全部测试、MSRV 版本上的全部测试、在不含 Node 的 `rust:1.98.1-trixie` 容器里构建纯代理并检查占位页、Node 20.19.0 和 24 两个版本下的前端 typecheck/build、先构建控制台再构建 release 并断言嵌入的是真控制台（构件是二进制、`LICENSE`、`NOTICE.md`、`THIRD-PARTY-LICENSES.md` 和它们的 SHA-256）、文档链接检查、`run.js fast`。`.github/workflows/differential.yml` 跑全量网络差分，同一个二进制先对 2.10.8、再对 2.10.10 各跑一遍 `run.js all`，最后用 `matrix.js` 比较两版，手动触发或每周一凌晨，结果归档上传。所有 action 都按提交哈希钉住版本，注释里写了对应的 tag。

性能基准与长连接稳定性另行记录配置、硬件、制品和资源曲线。macOS 测试不能代替 Linux/Windows 真机，编译成功不能替代证书、网络和 UI 工作流测试。

## 变更交接

先记录 git 状态和既有未提交内容；不要覆盖用户的 `_original/` 或其他工作。规则变更同时更新最小反例、差分语料和对应手册；行为变化写入 STATUS 的下一次快照。每次验收关联具体提交/制品与命令，标明 skipped/未运行项，禁止从历史路线图复制“全绿”。

文档分层保持稳定：根 README 是入口，操作细节放本文/OPERATIONS/参考手册，当前状态放 STATUS，活动任务放 ROADMAP，过程证据放历史记录。

## 发布与许可

发布物带三份许可文件：`LICENSE`（本项目，MIT）、`NOTICE.md`（哪些来自上游 whistle，附其 MIT 原文）、`THIRD-PARTY-LICENSES.md`（编进二进制的全部 crate 和控制台 npm 包的许可原文）。最后一份每次发布现生成，不入库：

```sh
node scripts/third-party-licenses.mjs --target x86_64-unknown-linux-gnu   # 需先 cargo fetch 和 npm ci --prefix ui-src
```

有包完全没声明许可时脚本失败；声明了却没带原文的只列 SPDX 标识并在 stderr 点名。crate 包的内容由 `Cargo.toml` 的 `include` 白名单决定——没有它，`cargo package` 会把本地未忽略的一切打进去，包括 `_original/` 里的上游源码。加新的顶层文件时，想让它进包就加进白名单。

检查包时用独立的 target 目录：`cargo package --locked --target-dir target/package-check`。不加的话，`cargo package` 会用解包后的源码（里面没有 `ui-src/dist`）重新编译，结果写进同一个 `target/debug/`，把本机带真控制台的二进制换成占位页版本；而且之后普通的 `cargo build` 也不会自己恢复——构建脚本以为前端产物没变，一直沿用那份占位页，要 `touch ui-src/dist/index.html` 再编译才回来。
