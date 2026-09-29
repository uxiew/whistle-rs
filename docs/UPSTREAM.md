# 上游对照基线

[项目说明](../README.md) · [对齐结论](STATUS.md) · [验证方法](DEVELOPMENT.md)

源码、手册与测试中形如 `_original/lib/rules/rules.js:1449` 的标记是上游源码定位线索，
不是自动证明兼容的测试结果。引用数量随代码变化，不再维护容易过期的总数。

上游源码不随本仓库分发（许可与来源说明见 [NOTICE.md](../NOTICE.md)）。`_original/` 已被 `.gitignore` 忽略，
也不会进 crate 包；复核时不要覆盖自己的既有副本。

## 版本不是同一个概念

| 对象 | 约束 |
| --- | --- |
| 可执行 oracle（基线） | npm 包 whistle **2.10.8**，连同全部传递依赖由 `tests/differential/package-lock.json` 固定 |
| 可执行 oracle（第二个对照） | npm 包 whistle **2.10.10**，由 `tests/differential/versions/2.10.10/package-lock.json` 固定；`run.js --whistle 2.10.10` 用它 |
| 源码定位 | 注释和文档里的 `_original/…:行号` 对应 tag **`v2.10.8` = 提交 `1df0805f09fd979e0e31fd6eab99ca97239ac1ec`** |
| 上游自带测试 | 所测版本那个 tag 的 `test/`（2.10.8 = `1df0805`，2.10.10 = `a1e4751`）；npm 包不带它，`upstream-suite.js` 按提交号从 GitHub 取（git 逐对象校验哈希），缓存在 `target/upstream-suite/`。v2.10.4、v2.10.8、v2.10.10 的 `test/` 完全相同 |
| 在线 master / 官网 | 2026-09-29 npm 的 `latest` 为 **2.10.10**；官网文档是浮动资料，不自动成为兼容基线 |

2026-09-29 核实 2.10.10：npm 包 whistle@2.10.10 的 `lib/`、`biz/webui/lib/`、`index.js` 与 tag `v2.10.10`（`a1e4751d157150e8fe9e6590f4b892a855664b7f`）逐字节相同。

2026-09-28 核实过这三者的对应关系：`git ls-remote` 显示 `v2.10.8` 是指向 `1df0805` 的轻量 tag；npm 包 whistle@2.10.8 的 228 个文件里，227 个（含 `package.json`）与该提交的源码树逐字节相同，唯一多出的 `biz/webui/htdocs/js/index.js` 是发布时构建的上游控制台产物。所以差分测的对照组就是 `1df0805` 的源码，按行号查引用时应检出这个提交。

**本机 `_original/` 未必是这个版本。** 这台机器上的是 `v2.10.4`（`6da6e6c`），行号会对不上几行甚至整段；跟引用前先 `git -C _original checkout 1df0805`，或按下面的方法另外克隆。

来源：[官方仓库](https://github.com/avwo/whistle)、[package.json](https://github.com/avwo/whistle/blob/master/package.json)、[更新日志](https://github.com/avwo/whistle/blob/master/CHANGELOG.md)、[官网文档](https://wproxy.org/docs/)。

**2.10.10 已按同一批语料复验（U1）。** 两版答案不同的地方、本项目各跟了哪一边、为什么，只写在 [STATUS 的 U1 记录](STATUS.md#2026-09-29-u1-上游版本矩阵)。基线仍是 2.10.8：文档里"measured against 2.10.8"的说法照旧成立，除 U1 表里列出的几处外，在 2.10.10 上也一样。以后再加版本，照[差分 README](../tests/differential/README.md#which-whistle-though)做，不要直接把旧报告里的版本号替换掉。

## 源码复核

```sh
# 在自行选定的空目录克隆，不覆盖仓库内已有 _original/
git clone https://github.com/avwo/whistle.git whistle-upstream
cd whistle-upstream
# 先验证旧记录的对象，再用于追溯旧行号
git show --no-patch 1df0805f09fd979e0e31fd6eab99ca97239ac1ec
git checkout 1df0805f09fd979e0e31fd6eab99ca97239ac1ec
```

引用中的 `_original/` 表示上游源码根。实际副本可以在其他位置，将前缀映射过去即可；
不是要求用户机器必须有某个绝对路径。若对象无法获取或与标签不一致，先记录并纠正来源，
不要拿当前 master 的同一行号冒充旧依据。

差分脚本经 `tests/differential/whistle-pkg.js` 读取所测版本的包：基线在 `tests/differential/node_modules/whistle/`，其他版本在 `tests/differential/versions/<版本>/node_modules/whistle/`，各自按锁文件用 `npm ci` 安装，见 DEVELOPMENT。
**npm 发布包不应被无条件描述为 Git 仓库的“同一棵树”**：2.10.8、2.10.10 的代理代码都与 tag 相同（见上），换版本要重新比对。

行号是定位提示，不是稳定 API。新记录优先附版本、文件、函数名、最小用例和结果；
Git 源码、npm 包与当前官网之间的差别必须显式说明。

## 目录对照

主要模块映射：

| 上游路径 | 本移植对应 |
|---|---|
| `lib/rules/rules.js` | `src/rules/mod.rs`、`src/rules/matcher.rs`、`src/rules/wildcard.rs` |
| `lib/util/index.js` | 散见各处；`replace-pattern-transform.js` 对应 `src/rules/replace.rs` |
| `lib/inspectors/req.js` | `src/proxy/apply.rs` 的请求侧 |
| `lib/inspectors/res.js` | `src/proxy/apply.rs` 的响应侧、`src/proxy/mod.rs` 的响应管线 |
| `lib/rules/protocols.js` | `src/rules/protocols.rs` |
| `lib/https/index.js`、`lib/https/ca.js` | `src/proxy/sni.rs`、`src/ca.rs` |
| `lib/socket-mgr.js` | `src/proxy/ws.rs` |
| `lib/plugins/` | `src/plugins/`（**协议不同**，见 [`PLUGINS.md`](PLUGINS.md)） |
| `biz/webui/` | `ui-src/`（**完全重写**，见 [`ARCHITECTURE.md`](ARCHITECTURE.md)） |

## 复核一条声明的做法

先确定版本、输入和要比较的可观测结果。解析问题优先直接运行现有 `rules-oracle.js`，
网络行为则运行受控源站和两种代理，同时比较客户端与源站两端。不要默认为“抄一段函数”
就覆盖了真实依赖、调用顺序或状态；独立摘录只能是更窄的补充证据。

报告关联 Rust 制品、上游版本、语料、命中数、归一化、预期偏离、未知差异和退出码。
“已解析”“已应用”“这些用例一致”“与该版本全量兼容”不能互相替换。历史结果见
[ROADMAP-HISTORY.md](ROADMAP-HISTORY.md)，本轮实际结果见 [STATUS.md](STATUS.md)。
