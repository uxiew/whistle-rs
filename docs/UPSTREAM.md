# 上游对照基线

[项目说明](../README.md) · [对齐结论](STATUS.md) · [验证方法](DEVELOPMENT.md)

源码、手册与测试中形如 `_original/lib/rules/rules.js:1449` 的标记是上游源码定位线索，
不是自动证明兼容的测试结果。引用数量随代码变化，不再维护容易过期的总数。

上游源码不随本仓库分发。2026-09-25 检查时本地已有未跟踪的 `_original/`，
本轮没有改动；复核时不要覆盖自己的既有副本。

## 版本不是同一个概念

| 对象 | 约束 |
| --- | --- |
| 可执行 oracle | `tests/differential/package.json` 固定 Whistle **2.10.8**；本轮读取已安装包确认一致 |
| 历史源码定位 | 旧文档记录 `1df0805f09fd979e0e31fd6eab99ca97239ac1ec` / `v2.10.8`；本轮未独立确认二者及发布包的逐文件对应关系 |
| 在线 master / 官网 | 2026-09-25 在线观察 `master/package.json` 为 **2.10.10**；官网与 master 都是浮动资料，不自动成为兼容基线 |

来源：[官方仓库](https://github.com/avwo/whistle)、[package.json](https://github.com/avwo/whistle/blob/master/package.json)、[更新日志](https://github.com/avwo/whistle/blob/master/CHANGELOG.md)、[官网文档](https://wproxy.org/docs/)。
升级基线按 ROADMAP 的 U1 做双版本复验，不直接把旧报告的版本号替换掉。

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

差分脚本实际读取 `tests/differential/node_modules/whistle/`；安装方式见 DEVELOPMENT。
**npm 发布包不应被无条件描述为 Git 仓库的“同一棵树”**：发布清单、生成物和测试资料可以不同。
当前差分目录也没有受版本控制的依赖锁文件，仅顶层版本固定，Q2 将补齐传递依赖可复现性。

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
