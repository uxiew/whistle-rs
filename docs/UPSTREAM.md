# The upstream reference

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

本移植的源码与文档里有 **513 处**形如 `_original/lib/rules/rules.js:1449` 的引用。
它们指向的是**原版 whistle 的源码**，是每一条对齐声明的凭据 —— 没有它，任何
「与上游一致」的说法都无法复核。

原版**不再随本仓库分发**（它是另一个项目的代码，34 MB，且有自己的 git 历史）。
需要复核时，按下面取回。

## 取回

```sh
# 在本仓库的**同级**目录下（引用路径是 ../_original/…）
cd ..
git clone https://github.com/avwo/whistle.git _original
cd _original
git checkout 6da6e6c174c4d308199b9512c1ce1a7a671893ba
```

| | |
|---|---|
| 仓库 | `https://github.com/avwo/whistle.git` |
| 提交 | `6da6e6c174c4d308199b9512c1ce1a7a671893ba` |
| 标签 | `Release v2.10.4` |
| 本移植对齐的版本 | whistle **2.10.4** |

**行号只对这个提交有效。** 上游后续版本会移动它们；如果你在核对时发现某个引用
指向了明显无关的代码，先确认 checkout 的是上面这个提交，再怀疑引用写错了。

## 目录对照

引用集中在这几个文件，按出现频率排：

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

本仓库里凡是「与上游一致」的说法，都应能这样验证：

1. 打开引用指向的上游代码，读它**实际做了什么**（而不是它的注释说做什么）。
2. 把那段逻辑抄成一个独立的 node 脚本 —— 上游没有 `node_modules`，
   `require` 整个包会失败，抄出你需要的函数比装依赖快得多。
3. 用同一批输入分别跑上游脚本与本移植，逐条比对。

本仓库已经这样做过两次，两次都推翻了先前基于阅读得出的结论：
`src/rules/wildcard.rs` 的三种通配符编译（正则源码逐字符比对），以及
`format_shorthand` 的展开表（期望值直接来自上游函数的输出）。
**读代码得出的结论比跑代码得出的结论弱一档**，本文件的存在就是为了让后者随时可做。
