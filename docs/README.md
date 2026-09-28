# 文档导航

[项目与快速开始](../README.md) · [当前状态](STATUS.md) · [活动计划](ROADMAP.md)

## 使用

| 文档 | 内容 |
| --- | --- |
| [COOKBOOK.zh-CN.md](COOKBOOK.zh-CN.md) / [English](COOKBOOK.md) | 域名转发、Mock、改写、限速、手机抓包、HAR 与嵌入场景 |
| [CLI.md](CLI.md) | 本项目命令行参数及与上游的差别 |
| [API.md](API.md) | 自有控制接口、读写参数、认证与副作用边界 |
| [RULES.md](RULES.md) | 规则语法、优先级、算子与已知偏离 |
| [CERTIFICATES.md](CERTIFICATES.md) | 下载、安装和信任 CA |
| [OPERATIONS.md](OPERATIONS.md) | 本机/局域网运行、敏感数据和安全边界 |

## 开发与扩展

| 文档 | 内容 |
| --- | --- |
| [DEVELOPMENT.md](DEVELOPMENT.md) | 构建顺序、测试命令、差分复现与证据要求 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 模块与请求生命周期；当前 UI 为 `ui-src/` Vue 应用 |
| [PLUGINS.md](PLUGINS.md) | 本项目自有插件协议、Rust 钩子与 JS/TS SDK；不是上游 npm 插件 API |
| [TEMPLATES.md](TEMPLATES.md) / [LINE_PROPS.md](LINE_PROPS.md) | 模板变量与规则行属性 |

## 状态与维护

[STATUS.md](STATUS.md) 是有日期、版本和证据范围的对齐快照；[ROADMAP.md](ROADMAP.md) 是唯一活动计划；[UPSTREAM.md](UPSTREAM.md) 定义上游基线与复核方法。

[ROADMAP-HISTORY.md](ROADMAP-HISTORY.md) 只保存历史调查。不要把它的勾选项、旧计数和「本轮全绿」复制成当前承诺。其余长篇参考手册保留详细技术说明，但不能单独证明某个提交已经通过验证；冲突先核对实现与测试，再同步本页链接的状态文档。
