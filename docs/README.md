# 文档导航

第一次用，先看仓库首页的 [README](../README.md)：whix 是什么、能做什么、五分钟上手。

## 用它

| 文档 | 什么时候看 |
| --- | --- |
| [COOKBOOK.md](COOKBOOK.md) 使用手册 | 想做一件具体的事：把线上域名指到本地、mock 接口、改请求和响应、模拟弱网、调手机、导出和重放请求 |
| [RULES.md](RULES.md) 规则手册 | 查某个规则怎么写、规则之间谁先谁后、和 Whistle 有哪些不同 |
| [CERTIFICATES.md](CERTIFICATES.md) 证书 | 在电脑、手机、Firefox 上安装和撤销根证书，HTTPS 报证书错误时 |
| [CLI.md](CLI.md) 命令行 | 查启动参数；从 Whistle 的 `w2` 命令换过来 |
| [INSTALL.md](INSTALL.md) 安装 | 下载哪个包、怎么校验、数据目录里有什么、升级和卸载 |
| [OPERATIONS.md](OPERATIONS.md) 运行与安全 | 给手机或局域网用之前；想知道请求记录存在哪、存了什么 |
| [API.md](API.md) HTTP 接口 | 用脚本、测试或 AI 编程助手控制 whix |
| [TEMPLATES.md](TEMPLATES.md) / [LINE_PROPS.md](LINE_PROPS.md) | 规则值里的模板变量；写在规则行上的行属性 |

## 扩展和参与开发

| 文档 | 什么时候看 |
| --- | --- |
| [PLUGINS.md](PLUGINS.md) 插件 | 用 JS/TS 或 Rust 写插件。协议是本项目自己的，Whistle 的 npm 插件装不上 |
| [DEVELOPMENT.md](DEVELOPMENT.md) 开发 | 构建、跑测试、跑和 Whistle 的差分对照、改代码要附什么证据 |
| [ARCHITECTURE.md](ARCHITECTURE.md) 架构 | 模块怎么分、一个请求在代码里怎么走 |
| [UPSTREAM.md](UPSTREAM.md) 上游基线 | 对照的是哪几个 Whistle 版本，怎么复核 |

## 项目状态

- [STATUS.md](STATUS.md)：每项任务测了什么、结果是多少、还有什么没验证，每条带日期和提交号。
- [ROADMAP.md](ROADMAP.md)：唯一的任务计划。
- [ROADMAP-HISTORY.md](ROADMAP-HISTORY.md)：早期的调查记录，只留作历史。里面的勾选、计数、"全绿"都是当时的，不代表现在。

许可与来源见仓库根目录的 [LICENSE](../LICENSE) 和 [NOTICE.md](../NOTICE.md)。文档和代码对不上时，以代码和测试为准，再回来改文档。
