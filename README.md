# whistle-rs

用 Rust 实现的 Whistle 核心调试代理：规则改写、HTTP/HTTPS 抓包、WebSocket 检查、内嵌 Web 控制台，也可作为 Rust 库嵌入应用。

**0.1.0，不是官方 Whistle，也不是完整的直接替代品。** 行为以 Whistle 2.10.8 为对照基线；插件协议、控制台 API 和部分 CLI 语义不同。依赖现成 `whistle.*` npm 插件、官方 `/cgi-bin/*` API 或 `w2 start/stop` 的工作流不能直接迁移。

**进度：** 质量门禁（Q1）、可复现差分门禁与 CI（Q2）、许可与来源（Q3）、安全运行契约（S1）已完成；上游 whistle 自带的测试已成为门禁（U0：可评判的 180 条中现在 160 条通过、20 条逐条声明原因）；失败的请求（DNS、连接、TLS、中途断开、客户端不信任证书）也会在控制台留下一条会话，写明停在哪一步（O1）。控制台检索能查请求头和 body（由代理查，只查已存下的部分），body 没存全时接口、HAR 和重放都会写明，只有 `enable://hide` 真正不记录请求（O2）。命中了但没执行的规则（body 超上限、事件流、压缩解不开、插件钩子失败）会在会话和控制台里写明原因（R1）。下一项是上游版本矩阵（U1）。详见[当前状态](docs/STATUS.md)与[计划](docs/ROADMAP.md)。

## 构建

需要 rustup（按 `rust-toolchain.toml` 自动安装 Rust 1.98.1，最低可编译 1.95）；构建控制台另需 Node.js `^20.19.0 || >=22.12.0`。

```sh
npm ci --prefix ui-src && npm run build --prefix ui-src   # 控制台，Rust 编译时嵌入
cargo build --locked --release                            # 产物 target/release/whistle-rs
```

只跑 `cargo build` 也能得到可用的代理，但首页是"控制台未构建"的占位页。运行代理不需要 Node（Node 插件除外）。改代码后要过的检查见[开发与验证](docs/DEVELOPMENT.md)。

## 使用

```sh
./target/release/whistle-rs -p 8899 --no-persist   # 默认只监听本机；--no-persist 不保存历史
```

控制台在 `http://127.0.0.1:8899/`；把客户端的 HTTP/HTTPS 代理设为 `127.0.0.1:8899`（根证书在首次启动时生成）：

```sh
curl --noproxy '' -x http://127.0.0.1:8899 http://example.com/
curl --noproxy '' -x http://127.0.0.1:8899 --cacert "$HOME/.whistle-rs/certs/root.crt" https://example.com/
```

规则在控制台里编辑（或启动时 `-r rules.txt`）：

```text
api.example.com/mock statusCode://503
api.example.com http://127.0.0.1:3000
example.com resHeaders://x-debug=1
```

具体的 mock 写在宽泛的转发之前——转发、文件、重定向、`statusCode` 共用一个规则槽，先匹配的生效。完整写法见[规则手册](docs/RULES.md)。

## 注意

**默认只监听 `127.0.0.1`、控制台无口令、开启 HTTPS 拦截、会话保存 7 天。** 给手机或别的机器用要显式 `-H 0.0.0.0`，而且先用 `-n/-w` 设控制台口令——能改规则的人就能让代理读写本机文件；本项目也不提供代理本身的访问控制，局域网里要靠防火墙限制谁能连。HTTPS 拦截要求客户端信任代理 CA，只用于获授权的流量，不用时撤销信任。完整的安全契约见[安全运行](docs/OPERATIONS.md)。

## 文档

[文档导航](docs/README.md) · [使用手册](docs/COOKBOOK.zh-CN.md) · [CLI](docs/CLI.md) · [API](docs/API.md) · [证书](docs/CERTIFICATES.md) · [插件](docs/PLUGINS.md) · [上游基线](docs/UPSTREAM.md)

## 许可

MIT，见 [LICENSE](LICENSE)。核心行为来自 [avwo/whistle](https://github.com/avwo/whistle)（MIT），哪些内容来自上游、发布包附带哪些第三方许可，见 [NOTICE.md](NOTICE.md)。感谢上游作者与贡献者。
