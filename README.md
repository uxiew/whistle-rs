# whistle-rs

用 Rust 写的 HTTP/HTTPS 调试代理，规则写法沿用 [Whistle](https://github.com/avwo/whistle)：转发请求、mock 响应、改请求头和 body、解密 HTTPS、查看 WebSocket 消息，自带网页控制台，也能作为 Rust 库嵌进你的程序。

版本 0.1.0，**不是官方 Whistle**，也不是能直接替换它的版本。区别见下文[和 Whistle 的区别](#和-whistle-的区别)。

## 安装

**下载现成的包：** Linux（x86_64、arm64）、macOS（Apple 芯片、Intel）、Windows（x86_64）都有，由 CI 构建。去哪下、怎么校验、装到哪、怎么升级和卸载，见 [INSTALL](docs/INSTALL.md)。

### 从源码构建

需要 [rustup](https://rustup.rs)（第一次执行 `cargo` 时按 `rust-toolchain.toml` 自动装 Rust 1.98.1），网页控制台还需要 Node.js（20.x 要 20.19 以上，或者 22.12 以上）。

```sh
npm ci --prefix ui-src && npm run build --prefix ui-src   # 先构建控制台
cargo build --locked --release                            # 再编译，控制台会被嵌进二进制
./target/release/whistle-rs --version
```

跳过第一行也能编译出能用的代理，只是打开控制台看到的是"控制台未构建"的占位页。运行代理本身不需要 Node。

## 快速开始

```sh
whistle-rs -p 8899
```

1. 浏览器打开控制台 `http://127.0.0.1:8899/`。
2. 把要调试的程序或浏览器的 HTTP/HTTPS 代理设成 `127.0.0.1:8899`。用 curl 试：

   ```sh
   curl -x http://127.0.0.1:8899 http://example.com/
   curl -x http://127.0.0.1:8899 --cacert ~/.whistle-rs/certs/root.crt https://example.com/
   ```

   第二条去掉 `--cacert` 会报 `curl: (60) SSL certificate problem`：要看 HTTPS 内容，客户端得先信任 whistle-rs 首次启动时生成的根证书，各系统怎么装、用完怎么撤销见 [CERTIFICATES](docs/CERTIFICATES.md)。环境里设了 `NO_PROXY` 时 curl 可能绕过代理，加 `--noproxy ''` 强制走代理。
3. 在控制台的 Rules 里写规则，保存后立即生效（也可以启动时用 `-r rules.txt` 读文件）：

   ```text
   api.example.com/mock statusCode://503
   api.example.com http://127.0.0.1:3000
   example.com resHeaders://x-debug=1
   ```

   第一行让 `/mock` 直接回 503，第二行把 `api.example.com` 其余请求转到本机 3000 端口，第三行给 `example.com` 的响应加一个头。具体的写在宽泛的前面：转发、本地文件、重定向和 `statusCode` 共用一个位置，先匹配到的那条生效。规则写了却没效果，先看控制台里那条请求的 Rules 标签页，写法见[规则手册](docs/RULES.md)和[使用手册](docs/COOKBOOK.zh-CN.md)。

停止：Ctrl+C。它会先把已完成的请求记录写完再退出。

## 和 Whistle 的区别

- **规则**：同一批用例同时发给 Whistle（2.10.8 和 2.10.10）和 whistle-rs 比对结果，没有说明原因的差异会让测试失败；已知的不同写在[规则手册](docs/RULES.md)里。
- **插件**：用本项目自己的协议和 [JS/TS SDK](docs/PLUGINS.md)，装不了 npm 上的 `whistle.*` 插件。
- **命令行**：没有 `w2 start/stop`，whistle-rs 在前台运行，每条 `w2` 命令的替代做法见 [CLI](docs/CLI.md#coming-from-w2)。
- **控制台接口**：本项目自己的 [HTTP API](docs/API.md)，不是 Whistle 的 `/cgi-bin/*`。
- **默认更保守**：只监听本机（Whistle 默认所有网卡），校验源站证书，客户端发给代理的 `Proxy-Authorization` 不转给源站。

## 注意

- **默认只有本机能用。** 给手机或别的电脑用要加 `-H 0.0.0.0`，并且先用 `-n 用户名 -w 密码` 给控制台设口令：能改规则的人就能让代理读写这台机器上的文件。
- **代理本身没有访问控制。** 局域网里能连上端口的设备都能用它转发，要靠防火墙限制谁能连。
- **记录里有敏感信息。** 请求记录默认在 `~/.whistle-rs` 保存 7 天，里面原样存着 Cookie 和 `Authorization`；`--no-persist` 不写盘。分享导出的 HAR 前先检查。
- **只拦截你有权调试的流量**，用完撤销对根证书的信任。

完整的安全说明见 [OPERATIONS](docs/OPERATIONS.md)。

## 现状

每次推送和 PR 都在 Linux、macOS、Windows 上跑全部测试，并把打好的二进制实际用一遍（HTTP、HTTPS、WebSocket、插件、改规则、重启后数据还在）；每周和 Whistle 两个版本做一次全量对照。测了什么、结果如何、还有哪些没验证，见 [STATUS](docs/STATUS.md)。

## 文档

[文档导航](docs/README.md) · [安装](docs/INSTALL.md) · [使用手册](docs/COOKBOOK.zh-CN.md) · [规则](docs/RULES.md) · [命令行](docs/CLI.md) · [证书](docs/CERTIFICATES.md) · [插件](docs/PLUGINS.md) · [API](docs/API.md) · [开发](docs/DEVELOPMENT.md)

## 许可

MIT，见 [LICENSE](LICENSE)。核心行为来自 [avwo/whistle](https://github.com/avwo/whistle)（MIT）；哪些来自上游、发布包附带哪些第三方许可，见 [NOTICE.md](NOTICE.md)。感谢上游作者和贡献者。
