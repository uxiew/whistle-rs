# whistle-rs

用 Rust 实现的 Whistle 核心调试代理，提供规则改写、HTTP/HTTPS 抓包、WebSocket 检查和内嵌 Web 控制台，也可作为 Rust 库嵌入应用。

**当前版本 0.1.0；不是官方 Whistle，也不是完整的直接替代品。** 行为对照基线为 Whistle 2.10.8；插件协议、控制台 API 和部分 CLI 语义不同。[对齐情况与验证结果](docs/STATUS.md) · [后续计划](docs/ROADMAP.md)

## 适用场景

- 将域名映射到开发服务，模拟接口，改写请求/响应，调试 HTTPS 和 WebSocket。
- 用控制台查看流量、编辑规则与 Values、使用 Composer/重放和 HAR 导出。
- 在 Rust 应用或测试工具中嵌入代理；通过自有 Rust 或 JS/TS 插件扩展能力。

依赖现成 `whistle.*` npm 插件、官方 `/cgi-bin/*` API 或 `w2 start/stop` 的工作流不能直接迁移。

## 构建

需要 Rust 工具链及平台编译工具；构建控制台另需 Node.js（Vite 要求 `^20.19.0 || >=22.12.0`）和 npm。在仓库根目录执行：

```sh
npm ci --prefix ui-src
npm run build --prefix ui-src
cargo build --locked --release
```

产物：`target/release/whistle-rs`（Windows 为 `.exe`）。控制台在 Rust 编译时嵌入，修改前端后需重新构建两者。仅运行 `cargo build --locked --release` 也可构建代理，但未生成前端时首页是占位页。正常运行代理不需要 Node；启动 Node 插件时才需要。

## 使用

```sh
# 推荐本机调试：只监听回环，不保存抓包历史
./target/release/whistle-rs -H 127.0.0.1 -p 8899 --no-persist
```

浏览器打开 `http://127.0.0.1:8899/`。将客户端的 HTTP、HTTPS 代理均设为 `127.0.0.1:8899`：

```sh
curl --noproxy '' -x http://127.0.0.1:8899 http://example.com/

# HTTPS：先启动代理生成 CA；此命令只让本次 curl 信任它
curl --noproxy '' -x http://127.0.0.1:8899 \
  --cacert "$HOME/.whistle-rs/certs/root.crt" https://example.com/
```

规则示例（通过控制台编辑；已有规则文件时启动可加 `-r rules.txt`）：

```text
api.example.com/mock statusCode://503
api.example.com http://127.0.0.1:3000
example.com resHeaders://x-debug=1
```

特定 mock 放在宽泛转发规则之前：转发、文件、重定向、`statusCode` 等共用规则槽，通常先匹配的规则优先。完整写法见[规则手册](docs/RULES.md)。

## 注意

**程序默认监听 `0.0.0.0`、未设置控制台口令、开启 HTTPS 拦截，并将会话持久化 7 天。** 上面的启动命令主动收紧了监听和持久化；`--no-persist` 不禁止显式写文件规则，也不会删除以前的历史。不要直接暴露到公网；控制台口令不等于代理访问控制。

HTTPS 拦截需要客户端信任代理 CA；仅用于获授权的流量，保护 CA 私钥并在不用时撤销信任。源站 TLS 证书默认校验，`--insecure-upstream` 会关闭该保护。抓包预览有长度上限，不等于保存完整报文。

## 文档

[文档导航](docs/README.md) · [使用手册](docs/COOKBOOK.zh-CN.md) · [CLI](docs/CLI.md) · [API](docs/API.md) · [证书](docs/CERTIFICATES.md) · [安全运行](docs/OPERATIONS.md) · [开发与验证](docs/DEVELOPMENT.md) · [插件](docs/PLUGINS.md)

## 来源与许可

核心行为参考 [avwo/whistle](https://github.com/avwo/whistle) 与[官方文档](https://wproxy.org/docs/)，感谢上游作者与贡献者。上游源码不随本仓库分发，[对照基线](docs/UPSTREAM.md)说明如何复核。本仓库目前缺少根目录 LICENSE 与完整分发许可说明，已列为发布前必办项；不应仅凭旧 README 的声明认定许可手续已完成。
