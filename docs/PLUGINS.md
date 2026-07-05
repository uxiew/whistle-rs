# 插件 / Plugins

[English README](../README.md) · [简体中文 README](../README.zh-CN.md)

whistle-rs 有一个**统一的插件系统**：一个插件就是一段作用于单个请求的中间件，它可以

1. **注入 whistle 规则**（对应原版 whistle 的 `rulesServer` 钩子），以及/或者
2. **直接返回一个响应**（`server` 钩子，即 mock）。

两种运行时共用同一套契约，都由 `plugin://<name>`（或 `pipe://<name>`）规则触发：

- **Rust 插件** —— 原生、进程内，实现 `RustPlugin` trait，零 IPC。
- **远程插件** —— 一个 Node（或任意语言）进程，通过下面的 JSON-over-HTTP 协议通信。
  whistle-rs 可以帮你**拉起 Node 进程**（`--node-plugin name=path.js`），也可以指向一个
  **已在运行**的插件（`--plugin name=host:port`）。

> 兼容性边界：本系统实现的是 whistle 插件里最常用的两个钩子（`server` 与 `rulesServer`）
> 的**等价能力**，而不是逐字节复刻原版基于 Node `req`/`res` 对象装饰的完整插件 API。
> 直接 `npm i whistle.xxx` 的现成插件通常无法原样运行；但按下面的约定用 Node 编写插件很简单。

---

## 触发方式

```
# 交给插件处理（可 mock，也可注入规则后继续代理）
example.com          plugin://demo

# 带参数：plugin://name/PARAM，PARAM 传给插件的 req.param
api.example.com      plugin://demo/mock
```

一次请求可命中多个插件：按出现顺序依次分发；任一插件返回 `response` 即短路，
其余插件不再执行；插件注入的 `rules` 会合并进已解析的规则集。

---

## 用 Rust 编写插件（进程内）

实现 `RustPlugin` trait 并注册到 `Plugins` 注册表：

```rust
use whistle_rs::plugins::{PluginReq, PluginResp, PluginResult, RustPlugin};

struct MyPlugin;

impl RustPlugin for MyPlugin {
    fn name(&self) -> &str { "myplugin" }

    fn dispatch(&self, req: &PluginReq) -> PluginResult {
        // 1) 注入规则：
        if req.param == "tag" {
            return PluginResult {
                rules: Some("* resHeaders://x-my=1".into()),
                response: None,
            };
        }
        // 2) 直接 mock 一个响应：
        PluginResult {
            rules: None,
            response: Some(PluginResp {
                status: 200,
                headers: vec![("content-type".into(), "text/plain".into())],
                body: format!("hello from {}", req.url).into_bytes(),
            }),
        }
    }
}

// 注册（自行嵌入构建时）：
// let mut plugins = whistle_rs::plugins::Plugins::new();
// plugins.register_rust(Box::new(MyPlugin));
// let state = AppState::with_plugins(config, rules, ca, plugins);
```

内置示例见 [`src/plugins/builtin.rs`](../src/plugins/builtin.rs)：`echo`（mock 响应）与
`tag`（注入头规则）。

---

## 用 Node 编写插件（子进程）

用零依赖的辅助库 [`examples/plugins/whistle-rs-plugin.js`](../examples/plugins/whistle-rs-plugin.js)：

```js
const { start } = require('./whistle-rs-plugin');

start((req) => {
  // req = { method, url, headers:[[k,v]…], clientIp, param, header(name) }

  if (req.param === 'mock') {
    return {
      response: {
        statusCode: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ hello: req.url, ua: req.header('user-agent') }),
      },
    };
  }
  return { rules: '* resHeaders://x-node-plugin=1' };
});
```

启动：

```bash
whistle-rs \
  --node-plugin demo=examples/plugins/example-plugin.js \
  --rule 'example.com plugin://demo'
```

whistle-rs 会执行 `node <path>`，通过环境变量 `WHISTLE_RS_PLUGIN_PORT` 分配端口、
`WHISTLE_RS_PLUGIN_NAME` 传名字，并在自身退出时结束该子进程。

也可以自己跑插件进程（任意语言，只要实现协议），再用：

```bash
whistle-rs --plugin demo=127.0.0.1:9000
```

---

## 远程 JSON 协议

whistle-rs → 插件：`POST /`

```json
{
  "method": "GET",
  "url": "http://example.com/x",
  "headers": [["host", "example.com"], ["user-agent", "…"]],
  "clientIp": "1.2.3.4",
  "param": "mock"
}
```

插件 → whistle-rs：

```json
{
  "rules": "example.com resHeaders://x=1",
  "response": {
    "statusCode": 200,
    "headers": { "content-type": "text/plain" },
    "body": "hello"
  }
}
```

- `rules` 与 `response` **均可选**。
- `rules`：一段 whistle 规则文本，合并进本次请求的规则集（对请求/响应生效）。
- `response`：直接短路上游请求；`headers` 支持对象 `{k:v}` 或数组 `[[k,v]…]`；
  `body` 为字符串，二进制 Body 用 `bodyBase64`（base64 编码）。
- 非 200 响应、连接失败或 JSON 解析失败都按「无操作」处理，不影响正常代理。

---

## 局限与后续

- 目前不向插件传递**请求体**（仅方法/URL/头/客户端 IP/param）；mock 与规则注入不受影响。
- 未实现的钩子：`reqRead`/`resRead`（流式读写）、`uiServer`/`statsServer`、`auth`、
  `sniCallback` 等；以及原版基于 Node 对象装饰的完整插件 API。
- 现成 npm `whistle.xxx` 插件的直接兼容需要移植 whistle 的插件加载器，属后续计划
  （见 [`ROADMAP.md`](ROADMAP.md)）。
