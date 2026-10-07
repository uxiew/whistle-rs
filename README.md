# whix

**一个跑在你自己电脑上的抓包、改包工具。** 浏览器、App、手机把请求先发给它，它再转给真正的服务器。经过它的每个请求和响应你都能看到全部内容，也能按你写的规则改掉，或者干脆不发给服务器、由它直接回答。

```text
浏览器 / App / 手机  ──→  whix（看、改、拦）  ──→  真正的服务器
```

规则的写法和 [Whistle](https://github.com/avwo/whistle) 一样，用过 Whistle 可以直接上手；但它不是 Whistle，区别见[和 Whistle 的关系](#和-whistle-的关系)。用 Rust 写成，一个二进制，运行不需要 Node。

## 能拿它做什么

每个场景一条规则就够，写在控制台的 Rules 里，保存后立即生效：

| 你遇到的事 | 规则 | 效果 |
| --- | --- | --- |
| 线上页面要换成本地正在改的代码 | `www.example.com http://localhost:5173` | 打开线上域名，看到的是本地开发服务的页面，不用改 hosts、不用改代码 |
| 接口还没写好，前端要先联调 | `api.example.com/users file:///Users/me/mock/users.json` | 这个接口直接返回本地文件，请求不到服务器（这叫 mock） |
| 想看接口出错时页面会怎样 | `api.example.com statusCode://503` | 这个域名的请求都回 503 |
| 想看网慢时页面会怎样 | `slow.example.com resDelay://2000` | 每个响应晚 2 秒到 |
| 接口要带个测试用的头 | `api.example.com reqHeaders://x-token=abc` | 发给服务器的请求都加上这个头 |
| 只想改响应里的一个字段 | `api.example.com/me resMerge://{"role":"admin"}` | 服务器照常回答，`role` 被改成 `admin` |
| 调用第三方接口被跨域挡住 | `api.thirdparty.com resCors://*` | 响应加上允许跨域的头 |

不写规则也有用：控制台里能看到每个请求的头、body、耗时，失败的请求写明停在哪一步（DNS、连接、TLS……）。手机连上它，就能看 App 发了什么。这些场景的完整做法见[使用手册](docs/COOKBOOK.md)。

## 先弄懂四个词

- **代理**：替你转发请求的程序。程序或浏览器的"代理设置"填上 `127.0.0.1:8899`，它的请求就会先到 whix。whix 不会替你改系统设置，你自己设，用完自己改回去。
- **规则**：一行"管哪些请求 + 怎么处理"，左边是网址（可以只写域名），右边是一个或几个 `名字://值`。几百种写法见[规则手册](docs/RULES.md)，常用的就上面那几种。
- **控制台**：whix 自带的网页，启动后打开 `http://127.0.0.1:8899/`。在这里写规则、看请求、导出记录。
- **根证书**：HTTPS 是加密的，whix 要看到内容，就得用自己的证书冒充网站，所以你的浏览器或手机必须先信任 whix 的根证书。不信任的话，所有 HTTPS 网页都会报证书错误（浏览器显示"您的连接不是私密连接"，curl 报 `(60) SSL certificate problem`）。根证书在第一次启动时生成，私钥只存在你这台电脑上。

## 五分钟上手

**1. 装上。** 还没有正式发布，二进制在 GitHub Actions 的构建产物里，怎么下载、校验见 [INSTALL](docs/INSTALL.md)；或者[从源码构建](#从源码构建)。

**2. 启动。**

```sh
whix
```

默认端口 8899，只有本机能连。Ctrl+C 停止，它会先把已完成的请求记录写完再退出。

**3. 让请求经过它。** 先用 curl 试：

```sh
curl -x http://127.0.0.1:8899 http://example.com/
```

再把浏览器或系统的 HTTP、HTTPS 代理设成 `127.0.0.1:8899`。打开控制台 `http://127.0.0.1:8899/`，Requests 里应该能看到刚才的请求。环境变量里设了 `NO_PROXY` 时 curl 可能绕过代理，加 `--noproxy ''` 强制走代理。

**4. 信任根证书（要看 HTTPS 内容时）。** 证书在 `~/.whix/certs/root.crt`，也能从 `http://127.0.0.1:8899/rootCA.crt` 下载。先用 curl 确认：

```sh
curl -x http://127.0.0.1:8899 --cacert ~/.whix/certs/root.crt https://example.com/
```

macOS、Windows、Linux、iOS、Android 各怎么装、用完怎么撤销，见 [CERTIFICATES](docs/CERTIFICATES.md)。只想转发、不想看 HTTPS 内容，就启动时加 `--no-intercept-https`，不用装证书。

**5. 写第一条规则。** 在控制台的 Rules 里写：

```text
example.com resHeaders://x-debug=1
```

保存，再访问一次 `example.com`，响应头里多了 `x-debug: 1`。规则写了没效果时，点开那条请求的 Rules 标签页看它命中了什么，或者不发请求直接问：

```sh
whix explain https://example.com/ --rule 'example.com resHeaders://x-debug=1'
```

## 适合做什么，不适合做什么

**适合：**

- 在自己电脑上调试你负责的网页、App、接口：联调、mock、模拟出错和弱网、看清 HTTPS 请求里到底发了什么。
- 让脚本或 AI 编程助手（也叫 agent，能自己执行命令、调接口的自动化程序）来操作它：它有 [HTTP 接口](docs/API.md)，`whix explain` 能直接回答"这个请求会命中哪些规则"。做法见使用手册的[「用脚本驱动它」](docs/COOKBOOK.md#用脚本驱动它或者交给一个-agent)。
- 写自动化测试时，把它当一个能用代码控制的代理，可以作为 Rust 库嵌进你的程序（[`examples/embedded.rs`](examples/embedded.rs)）。

**不适合：**

- **当线上的网关、反向代理或负载均衡。** 它是调试工具，没有为长期承载正式流量设计过，性能只在本机测过。
- **放在公网或多人共用的网络上给别人用。** 代理端口本身没有访问控制，能连上的人都能用它转发；控制台能改规则，而规则能读写这台电脑上的文件。
- **抓不属于你的流量。** 只拦截你有权调试的流量，用完撤销对根证书的信任。
- **需要 Whistle 生态的东西。** 装不了 npm 上的 `whistle.*` 插件，没有 `w2 start/stop` 后台服务，控制台接口也不是 Whistle 的 `/cgi-bin/*`。需要这些就用官方 Whistle。
- **需要签过名的正式安装包。** 现在是 0.1.0，还在作者自己日常使用、打磨的阶段，没有正式发布，二进制没有代码签名，macOS 和 Windows 可能会拦下来要你手动放行。

## 安全须知

- **默认只有本机能用。** 给手机或别的电脑用要加 `-H 0.0.0.0`，并且先用 `-n 用户名` 加环境变量 `WHIX_PASSWORD` 给控制台设口令。别用 `-w` 给口令：命令行在进程列表里，这台机器上谁都看得到。
- **请求记录里有敏感信息。** 记录默认在 `~/.whix` 存 7 天、最多 1 GiB，Cookie 和 `Authorization` 原样保存；`--no-persist` 就不写盘。分享导出的 HAR 文件前先检查。
- **根证书的私钥** 在 `~/.whix/certs/root.key`，拿到它的人能对信任这张证书的设备冒充任何网站。别拷给别人，不用了就撤销信任。

完整的安全说明见 [OPERATIONS](docs/OPERATIONS.md)。

## 和 Whistle 的关系

- **规则**：同一批用例同时发给 Whistle（2.10.8 和 2.10.10）和 whix，比对结果；没写明原因的差异会让测试失败。已知的不同写在[规则手册](docs/RULES.md)里。
- **插件**：本项目自己的协议，用 [JS/TS SDK](docs/PLUGINS.md) 写，和 Whistle 插件不通用。
- **命令行**：whix 在前台运行，没有 `w2` 的后台管理命令，每条 `w2` 命令的替代做法见 [CLI](docs/CLI.md)。
- **默认更保守**：只监听本机（Whistle 默认所有网卡），校验源站证书，客户端发给代理的 `Proxy-Authorization` 不转给源站。

## 从源码构建

需要 [rustup](https://rustup.rs)，第一次执行 `cargo` 时会按 `rust-toolchain.toml` 自动装好 Rust 1.98.1。网页控制台还需要 Node.js（20.19 以上的 20.x，或者 22.12 以上）。

```sh
npm ci --prefix ui-src && npm run build --prefix ui-src   # 先构建控制台
cargo build --locked --release                            # 再编译，控制台会被嵌进二进制
./target/release/whix --version
```

跳过第一行也能编出能用的代理，只是控制台是一张"控制台未构建"的占位页。

## 文档

| 你想 | 看这篇 |
| --- | --- |
| 照着步骤做一件具体的事（转发、mock、弱网、调手机、导出 HAR） | [使用手册](docs/COOKBOOK.md) |
| 查某个规则怎么写、优先级怎么算 | [规则手册](docs/RULES.md) |
| 安装根证书、撤销信任 | [证书](docs/CERTIFICATES.md) |
| 查命令行参数 | [命令行](docs/CLI.md) |
| 下载、升级、卸载，数据目录里有什么 | [安装](docs/INSTALL.md) |
| 安全边界、记录里存了什么 | [运行与安全](docs/OPERATIONS.md) |
| 写插件 | [插件](docs/PLUGINS.md) |
| 用脚本或程序控制它 | [HTTP 接口](docs/API.md) |
| 参与开发 | [开发](docs/DEVELOPMENT.md)、[架构](docs/ARCHITECTURE.md) |
| 测了什么、还有什么没验证 | [当前状态](docs/STATUS.md) |

全部文档见[文档导航](docs/README.md)。每次推送都在 Linux、macOS、Windows 上跑全部测试，并把打好的二进制实际用一遍；每周和 Whistle 两个版本做一次全量对照。

## 许可

MIT，见 [LICENSE](LICENSE)。核心行为来自 [avwo/whistle](https://github.com/avwo/whistle)（MIT）；哪些来自上游、发布包附带哪些第三方许可，见 [NOTICE.md](NOTICE.md)。感谢上游作者和贡献者。
