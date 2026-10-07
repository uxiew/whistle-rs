# 命令行

[项目说明](../README.md) · [规则](RULES.md) · [当前状态](STATUS.md) · [路线图](ROADMAP.md)

whix 就是一个前台进程。没有 `w2 start`，没有要停的后台守护进程，也没有实例登记表——直接运行可执行文件，用 `Ctrl-C` 停掉。

```sh
whix -H 127.0.0.1 -p 8899 -r rules.txt --no-persist
```

有些参数有意做得和上游相似，但命令不能原样照搬。这份参考里混着实现细节和对照 Whistle 2.10.8 的历史实测；当前的验证情况记在 [STATUS.md](STATUS.md) 里。到底接受哪些参数，以这个可执行文件的 `--help` 为准。控制台的登录凭据不管代理转发的认证，见 [OPERATIONS.md](OPERATIONS.md)。

- [参数](#参数)
- [`-M/--mode`](#-m--mode)
- [从 `w2` 迁移过来](#从-w2-迁移过来)
- [常见用法](#常见用法)

## 参数

`✅` 支持 · `⚠️` 接受，但行为不完全一样 · `➖` whistle 有，本项目里没有它能作用的东西。

| whistle | whix | |
| --- | --- | --- |
| `-p, --port` | `-p, --port` | ✅ |
| `-H, --host` | `-H, --host` | ⚠️ 默认是 `127.0.0.1`，不是所有网卡——[见下文](#对本机以外开放) |
| `-P, --uiport` | `-P, --uiport` | ✅ 另开一个只服务控制台的端口（代理端口上的控制台照样在） |
| `-n/-w`, `-N/-W` | 相同 | ⚠️ 控制台登录账户和只读账户；口令最好用 `WHIX_PASSWORD`/`WHIX_GUEST_PASSWORD` 给（[为什么](#对本机以外开放)）；只给 `-N/-W` 不给 `-n/-w` 会被拒绝，而不是让控制台敞着 |
| `-l, --localUIHost` | `-l, --local-ui-host` | ✅ 在内置的三个之外追加，和上游一样 |
| `-M, --mode` | `-M, --mode` | ⚠️ 支不支持要看具体模式和组合——见下面的模式表 |
| `-t, --timeout` | `-t, --timeout` | ✅ 默认值相同，360000 ms |
| `-R, --reqCacheSize` | `-R, --req-cache-size` | ✅ |
| `-F, --frameCacheSize` | `-F, --frame-cache-size` | ✅ |
| `--socksPort` | `--socks-port`（也认 `--socksPort`） | ✅ 入站 SOCKS5 |
| `-r, --shadowRules` | `-r, --rules` | ⚠️ **不是一回事**——见下面的说明 |
| `-D, --baseDir` / `-S, --storage` | `--dir` | ⚠️ 只有一个目录，写完整路径；一个目录同时只能跑一个实例，第二个会被拒绝（[为什么，以及怎么跑两个](INSTALL.md#数据目录)） |
| `-z, --certDir` | `-z, --cert-dir`（也认 `--certDir`） | ✅ [见下文](#手动提供证书) |
| `-c, --dnsCache` / `--dnsServer` | — | ➖ DNS 交给操作系统的解析器 |
| `-s, --sockets` | — | ➖ 没有东西可限：本项目从不限制一个源站能有多少条连接，只把空闲连接留给当初打开它们的那条客户端连接复用（[怎么做的](ARCHITECTURE.md#复用源站连接)）。实测：在上游，这个参数也不改变客户端能看到的任何东西——设 `sockets: 1`，6 个并发请求照样并行完成 |
| `--httpPort` / `--httpsPort` | — | ➖ 只有一个代理端口；要把控制台挪到别的端口，用 `-P` |
| `--allowOrigin` | `--allow-origin`（也认 `--allowOrigin`） | ✅ [见下文](#从别的页面调用控制台) |
| `-A, --addon` / `-L, --pluginHost` / `-e, --extra` | — | ➖ 本项目有自己的插件系统（[`PLUGINS.md`](PLUGINS.md)） |
| `-m, --middlewares` / `-f, --secureFilter` | — | ➖ 它们指定要加载的 Node 模块 |
| `--cluster` / `--inspect` / `--inspectBrk` | — | ➖ 属于 Node 进程层面的事 |
| `--init` / `--config` / `--rcPath` / `--no-prev-options` | — | ➖ 属于 `w2` 的后台守护进程，本项目没有对应的东西 |
| `-C, --copy` / `--no-global-plugins` | — | ➖ 同上 |

whistle 的列表之外还有：`--rule`（直接在命令行里写规则）、`--value`、`--plugin` / `--node-plugin`、`--insecure-upstream`、`--no-intercept-https`、`--no-persist`、`--persist-days`、`--persist-max-mb`、`--body-preview-limit`、`--body-rewrite-limit`、`--weinre <URL>`（weinre 服务器跑在哪，给 `weinre://id` 规则用——[为什么需要它](RULES.md#weinre-html-debug-injection)）、`-v/--verbose`（每个请求打一行，带完整 URL——默认日志里没有这些行；两种日志里各有什么，见 [OPERATIONS](OPERATIONS.md#默认值与共享访问)）。`whix --help` 会列出全部参数；`whix explain` 不发请求，就能回答"这个 URL 会命中哪些规则"。

### 唯一一个含义不同的参数

**在这里，`-r` 把一个规则文件加载进 Default 规则组。在 whistle 里，`-r` 是 `--shadowRules`。** 两边都会读这个文件，也都会让它生效。区别在于之后谁能看到它：whistle 的 shadow rules（影子规则）是压在所有东西*底下*的一层，控制台里根本看不到——规则照样生效，`/cgi-bin/rules/list` 却返回空；而本项目加载的规则进了 Default 规则组，在列表里看得到，能编辑，也能关掉。

如果你照搬的命令行是用 `-r` 强加一些规则，不想让操作控制台的人删掉，那这个效果搬过来就没了。

## `-M/--mode`

whistle 的 `--mode` 接受一个用 `|`、`,` 或 `&` 分隔的列表，列表项来自一套 **56 个**词（token）。`tests/differential/mode-bench.js` 为每个词各起一个代理（whistle 和 whix 轮流），对每个代理跑同样的 9 个探测。其中 **16 个**会改变客户端能看到的东西（15 个是对照 whistle 自己的默认行为测出来的，第 16 个要打开 HTTPS 拦截后才显现），归并下来是 6 种行为——**这 6 种本项目全都支持**。其余 40 个是控制台选项、部署形态和 Node 层面的事。其中有两个控制台选项本项目也支持，因为本项目的控制台有它们要锁住的开关：`notAllowedDisableRules`（不许"关闭全部规则"）和 `notAllowedDisablePlugins`（不许关掉插件；`admin` 带着它）——见[开关](API.md#开关https全部规则插件)。

历史上完整跑过一次，结果是 `ran: 57, differing: 0, declared: 0`。2026-09-25 的文档审计没有重跑这一次，所以它不能当作对当前每个上游版本都兼容的新证明。

| 模式（及其各种写法） | 作用 | |
| --- | --- | --- |
| `pureProxy`, `proxyOnly`, `httpProxy` | 不再以控制台主机名应答——`local.whistlejs.com` 这类名字变回普通域名，照常转发 | ✅ |
| `headless`, `shadowRulesOnly` | 完全没有控制台。根证书、PAC 文件和 `/api/status` 仍然应答，因为客户端拿不到它们，就没法配置成走这个代理 | ✅ |
| `capture`, `intercept`, `enableCapture`, `enableHttps`, `persistentCapture` | 一启动就拦截（解密）HTTPS——本项目本来就默认这样。`disableCapture` 是关闭开关，也就是换成 whistle 名字的 `--no-intercept-https` | ✅ |
| `keepXFF`, `forwardedFor` | 让客户端自己带的 `x-forwarded-for` 传到源站。两个代理默认都会丢掉它，免得客户端塞给源站一个看起来有代理担保的地址 | ✅ |
| `enableRequestHeaderRules` | 允许请求在 `x-whistle-rule-value` 及另外四个配套的头里自带规则。**存储的**规则仍然优先 | ✅ |
| `multiEnv`, `nohost`, `multienv` | 同上，区别是：请求自带的规则优先；也会读 `x-whistle-rule-name`；只有默认规则组生效；HTTPS 不再因为开关而被拦截 | ✅ |
| `notAllowedEnableHTTPS` | 禁止打开 HTTPS 拦截——上游的实现方式是干脆完全不拦截 | ✅ |
| `strict` | 到头来还是不读那些规则头。只有和上面两个之一一起用才看得出效果，上游的 `admin` 预设就是这么组合的 | ✅ |
| `x-forwarded-host` | 相信前置代理所说的、客户端原本要访问的主机，并把请求发到那里 | ✅ |
| `x-forwarded-proto` | 相信前置代理所说的协议（scheme）；这决定了以明文到达的请求能不能匹配 `https://` 匹配串 | ✅ |
| `ipv4first`, `ipv6first`, `verbatim`（也可写作 `ipv4First`, `ipv6First`） | 一个域名同时有 IPv4 和 IPv6 地址时，先连哪个。**默认 IPv4 优先**，和 whistle 2.10.10 一样；`verbatim` 是按解析器自己给的顺序，到 2.10.8 为止一直是默认值 | ✅ |

这几个 DNS 顺序开关不改变请求里带的任何东西，所以 mode bench 看不到它们；`src/proxy/upstream.rs` 测它们的办法是：IPv4 和 IPv6 上各开一个监听，再去连 `localhost`。它们针对的症状是：一个网站在浏览器里直接能打开，走代理却在 16 秒后报连接超时——在 IPv6 路由会丢包的网络上，以前先试的是 IPv6 地址，它把整个连接时限都耗光了。在这种网络上，`-M ipv6first` 或 `-M verbatim` 会把这个问题带回来。`ipv6Only` 不支持。

> **`-M multiEnv` 让发请求的人决定请求去哪。** 请求头里写明目标地址、一段规则文本，以及要展开进规则的 Values。这个模式*本来就是干这个的*——一个代理服务多套环境，每个请求自己指定——这也是两个代理都默认关掉它的原因。只要网络上还有别的东西能连到这个代理，就不要打开它。[请求头里的规则](RULES.md#rules-in-a-request-header) 讲了完整格式，包括五个头里哪一个会传到源站。

还有两个头也属于这一类，**在上游完全不设门槛就会被读取**，本项目没有跟着这么做：

| 头 | 上游 | 本项目 |
|---|---|---|
| `x-whistle-real-host` | 改变请求的去向，**任何**模式下都这样 | 只在 `-M x-forwarded-host` 下生效；无论哪种情况，都会从每个请求里删掉 |
| `x-whistle-forwarded-props` | 值里带 `host` / `proto` / `ip`，就会**只为这一个请求**打开对应的门，任何模式下都这样 | 从每个请求里删掉，从不读取 |

模式是运行代理的人在启动时一次性做的决定：前面确实有个前置代理，而且可以信它。头则是*发送方*在做决定——代理没法分辨这是运行者自己的前置代理，还是网络上随便哪个客户端，因为头是唯一的证据，而头正是发送方写的。不设任何模式，对照 whistle 2.10.8 实测：`x-whistle-real-host` 把请求发到了另一个源站，`x-whistle-forwarded-props: proto` 让 `https://…` 匹配串在明文请求上生效了。`tests/differential/forwarded-bench.js` 逐个探测声明了这处偏离。

组合列表之前，有三处相互影响值得先知道：

* **`multiEnv`（以及 `nohost`）会关掉 HTTPS 拦截**，不管 `capture` 怎么说、顺序怎么排——`isEnableCapture()` 一开头就是 `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`，开关根本轮不到被查看。从这两个名字都看不出这一点。按主机写的 `enable://capture` **规则**仍然有效；
* **不信 `x-forwarded-host` 和 `x-forwarded-proto` 时，它们会接着往下传。** 上游删除它们的代码在使用它们的那个分支里，所以没开这个模式时，源站仍然能看到前置代理的说法——源站也可能确实需要它。本项目要是照样把它们删掉，就是在自创策略；它只对上面那两个不设门槛的头这么做，因为它根本不会照那两个头办事；
* **`strict` 只收回"读取"这一项**，别的都不动。在 `-M strict|multiEnv` 下，这些头照样会从请求里拿走，命名规则组照样不生效，HTTPS 照样不拦截——只是规则文本被忽略。`-M admin` 带着 `strict`，所以 `admin` 实例从不读取这些头。

本项目用不上的词不会被悄悄吞掉：whistle 有、而本项目没法应用的模式，启动时会点名；两个程序**都**不认识的，会报告为可能的拼写错误。

`x-forwarded-proto` 已经实现，不要拿它当不支持的词的例子。`notAThing` 这类不认识的写法会产生一条警告；以模式表和实际的启动输出为准，别照抄旧的日志记录。

磁盘上有命名规则组时，`nohost` 会多打一行，因为一个组加载了却不生效，值得明说：

```
INFO -M multiEnv: 2 named rule group(s) loaded but not resolved; the default group and each request's own rules apply
```

`multiple` 和 `admin` 是组合词，会先展开，展开方式和上游完全一样；所以 `-M multiple` 确实会连带 `keepXFF` **和** `multiEnv`，`-M admin` 会连带 `strict`。

## 对本机以外开放

除非用 `-H` 另行指定，whix 只监听 `127.0.0.1`，所以刚启动时它只是本机的代理——控制台也只对本机开放。上游默认监听所有网卡，这让一个新实例成了整个网络都能用的开放代理，网络上任何人都能改它的控制台，而规则是能读写文件的。想让手机或别的机器连进来，要明确开放，并且先设好登录：

```sh
export WHIX_PASSWORD='…'   # 从你存放密钥的地方取
whix -H 0.0.0.0 -n admin
```

**口令放在环境变量里，别放在命令行上。** `WHIX_PASSWORD` 对应 `-w`，`WHIX_GUEST_PASSWORD` 对应 `-W`。这两个参数还能用，但 `-w "$PASSWORD"` 会被 shell 展开写进命令行，而本机任何用户都能用 `ps -A -o args=` 看到命令行；进程的环境变量只有它的属主能读。口令来自参数时，启动会给出警告。两者都设时以参数为准；变量为空等于没设；`--node-plugin` 启动的进程不会带上这两个变量。

启动日志会说明是哪种情况：只监听回环地址时，打一行 INFO，给出开放要用的命令；监听了回环以外的地址却没设 `-n/-w` 时，打一行 WARN。控制台的 Status 面板只在代理能从网络访问时，才显示给手机扫的二维码。本项目没有代理认证，也没有 IP 白名单，所以在共享网络上，由防火墙决定谁能连——见 [`OPERATIONS.md`](OPERATIONS.md)。

## 给手机用的二维码

`gui/mobile.md` 是一页教你在手机上手动输入代理地址的说明。两个控制台都用二维码省掉这一步，每个局域网地址一个（用 `-H 0.0.0.0` 启动时显示）；本项目还把它做成了一个命令：

```sh
whix qr "http://192.168.1.5:8899/rootCA.crt"   # 画在终端里
whix qr --svg 6 "http://192.168.1.5:8899/"     # 往 stdout 输出一个 SVG
whix qr --matrix "hello"                       # 输出一行行的 0/1
```

控制台在 `GET /api/qr?text=…&scale=…` 提供同样的功能。编码器最多处理 213 字节（字节模式，纠错等级 M，版本 1-10）；超过就回 400，控制台退回到直接显示链接。

## 手动提供证书

`-z/--cert-dir` 指定一个证书目录，代理会出示里面的证书，**而不是代理签发的站点证书**。客户端固定（pin）了服务器证书时，就靠它来看流量：把真实的私钥和证书交给代理，它就出示这一套，而不是自己签的那张。

```
certs/
  api.example.com.key    # 私钥
  api.example.com.crt    # ……和它的证书（.cer 和 .pem 也行）
  root.key               # 可选：替换根证书本身
  root.crt
```

文件名只用来把两个文件配成对。**一张证书管哪些域名，看它自己的 `subjectAltName`**——带 `DNS:api.example.com` 和 `DNS:*.wild.example` 的证书两个都管，不管文件叫什么；反正 TLS 客户端也只认这种读法。通配符只覆盖一级：`*.wild.example` 管 `api.wild.example`，不管 `wild.example`。

没有 `subjectAltName` 的证书里没有任何请求能匹配的名字，会被跳过，并打一行日志说明；不是证书的文件、旁边没有私钥的证书也一样处理。这个目录里放什么，都不会让代理启动失败。

`root.key` + `root.crt` 会**替换根证书**，这也是自己提供根证书的唯一途径——whistle 的控制台也出于同样的原因，不接受通过上传表单提交根证书。之后，凡是手动提供的证书没覆盖到的，都由你的根证书签发。启动日志会写出实际在用的文件，要安装的就是它：

```
INFO root CA supplied by hand: /path/to/certs/root.crt
INFO root CA: /path/to/certs/root.crt (download at http://127.0.0.1:8899/rootCA.crt)
INFO certificates supplied by hand for: *.wild.example, api.example.com
```

插件也可以按连接挑选证书，相当于同一件事的动态版——见 [`RULES.md`](RULES.md) 里的 `sniCallback://`。

## 从别的页面调用控制台

默认情况下，别的网站上的页面读不了控制台的 API——浏览器会拒绝，因为响应里没有 `Access-Control-Allow-Origin`。`--allow-origin` 用来指定允许读的站点（origin）：

```sh
whix --allow-origin 'dash.example.com|*.internal.test'
whix --allow-origin '*'          # 任何站点
```

多个站点用 `|`、`,` 或 `&` 分隔。每一项都可以像规则的匹配串那样在域名里用星号——`*` 匹配一级，`**` 匹配任意多级，`***.` 表示这一级可有可无——列表里任何位置出现单独一个 `*`，就表示所有站点。

匹配看的是站点的**主机名**，不看端口；响应头回显的 `Origin` 和浏览器发来的一字不差，端口也在内。不带 `Origin` 的请求，或者浏览器标了 `sec-fetch-site: same-origin` 的请求，不算跨域，什么 CORS 头也不加。

**有两个路径不管有没有名单，对任何站点都应答**——`/api/status` 和根证书。代理是否还活着、该信任哪张证书，是一个页面向不归它管的代理可以合理询问的两件事；上游开放的也是这两个。

> **`/api/status` 回给这些调用方的内容比回给控制台的少。** 上游的 status 只有一个存储名、两个标签和一个版本号。本项目的还会报告存储*路径*（里面带着账户的用户名）、本机的局域网地址和已安装的插件——运行代理的人从没点名的页面，凭这些就足以给这台主机做指纹。所以*只*靠这条一律放行的例外被放进来的调用方，只拿到表明存活的那一小部分：
>
> ```json
> { "version": "0.1.0", "port": 8899 }
> ```
>
> 运行代理的人确实信任的调用方，仍然能看到完整内容：控制台自己（同源）、`--allow-origin` 名单上的主机、特意设置的 `--allow-origin '*'`，以及完全不发 `Origin` 的客户端——CORS 从来管不到这种客户端，它反正也能直接连端口来读。两种情况下响应头都一样，所以"status 对谁都应答"依然成立；只是 body 变小了。

> **预检请求（preflight）不在此列**，本项目和上游都一样：两边都不发 `Access-Control-Allow-Methods` 或 `-Allow-Headers`，所以浏览器需要预检的请求——带自定义头的、`Content-Type: application/json` 的——不管名单怎么写都会被拒绝。要放宽这一点，就等于把整个 API 交给名单上的站点，而这个控制台另外唯一的门槛可能只是一个口令。

**能不能读由 CORS 决定；能不能写在请求执行之前就决定了。** body 为 `text/plain` 的 `POST` 是*简单*请求，浏览器不先询问就直接发出，CORS 只是事后把回答藏起来——而那时规则已经被改了。所以带 `Origin` 的 `POST` 或 `DELETE` 必须来自控制台自己的页面或名单上的站点，其他的在路由执行前就回 `403`。不带 `Origin` 的请求（curl、脚本）不是浏览器在替某个网站发请求，不受影响。上游在这里什么都不检查。因此这份名单会把**写权限**交给它列出的站点，而 `'*'` 会把写权限交给所有网站：请写具体的名字。

控制台只在用它自己的名字访问时应答——IP 地址、`localhost`，或者控制台主机名（内置的那些和用 `-l` 加的）——DNS rebinding 就是靠这个挡住的。在代理端口上，用别的名字来的请求会像普通代理流量一样转发给那个名字，和上游一样；如果这个名字解析回本机，就会得到一个跳到控制台地址的 `302`；在 `-P` 开的控制台端口上，则得到 `403`。想用别的名字打开控制台，用 `-l` 把它加上。

## 从 `w2` 迁移过来

whistle 的命令行是套在代理外面的一个进程管理器。本项目只是代理本身，所以那些子命令没有对应的东西——下面是各自的替代做法。

| `w2 …` | 本项目 |
| --- | --- |
| `w2 start` / `run` | 直接运行可执行文件。它停在前台；要放到后台，用 shell、服务配置文件或容器 |
| `w2 stop` / `restart` | `Ctrl-C`，或者交给管着这个进程的东西 |
| `w2 status` | 在控制台端口上 `GET /api/status`——里面有和 `w2 status` 打印的一样的 `lan_addresses` 列表 |
| `w2 ca` | 自己安装证书——见 [`CERTIFICATES.md`](CERTIFICATES.md)；在设备上，设好代理后直接打开 <http://rootca.pro/> 就行 |
| `w2 proxy` | 用操作系统自带的工具设置系统代理 |
| `w2 add` | 启动时用 `--rules` / `--rule`，运行中用 `POST /api/rules` |
| `w2 install` / `uninstall` / `exec` | 本项目有自己的插件系统，见 [`PLUGINS.md`](PLUGINS.md) |
| `w2 start -p 8010 -S 8010`（多个实例） | `--port 8010 --dir /some/dir/8010`——每个实例一个端口、一个目录，规矩一样 |

## 常见用法

**一个单纯的正向代理，没有控制台，没什么可乱动的。**

```sh
whix -p 8899 -M "headless|pureProxy" -r rules.txt
```

代理照常工作。证书、PAC 文件和 `/api/status` 仍然应答——这样客户端照样能配置，也照样有办法判断进程是否还活着——控制台端口上的其他一切都回 404。

**网络上共享的代理，除了你，其他人都只读。**

```sh
export WHIX_PASSWORD='…' WHIX_GUEST_PASSWORD='…'
whix -H 0.0.0.0 -p 8899 -n admin -N guest
```

登录保护的是控制台，**不是**流量——对登录一无所知的客户端照样能走代理，任何连得上的设备都能用它，所以由网络或防火墙决定能连的是谁。guest 账户只能 `GET`，别的都不行——但这已经包括每个抓到的请求的头，cookie 和 `Authorization` 都在里面。只给 `-N/-W` 不给 `-n/-w` 会在启动时被拒绝：没有管理员账户，就没有人会被要求登录，guest 也一样。

**看流式 body 一点点到达**（LLM 吐出的 token、分块传输的 JSON 流）：

```
api.example.com enable://captureStream resHeaders://(x-whistle-custom-frame-separator=%0A)
```

每一行在 Frames 面板里成为一帧。事件流（`content-type: text/event-stream`，带不带 `charset` 都行）既不需要这个开关，也不需要这个头。用头的写法时，开关不能省——whistle 也要求这两样一起出现，而且分隔符头也可能来自源站，不一定是你加的。

> whistle 的 FAQ 里这个例子写的是 `%A0`，和它想表达的换行（`%0A`）不是同一个字节，结果整个 body 被当成一帧。两个代理对它的处理一样，所以照抄这个例子，在两边会以同样的方式失败。

**前面还有一层代理，保留客户端的真实地址。**

```sh
whix -p 8899 -M keepXFF
```

**完全不拦截 HTTPS**（所有流量原样走隧道）：

```sh
whix -p 8899 --no-intercept-https      # 或者：-M disableCapture
```

这只决定启动时的状态。运行中可以在控制台的 Status 页切换（`POST /api/switches {"intercept_https":false}`），只对新连接生效；重启后又回到命令行指定的设置。

**同时跑几个代理，每个都有自己的控制台**——给每个代理单独的端口和目录，并把控制台放在好找的端口上：

```sh
whix -p 8899 -P 9899 --dir ~/.whix/a
whix -p 8900 -P 9900 --dir ~/.whix/b
```
