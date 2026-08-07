# 使用手册 / Cookbook

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [English version](COOKBOOK.md) · [规则参考](RULES.md)

按任务组织的实操手册。每一条都是一个你真会遇到的问题、解决它的规则，以及**为什么**这么写。
[`RULES.md`](RULES.md) 是每个算子的完整参考；这份文件是你**先**该读的那半。

这里的每一条都在写下来之前用运行中的代理实测过。

- [开始之前](#开始之前)
- [把站点交给本地开发服务](#把站点交给本地开发服务)
- [Mock 一个接口](#mock-一个接口)
- [在传输途中改请求或响应](#在传输途中改请求或响应)
- [模拟糟糕的网络](#模拟糟糕的网络)
- [把规则的作用范围收窄](#把规则的作用范围收窄)
- [调试手机或其它设备](#调试手机或其它设备)
- [抓包、导出与重放](#抓包导出与重放)
- [把代理嵌进你自己的程序](#把代理嵌进你自己的程序)
- [规则不生效时](#规则不生效时)

---

## 开始之前

```bash
cargo build --release
./target/release/whistle-rs -p 8899 -r rules.txt
```

同一个端口上听着**两样不同的东西**，把它们搞混是最常见的入门错误：

| 你想 | 你写 |
|------|------|
| 让流量**经过**代理 | `curl -x http://127.0.0.1:8899 http://example.com/` |
| 直接**访问**代理本身 —— 控制台、PAC、根证书、JSON 接口 | `curl --noproxy '*' http://127.0.0.1:8899/api/status` |

`--noproxy '*'` 是必要的：shell 里如果设了 `http_proxy`，那么连
`http://127.0.0.1:8899/` 都会被送到那个变量指向的代理去。症状是一个带
`Proxy-Connection` 头的 `502`。

浏览器打开 <http://127.0.0.1:8899/> 就是控制台：请求表格、详情面板，以及一个会标出
**代理将拿哪个 token 去匹配**的规则编辑器。

调试期间，`--no-persist` 让抓到的流量不落到 `~/.whistle-rs`，`--dir` 把根证书与规则分组
放到一个用完即弃的目录：

```bash
./target/release/whistle-rs -p 8899 -r rules.txt --no-persist --dir /tmp/w
```

---

## 把站点交给本地开发服务

whistle 存在的理由就是这一行。一个 token，没有算子：

```
www.example.com       http://localhost:5173
```

现在 `www.example.com` 的每个请求都由你的 Vite / webpack / 随便什么开发服务来应答，而地址栏里
仍然是真实域名 —— 于是 cookie、`localStorage`、CORS origin、OAuth 回调 URI 全都照常工作，
而这恰恰是地址栏里写 `localhost:5173` 会破坏的东西。

### 路径会跟着走，这一点常让人意外

pattern 没吃掉的部分会**拼**到目标后面：

| 规则 | 请求 | 实际转发到 |
|------|------|-----------|
| `example.com http://localhost:5173` | `/a/b?q=1` | `http://localhost:5173/a/b?q=1` |
| `example.com http://localhost:5173/base` | `/a/b?q=1` | `http://localhost:5173/base/a/b?q=1` |
| `example.com/api http://dev.local/v2` | `/api/users?x=2` | `http://dev.local/v2/users?x=2` |

第三行请读两遍。pattern 里的 `/api` 是**被消耗掉**的，不是保留的：路径中被 pattern 匹配到的
那一段，会被目标的路径**替换**。`/api/users` 变成 `/v2/users`，而不是 `/v2/api/users`。
如果你要保留这个前缀，就把它写进目标里（`http://dev.local/v2/api`）。

想关掉拼接、永远打同一个 URL，就用 `< >` 包住值：

```
example.com/api    http://<dev.internal/fixed>
```

### `http://…` 会改 Host 头，`host://` 不会

两者都能把请求指到别处，但只有一个是**源站能看见**的：

| | socket | `Host:` 头 | 路径 | scheme |
|---|---|---|---|---|
| `example.com http://localhost:5173` | 变 | **变成 `localhost:5173`** | 重写 | 变 |
| `example.com host://127.0.0.1:5173` | 变 | **仍是 `example.com`** | 保留 | 保留 |

对端**按 `Host` 路由**时用 `host://` —— nginx 后面的预发机、CDN 源站、任何有虚拟主机的东西。
指向一个根本不看 Host 的开发服务时，用裸 URL。

```
# 打到预发机，但保留域名，好让它的 vhost 命中
www.example.com     host://10.0.0.9

# 同一个域名，换端口
.example.com        host://:8443

# 这个地址有人监听就用它，连不上就照原地址走
www.example.com     xhost://10.0.0.9
```

裸写 `127.0.0.1:5173` 是 `host://127.0.0.1:5173` 的简写 —— 但这**只因为它是 IP**。
`localhost:5173` 是**域名**，而域名会被读成转发目标，于是它**会**改 `Host` 头，而 IP 形式不会。
这个不对称来自上游（`net.isIP`），也很容易踩。

### mock 必须写在转发**上面**

`file://`、`redirect://`、`statusCode://`、模板家族，以及裸目标 URL，**共用一个槽位**。
第一条填进去的应答，其余的**完全不生效** —— 所以下面这样是**不行**的：

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true})     # 永远不会被服务
```

转发那一行写在前面，于是它连 `/api/flags` 也一起赢了，请求照样发给开发服务。
把更窄的规则写在更宽的上面：

```
example.com/api/flags  file://({"beta":true})
example.com            http://localhost:5173
```

……或者标记为 important，它就与行序无关地排到最前：

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true}) lineProps://important
```

同一家族在**一行之内**也共用一个槽位，先写的那个赢：

```
example.com  file://({"beta":true})  statusCode://204   # 服务文件
example.com  statusCode://204  file://({"beta":true})   # 回 204
```

**不属于**这个家族的算子 —— `resHeaders://`、`reqHeaders://`、`resDelay://`、筛选器 ——
照常累加，不需要这样处理。

---

## Mock 一个接口

mock 的内容可以放在三个地方，三种都能用；选哪种取决于**这份 mock 要不要跟着规则文件走**。

### 直接写在规则里

圆括号的意思是「这**就是**内容」，而不是「去这里找内容」：

```
api.example.com/health   file://({"status":"ok"})   resType://json
```

适合一行能写完的。里面**不能有换行**，而且 —— 见下文 —— 也**不能有空格**。

### 写在同一个规则文件的围栏块里

一个 ` ``` ` 块声明一个命名值，文件里的其它行可以引用它。规则和它服务的 JSON 待在同一个
文件里 —— 当「规则文件」本身就是你要分发的产物时，你要的就是这个：

````
api.example.com/users    file://{users.json}

``` users.json
[
  {"id": 1, "name": "Ada"},
  {"id": 2, "name": "Grace"}
]
```
````

起始围栏是三个或更多反引号，后面跟**一个**名字，再无别的；结束围栏必须是**同样数量**的
反引号。所以内容里含有较短围栏的块，只要用更长的围栏打开就能完整保留。

### 放在磁盘上的文件里

```
api.example.com/users    file:///Users/me/mock/users.json
```

只有这一种能**白拿正确的 `Content-Type`**：whistle-rs 从文件扩展名猜。另外两种没有文件名可猜，
默认是 `text/html; charset=utf-8`，所以客户端挑剔时要加 `resType://json` ——
`fetch().then(r => r.json())` 不在乎，严格的客户端在乎。

目录也可以，请求路径会拼到它后面：

```
static.example.com       file:///srv/static
# /js/app.js  ->  /srv/static/js/app.js
```

### 状态码，以及 `statusCode://` 为什么吃掉你的 body

`statusCode://` 用那个状态码应答，**body 为空**；同一行里它还**压过** `file://`：

```
api.example.com/gone     statusCode://410               # 410，无 body
api.example.com/created  file://({"id":7})  statusCode://201   # 201，**没有** body
```

要在非 200 状态下**带 body**，用 `replaceStatus://` —— 它改的是一个响应的状态码，
而不是凭空造一个响应：

```
api.example.com/created  file://({"id":7})  replaceStatus://201  resType://json
# -> 201 Created, {"id":7}
```

### 会读请求的 mock

`tpl://` 会把 `${…}` 变量对着实际请求渲染。这里**没有模板引擎** —— 没有循环、没有条件，
上游本来也没有 —— 但变量表很有用：

````
api.example.com/greet    tpl://{greet.json}  resType://json

``` greet.json
{"hello": "${query.name}", "ua": "${reqHeaders.user-agent}"}
```
````

```
$ curl -x http://127.0.0.1:8899 'http://api.example.com/greet?name=world'
{"hello": "world", "ua": "curl/8.7.1"}
```

完整变量表、`.replace(a,b)` 修饰符与两遍替换见 [`TEMPLATES.md`](TEMPLATES.md)。
有一道闸门要知道：文件里必须至少出现一处 `{…}`，且**花括号之间不含空白**，否则两遍都不执行。

### 改真实响应，而不是替换它

想要源站的答案、只改其中一处时，就让请求照常上行，回来的时候打补丁：

```
api.example.com/config   resMerge://{"env":"staging","featureX":true}
```

`resMerge://` 会**深合并**进 JSON body。`{"env":"production","flag":false,"n":1}`
回来变成 `{"env":"staging","featureX":true,"flag":false,"n":1}` —— 你没点名的键原样不动。
非 JSON body 用 `resReplace://from=to` 做文本替换。

要在请求仍然打到源站的前提下**整体换掉 body**（于是头、状态码、耗时都还是真的），
用 `resBody://`：

```
api.example.com/config   resBody://({"env":"staging"})   resType://json
api.example.com/config   resBody://{config.json}
```

圆括号形式的意思是「值**就是**这段内容」，且它对**每一个**算子都生效，不只 body 家族：
`reqBody://(Hello)` 发出去的是 5 个字节，括号被剥掉。

`file://` 的三种取值形式里有两种能沿用，第三种不能：`resBody:///Users/me/mock.json`
会把这个**路径本身**当 body 发出去 —— 本移植的算子取值不从文件或 URL 加载，
所以放在磁盘上的 mock 只能靠 `file://`（它会短路请求）或者作为 value 引进来。

任何响应体算子还会顺带**禁掉请求的缓存**，否则客户端的条件请求会被答 `304 Not Modified`
且没有 body，改写就悄悄消失 —— 而且是间歇性的，取决于浏览器手上缓存了什么。

---

## 在传输途中改请求或响应

### 头

```
api.example.com    reqHeaders://x-token=abc&x-env=dev
api.example.com    resHeaders://x-mitm=intercepted
api.example.com    delete://reqHeaders.user-agent
```

多行会累加：几行 `reqHeaders://` 全都生效；两行指定同一个头名时，**首行**获胜。

**取值里不能有空格。** 规则行是按空白切分的，所以

```
api.example.com    reqHeaders://authorization=Bearer secret
```

会设成 `authorization: Bearer`，然后把 `secret` 读成**第二个算子** —— 一个裸词，
也就是**转发目标**，于是你的请求被发到一台叫 `secret` 的主机上去了。
百分号编码也救不了：`%20` 会原样到达源站。正确做法是命名 value 加 `${…}` 引用：

````
api.example.com    reqHeaders://authorization=${bearer}

``` bearer
Bearer eyJhbGciOi...
```
````

或者从命令行给：

```bash
whistle-rs --value 'bearer=Bearer eyJhbGciOi...' -r rules.txt
```

注意两种花括号写法的区别。`{name}` 替换的是**整个**算子取值（`file://{users.json}`）；
`${name}` 替换的是取值**内部**的一段（`reqHeaders://authorization=${bearer}`）。
写头的时候你要的是 `${name}`。

要**删**而不是设，用 `delete://` —— `reqHeaders://x-a=` 发的是一个**空值头**，不是删除。

### Cookie

```
api.example.com    reqCookies://sid=42
api.example.com    resCookies://{"sid":{"value":"abc","path":"/","httpOnly":true,"maxAge":600}}
api.example.com    delete://reqCookies.tracking
```

`reqCookies://` 是**合并**进客户端发来的 Cookie 里（`old=1` 变成 `old=1; sid=42`）。
Cookie **属性**必须用 JSON 形式 —— `k=v` 形式没地方放属性，而字面写 `; Path=/`
会先被空格切开、再被百分号编码进值里。上面那条 JSON 产出：

```
set-cookie: sid=abc; Expires=…; Max-Age=600; HttpOnly; Path=/
```

`resHeaders://set-cookie=…` 是**按名字合并**而不是替换整个头，所以设置 `sid`
不会动源站发的 `csrf`：

```
# 源站发 csrf=origin1 与 sid=origin2，规则写 sid=fromrule
set-cookie: sid=fromrule
set-cookie: csrf=origin1; Path=/
```

### JSON body 里的某个字段

响应侧，深合并：

```
api.example.com/me    resMerge://{"role":"admin"}
```

请求侧，按 body 的形状合并进去：

```
api.example.com    params://uid=42          # 合进 JSON / form body
api.example.com    urlParams://trace=1      # 恒进查询串
api.example.com    delete://reqBody.password
```

`params://` 只作用于**其中一处**，绝不同时：JSON、form-urlencoded 或 multipart body
会接走它，其余情况它进查询串。`urlParams://` 无条件进查询串。
判定表见 [`RULES.md#where-params-lands`](RULES.md#where-params-lands)。

### CORS

浏览器要访问一个不允许你这个 origin 的接口时：

```
api.thirdparty.com   resCors://*
```

`resCors://enable` 会回显请求自己的 `Origin` 并加上
`Access-Control-Allow-Credentials: true` —— 调用要带 cookie 时用这个。

预检要多留意一步。在 `OPTIONS` 上配 `*` 或 `enable` 时，whistle-rs 把请求的方法
回写成 **`Access-Control-Allow-Method`** —— 单数，而这**不是**一个真实的 CORS 头。
这是上游的笔误，本移植照抄以保证两边发出同样的字节；浏览器会忽略它。
自己把方法写清楚，写在第二行：

```
api.thirdparty.com   resCors://*
api.thirdparty.com   resCors://methods=GET,POST,PUT&headers=x-token&maxAge=600
```

两行会折叠成同一组头。如果源站根本不处理 `OPTIONS`，就别把预检转发上去，本地答掉：

```
api.thirdparty.com   resCors://*
api.thirdparty.com   statusCode://204   includeFilter://m:OPTIONS
```

筛选器保证这个短路不会打到你真正的 `GET` 上。

### 方法、URL 与 User-Agent

```
api.example.com      method://POST
api.example.com/api  urlReplace://v1=v2            # /api/v1/x -> /api/v2/x
example.com          ua://MyBot/1.0                # ……但仍受上面「不能有空格」的限制
example.com          referer://https://example.com/
```

---

## 模拟糟糕的网络

### 延迟

```
slow.example.com     reqDelay://500      # 转发前等
slow.example.com     resDelay://2000     # 应答前等
```

**单位恒为毫秒。** 单位后缀会被解析掉然后**丢弃**，而不是换算：`resDelay://500ms`
如你所愿是 500 毫秒，但 `resDelay://1s` 是**1 毫秒** —— 数字按 `parseInt` 语义读，
`s` 被忽略。请写 `resDelay://1000`。

`reqDelay://` 在**所有短路之前**执行，所以它也会延迟一个 `file://` mock ——
这正是两者搭配使用的全部意义。

### 限速

```
slow.example.com     resSpeed://800      # 约 100 kB/s 下行
slow.example.com     reqSpeed://200      # 约 25 kB/s 上行
```

**单位是千比特每秒，不是千字节。** `resSpeed://800` 是 800 kbit/s ≈ 100 kB/s；
一个 64 KiB 的响应约需 0.65 秒。本移植此前把它读成千字节，于是每一条限速都**快了 8.192 倍**；
按旧行为写的规则，把数值乘以 8。

大致对照：

| 你想要 | 就写 |
|--------|------|
| 2G 级（约 50 kbit/s） | `resSpeed://50` |
| 3G 级（约 1.6 Mbit/s） | `resSpeed://1600` |
| DSL（约 8 Mbit/s） | `resSpeed://8000` |

限速会把 body 缓冲后按节奏分块重发，因此它会把一个定长响应变成 chunked 传输。

### 失败

```
flaky.example.com    enable://abort         # 直接销毁连接，不产生响应
api.example.com      statusCode://503       # 干净的 503
api.example.com      statusCode://500  includeFilter://chance:5%   # 5% 的请求
```

`enable://abort` 是销毁 socket 而不是应答 —— 客户端看到的是连接被重置（curl 退出码 52），
这正是超时处理代码真正需要被喂到的失败形态。`statusCode://` 是它温和的版本。

`chance:` 按请求逐次采样，所以它适合回答「重试逻辑对不对」，而不是「这个接口是不是挂了」。

### 别再等一个永远不答的主机

一个**丢包**而不是拒绝连接的目标，会把请求挂到操作系统的 TCP 超时为止 —— 一分多钟。
`-t` 给这个等待封顶：

```bash
whistle-rs -t 3000 -r rules.txt      # 连接 3 秒还建立不起来就放弃
```

关于它有两件事从参数名上看不出来：

- **它只约束连接的「建立」阶段。** 已经连上的连接绝不会被切断，所以慢响应、SSE 流、
  长轮询都不受影响。它**不是**「N 毫秒后杀掉请求」的开关。
- **它只会收紧，不会放松。** 底下还有一道 16 秒的硬上限，所以默认的 `360000`
  实际含义是 16 秒，`-t` 只有在你把它设到 16 秒**以下**时才起作用。`-t 0`
  会被夹到 1 毫秒，而不是「不限」。

要让**某一个**请求变慢而不是让整个代理变有耐心，用 `reqDelay://` ——
`-t` 是安全网，不是模拟工具。

### 限速做不到的事

body 算子与流式响应不兼容，但**是不是事件流**决定了后果完全不同。

**`text/event-stream` —— 算子被跳过，流照常往下走。** body 算子
（`resBody`、`resAppend`、`resReplace`、`resMerge`、html/js/css 家族）、
强制的 `enable://gzip`、以及插件声明的 `responseBody` 钩子，在事件流上一律被丢弃，
事件原样通过。你得不到改写；插件钩子被跳过时控制台会打一行日志，
免得看起来像钩子悄悄失效了。

这不是算子生效了，而是算子主动让路。上游**确实**会改写事件流，因为它的 body 层
从头到尾是流式的；本移植是先缓冲再变换，而缓冲一条「服务端不说结束就不结束」的流
—— 对 SSE 通常是永不 —— 不是让响应变慢，是让它彻底不返回。两者之间，跳过才是诚实的那个。

**chunked 但不是事件流 —— 整个 body 仍会被缓冲完。** 长轮询或慢速 chunked 下载
若挂了 body 算子，会被扣到最后一个字节。实测一条 600 毫秒的流：
不带 body 算子首字节 3 毫秒，带上是 621 毫秒。延迟与限速没问题，body 改写有问题。

两者是同一个结构性缺口，原因见 [`ROADMAP.md`](ROADMAP.md)。

---

## 把规则的作用范围收窄

### 筛选器

`includeFilter://` 是**唯一**做「包含」的拼写。`filter://` 与 `ignore://<条件>`
都是**排除**。

```
# 只对 POST
api.example.com   host://10.0.0.1     includeFilter://m:POST

# 只对带 canary 头的请求（按包含比较）
api.example.com   resHeaders://x-canary=1   includeFilter://reqH.x-canary:on

# 健康检查除外
api.example.com   host://10.0.0.1     excludeFilter://*/health

# 只对这个客户端
api.example.com   resHeaders://x-a=1  includeFilter://clientIp:192.168.1.44

# 只对一部分流量
api.example.com   statusCode://503    includeFilter://chance:5%
```

include 之间是 **OR**；任意一条 exclude 命中就否决整条规则，无论 include 怎么说。
条件也可以问**响应** —— `s:404`、`resH.content-type:json`、`serverIp:` ——
这些在响应头到达后的第二遍解析里求值。

筛选器里的 URL pattern **总是**按 `^` 解读，这就是 `excludeFilter://*/health`
能通配路径、而同样的 token 作为规则 pattern 却不能的原因。

### `lineProps://important` —— 插队

```
example.com    host://1.1.1.1
example.com    host://2.2.2.2  lineProps://important   # 这条赢
```

important 规则先于普通规则解析，与行序无关。当你的窄规则在宽规则下面、又不想重排文件时，
这就是那个逃生口。

`$` **不是**它。`$` 是精确匹配 —— `$example.com` 指的是站点根路径、且不含其下任何路径 ——
它在上游和这里都不带任何优先级。

### `ignore://` —— 在宽规则上挖个洞

```
.example.com          host://10.0.0.1
static.example.com    ignore://host      # 这个子域保留真实地址
example.com/health    ignore://all       # 这个路径绕过所有规则
```

`ignore://` 点名要从解析结果里**丢掉的协议**。如果后面跟的看起来像筛选条件
（含 `:`、`.` 或 `=`），它就被读成一个 exclude 筛选器 —— 两种读法不可能撞车。

### 规则分组 —— 整组开关

多个命名规则集与默认组并列。在控制台里它们就是左侧的来源列表，双击切换启用。
用 HTTP：

```bash
curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"name":"staging","text":"api.example.com host://10.0.0.9\n"}' \
     http://127.0.0.1:8899/api/rule-groups

curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"name":"staging"}' http://127.0.0.1:8899/api/rule-group/toggle
# {"ok":true,"enabled":false}

curl --noproxy '*' http://127.0.0.1:8899/api/rule-groups
# [{"enabled":true,"name":"default","rules":1},{"enabled":false,"name":"staging","rules":1}]
```

分组持久化到 `<存储目录>/rules/`，重启后自动回来。被禁用的组什么都不贡献 ——
连它围栏块声明的 value 也不贡献。

**具名分组压过默认分组。** 每个启用的具名分组按列表顺序先解析，默认分组最后 ——
这是上游自己的顺序，也是它的控制台把 Default 列在最下面的原因。所以那些你要随手开关的
覆盖规则，应该放进一个具名分组里。

### 从别处引入规则

```
@/etc/whistle/team.rules          # 以 @ 开头的行引入那个文件
@https://intra/rules.txt          # ……或那个 URL，启动时抓取
```

`@` 引入只在**加载时**解析一次。要运行时引入，用 `rulesFile://` 与 `rule://`：
它们把一个文件或一个命名 value 作为**更多规则**引进来，且只对命中的请求生效。

---

## 调试手机或其它设备

### 1. 让代理可达

whistle-rs 默认绑定**所有网卡**，所以它已经在你的局域网地址上监听了。找出这个地址：

```bash
ipconfig getifaddr en0        # macOS
ip -4 addr show scope global  # Linux
```

下文都假设是 `192.168.1.5:8899`。想显式绑定就 `-H 0.0.0.0`；想让代理完全不上网络，
用 `-H 127.0.0.1`。

### 2. 把设备指过来

手动：Wi-Fi 设置 → 该网络 → HTTP 代理 → 手动 → `192.168.1.5`，端口 `8899`。
**HTTP 与 HTTPS 都要设**。

或者用 PAC 文件，有些平台上手动配代理很别扭，这个更顺：

```
http://192.168.1.5:8899/proxy.pac
```

PAC 是**按取回它的那个请求的 `Host` 头**生成的 —— 设备用哪个地址访问到这个页面，
它就会被告知用哪个地址做代理。所以**在设备上打开这个 URL**是最可靠的做法。

### 3. 装根证书，否则你只能看到 `CONNECT`

没有被信任的 CA，HTTPS 就只是一条隧道：你只会看到一行 `CONNECT`，看不到内容。
在设备上打开：

```
http://192.168.1.5:8899/rootCA.crt
```

然后信任它。各平台分步说明 —— 包括 iOS 那两步（先安装、**再到「关于本机 → 证书信任设置」
里启用完全信任**，大多数人在第一步就停下了），以及 Android 7+ 的用户证书限制 ——
见 [`CERTIFICATES.md`](CERTIFICATES.md)。Firefox 有自己的证书库，不看系统的。

先在笔记本上验证一遍，那里的失败信息更好读：

```bash
curl -x http://127.0.0.1:8899 --cacert ~/.whistle-rs/certs/root.crt \
     https://example.com/ -D - -o /dev/null
```

### 4. 把设备的流量指向你的笔记本

到这一步，规则和别的配方就没区别了。最常用的第一条通常是：

```
www.example.com     http://192.168.1.5:5173
```

注意写的是**局域网地址**而不是 `localhost` —— 目标是由**代理**去连的，所以 `localhost`
指的是跑 whistle-rs 的那台机器。开发服务恰好在同一台笔记本上时它碰巧是对的，
一旦不在，就错了。

### 放过某一个域名

证书绑定（pinning）的 App 一被拦截就崩，而通常有用的答案是**不拦这一个域名**，
而不是干脆放弃：

```
pinned.example.com    sniCallback://no-mitm
```

`no-mitm` 是一个内建插件，它拒绝拦截；该连接被逐字节中继。它**仍然按规则路由** ——
`host://` 与代理家族照常生效 —— 只是里面的内容不被读取，因此也不抓包。

### 只路由 HTTPS 而不解密它 —— 连证书都不用装

有时你并不需要**读**流量，你需要的是把它**发到别处**。把设备的 TLS 指向一台预发机、
或者只是想知道某个 App 到底在跟哪些域名说话，都用不着中间人；而用不着中间人，
就意味着设备上**根本不用装证书**：

```bash
whistle-rs -p 8899 --no-intercept-https -r rules.txt
```

```
secure.example.com   host://10.0.0.9
```

保留了什么、放弃了什么（两栏都是对着一个自签名源站实测的）：

| | 开启拦截 | `--no-intercept-https` |
|---|---|---|
| `host://` 与代理家族 | 照常路由 | **照常路由** |
| 客户端看到的证书 | whistle-rs 用自己根 CA 签的 | **源站自己的** |
| 必须安装根证书 | 是 | **否** |
| `resHeaders://` 等所有内容算子 | 生效 | **不生效** |
| 出现在抓包里 | 是 | **否** |
| 自签名源站 | `502`，除非加 `--insecure-upstream` | 没问题 —— 由**客户端**自己决定信不信 |

最后一行是反方向最容易踩的：开着拦截时，源站证书是由 whistle-rs 自己校验的，
自签名源站就是 `502`；关掉拦截后代理**无物可校验** ——
TLS 会话是客户端与源站之间的，代理只搬字节。

上面的 `sniCallback://no-mitm` 就是同一件事的「按域名」版本。整体要用就用这个参数，
只有一个绑定证书的域名捣乱就用那条规则。

---

## 抓包、导出与重放

<http://127.0.0.1:8899/> 上的控制台是交互式的那一面。它展示的一切同时也是接口，
这是写脚本时你要的。下面这些都是**直连**请求，不走代理：

| 接口 | 返回 |
|------|------|
| `GET /sessions.json` | 每一条抓到的事务：id、方法、url、状态码、目标、上下行字节、耗时，以及**命中了哪些规则** |
| `GET /session.json?id=N` | 单条事务，含请求/响应头与 body 预览 |
| `GET /frames.json?id=N` | 第 `N` 条连接的 WebSocket 帧，双向 |
| `GET /sessions.har` | 全部导出为 HAR 1.2 文件 |
| `GET /api/status` | 端口、TLS 姿态、根证书路径、规则数、已注册插件 |
| `POST /api/sessions/clear` | 清空抓包 |

```bash
# 看一眼都抓到了什么
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
for s in json.load(sys.stdin): print(s["status"], s["method"], s["url"])'

# 一个能直接拖进 Chrome DevTools 的 HAR
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.har -o capture.har
```

Body 预览是有界的 —— 默认 16 KB，`--body-preview-limit` 可调。`gzip`/`deflate`/`br`
会为查看而解码，且抓取用的是流式 tee，所以 chunked 或 SSE 响应可以查看而不破坏流式。

WebSocket 连接以状态码 `101` 的会话出现，双向每一帧都被记录：

```json
[{"session":1,"dir":"receive","opcode":"text","len":17,"preview":"hello from origin","ignored":false},
 {"session":1,"dir":"send","opcode":"text","len":16,"preview":"ping from client","ignored":false}]
```

### 重放

把抓到的请求重新走一遍完整管线 —— 于是它吃到的是你**现在**的规则，而不是抓包当时的：

```bash
curl --noproxy '*' -X POST -H 'content-type: application/json' \
     -d '{"id":6}' http://127.0.0.1:8899/api/replay
```

`{"ids":[6,7,8]}` 批量重放（最多 100 条）。返回的 JSON 会逐条报告实际发出了什么 ——
包括请求体有多少可以重发，因为 body 只能重发**抓到的那部分**，而抓取受
`--body-preview-limit` 约束。

重放的这一跳带有 Composer 标记，所以规则可以把它与它所来自的流量区别对待：

```
api.example.com   resHeaders://x-replayed=1   includeFilter://from:composer
```

这个头只会落在重放上，别的请求一概没有。

### 让抓包跨重启保留

会话以 JSONL 写到 `<存储目录>/sessions/`，每日轮转，启动时回加载。
`--persist-days N` 控制保留天数；`--no-persist` 整个关掉 —— 测试夹具里你要的就是这个。

---

## 把代理嵌进你自己的程序

whistle-rs 是「一个库 + 跑在它上面的二进制」。如果你自己的程序需要流量拦截 ——
一个要对出站调用做断言的测试夹具、一个自带检查器的桌面应用、你自己的代理 ——
把它嵌进去，而不是去 shell 出一个进程：

```rust
use whistle_rs::embed::Proxy;

let proxy = Proxy::builder()
    .port(0)                          // 0：系统挑端口，addr() 告诉你挑了哪个
    .host("127.0.0.1".parse()?)       // 不暴露到网络上
    .rules("api.example.com  http://127.0.0.1:3000")
    .on_session(|s| println!("{} {} -> {}", s.method, s.url, s.status))
    .start()
    .await?;

let addr = proxy.addr();              // 把客户端指到这里
proxy.set_rules("api.example.com  statusCode://503");   // 运行中热更新，不必重启
proxy.shutdown().await;
```

`.port(0)` 与 `addr()` 这一对是它在测试里好用的关键：不用预留端口，并发跑的测试二进制之间
也不会撞。

要**改**流量而不只是看，就注册一个进程内钩子。它就是内建插件用的那个 `RustPlugin` trait，
因此可以改写请求头、注入规则、直接应答请求、做鉴权拦截、变换响应，或在握手期挑证书：

```rust
struct MockApi;

impl RustPlugin for MockApi {
    fn name(&self) -> &str { "mock-api" }
    fn on_request(&self, _req: &PluginReq) -> PluginResult {
        PluginResult {
            response: Some(PluginResp {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: br#"{"answered_by":"your program"}"#.to_vec(),
            }),
            ..Default::default()
        }
    }
}

Proxy::builder().plugin(MockApi).rules("api.test  plugin://mock-api")
```

[`examples/embedded.rs`](../examples/embedded.rs) 把上面这些端到端跑一遍 ——
`cargo run --example embedded`。builder 还覆盖 SOCKS5 端口、存储目录
（两个 embedder 共用同一目录即共用一份 CA）、values、Body 抓取上限，以及
`intercept_https(false)` —— 只路由 TLS 而不解密。facade 之外的东西都可以从
`proxy.state()` 拿到。

进程外的 JS/TS 插件见 [`PLUGINS.md`](PLUGINS.md)。

---

## 规则不生效时

**先问抓包命中了什么。** 每条会话都记录了为它解析出来的算子，包含「原文」与「结果」两栏：

```bash
curl -s --noproxy '*' http://127.0.0.1:8899/sessions.json |
  python3 -c 'import sys,json
s = json.load(sys.stdin)[0]
print(s["url"])
for r in s["rules"]: print(" ", r["raw"], "->", r["value"])'
```

```
http://api.example.com/anything
  host://127.0.0.1:5173             -> 127.0.0.1:5173
  reqHeaders://x-token=abc          -> x-token=abc
  reqHeaders://authorization=${bearer} -> authorization=Bearer eyJhbGciOi
```

不在这张表里的算子就是**根本没匹配上** —— 去看它的 pattern。在表里但 `value`
不是你期望的那个，那就是替换或路径拼接的问题，不是匹配的问题。注意这张表是
**解析出来**的东西，不总等于**实际执行**的：[共用槽位](#mock-必须写在转发上面)
的两个竞争者都会出现，而只有第一个真的应答了。

然后看日志。每个请求都会打印它解析出的目标，其余的答案通常就在这一行里：

```
INFO GET http://seg.test/path/to/x    -> 127.0.0.1:5173 (http)   # 规则命中
INFO GET http://seg.test/path/toxxx   -> seg.test:80    (http)   # 没命中
INFO OPTIONS http://api.test/users    -> short-circuit           # 本地应答
```

这几行是 `INFO`，不加任何参数就有。`-v` 补上失败的**原因** —— 这是光看 `502` 得不到的：

```
INFO  GET http://dead.test/ -> 127.0.0.1:9 (http)
DEBUG request failed: connecting to 127.0.0.1:9: Connection refused (os error 61)
INFO  GET https://sec.test/ -> 127.0.0.1:5443 (https)
DEBUG request failed: upstream TLS handshake: invalid peer certificate: …
```

然后按这张表往下排查：

| 现象 | 原因 |
|------|------|
| 规则命中了你以为不该命中的 URL，或反过来 | 路径前缀只在 `/`、`\`、`?` 边界上匹配：`example.com/path/to` 命中 `/path/to/x`，但**不**命中 `/path/toxxx` |
| 路径里的 `*` 什么都匹配不到 | `*` **只在域名部分**是通配符。在路径里它是字面量，因为 `*` 是合法的 URL 字符。`example.com/old/*` 匹配的是真的含有 `*` 的 URL；要路径通配请写 `^http://example.com/old/**`。筛选器是例外 —— 它的 pattern 总按 `^` 解读，所以 `excludeFilter://*/health` 是有效的 |
| mock / 重定向 / 转发被忽略 | [共用槽位](#mock-必须写在转发上面)里另有一行写在前面。把它往上挪，或标 `$` |
| 算子取值被截断了 | 里面有空格。改用 `${name}` 加 value —— 见[头](#头) |
| 自签名 / 私有 CA 源站返回 `502` | 与上游不同，whistle-rs **校验**源站证书。用 `--insecure-upstream` 关掉 |
| 写了 `1s` 的延迟瞬间就过去了 | 延迟单位是毫秒；后缀被丢弃而不是换算。写 `1000` |
| 限速比预期快 8 倍 | `resSpeed://` 的单位是**千比特**，不是千字节 |
| body 改写时灵时不灵 | 现在不会了 —— 响应体算子会顺带禁掉请求缓存，`304` 吞不掉它。如果你用的是旧版本，加 `disable://cache` |
| chunked 响应不再流式 | 上面挂了 body 算子，它会把整个 body 缓冲完。去掉它，或者用筛选器把它避开 |
| body 算子对 SSE 流毫无作用 | 那是刻意跳过的，为的是让流继续走 —— 见[限速做不到的事](#限速做不到的事) |
| 控制台只显示 `CONNECT`，里面什么都没有 | 客户端不信任根证书 —— 见 [`CERTIFICATES.md`](CERTIFICATES.md) |
| 直连控制台却返回带 `Proxy-Connection` 的 `502` | 你的 shell 设了 `http_proxy`。`curl --noproxy '*'` |
| 失败的请求在控制台里根本找不到 | **没有拿到响应**的请求 —— 连接被拒、DNS 失败、TLS 握手失败 —— 不会被记为会话。它只出现在代理日志里，这也是调试期间该一直开着 `-v` 的另一个理由 |
| 编辑器把「不该是 pattern 的 token」标成了 pattern | 它说的是实话。`example.com http://localhost:5173` 是 pattern + 目标；`http://a.com/x host://1.2.3.4` 是 pattern + 算子。它标出来的那个，就是代理真正会拿去匹配的 |

更多失败形态、以及哪些是结构性而非可修的，见两份 README 的故障排查段落与
[`ROADMAP.md`](ROADMAP.md)。
