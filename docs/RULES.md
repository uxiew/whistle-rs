# 规则手册

> 当前的兼容范围和实际跑过的检查，见 [STATUS.md](STATUS.md)。
> 各算子条目讲的是语义和限制；某个算子出现在这里，不等于声称整个产品都兼容。
> 历史审计记录保存在 [ROADMAP-HISTORY.md](ROADMAP-HISTORY.md)。

whix 用的是 whistle 的规则语法。本文是 Rust 内核所支持的那部分语法的完整参考。
原版 whistle 详尽的规则文档见 <https://wproxy.org>。

> **想知道怎么*做*某件事？** [`COOKBOOK.md`](COOKBOOK.md) 是按任务组织的那一半——
> 把站点交给开发服务器、mock 一个接口、给连接限速、调试手机——每个例子都完整地实际跑过。
> 本文则是你知道自己要用哪个算子之后，回头来查的参考。

## 从这里开始

规则文件就是一行一行的文本。每一行是**一个匹配串（pattern），后面跟任意多个算子**：

```
example.com          http://localhost:5173
└─ pattern ────┘     └─ operator ───────┘
```

匹配串决定*这一行对哪些请求生效*；算子决定*对这些请求做什么*。整个语法就这么多。
由此引出三点，新手栽跟头的恰恰就是这三点：

**1. 看位置，不看长相。** 第一个 token（用空白隔开的一段）是匹配串，后面的全是算子，
不管它写成什么样。所以 `example.com http://localhost:5173` 的意思是
“发往 example.com 的请求转到 localhost:5173”——第二个 token 虽然长得像 URL，
但它不是第二个匹配串。唯一的例外是对调写法：算子写在最前面，好让多个匹配串共用它：

```
example.com     http://localhost:5173     # 先匹配串，后算子
host://9.9.9.9  a.com  b.com  c.com       # 先算子，后匹配串
```

把这个顺序写反，是写出“不报错、但什么也不做”的规则最常见的原因。
控制台的规则编辑器会高亮代理实际拿来匹配的那个 token，所以答案你能直接看到，不用猜。

**2. token 之间用空白分隔，所以算子的值里不能有空格。**
`reqHeaders://authorization=Bearer secret` 设置的是 `authorization: Bearer`，
然后把 `secret` 当成另一个算子来读。用百分号编码也没用。
把值放进 [Values](#开关引入与-values)，再用 `${name}` 引用它。

**3. 大多数算子会叠加，少数会互相竞争。** 写几行 `resHeaders://`，它们全都生效。
但 `file://`、`redirect://`、`statusCode://`、模板那一族，以及一个裸的目标 URL，
共用**同一个槽位**，所以只有其中最先匹配上的那一个来应答——见[短路](#短路不向源站发请求)。

匹配串能写成四类：[域名或 URL 前缀](#1-域名--url-前缀最常用)、
[通配符](#3-通配符)、[正则](#5-正则表达式)或[端口](#6-端口)。
前面加 `$`，匹配串就变成[精确匹配](#--精确匹配串)；
前面加 `^`，[`*` 在任何位置都是通配符](#4---处处可用的通配符)。

最值得先学的几个算子是：
[`host://`](#目标地址)（改变请求发往哪里，但保留它的 `Host` 头）、
[`file://`](#短路不向源站发请求)（在本地直接应答）、
[`reqHeaders://` / `resHeaders://`](#请求改写)（加一个头）、
[`resBody://` 及其同类](#body)（改写返回的内容），以及
[`includeFilter://`](#筛选条件)（给上面任何一个收窄范围）。

---

## 目录

- [文件格式](#文件格式) —— [引入另一份规则文本（`@`）](#引入另一份规则文本)
- [匹配串](#匹配串) —— [前缀](#1-域名--url-前缀最常用) ·
  [前导点](#2-前导点匹配子域名) · [通配符](#3-通配符) ·
  [`^`](#4---处处可用的通配符) · [`$0`…`$9` 捕获](#09--匹配串捕获到了什么) ·
  [正则](#5-正则表达式) · [端口](#6-端口) · [`!` 取反](#--取反的匹配串) ·
  [`$` 精确](#--精确匹配串) ·
  [与上游不同的地方](#匹配串与上游不同的地方)
- [算子](#算子)
  - [匹配串的位置](#匹配串的位置) · [简写](#简写)
  - [算子的值可以是什么](#算子的值可以是什么) ——
    [从文件或 URL 读取](#从文件或-url-读取的值) ·
    [反引号模板](#反引号模板) ·
    [在规则文本里声明的值](#在规则文本里声明的值)
  - [目标地址](#目标地址) —— [转发到另一个 URL](#转发到另一个-url)
  - [上级代理](#上级代理) —— [PAC](#pac)
  - [URL 改写](#url-改写) —— [`params://` 加到哪里](#params-落在哪里)
  - [筛选条件](#筛选条件) —— [条件](#条件) ·
    [响应阶段](#响应阶段) · [body 条件](#body-条件) ·
    [来源标记](#来源标记)
  - [禁用算子](#禁用算子) ·
    [短路](#短路不向源站发请求)
  - [请求改写](#请求改写) —— [`auth://`](#auth-的四种写法)
  - [插件](#插件) · [选择中间人证书](#选择中间人证书) ·
    [脚本](#脚本) · [`log://`](#log--页面的控制台搬到这里) ·
    [weinre](#weinrehtml-调试注入)
  - [开关、引入与 Values](#开关引入与-values) —— [trailer](#trailers尾部头) ·
    [`enable://abort`](#enableabort-是两道闸不是一道) ·
    [多行 `rulesFile://`](#多行-rulesfile-怎么合并)
  - [转储文件](#转储文件) · [延迟与限速](#延迟与限速)
  - [改写响应](#改写响应) · [删除](#删除) ·
    [Cookie](#cookie) · [Body](#body)
- [优先级](#优先级) —— [同一个算子写了多行时怎么合并](#同一个算子写了多行怎么合并)
- [速查表](#速查表)
- [算子覆盖情况](#算子覆盖情况) —— [运行时生效的](#运行时生效的算子) ·
  [元数据与仅上游才有的基础设施](#元数据与只有上游才有的基础设施) ·
  [相比上游有简化的](#相比上游做了简化的地方) ·
  [wproxy.org 与 whistle 说法不一的地方](#wproxyorg-文档和-whistle-实际行为不一致的地方)
- [源站证书校验](#源站证书校验)

---

## 文件格式

规则文件是纯 UTF-8 文本，一行一条规则：

```
pattern  operator1  operator2  …  operatorN
```

- token 之间用**任意长度的空白**分隔。
- 以 `#` 开头的行是**注释**，会被忽略。
- 空行，或者不到两个 token 的行，会被忽略。
- 第一个 token 通常是**匹配串**，其余的是**算子**。如果第一个 token 本身就是算子
  （带有已知的 `protocol://` 前缀，或者是裸的 `host:port`），whix 会退一步，
  往后找第一个匹配串 token——在常见情况下，这和 whistle 的“先算子、后匹配串”写法一致。

规则有三种加载方式：

```bash
whix -r rules.txt              # 从文件加载
whix --rule "example.com host://127.0.0.1:8080"   # 直接写在命令行里
whix -r rules.txt --rule "…"   # 先读文件，再把命令行里的规则追加在后面
```

### 引入另一份规则文本（`@`）

如果一行**只有** `@` 加一个来源，这一行就会被替换成那个来源里的规则，
替换就发生在这一行所在的位置：

```
example.com          host://10.0.0.1
@/etc/whistle/team.rules      # 这个文件，每 5 秒重读一次
@https://intra/rules.txt      # 这个 URL，每 10–30 秒重新拉取一次
@~/personal.rules             # $HOME 下的一个路径
```

**所有**规则文本都支持这个写法：`-r`/`--rule`、控制台的编辑器、`POST /api/rules`、
命名的规则组、导入的规则包，以及重启后从磁盘读回来的内容。
它的实现方式带来五点后果，在依赖它之前，每一点都值得先弄清楚：

- **就地拼接。** 引入进来的行，就是它所在那份文本里的普通行，所以[优先级](#优先级)
  就是你眼睛看到的顺序：写在 `@` 上面的行优先于它引入的内容，写在下面的行则不然；
  被引入文本里的一条 `lineProps://important`，会压过它上面的一条普通行，
  跟你直接把它敲在那里完全一样。
- **你敲的文本还是你敲的文本。** 控制台显示的是那行 `@`，保存时也不会把拉取到的规则
  写死进你的文件。想知道某个引入到底生效没有，问 `GET /api/rule-groups`——
  它的 `rules` 计数统计的是*解析后*的规则，所以来源到了之后，这个数会变大。
- **设置规则从不等网络。** 保存会立即返回，引入的内容在拉取完成时生效——
  通常只要几毫秒，每个来源最多等 16 秒、最多 256 KB。在那之前，这一行什么也不贡献，
  上游也是这样。一份文本的所有来源是同时拉取的，所以某一个卡住，不会拖住其他的。
- **启动时会等，但不会等太久。** 启动代理时，如果规则里带有引入，它会在应答任何请求之前
  最多等 3 秒，所以只要来源有响应，第一个请求就已经用上了它（上游根本不等）。
  过了 3 秒，它就不等剩下的来源，直接开始应答——日志里会写
  `rules includes still loading after 3 s` 并列出它们——等它们到了，那些规则再生效。
  以前它会挨个等完每个来源：放在一台卡死的服务器上的三个来源，
  曾让它（连同控制台）整整 48 秒没有任何反应。
- **只有一层。** 被引入的文本*里面*的 `@` 行不会再被跟进，所以根本不存在循环的问题。
  每份规则文本最多解析 20 行 `@`（上游的 `MAX_REMOTE_RULES_COUNT`）。

来源可以是 `/absolute` 绝对路径、`~/` 路径、Windows 盘符路径、`http(s)://` URL、
`whistle.<plugin>` 名字，或者 `$<key>` 形式的插件存储引用。后两种**这里没有实现**——
whix 里的插件是外部 HTTP 服务器，没有这样的端点（见 [`PLUGINS.md`](PLUGINS.md)）——
这样的行会记一条日志，然后什么也不贡献。除此之外的写法都不算引入，
原本是什么意思，还是什么意思：

```
@team.rules              # 相对路径：不算引入（上游的正则也这么认为）
@ /etc/team.rules        # @ 后面有空格：不算引入
example.com @/etc/x      # 前面有匹配串：这是 G:// 算子
@/etc/team.rules extra   # 后面还跟着文字：不算引入
@`/etc/team.rules`       # 允许用反引号，而且反引号里的 ${port} 会被展开
@/etc/team.rules # note  # 允许在行尾加注释
```

出现在 ```` ``` ```` [围起来的值](#在规则文本里声明的值)里面的 `@` 行，
是内容，不是一行规则，永远不会被拉取。被引入的文本里声明的值，引入它的那份文本也能用；
两边声明了同名的值时，**引入方**的文本胜出。

> **只有一处偏离，而且是更安全的那一边。** 拉取失败时，那个来源上一次给出的文本
> 会原样留着，并在日志里记下原因。上游能容忍连续三次失败，之后就套用一份空文本，
> 把那个来源带来的规则删掉——遇到重定向，或者原本存在的文件不见了，它会立刻清空
> （`updateBody` / `readFile`，`_original/lib/util/http-mgr.js:280-294,:377-401`）。
> 内网抖一下，不应该悄悄把一个团队的规则从正在运行的代理里删掉；
> 而且它留下的状态，和这个引入从来没生效过，看起来一模一样。
> 一个*从未*加载成功的来源什么也不贡献，这也正是上游的初始状态；
> 而一个返回 `204` 或空 body 的来源，确实会把自己清空——那是一个回答，不是失败。

---

## 匹配串

匹配串（pattern）决定**一条规则对哪些请求生效**。whix 支持四类匹配串，
它会根据 token 长什么样，自动判断是哪一类。

### 1. 域名 / URL 前缀（最常用）

```
example.com                 # 主机名正好是 example.com 的任何请求
example.com/api             # 主机名是 example.com，并且路径以 /api 开头
http://example.com/api      # ……只限 http 协议
https://example.com         # ……只限 https
```

匹配规则：

| 匹配串的组成部分 | 行为 |
|--------------|-----------|
| 协议（`http://`、`https://`、`ws://`、`wss://`、`tunnel://`） | 可选；写了的话，必须和请求本身的协议一致——WebSocket 的 URL 是 `ws://…`，所以 `http://example.com` **匹配不到**它，`example.com` 则能匹配到 |
| 主机名 | 必填，而且是**精确**匹配（不区分大小写——这是一处[偏离](#匹配串与上游不同的地方)），除非它以点开头（见下文） |
| 端口 | 可选；`example.com:8080` 只匹配这个主机的这个端口 |
| 路径 | 作为请求的 path+query 的**前缀**来匹配 |

没有**主机名**的匹配串什么也匹配不到：`http://`、`http:///api`、`:80/api`
和 `///example.com` 全是死文本，因为上游是拿匹配串去和请求 URL 比较的，
而每个 URL 都有 authority（主机名加端口那一段）。

这也是所有“没法求值”的匹配串的统一结局——没有主机名、正则编译不过、端口不是数字：
它**什么也匹配不到**，它所在的那一行什么也不做。匹配串本身就是那道闸门，
而不是闸门上的修饰，所以它没有第三种状态可落，出错时总是让闸门保持关闭。
[筛选条件](#筛选条件)才是修饰，而它确实有第三种状态——
这就是为什么解析不了的*筛选器*是两者中更危险的那个，这一点放在那一节讲，不在这里。

匹配串可以**不带路径，改带 query**——`example.com?a=1` 就是 `example.com/?a=1`——
这样的匹配串仍然算“只有主机名”，所以对任何端口都生效。

只有“只有主机名”的匹配串会忽略端口。`example.com` 能匹配
`http://example.com:8080/x`；`example.com/` 和 `example.com/api` 则不能，
因为带路径的匹配串是拿 URL 文本来比的，连端口一起比。

### 路径匹配必须停在段边界上

路径前缀只有停在 `/`、`\` 或 `?` 这样的边界上才算匹配——上游文档
（`_original/docs/docs/rules/pattern.md`）写的就是这条规则，代码在
`rules.js:1091-1097` 实现了它：

```
example.com/path/to
  ✅ example.com/path/to
  ✅ example.com/path/to/xxx?q=1
  ✅ example.com/path/to?q=1
  ❌ example.com/path/toxxx        # `to` 后面没有边界
```

本身已经以 `/` 结尾的匹配串，不再额外要求边界。带 query 的匹配串，
意思是“**路径相同**，query 是前缀”：

```
example.com/path/to?xxx
  ✅ example.com/path/to?xxx
  ✅ example.com/path/to?xxxyyy&z
  ❌ example.com/path/to/yyy?xxx   # 路径必须完全一致
  ❌ example.com/path/to           # 必须带 query
```

### 2. 前导点：匹配子域名

以 `.` 开头的主机名，既匹配域名本身，**也匹配它的所有子域名**：

```
.example.com  host://5.5.5.5
```

能匹配 `example.com`、`www.example.com`、`a.b.example.com`……

### 3. 通配符

`*` 只在**主机名里**是通配符，在其他地方都是普通字符——`*` 在 URL 路径里是合法字符，
所以 whistle 不会不声不响地把它从你手里拿走
（`_original/docs/docs/rules/pattern.md`，“域名通配符”）：

| 在主机名里 | 匹配 |
|-------------|---------|
| `*` | 任意一串**不含点**的字符——`[^/?.]*` |
| `**` | 任意一串不含 `/` 和 `?` 的字符——`[^/?]*` |
| `***` 及更多 | 同 `**`，并且它后面的那个点变成可有可无 |

```
*.example.com          host://10.0.0.9      # 匹配 www.example.com，但不匹配 a.b.example.com
**.example.com:8*      host://10.0.0.9      # 任意层级，任意 8xxx 端口
.example.com           host://10.0.0.9      # 域名本身和它的所有子域名
```

主机名后面的路径按普通前缀来匹配，段边界的规则和其他匹配串一样。

### 4. `^` —— 处处可用的通配符

在匹配串前面加 `^`，`*` 在**路径和 query** 里也变成了通配符，
能匹配多远，取决于你连写几个：

| | 路径 | query |
|---|---|---|
| `*` | 一个段以内（`[^?/]*`） | 一个值以内（`[^&]*`） |
| `**` | 跨段，直到 `?` 为止（`[^?]*`） | 剩下的全部，包括 `&`（`.*`） |
| `***` | 剩下的全部，包括 `?`（`.*`） | — |

末尾的 `$` 锚定结尾；`^` 匹配串不区分大小写（写成 `^^` 才区分大小写）：

```
^https://*.example.com/path/*/to$    statusCode://204
^http://*.example.com/v0/users/**    file:///mock/$1/$2
```

### `$0`…`$9` —— 匹配串捕获到了什么

正则或通配符匹配串，会把它匹配到的内容交给同一行的算子。`$0` 是请求 URL；
`$1`…`$9` 是各个分组，从左往右数——`^` 匹配串里每个 `*` 算一组，
正则里每对 `( )` 也算一组：

```
^http://*.example.com/v0/users/**       file:///mock/$1/$2
/\/regexp\/(user|admin)\/(\d+)/         reqHeaders://X-Type=$1&X-ID=$2
*.example.com/api                       reqHeaders://X-Tenant=$1
```

`$$1` 插入的是**百分号编码后**的分组内容，`\$1` 则是字面上的 `$1`——
和 [`*Replace` 算子](#replace-细节)用的转义规则一样，因为背后是同一个展开器。
没有分组的匹配串什么也不替换，所以它的值里写的 `$1` 会原样保留。

### 5. 正则表达式

用斜杠包起来的匹配串是一个正则，拿来测试**完整的请求 URL**
（`scheme://host[:port]/path?query`），其中主机名保持客户端写的原样。
末尾加 `i` 表示不区分大小写：

```
/\.js(\?|$)/          resType://application/javascript
/^https:\/\/cdn\./i   host://10.0.0.9
```

标志只有 `i` 和 `u` 两个，顺序随意——上游的 `REG_EXP_RE` 是
`/^\/(.+)\/(i?u?|ui)$/`，别的一概不认。`/echo/g`、`/echo/m` 和 `/echo/s`
**不是**正则；它们会落到上面那几类匹配串里，而在那里它们没有主机名，
所以什么也匹配不到。

**语法是 JavaScript 的**，因为 whistle 的就是：斜杠之间的所有内容都交给一个
ECMAScript 引擎（[regress](https://docs.rs/regress)，也就是这里的脚本引擎实现 `RegExp`
用的那个）。前瞻、后顾、反向引用和命名分组都能用——在匹配串里、
在[筛选器](#筛选条件)里、在 [`*Replace` 一族](#replace-细节)里，
以及模板的 `.replace(/…/)` 里：

```
/\/api\/(?!internal\/)/        proxy://127.0.0.1:8888   # /api 下除了 /api/internal 以外的一切
/(?<=\/v)\d+\/users/           resHeaders://x-versioned=1
example.com  resReplace://{r}  excludeFilter://m:/^(?!GET$)/   # 只对 GET 生效
```

2026-09-30 之前，这些正则是用 Rust 的 `regex` crate 编译的，而上面这四样它一样都不支持。
它编译不了的表达式，会被悄悄当成别的东西来读，于是上面三行的结果分别是：
什么也不做、什么也不做，以及——最危险的那个——效果正好相反
（一个从来不排除任何东西的 `excludeFilter`，于是规则对所有方法都生效）。

“语法是 JavaScript 的”意味着：

- `\d`、`\w` 和 `\b` 只认 ASCII，和 JavaScript 一样。（`regex` 让它们支持 Unicode。）
- `u` 是 JavaScript 的 Unicode 模式，**更严格**：`/a\-b/u` 在那边和这边都是语法错误。
- JavaScript 也编译不了的 `/…/`——比如 `/a(/`——要么让它所在的规则被丢弃（匹配串），
  要么被当成字面文本（筛选条件的值、模板的 `.replace()`），要么什么也不替换
  （`*Replace`），每种情况都和上游一样。只是它不再静默了：日志会打一次
  `rules: /a(/ (pattern; the rule is dropped) is not a regular expression: …`，
  `whix explain` 也会在 URL 下面打出同样这一行。
- 病态表达式的代价，和在 Node 里一样。`/(a+)+$/` 去匹配一长串 `a`，
  在两边都是指数级的；引擎会回溯，和 V8 一样。

本项目自己*生成*的匹配串——[通配符](#3-通配符)展开出来的、[端口](#6-端口)匹配串——
不是用户写的文本，仍然走线性时间的引擎。

### 6. 端口

单独一个 `:<port>`，把规则限定在某个端口上，不管主机名是什么：

```
:8080          host://127.0.0.1:3000    # 只匹配发往 8080 端口的请求
```

普通匹配串上的端口同样有效——`example.com:8080` **只**匹配这个主机的这个端口。

### `!` —— 取反的匹配串

在**正则**（或端口匹配串）前面加 `!`，就把它取反：

```
!/example\.com/   host://127.0.0.1     # 除 example.com 以外的一切
```

和上游一致，只有正则和端口匹配串支持取反：取反的字面匹配串或通配符匹配串
会**在解析时被丢弃**（`_original/lib/rules/rules.js:1259-1268`），
所以 `!example.com host://x` 在两边的实现里都等于什么也没配置。

### `$` —— 精确匹配串

在匹配串前面加 `$`，请求 URL 就必须和它**完全相等**，而不只是以它开头。
不加 `$` 时匹配串是前缀，正因为这样，`example.com/api` 才能覆盖 `/api` 下的一切。

```
$http://example.com/api    file:///mock.json   # 只匹配 /api
http://example.com/api     file:///mock.json   # /api 以及它下面的一切
```

实测得到的真值表——不带 query 的匹配串只按路径匹配；带 query 的，query 也必须匹配；
不带路径的匹配串，指的是站点根路径：

| 匹配串 | `/p` | `/p?a=1` | `/p?b=2` | `/p/s` | `/` |
|---|---|---|---|---|---|
| `$http://example.com/p` | ✅ | ✅ | ✅ | — | — |
| `$http://example.com/p?a=1` | — | ✅ | — | — | — |
| `$example.com` | — | — | — | — | ✅ |

请求的 **query** 仍然会传给目标地址，因为精确匹配串只消耗了路径：
`$example.com/search http://dev.test/search` 会把 `?q=cat` 一起转发过去。
如果匹配串自己写了 query，那这个 query 已经被它消耗掉了。

`$` 放在**通配符**前面，得到的是一个精确的通配符，而不是拿字面文本做精确匹配：
`$*.example.com/api` 指的是任意一级子域名下的 `/api`，不包括它下面的路径。

`!$…` 是**取反的精确**匹配串——除了那一个 URL 以外的所有 URL。
普通匹配串不能取反，它却可以，因为上游处理 `$` 的分支，
在丢弃那些匹配串的检查之前就运行了。

> **`$` 不带任何优先级，而本项目以前以为它带。** 它曾把这个前缀当成
> “important” 的简写——这个偏离是自己凭空发明的，不是从上游继承来的。
> 由此带来两个后果，都对照 whistle 2.10.8 实测过：在上游那边，写在 `$` 规则*前面*的
> 普通规则依然胜出；而 `$example.com` 在上游指的是站点根路径，本项目却让它匹配
> 该主机上的所有 URL。要提高优先级，只有一种写法：`lineProps://important`。

### 匹配串与上游不同的地方

一共三处，每一处都对照 whistle 2.10.8 实测过，而且每一处上游的结果，
都是把匹配串和 URL 当**文本**来比较带来的意外。每一处都会让人写下的规则
变成一条永远不会触发的规则，所以不可能有哪个规则文件依赖上游的那种结果。

| 匹配串 | 上游 | 本项目 |
|---|---|---|
| `EXAMPLE.com`（或者请求的 `Host` 是大写） | 不匹配：两个字符串不一样 | 匹配——主机名不区分大小写 |
| http 请求上的 `example.com:80`（https 上的 `:443`） | 永远不匹配：`getFullUrl` 在比较任何东西之前就去掉了默认端口，所以 URL 里永远不会出现 `:80` | 匹配 80 端口，而且只匹配 80 端口 |
| 不带端口的 `[::1]`，对 `http://[::1]:8080/` | 不匹配：只有主机名的匹配串，同样是拿去掉端口后的 URL 来比，而 `removePort` 在协议之后的第一个 `:` 处截断——这个 `:` 在方括号里面，结果只剩下 `http://[` | 匹配 |

不区分大小写这一条，只适用于普通的主机名前缀形式。**正则**或**通配符**匹配串，
是拿客户端原样写出的 URL 来匹配的，这是上游的行为，也正是它让 `$0` 和 `${url}`
能如实反映真实的请求——所以 `/API\.example\.com/` 能匹配大写的主机名，
`/api\.example\.com/` 则不能。

---

## 算子

算子的形式是 `protocol://value`。解析时 whix 认得 **whistle 的全部协议**，运行时也基本实现了所有常用算子（例外见[算子覆盖情况](#算子覆盖情况)）。

### 匹配串的位置

一行规则按空白切成若干段，第一段是匹配串（pattern），**其余每一段都是算子**——看的是位置，不是长相。正因为这样，`example.com http://localhost:5173` 才是一条转发规则，而不是两个匹配串。

唯一的例外是 whistle 的倒置写法：算子放在最前面，后面几个匹配串共用它：

```
example.com    http://localhost:5173     # 先匹配串，后算子
host://9.9.9.9  a.com  b.com  c.com      # 先算子，后匹配串
```

whistle 判断一行是哪种写法，靠的是找第一个只可能是匹配串的段（`indexOfPattern`，`_original/lib/rules/rules.js:1449`）。带 `scheme://` 的段一定不是，**光秃秃的 IP 地址**也一定不是——IP 是 `host://` 的简写。带端口的*域名*不算这种简写：`localhost:8080` 是目标地址，`127.0.0.1:8080` 才是改 host。

### 简写

| 你写的 | 实际含义 |
|-----------|----------------|
| `127.0.0.1:8080` | `host://127.0.0.1:8080` |
| `127.0.0.1` | `host://127.0.0.1` |
| `/abs/path` · `C:\path` | `file:///abs/path` … |
| `(text)` · `{name}` · `<path>` | `file://` 加上对应的括号写法——见下文 |
| 其他任何段 | 目标地址——见下文 |

**这里的路径只指绝对路径**。`FILE_RE`（`_original/lib/rules/rules.js:36`）只认盘符或*单个*开头斜杠，别的都不算：拿 whistle 2.10.8 实测，`a.com ~/mock.json` 会解析成目标地址 `http://~/mock.json/…`，而不是文件。在实测之前，本项目也把 `~/` 和 `./` 当成路径；这个方便同时也悄悄改了含义，因为 `a.com .internal.example` 会变成一个并不存在的本地文件。在算子的*值*里，`~/` 仍然表示用户主目录（`file://~/mock.json`），那是上游的 `convertSlash` → `getHomePath`（`lib/util/file-mgr.js:13-16`），是另一回事。

### 算子的值可以是什么

`protocol://value` 里的 `value` 不一定就是你写的那段文字。一共六种写法，按下面的顺序解析：

| 你写的 | 值实际是 |
|-----------|-------------------|
| `resBody://patched` | 文本 `patched` |
| `resBody://(patched)` | 文本 `patched`——这是明确表示"这**就是**内容"的写法（`getValue`，`_original/lib/rules/rules.js:271-287`），也是写出一段否则会被当成路径的文本的唯一办法 |
| `resBody://{mock}` | 名为 `mock` 的值的全部内容 |
| `resHeaders://x-v=${mock}` | `x-v=` 后面接上那段内容 |
| `resBody:///tmp/mock.json`<br>`resBody://https://cdn.test/mock.json` | **那个文件或那个 URL 的内容**——见下文 |
| ``resHeaders://`x-m=${method}` `` | 按当前请求渲染——见[反引号模板](#反引号模板) |

别忘了一行规则是按空白切段的，所以这些写法里都不能有空格。Values 就是为这个准备的。

#### 从文件或 URL 读取的值

有些算子接受的是一个*位置*，而不是值本身。`readRuleValue`（`_original/lib/util/index.js:1189-1213`）会在算子生效之前先把它读出来，所以算子拿到的是文件内容：

```
example.com   reqHeaders:///etc/whistle/headers.json    # {"x-env":"staging"}
example.com   resBody://https://cdn.test/mock.json      # 每个请求都去取一次
example.com   resBody://~/mock/a.html|~/mock/b.html     # 两个都读，用 CRLF 拼起来
```

**数据值的三种写法，和两条读取路线**。直接写在规则行上的值，和从 `{name}`、文件或 URL 加载来的值，读法不一样——`tryParseMatcher` 排在 `_parseJSON` 前面，而且只看前一种（`_original/lib/util/index.js:1165-1171,:1303`）：

| | 写在规则行上的值 | 加载来的值 |
|---|---|---|
| JSON | 按 JSON 读 | 按 JSON 读 |
| `a=1&b=2` | 按查询字符串读，带空白也照读 | **只有**不含空白时才按查询字符串读 |
| 每行一个 `a: 1` | **什么都不是**——没有 `=`，就没有值 | 按行格式读 |

所以如果 `v` 有两行，`reqHeaders://x-a=${v}` 会把换行留在值里，这个头会被丢掉；而同样的两行放在 `{value}` 里，就成了两个头。同样，`reqHeaders://bare` 什么也不设置，而 `{value}` 里单独一行 `bare` 会设置一个空值的头。这两点都拿 whistle 2.10.8 实测过。

行格式里，分隔符优先取第一个 `": "`，没有就取第一个 `:`，再没有就取第一个 `=`；用成对的 `"`、`'` 或 `` ` `` 包起来的值会去掉引号（反引号包的还会把 `\n` 变成真正的换行）；没加引号的安全整数（safe integer）会变成数字，而不是字符串。只有 `reqMerge`/`resMerge` 会把带点的名字当成对象里的路径（`RESOLVE_KEY_RE`，`util/index.js:95`）。

**哪些算子会这样读**。分两类，因为上游用两个不同的读取函数处理它们：

| 类别 | 算子 | 既不是 `{json}` 也不是 `k=v` 键值对的值 |
|--------|-----------|--------------------------------------------------|
| JSON 类值（`parseRuleJson`，`_original/lib/inspectors/req.js:463-472`，`res.js:830-841`） | `reqHeaders`, `resHeaders`, `reqCookies`, `resCookies`, `reqCors`, `resCors`, `reqReplace`, `resReplace`, `urlReplace`, `params`, `urlParams`, `resMerge`, `trailers`, `auth`, `cipher` | 是一个位置 |
| 文本类值（`getRuleValue`，`req.js:545-548`，`res.js:984`） | `reqBody`, `resBody`, `reqPrepend`, `resPrepend`, `reqAppend`, `resAppend`, `htmlBody`, `htmlPrepend`, `htmlAppend` | 是一个位置 |
| 文本类值，**只认文件** | `jsBody`, `jsPrepend`, `jsAppend`, `cssBody`, `cssPrepend`, `cssAppend` | 路径是位置；URL 不是 |

最后一行是上游自己的划分，不是本项目图省事：`readRuleValue` 的 `checkUrl` 参数恰好只对 `js*`/`css*` 这两族打开（`util/index.js:1339`），所以在 **HTML** 响应上，这里的 URL 还是 URL，会变成 `<script src=…>` / `<link rel=stylesheet>`；而在 JS 或 CSS 响应上，同一个 URL 会被取回来内联进去。whix 在请求阶段就读值，那时还没有响应可以判断类型，所以它保留 HTML 场景下的含义（也就是文档里写的那种），这六个算子从不去取 URL。

**什么算位置**。`http://` 或 `https://` 开头的 URL；或者一个路径，以根目录（`/tmp/x`）、用户主目录（`~/x`，全角的 `～/x` 也算）、Windows 盘符（`C:\x`）开头，或者明确写了 `./` / `../`。

> **`temp/…` 在这里不算位置，在上游算**。whistle 的控制台允许你在规则编辑器里 Cmd+点击一个 `protocol://temp.json`，在弹出的对话框里填好内容并保存——它会把这一行改写成 `protocol://temp/<64 hex>.json`，然后在自己的 `temp_files` 目录下解析这个路径（`TEMP_PATH_RE`，`_original/lib/util/common.js:167`；`getTempFilePath`，`util/index.js:1180-1187`，它会去掉扩展名，扩展名只留着用来猜类型）。本项目既没有这个目录，也没有这个编辑器，所以这个值就是它看上去的那段字面文本，文本类算子会原样写出它：实测 `resBody://temp/blank.json` 在 whistle 里返回源站的页面，在这里返回 `temp/blank.json` 这串文本。这里只记下差异，不做半吊子实现——没有编辑器的话，这个路径是一个没人造得出来的文件名，因为它是个哈希。`auth://temp/…` 不受影响：反正带斜杠就算位置，两个代理也都不会为它发送凭据。

有一个例外，也是上游的行为：`reqCors://` / `resCors://` 上的 URL 表示允许的 **origin**，在读取之前就被折成 `{"origin":…}`（`isCors`，`_original/lib/util/index.js:1344,:1361-1370`）。`resCors://https://app.test` 是一条 CORS 规则，不会去取这个 URL。不过这里写*路径*的话，照样会读。

> **故意比上游窄**。whistle 不看值长什么样：对文本类算子来说，*所有*非内联的值都是路径，光写一个 `resBody://patched` 就是去读 `./patched`——相对于规则文件的根目录（`rule.root`，只有插件或 `@` 引入带进来的规则才有），没有的话就相对于 whistle 自己的工作目录。读会失败，然后算子悄悄设置一个**空** body。whix 没有 `rule.root`，而相对于代理工作目录的路径也不是规则文件能指望的东西，所以光秃秃的值就保持为字面文本，和本文前面说的一样。凡是在上游*能用*的写法，这里照样会加载。
>
> 对 JSON 类算子还多收窄了一点：含 `=` 的值一律按键值对读，绝不当路径，所以 `urlReplace:///api/v1=/api/v2` 不会碰文件系统。上游绕远路得到同样的结果——先按路径读，什么也没读到，再退回去把 matcher 当查询字符串解析（`tryParseMatcher`，`util/index.js:1165-1171,:1303`）。只有文件名里带 `=` 的文件才看得出差别。
>
> **`{name}` 找不到对应的值时，规则不生效**，这适用于 body 类算子——`reqBody`/`reqPrepend`/`reqAppend`、`resBody`/`resPrepend`/`resAppend`，以及 `html*`、`js*`、`css*` 各三个——因为 whistle 也不让它生效：它把 matcher 记在 `rule.key` 下（`getKey`，`rules.js:263-270`），值里这个名字下面什么都没有，`getRuleValue` 就什么也不交给算子。响应保持原样，也不会带上注入时会加的缓存头。有一种花括号包起来的值不算名字：JSON 对象——带 `{`、`:` 和 `}`，并且 json5 能解析——算内容，上游的 `isJson` 兜底就是这么处理的（`getValue`，`rules.js:272-288`），所以 `resBody://{"a":1}` 的 body 就是这段 JSON。
>
> 会话里仍然会列出这个算子，并附一条类型为 `missing-value` 的 `unapplied` 记录，写明是哪个引用，所以拼错了会在控制台里看出来，而不是等到流量里才发现。2026-10-02 之前，本项目会把 `{typo}` 这六个字符当 body 写出去，理由是：要区分引用和花括号包起来的字面文本，需要一套两边都没有的语法；其实上游有，就是先 `getKey` 再 `isJson`，也就是上面这条规则。值*内部*的 `${name}` 是另一回事，这一点上游和本项目一致：查不到就原样显示。

**要注意的细节**：

- `a|b|c` 会**拼接**起来，用 CRLF 连接，不存在的项直接略过（`readFileText`，`_original/lib/util/file-mgr.js:96-102,:157-166`）。这和 `file://` 规则的"第一个存在的胜出"*不一样*，后者只返回存在的那一个。
- 路径会先做百分号解码，`?` 或 `#` 之后的部分会被截掉（`decodePath`，`util/index.js:1403-1418`）。
- 带 `..` 段的路径直接拒绝，和 `joinPath` 的做法一样。
- 读文件走的是和 `file://` 同一个以 mtime 为键的缓存：每个请求仍会 `stat` 一次，所以改了 mock 文件马上生效。
- **URL** 在每个匹配的请求上都会去取一次——上游也不缓存——超时 16 秒（`TIMEOUT`，`_original/lib/util/http-mgr.js:14`），大小上限 256 KB（`MAX_URL_VAL_LEN`，`lib/plugins/index.js:1497`）。状态码不是 200、超时、body 超长，都算失败。不想每个请求都往外发一次请求，就把内容放进文件。
- 对 `reqBody`、`resBody`、`reqPrepend`、`resPrepend`、`reqAppend` 和 `resAppend`，内容是文件的原始**字节**，原样发出——GBK 编码的页面或者图片都没问题，被 `a|b` 拆在两个文件里的一个字符也能拼回来——绝不会按响应的 `charset=` 重新编码。这就是上游的 `binProtocols`（`lib/rules/protocols.js:121-128`）。其他算子都把内容当 UTF-8 文本读。
- `(inline)` 和整个值就是一个 `{name}` 的写法，本身已经是内容，不会再去读（`if (rule.value)`，`util/index.js:1177-1179`）。

**读取失败时**，两类算子就分道扬镳了，两边的表现都来自上游：

- **JSON 类**算子保留写的原值，因为上游的 `tryParseMatcher` 兜底会在读到空内容后把 matcher 当查询字符串解析——所以一条压根没打算用这个功能的规则，不会被它弄坏。同时会打一行 `warn` 日志。
- **文本类**算子的值变成**空**。这里故意不退回原文：那段原文是路径，路径绝不能作为请求 body 发到源站。

#### 反引号模板

算子的值如果**整个**用反引号包起来，就是一个模板，会先按当前请求渲染，然后才交给其他环节处理（`renderTpl`，`_original/lib/rules/rules.js:762-772`）：

```
example.com   reqHeaders://`x-method=${method}&x-when=${now}`
example.com   resHeaders://`x-status=${statusCode}`
example.com   redirect://`https://b.com${path}`
```

能用的变量和 `tpl://` 文件用的是同一份封闭白名单——同一份实现，所以规则里的值和模板文件对 `${query.id}` 的理解永远一致。变量表、`.key` 子路径、`${{var}}` 的 URI 编码和 `.replace(a,b)` 修饰符，见 [`TEMPLATES.md`](TEMPLATES.md)。

和 `tpl://` 文件有两点不同，都是上游的行为：

- **只**跑 `${var}` 这一遍替换。没有 `{name}` 查询串插值，也没有"文本里必须含 `{…}`"这道门槛——那些属于文件处理器（`file-proxy.js:15,360`），不属于 `resolveTplVar`。
- 整个值都得用反引号包起来。``reqHeaders://x=`${method}` `` 不是模板，那两个反引号就是两个普通字符。

**反引号前面可以带 scheme**，因为 `TPL_RE` 是 `/^((?:[\w.-]+:)?\/\/)?(`.*`)$/`（`rules.js:72`）——前缀原地不动，只渲染后面的主体。这只在**目标地址**上看得出来，因为目标地址的 scheme 是值的一部分，下面两种写法意思相同：

```
www.example.com   `http://${method}.dev`
www.example.com   http://`${method}.dev`      # 同一条规则
```

**先渲染，再拼路径**。请求剩下的路径拼在模板渲染*出来*的结果后面，而不是拼在模板上（`resolveVar` 在解析过程中运行，`getPathRule` 在它之后拼接，`rules.js:936-948,:1010`），所以 ``example.com file://`/srv/${method}.json` `` 遇到 `/x` 时读的是 `/srv/GET.json/x`。括号写法也是在渲染之后才识别：``resBody://`({"m":"${method}"})` `` 会 mock 出 `{"m":"GET"}`——去掉括号，当内容，也不拼路径。

**容易忽略的一点**。如果值本来*就是*反引号模板，那么里面的 `${name}` 从 [Values](#开关引入与-values) 取回来的内容也会被渲染（`rule.isTpl && key ? resolveTplVar(key, req) : key`，`rules.js:779`）：

```
# values: greeting = x-hello=${method}
example.com   reqHeaders://`${greeting}`     # → x-hello=GET
example.com   reqHeaders://${greeting}       # → x-hello=${method}, sent literally
```

存起来的值只有这一种办法能拿到请求信息：它只写一次，被每条引用它的规则复用，所以要靠*规则*行上的反引号来表明"把展开后的内容也渲染一遍"。

**整值**写法（整个值就是一个 `{name}`）也能套反引号，而且这是匹配串的捕获组唯一能传进存储值的地方——只是写法不一样（`SUB_VAR_RE`，`rules.js:99,:826-830`）：

```
# values: mock = {"m":"${method}","id":"${RegExp.$1}"}
/example\.com\/api\/(\d+)/   resBody://`{mock}`   # 两个都会替换
/example\.com\/api\/(\d+)/   resBody://{mock}     # 都不替换：内容就是原始字节
```

在那里只有 `${RegExp.$1}`…`${RegExp.$9}` 和 `${RegExp.$&}`（整个请求 URL）这几种捕获写法有效。值里直接写 `$1` 会原样保留——`$1` 是在规则行上替换的，而规则行上写的是 `{mock}`，这六个字符里没有 `$`。在 **`${name}`** 引用里则反过来：先展开值，再替换捕获组（先 `resolveVar` 再 `replaceSubMatcher`，`rules.js:1010-1012`），所以那里直接写的 `$1` 确实会被替换掉。

上游的 `log://` 和 `weinre://` 在解析时就退出了模板机制（`rule.isTpl = false`，`rules.js:1357-1359`）——它们的值是一个通道名，里面的反引号就是普通反引号。

**响应阶段**的算子（`resHeaders://`、`resBody://`、`trailers://`……）上的反引号值，渲染时已经拿到了响应的状态行和头，所以 `${statusCode}`、`${resHeaders.x}`、`${resCookies.x}`、`${serverIp}` 和 `${serverPort}` 在这里都有值。在 `tpl://` 文件里它们仍然是空的，因为模板在任何源站回复之前就短路了。

#### 在规则文本里声明的值

用 ```` ``` ```` 围起来的一段，可以在用它的规则旁边声明一个值（`resolveInlineValues`，`_original/lib/util/index.js:211-224`），规则文件就是这样自带 mock 数据的：

````
``` mock.json
{"ok": true}
```
example.com/api   file://{mock.json}
````

名字必须是一段不含空白的文本；结束围栏必须是同样数量的反引号，所以块里含有更短的围栏也不会被截断；同一个名字声明两次，保留**第一个**块；没有闭合的围栏什么也不声明。

取回来的是**内容，不是规则**：里面的东西不会再被扫描一遍，所以 mock body 里的 `${…}`、`{…}` 或围栏，就是这个 mock 本来要包含的文本。

**块属于声明它的那个规则组**。别的组里的 `{v}` 不会用到它，别的组里同名的块也遮不住它——名字以 `key + '\n\r' + <group>` 的形式存放，也按这个形式查找，这是上游的 `getInlineKey` / `getValueFor`（`util/index.js:205-209`，`rules.js:785-796`）。请求过程中**生成**的规则会解析成一套单独的规则集，而写下这个引用的文件里的块在另一套里——所以 `reqRules://` 上面三行的块，够不着这一行生成的规则。`rulesFile://`/`reqScript://` 这一族生成的文本，或者 `resRules://`/`resScript://` 生成的文本，除了 [Values](#开关引入与-values) 之外，*能*读到的是它自己的这些：

- 生成的文本自己里面的 ``` 块；
- 生成它的脚本设置在 `values` 上的内容（值是对象的话取它的 JSON）——文本自己的块优先于这些。

````
```mock.js
values.body = 'from the script';
rules.push('example.com resBody://{body}');
```
example.com reqScript://{mock.js}
````

这是上游的 `resolveRulesFile`：它用脚本的 `values` 构造生成的规则集，再让 `Rules#parse` 把文本里的块盖在上面（`rules/index.js:520-529`，`rules.js:2033-2059`）——两个代理都实测过。`rule://` 的文本和插件的规则只读 Values。引入行上的*名字*在它被写下的地方解析，所以 `rule://more` 旁边有个用 ```` ```more ```` 围起来的块的话，照样能找到。

**块优先于 Values 里的同名项**，上游也是这样——`getValueFor` 先查内联的表，查不到再查 Values。在控制台里设置的值就属于 Values。唯一能压过块的是命令行上的 `--value`：它是针对这次运行的指令，所以 `whix -r team.rules --value mock=local` 返回的是 `local`，哪怕 `team.rules` 自己声明了 ```` ```mock ````。（2026-09 之前是 Values 压过所有块；这是上游自己的测试集发现的——`test/units/keys.test.js`。）

### 目标地址

| 算子 | 值 | 效果 |
|----------|-------|--------|
| *（直接写 URL）* | `[scheme://]host[:port][/path]` | **把请求转发**到那个 URL：socket 连接、`Host` 头、路径和 scheme 全都跟着变 |
| `host` | `ip` / `ip:port` / `host:port` / `:port` | 改写请求实际连接的目标地址。**Host 头和 TLS SNI 仍是原来的主机名**，只有 socket 连接的目标变了。`:port` 保留主机，只换端口。 |
| `xhost` | 同 `host` | **直通**（pass-through）写法：地址能连上就用，连不上就*忽略*它；而 `host://` 连不上时请求直接失败。 |

```
api.example.com   host://127.0.0.1:9000
.example.com      host://:8443            # 主机不变，强制用 8443 端口
api.example.com   xhost://127.0.0.1:9000  # ……除非那里没有服务在监听
```

#### 转发到另一个 URL

直接写一个 URL 是 whistle 最常用的规则：它把请求的 URL 整个换掉。scheme 可以省略，省略时沿用请求本身的 scheme：

```
www.example.com        http://localhost:5173     # 整个站点交给开发服务器
www.example.com/api    https://staging/v2        # ……API 再转到别处
www.example.com        //localhost:5173          # 请求是 https 就还用 https
www.example.com        localhost:5173            # 同上，写得更短
```

和 `host://` 的区别值得专门说一次：两者都是"把请求指到别处"，但只有一种是源站看得出来的：

| | socket | `Host:` 头 | 路径 | scheme |
|---|---|---|---|---|
| `host://1.2.3.4` | 变 | **不变** | 不变 | 不变 |
| `http://localhost:5173` | 变 | **变** | 重写 | 变 |

**剩下的路径会跟过去**。匹配串没吃掉的部分，会拼到目标地址后面——也就是把一个目录映射到一个 URL 前缀时用的那套"自动拼接路径"：

| 规则 | 请求 | 转发到 |
|------|---------|--------------|
| `example.com http://localhost:5173` | `/a/b?q=1` | `http://localhost:5173/a/b?q=1` |
| `example.com/api http://dev/v2` | `/api/users?x=2` | `http://dev/v2/users?x=2` |
| `example.com file:///srv/static` | `/js/app.js?v=2` | `/srv/static/js/app.js` |
| `example.com file:///srv/mock.json` | `/` | `/srv/mock.json`——**什么都不**拼 |

最后一行请求的是根路径，这种情况有自己的规矩：**域名**匹配串存储时带着结尾斜杠（`formatUrl`，`_original/lib/util/common.js:526-536`），所以请求 `/` 时完全没有剩余路径。这对指向*文件*的值很重要——`/srv/mock.json/` 是一个不存在的目录——这也是为什么 `example.com file:///srv/static` 在两个代理上对 `/` 都回 **404**：`index.html` 这个候选来自你写的值末尾的斜杠（`getRuleFiles`，`lib/util/index.js:1443-1450`），所以想返回 index，就写 `file:///srv/static/`。带路径的匹配串存储时不带斜杠，所以 `example.com/api file:///srv/d` 遇到 `/api/` 时确实会拼上 `/`。

用 `< >` 把值包起来可以关掉路径拼接，用 `( )` 包起来则表示这个值*是内容*，而不是位置：

```
example.com/api  http://<dev.internal/fixed>       # 永远就是这个 URL，一个字不改
example.com/api  file://({"status":"ok"})          # 一行写完的 mock
```

文件规则可以用 `|` 列出多个候选，每个候选都会拼上路径：

```
static.example.com   file:///srv/a|/srv/b        # 第一个存在的胜出
```

只有 **file** 这一族是列表。`getFiles` 只为 `rule.files` 拆分 matcher，别的都不拆（`rules.js:290,:943-948`），所以目标地址里的 `|` 就是普通字符——`example.com http://dev/api?f=a|b` 会把写好的过滤参数原样转发，要是拆开了，源站只会收到一半。

> `rule://<name>` **不是**目标地址：它是本项目自己的写法，用来把 Values 里的一项当作更多规则引进来。上游把它归在同一个位置，结果只能得到一个没法用的 URL `rule://<name>`。

> **`location://` 不是协议**。上游的协议注册表和别名表里都没有它，所以这一段是一个*目标地址*，而它的 scheme 没有谁能处理，两个代理都回 **502**。本项目以前把它当作 `redirect://` 的同义词，回 `302`——这个名字是本项目自己编的，而且一直没有任何用例检查过它，直到 `coverage-ops.js` 专门去找那些没有任何用例能证明其行为的算子。要 302 就写 `redirect://`，要页面自己跳转就写 `locationHref://`。

**目标地址只能是 `http` 或 `https`**。普通请求被指到其他任何 scheme，都会回 **502 `unsupported protocol <scheme>:`**，而不是真的发过去——`ws://`、`wss://` 和 `tunnel://` 的文档里就是这么写的（"普通 HTTP/HTTPS 请求：返回 502"），whistle 在同一个函数的同一行里，对其他所有写法也是这么处理的：`isWebProtocol` 就是 `protocol == 'http:' || protocol == 'https:'`，其余一律 `next(new Error('Unsupported protocol …'))`（`_original/lib/rules/protocols.js:269-271`，`lib/handlers/http-proxy.js:5-11`）。

这条规定真正起作用的时候，往往是写错了字：

```
example.com   socks5://127.0.0.1:1080     # 回 502——正确的算子是 socks://
```

`socks://` 是一种[上级代理](#上级代理)；`socks5://` 根本不是算子，所以这一行落到了目标地址这个位置。真要转发的话，就会对一个说 SOCKS 协议的端口发起**明文 HTTP** 连接。不写 scheme 的目标地址不受影响：它沿用请求自己的 scheme，必然是这两种之一。

*对 **WebSocket** 请求和 **`CONNECT`** 隧道来说，目标地址走各自的流程确定，`ws://`/`wss://`/`tunnel://` 正是为它们准备的；上面说的只适用于普通 HTTP 请求。*

#### 路由类规则用哪个 URL 来匹配

一旦直接写 URL 的规则把请求挪走了，`host://`、[代理这一族](#上级代理)和 `pac://` 就拿**挪过去之后的 URL** 来匹配，而不是客户端原本请求的那个。其他规则都不这样：请求头算子、body 算子、`cipher://`、各种开关（flag），以及守在它们前面的筛选器，都还按客户端自己的 URL 的匹配结果来。

```
a.example.com/    http://b.internal:9311/echo
b.internal        proxy://10.0.0.1:8888        # 生效：它匹配的是目标地址
a.example.com     proxy://10.0.0.2:8888        # 不生效：现在没有 URL 会匹配到它
```

这是上游的第二轮解析——`getProxy` 拿到请求改写后的 URL，用它重新解析这三类规则（`_original/lib/rules/index.js:125-152`，`lib/inspectors/res.js:196,:207-210`）。第二轮的结果会*替换*第一轮，哪怕结果是"没有"：只有原始 URL 能匹配的 `host://` 会被丢掉，不会保留。行里的筛选器和 `$1` 这类捕获组也会按目标地址重新取，因为它们本来就是匹配时产生的。

关于这一轮，有两处细节本项目与上游不同，都在 `tests/differential/cases-proxy.js` 里实测过：

* 用的 URL 是**替换规则**写出来的那个，在 `urlReplace://`、`params://` 或 `delete://` 改写路径之前——上游用的是改写之后的；
* `enable://proxyHost`、`enable://proxyFirst` 和 `enable://proxyTunnel` 只从第一轮读取。上游恰恰对这三个取两轮的并集（`isProxyEnable`，`lib/rules/index.js:87,:154,:229`）。

`xhost://` 只重试**一次**，连的是请求原本要去的主机和端口，而且只在连接*建立*不起来时才重试——请求一旦写进了 socket 就没法重放，`x` 开头的[代理写法](#上级代理)也有同样的保护（`retryXHost`，`_original/lib/inspectors/res.js:571-600`）。带任何代理规则的请求都不会走到这一步：whistle 先检查代理规则，host 规则放在它的 `else if` 里，所以失败的那个连接是连代理的。上游在查 DNS 之前，还会把那个连不上的地址再试一次（`if (retryXHost > 1)`，本意肯定是 `>= 1`）；本项目跳过了这次白费的尝试。

### 上级代理

让转发出去的请求再经过另一个代理。地址写成 `[user[:pass]@]host[:port]`；端口默认 80（http）、443（https）或 1080（socks）；IPv6 字面量可以加方括号（`[::1]:8888`），也可以不加。地址到这里就结束了：写在它后面的路径或查询串（`proxy://10.0.0.1:8888/x`）不算地址的一部分，而查询串正是 whistle 放它自己那些开关的地方——见下文的 `?proxyHost` 和 `?host=`。

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `proxy` / `http-proxy` | `[user[:pass]@]host[:port]` | 经 HTTP 代理转发 |
| `https-proxy` | `[user[:pass]@]host[:port]` | 同上，但*到代理*的那条连接走 TLS |
| `socks` | `[user[:pass]@]host[:port]` | 经 SOCKS5 代理转发 |
| `http2https-proxy` | `[user[:pass]@]host[:port]` | 经 HTTP 代理，而且就算请求是 `http://`，连**源站**也走 TLS |
| `https2http-proxy` / `internal-proxy` / `internal-http-proxy` | `[user[:pass]@]host[:port]` | 经 HTTP 代理转给另一个 whistle：`https://` 源站的 TLS 在这一跳被**剥掉** |
| `internal-https-proxy` | `[user[:pass]@]host[:port]` | 同上，只是到代理的连接走 TLS |

上面每个算子还有一种加 `x` 前缀的写法——`xproxy://`、`xsocks://`、`xhttp-proxy://`、`xhttps-proxy://`、`xinternal-proxy://`——意思不变，但这一跳建不起来时会**退回直连**。见下文“如果上级代理连不上”。

```
example.com        proxy://127.0.0.1:8888
.internal.corp     http-proxy://user:pass@10.0.0.1:3128
secure.example.com socks://127.0.0.1:1080
flaky.example.com  xproxy://127.0.0.1:8888     # 走代理；代理挂了就直连
```

**会改协议的代理。** 有两类代理会改变*源站*那条连接用的协议，它们的名字说的就是这件事：

- `http2https-proxy://` 即使请求是 `http://`，也用 TLS 连源站（`options.protocol = 'https:'`，`_original/lib/inspectors/res.js:236-237`）；
- `https2http-proxy://` 和 `internal-*` 这一族交给下一跳的是**明文**请求——它们本来就是为了串到另一个 whistle 上，好让那边能检查请求——同时把原来的协议放进 `x-whistle-https-request` 头，让那个 whistle 恢复回来（`res.js:229-234`、`lib/init.js:190-193`）。whix 当发送方时会设置这个头，当接收方时会认这个头（并把它删掉），所以两个 whix 实例能像 whistle 那样串起来。要是把它指向一个不归你管的代理，请求就是明文传过去的。

`lineProps://internalProxy` 能让一条普通的 `proxy://` 行按上面第二种来处理，而不用改它的写法。它可以写在代理那一行、`host://` 那一行，也可以写成 `enable://internalProxy` 对整个请求生效（`isInternalProxy`，`_original/lib/util/index.js:3801-3807`）。

**这一跳怎么建。** 只有“普通 HTTP 代理去取普通 HTTP 源站”这一种情况，才用 absolute-form（请求行里写完整 URL，`GET http://host/path`）发请求；TLS 源站、SOCKS 代理、HTTPS 代理，以及跟代理一起带了地址覆盖的情况（一条 `host://` 规则，或代理 URL 自己的 `?host=`），都改为打开一条 `CONNECT` 隧道。absolute-form URI 里的主机名取自请求的 `Host` 头，所以 `reqHeaders://` 改过的 `Host` 会生效，而 `host://` 的覆盖地址永远不会交给上级代理。

**这一跳上带了什么。** `CONNECT` 带上 `Host`、`Proxy-Connection: keep-alive`、客户端的 `User-Agent`，以及 `Proxy-Authorization`——代理 URL 里写了凭据就用它，没写就用客户端自己的 `Proxy-Authorization`。没有密码的凭据（`proxy://user@host`）原样做 base64，和 whistle 一致：发的是 `Basic base64("user")`，不是 `Basic base64("user:")`。SOCKS5 则在第一个冒号处拆开同一份凭据，密码发空；只要写了凭据，它就只提供用户名/密码这*一种*认证方式——绝不和“无需认证”一起提供，免得一个也接受匿名连接的代理悄悄把凭据丢掉。主机名不在本地解析，原样交给代理（SOCKS5 地址类型 3），由代理去查 DNS。

**如果上级代理连不上**，或者它拒绝了 `CONNECT`，请求以 502 失败——不带前缀的写法永远不会改成直连重试。要退回直连，得用带 `x` 前缀的写法（`X_RE`，`_original/lib/inspectors/res.js:31,:546-560`）：`xproxy://127.0.0.1:8888` 能走代理就走代理，走不了就直连源站。这个重试只管**没建起来**的那一跳——连代理被拒、`CONNECT` 被拒、SOCKS 握手失败。请求一旦写进 socket 就没法重放，所以代理接下隧道之后才出错的，会直接报错，不会重试；whistle 给自己的重试也是这样把关的（`piped`，`res.js:529`）。

代理算子的值为空或不可用时（`proxy://`、`socks://@`），会报 `proxy:// is not a usable proxy address` 失败，而不是悄悄变成直连。whistle 也会拒绝，只是说得没那么清楚：匹配值仍然是真值，于是地址变成 `http://`，请求最后在解析器里以 `DNS Lookup Failed` 告终。（本页早先的版本说 whistle 在这里会直连。并不会——对 2.10.8 实测了 `proxy://`、`socks://`、`http-proxy://@` 和 `proxy://?proxyHost` 四种，全都返回 502。）**PAC** 文件取不到或者执行时抛错，才是 whistle 真的退回直连的情况——它的失败只进了 `logger.error`（`_original/lib/rules/index.js:295`）。本项目在这里也拒绝，理由相同：一条点名了代理的规则，已经排除了直连。

**去掉代理。** `ignore://proxy` 指的是整个代理家族，所以匹配上的是哪个代理算子，它就去掉哪个——`socks://`、`https-proxy://`、`http2https-proxy://` 等等都算，不只是字面上的 `proxy://`。这是 whistle 的行为，它把这些写法都放在同一个协议键下（`resolveProxy`，`_original/lib/rules/rules.js:2419-2443`）。只点名一种写法（`ignore://socks`），就只去掉那一种。代理算子匹配上了、又被 ignore 掉时，同一个请求上的 `pac://` 规则**不会**拿来兜底（`_original/lib/rules/index.js:238`）；要单独去掉 PAC 规则，用 `ignore://pac`。

```
example.com   socks://127.0.0.1:1080
example.com   ignore://proxy          # → direct, despite the socks rule
```

**代理指向自己。** `proxy://127.0.0.1:8899`——本机上本代理自己的端口，`--socks-port` 也算——会把请求送回 whix，whix 又匹配到同一条规则、再送一遍，直到进程把 socket 用光。这样的一跳会被拒绝：请求得到一个指向 whix 自己端口的 302（这是 whistle 在 HTTP 路径上的做法，`_original/lib/inspectors/res.js:302-316`），日志里会有一条 `self loop via <address>` 警告。不经代理、直接连到我们自己端口上的源站，则不拦：这不会递归，因为我们发出去的请求不是代理请求。

**和 `host://` 一起用。** 默认情况下，匹配上的 `host://` 直接胜出，代理被丢掉。`proxyHost`（写成 `lineProps://proxyHost`、`enable://proxyHost`，或者直接写进代理自己的 URL，如 `http-proxy://…?proxyHost`）两个都保留：请求经代理到达源站，并让代理去连 `host://` 给的地址。`proxyFirst` 优先用代理——而且它和 `proxyHost` 不同，它是在两条规则之间定输赢，而不是把两者合起来，所以 `host://` 的地址**完全不用**：请求以 absolute-form 发给代理，里面写的是它原本要访问的源站。`proxyHostOnly` 的行为和 `proxyHost` 一样，但没有 `host://` 匹配上时，还会把代理也丢掉。

```
pinned.test        http-proxy://127.0.0.1:8888?proxyHost
pinned.test        host://10.0.0.9
```

代理 URL 自己也能带同样的覆盖，写成 `?host=<host[:port]>`（`P_HOST_RE`，`_original/lib/rules/index.js:81,:243`）——不用另写一行 `host://`，也不需要 `proxyHost`，因为这个查询串已经明说了要用代理。匹配上的 `host://` 规则优先于它。端口可以省略，省略时沿用请求自己的端口。

```
pinned.test        http-proxy://127.0.0.1:8888?host=10.0.0.9
```

不管哪种写法，这一跳都会改用 `CONNECT`，那个地址就是让代理去连的目标——隧道里的请求仍然带着原来的 `Host`。

**`proxyTunnel`。** 有覆盖地址时，`lineProps://proxyTunnel`（或 `enable://proxyTunnel`，或写在 `host://` 那一行上的同名属性）表示被覆盖成的那个地址*本身*就是一个代理：whix 经第一个代理 `CONNECT` 到它，再在这条隧道**里面**发第二个 `CONNECT`，点名真正的源站，并标上 `x-whistle-policy: intercept`，让远端的 whistle 拦截，而不是闷头转发（`_original/lib/tunnel.js:535-537`、`lib/util/patch.js:120-140`）。两样缺一不可：没有覆盖地址，就没有可穿过的隧道，这个开关什么也不做。只对 HTTP 和 HTTPS 代理有效——SOCKS 这一跳会忽略它，上游也一样。

```
# 先经 127.0.0.1:8888，再到 10.0.0.9:8899，从那里出去访问源站
chained.test       proxy://127.0.0.1:8888?host=10.0.0.9:8899 lineProps://proxyTunnel
```

两个 `CONNECT` 带的是同一个 `Proxy-Authorization`，所以**第二个**代理看到的是写给第一个代理的凭据。如果代理 URL 本身没带凭据，那就是*客户端*自己的 `Proxy-Authorization`——客户端本来是给 whix 的凭据，被多带出去了一跳，而客户端看不到这一跳。这和 whistle 一致（`lib/util/patch.js:120-140`）：涉及的每个地址都是规则点名的，而扣下凭据会让需要认证的第二跳悄无声息地连不上。把一条代理链指向你管不了的代理，漏出去的就是这个。

**有多个代理算子同时匹配时**，写在**最前面**的胜出，不管它是哪种写法。whistle 把所有写法都归到同一个 `proxy` 键下（`PROXY_RE` → `protocol = 'proxy'`，`_original/lib/rules/rules.js:1286`），所以 `socks://` 和 `proxy://` 是当作同一个算子来竞争的，由规则顺序决定——和其他地方一样，带 `important` 的行排在前面。只有一个代理算子都没匹配上时，才会去看 `pac://`。

```
example.com        proxy://127.0.0.1:8888     # 用的是这条
example.com        socks://127.0.0.1:1080     # ……不是这条
```

#### PAC

`pac://<location>` 执行 PAC 文件里的 `FindProxyForURL(url, host)` 来挑代理。结果按 PAC 列表本来的意思从左往右读：第一个 `PROXY`/`HTTP host:port`、`HTTPS host:port` 或 `SOCKS`/`SOCKS5 host:port` 条目胜出。在这些条目**之前**出现的 `DIRECT` 就是答案——不经代理，直连。出现在选中的代理**之后**的 `DIRECT` 是那个代理的兜底，所以 `PROXY 10.0.0.1:8080; DIRECT` 在代理连得上时走代理，连不上时直连，和 `xproxy://` 完全一样。

上游只用一个正则来读同样的结果：`/(PROXY|SOCKS)\s+([^;\s]+)/i`（`node-pac/lib/Pac.js:7`）。这带来两个后果，whix 都不照搬：`SOCKS5 host:port` 在那边什么也匹配不上，请求直连；而且就算 `DIRECT` 在列表里排在前面，`PROXY` 条目也会胜出。这里尊重顺序，也认 `SOCKS5`。

location 可以是本地文件、`http(s)://` URL，或者（仅 whix 支持）直接把脚本本身内联写进去——实际上这意味着脚本里不能有任何空白，因为规则里的一个 token 到第一个空格就结束了。

```
.corp.example.com   pac:///etc/whistle/corp.pac
.corp.example.com   pac://http://wpad.corp.example.com/proxy.pac
```

远程 PAC 文件取一次后缓存 5 分钟，最多同时缓存十个文件（whistle 缓存十个，而且从不重新读取，`cachedPacs`，`_original/lib/rules/index.js:264-274`）。刷新失败时，继续用缓存里那份。

PAC 文件能调用的辅助函数都有：`isPlainHostName`、`dnsDomainIs`、`localHostOrDomainIs`、`isResolvable`、`isInNet`、`dnsResolve`、`myIpAddress`、`dnsDomainLevels`、`shExpMatch`、`weekdayRange`、`dateRange`、`timeRange`、`convert_addr`、`alert`，以及微软的 `isResolvableEx`、`isInNetEx`、`dnsResolveEx`、`myIpAddressEx`、`sortIpAddressList`、`getClientVersion`。脚本自己定义了同名函数的，会覆盖我们的。名字解析只支持 IPv4，所以 `*Ex` 这几个辅助函数用的是同一份数据，不假装知道得更多。

**PAC 文件出错不等于 `DIRECT`。** 如果脚本取不到或读不了、解析失败、没有定义 `FindProxyForURL`、抛异常，或者返回的东西里没有可用条目（比如一个 `SOCKS4` 代理——本项目只支持 SOCKS5），请求会**以 502 失败**，并写明原因。whistle 会记下错误，然后直连（`_original/lib/rules/index.js:295`）；可一条把流量钉在公司代理上的规则悄悄不钉了，如果说有什么结果必须拒绝，就是这个。只有显式写出的 `DIRECT` 才是直连。

还没做的：PAC URL 上的 `user@` 前缀不会被当作代理凭据（上游的 `_pacAuth`），也不支持 `SOCKS4`。

### URL 改写

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `urlReplace` | `from=to`（或 `/regex/[i]=to`） | 在请求的路径+查询串里做替换（多条叠加） |
| `params` | `k=v&k2=v2` 或 `{json}` | 添加/覆盖参数——请求带着 whistle 认得的 body 时，加在**请求 body** 里，否则加在查询串里（多条叠加） |
| `urlParams` | `k=v&k2=v2` 或 `{json}` | 添加/覆盖**查询串**参数，无论什么情况（多条叠加） |

```
example.com/api    urlReplace://v1=v2                 # /api/v1/x -> /api/v2/x
example.com/api    urlReplace:///users\/\d+/=/users/me # 正则写法
example.com        params://debug=1&trace=on
```

> 注意 `/regex/` 这个约定：路径本来就以 `/` 开头，所以写字面量时两边不要加斜杠（`urlReplace://old=new`），`/…/` 留给正则用。

#### `params://` 落在哪里

`params` 只往**一个**地方加，绝不会两处都加——上游的 `_params = hasBody ? null : params`（`handleParams`，`_original/lib/inspectors/req.js:157-232,421`）。加在哪，由请求*转发出去时*的方法和 `Content-Type` 决定（也就是经过 `method://`、`reqType://` 和 `reqHeaders://` 之后的）：

| 请求 | 参数加到哪 |
|---|---|
| `Content-Type: multipart/…` **且带 `boundary=`** | body：`name=` 对得上的 part 整个替换，其余的作为新 part 追加 |
| `Content-Type: application/x-www-form-urlencoded`，**仅限 POST** | body，按查询串格式 |
| JSON 类内容类型，且方法允许带 body（不是 `GET`/`HEAD`/`OPTIONS`/`CONNECT`） | body，**深度**合并进它第一段看着像 JSON 的内容 |
| 其他情况 | 查询串 |

表单 body 只认 POST，这是上游 `isUrlEncoded` 的规则（`_original/lib/util/common.js:692-695`）；同样的规则用在 `PUT` 上，两边的实现都会把参数加到查询串里。

`delete://reqBody.<path>` 走的是同一套变换，所以它也只对上面这三种 body 起作用：从 JSON body 里按点分路径删字段，从表单 body 里删一个名字，或者删掉一个 multipart part。

body 为空时，参数直接成为整个 body——JSON 是 `{"a":"1"}`，表单是 `a=1`。`params://{"a":{"b":1}}` 进 JSON body 时保留嵌套结构；遇到表单 body 则会被序列化（whistle 在那里写的是 `a[b]=1`）。

在 **multipart** body 里，一个对象就是一个**文件** part——上游的 `toMultipart`（`lib/inspectors/req.js:61-95`）：

```
upload.example.com  params://{"avatar":{"filename":"a.png","base64":"iVBORw0…"},"note":{"value":"hi"}}
```

文件名取 `filename`（或 `name`），都没有就用字段自己的名字；内容取 `content` 或 `value`（这里给的如果是对象，会以带缩进的 JSON 发出），或者 `base64` 解码出来的字节；`Content-Type` 取 `type`（像 `png` 这样的裸扩展名会去查表），或者按文件名推断，两者都给不出时用 `application/octet-stream`。

```
api.example.com   params://uid=42            # POST 的表单/JSON body 里多出 uid
api.example.com   urlParams://trace=1        # ?trace=1，不管 body 是什么
api.example.com   delete://reqBody.password  # 从 body 里删掉
```

### 筛选条件

`includeFilter` 给规则加一个条件，请求满足它，规则才生效；`excludeFilter` 则在条件成立时跳过这条规则。上游讲这套语法的文档是 `_original/docs/docs/rules/filters.md`。

```
example.com   host://10.0.0.1   includeFilter://reqH.x-canary:1
```

> ⚠️ **只有 `includeFilter://` 这一种写法是“包含”。** `filter://` 和 `ignore://<condition>` 都是**排除**筛选器——whistle 用 `isInclude = matcher[1] === 'n'` 来判断（`_original/lib/rules/rules.js:1563`），只有 i**n**cludeFilter 满足这一条。whix 曾经把 `filter://` 当成包含，直到这处被修正，所以用了它的规则文件做的事和它想要的*正好相反*。如果你有照旧行为写的 `filter://` 规则，它们现在是排除；请改写成 `includeFilter://`。

**多个筛选器怎么组合**（whistle 的 `matchExcludeFilters`，`_original/lib/rules/rules.js:1967`）：

- 包含筛选器之间是**或**——有一个成立就够；
- 只要有一个**排除**筛选器成立，这条规则就被否决，不管包含筛选器怎么判；
- 只有排除筛选器的规则，除非其中某个成立，否则都生效。

#### 条件

条件写成 `<name><sep><value>`。在任何筛选器算子后面，`<sep>` 都可以是 `:`；`.` 和 `=` 只能用在 `includeFilter`/`excludeFilter` 后面，这对应上游 `PROPS_FILTER_RE` 和 `PURE_FILTER_RE` 的分工（`_original/lib/rules/rules.js:57-60`）。**任何**条件的值都可以写成 `/regexp/[i]`，代替字面量。

| 条件 | 写法 | 匹配什么 |
|---|---|---|
| 请求头 | `reqH.<key>:<v>` ← 标准写法；也可以写 `reqH.<key>=<v>`、`req.`/`reqHeader.`/`reqHeaders.`、`reqH:<key>=<v>` | 头的值**包含** `<v>`，不区分大小写。不写 `<v>` 就是判断有没有这个头 |
| 任一头 | `h:<key>=<v>`、`header:<key>=<v>` | 看**请求**头；请求里没有这个键时，退而看**响应**头——见[响应阶段](#响应阶段) |
| 响应头 | `resH.<key>:<v>`；也可以写 `res.`/`resHeader.`/`resHeaders.` | 那个响应头，按包含匹配（响应阶段） |
| 状态码 | `s:<v>`、`statusCode:<v>` | 响应状态码（响应阶段） |
| 方法 | `m:<v>`、`method:<v>` | 请求方法（正则一律不区分大小写） |
| 客户端 IP | `clientIp:<v>`、`clientIP:`、`remoteAddress:<v>` | 客户端的 IP |
| 客户端或服务端 IP | `i:<v>`、`ip:<v>` | 客户端的 IP——见下面的说明 |
| 客户端端口 | `clientPort:<v>`、`remotePort:<v>` | 客户端 socket 的端口 |
| 服务端地址 | `serverIp:<v>`、`serverIP:` | 请求实际发往的地址——用了上级代理时就是代理的地址（响应阶段） |
| 服务端端口 | `serverPort:<v>` | 请求发往的端口（响应阶段） |
| 主机 | `host:<v>`、`host=<v>` | 请求的主机——这是一处[偏离](#筛选条件与上游的不同之处) |
| 请求 body | `b:<v>`、`body:<v>` | 请求 body **包含** `<v>`——见[body 条件](#body-条件) |
| 环境变量 | `env:<KEY>=<v>` | whistle 自身进程的环境变量 `<KEY>` 包含 `<v>`。键名**区分**大小写，且只能用 `=` 分隔 |
| 来源 | `from:<marker>`、`from=<marker>` | 请求从哪来——见[来源标记](#来源标记) |
| 抽样 | `chance:<p>`、`chance:<n>%`、`probability:` | 随机抽一部分请求（`Math.random() < p`） |
| URL | 其他任何写法 | 完整的请求 URL，用的是和规则自己的[匹配串](#匹配串)同一套匹配引擎——正则、通配符或前缀 |

> ⚠️ **行为变化：** 头的值按**包含**来匹配，和上游的 `filterHeader`（`rules.js:1922`）一样——`reqH.content-type:json` 能匹配 `application/json`。本项目原有的 `h:<key>=<value>` 写法过去要求值**完全相等**；现在也改成按包含匹配，所以它能匹配上的请求只多不少。原来依赖精确匹配的地方，请改写成 `reqH.<key>:/^value$/`。

URL 条件可以写成正则，四个算子分两种写法。`includeFilter://` 和 `excludeFilter://` 跟其他值一样，用带分隔符的 `/<expr>/[i]`。`filter://` 和 `ignore://` 则把**最后一个**字符是 `/`（或以 `/i` 结尾）的内容当成正则，开头如果有一个 `/` 就去掉——所以 `filter:///echo$/`、`filter://echo$/` 和 `ignore:///echo$/` 是同一个表达式，而结尾没有斜杠的 `filter://*/echo` 则是通配符。对应上游的 `PATTERN_FILTER_RE` 和 `util.isRegExp`（`rules.js:54`、`util/index.js:606`）。

`!` 把条件取反。它可以放在值前面（`m:!GET`），紧跟在头的键名后面（`reqH.x-tag!:v`），或者放在 URL 匹配串前面（`includeFilter://!*.cdn.com`）；两个 `!` 互相抵消。注意，放在条件*名字*前面的 `!` 不是取反——`includeFilter://!m:GET` 是一个取反的 URL 匹配串，这里和上游都是这样。

```
example.com   host://10.0.0.1      includeFilter://m:POST            # 只对 POST
example.com   host://10.0.0.1      includeFilter://m:/^P/            # POST, PUT, PATCH
example.com   resHeaders://x-a=1   excludeFilter://clientIp:127.0.0.1
.example.com  host://5.5.5.5       includeFilter://reqH.content-type:json
example.com   statusCode://503     includeFilter://chance:5%         # 让 5% 的调用失败
example.com   host://10.0.0.1      excludeFilter://*/health
```

#### 响应阶段

whistle 会给一个请求匹配**两遍**规则：一遍在请求发出之前（`resolveReqRules`），另一遍在响应头部到达之后（`resolveResRules` → `pluginMgr.getResRules`，`_original/lib/rules/rules.js:2302-2308`、`lib/plugins/index.js:1322`）。正是这第二遍，让规则能拿响应来做判断。whix 也是这样。

**每一遍决定什么。** 上游把算子分给两遍，本项目照着分：响应阶段负责 `pureResProtocols`（`_original/lib/rules/protocols.js:82-111`）——

> `replaceStatus`, `cache`, `attachment`, `resMerge`, `resDelay`, `resSpeed`,
> `resType`, `resCharset`, `resCookies`, `resCors`, `resHeaders`, `trailers`,
> `resPrepend`, `resBody`, `resAppend`, `resReplace`, `resWrite`, `resWriteRaw`,
> `cssAppend`/`htmlAppend`/`jsAppend`, `cssBody`/`htmlBody`/`jsBody`,
> `cssPrepend`/`htmlPrepend`/`jsPrepend`, `responseFor`, `log`, `weinre`

——其余的都在请求发出之前就定了。所以响应条件能让 `resHeaders://` 生效，却永远不能让 `host://` 生效：

```
example.com   resHeaders://x-slow=1   includeFilter://s:/^5/   # 遇到 5xx 时生效
example.com   host://10.0.0.1         includeFilter://s:200    # 永远不生效
```

第二行不算错——上游也会匹配它，只不过是在请求阶段。那时状态码还不知道，于是这个条件失败关闭（fail closed，说白了就是按“不成立”处理；具体是哪些条件，紧接着下面列出）。等知道状态码的时候，请求早已发往规则选定的源站了。

**第二遍能回答哪些条件：** `s:`/`statusCode:`、`resH.`（以及它的 `res.`/`resHeader.`/`resHeaders.` 写法）、`serverIp:`、`serverPort:`，还有 `h:`/`header:` 退回去看响应头的那部分。在请求阶段，它们无从回答，一律失败关闭；这时加 `!` 也救不回来，等答案知道了才行：

```
example.com   resHeaders://x-not-ok=1   includeFilter://s:!200
```

**优先级。** 两遍的结果按*书写顺序*合并：每个算子都带着写它的那一行的位置，所以胜出的，就是对整个文件只走一遍时会选中的那个，不管它是在哪一遍匹配出来的。

```
example.com   replaceStatus://502
example.com   replaceStatus://500   includeFilter://s:404      # 502 胜出，因为它写在前面
```

> 上游的 `mergeRule`（`_original/lib/util/index.js:2147-2171`）则是无条件优先用响应那一遍的结果。它这样做没问题：它的两遍读的是*互不相交*的算子集合，所以同一个规则文件里，同一种算子永远不会同时拿到两个。到了这里两者可能撞上，而按书写顺序合并，才能复现上游在外面看得到的行为。

在响应阶段匹配到的 `ignore://`，能作用到请求阶段已经匹配出的结果，但只限于上面那些响应阶段的算子——上游的 `ignoreRules(origin, …, isResRules)`（`_original/lib/util/index.js:2083`）。所以 `ignore://resHeaders includeFilter://s:404` 会在源站返回 404 时，压掉*其他*行设置的响应头，而且永远碰不到 `host://`。

**开销。** 每个规则组在解析时就记下自己哪些行可能需要响应阶段。规则文件完全不涉及响应时，整个第二遍都跳过（实测每个响应约 2 ns，对比 500 条规则的请求阶段约 2.4 µs）；涉及时，只为那几行付出代价——500 行里有一行带这种条件，花费约 24 ns。

**请求中途合并进来的规则也走两遍。** `rule://` 的值、`rulesFile://` 合并进来的规则、插件注入的规则，都各自以解析好的形式留着，等头部到达时再匹配一次——上游在 `getResRules` 里也是对同样这几组规则管理器再匹配一次（`fRules`/`pRules`/`hRules`，`_original/lib/plugins/index.js:1326-1335`）。在两遍里，它们都排在把它们拉进来的那个文件所匹配出的一切*之后*。每个响应的开销：什么都没合并时约 7 ns，合并进来的文本里没有依赖响应的行时约 9 ns，有这样一行时约 250 ns。

**所有产生响应的路径都覆盖到了**，包括两条不去源站的路径：应答了请求的 `plugin://` 钩子，以及短路规则（`file://`、`tpl://`、`redirect://`、`statusCode://`）。这两种都按产生出来的头部来匹配，在任何算子碰它之前——所以 `s:404` 看到的是插件自己给的 404，而不是同一行上的 `replaceStatus://200`。whistle 在这两条路径上也会进入它的响应处理（inspectors）：`plugin://` 规则其实是到插件自己服务器的一跳代理，所以应答是作为普通响应回来的（`_original/lib/inspectors/res.js:825`）。

**没覆盖到的：** WebSocket 和隧道（`CONNECT`）流量在这里没有响应阶段。两条本身不产生响应的路径也没有——自环重定向和 `enable://abort`——这一点顶层规则也一样。

`serverIp:` 的答案来自**已连接的 socket**，所以用域名指定的源站也能回答：地址是从连接上读回来的，而不是再问一次解析器去猜（在轮询 DNS 下，再问一次可能得到一个请求根本没去过的主机）。请求经过上级代理时，地址是**代理的**——whistle 报的也是这个，因为只要有代理规则匹配上，它就用解析出来的代理地址设置 `req.hostIp`（`_original/lib/inspectors/res.js:238,:259`）。请求根本没连上时，这个条件无从回答，失败关闭。

#### body 条件

`b:` / `body:` 读的是**请求 body**，这意味着匹配规则之前得先把 body 缓存下来——这是请求路径上唯一一件做了就撤不回来的事。所以两边的实现都分两步来决定，whix 照的是上游的做法：

1. 解析时，所有带 `b:` 筛选器的行都被收进一个单独的列表（上游的 `_bodyFilters`，`_original/lib/rules/rules.js:1390-1392`）；
2. 匹配规则之前，代理先看这些行里有没有哪一行的**匹配串**接受这个请求。有，才去读 body（`resolveBodyFilter` → `req.getPayload`，`rules.js:2455-2465`、`lib/inspectors/rules.js:193-205`）。

这一行的其他条件在第 2 步里没有发言权，这是有意的：上游的 `resolveBodyFilter` 传了 `isFilter`，它让 `checkFilter` 在 `matchExcludeFilters` 运行之前就提前返回（`rules.js:983`）。拿其他条件来缩小范围，看着不花钱，其实不然——一个 `excludeFilter://b:` 会从它自己那个“假定为真”的条件推出这一行已经被排除了，于是永远不去读它做判断本来需要的那个 body。

所以，没有 `b:` 的规则文件从不碰 body；`b:` 限定在某个主机或路径上的，对被匹配串挡掉的请求几乎没有开销。在 500 条规则的文件上实测：没有 `b:` 行时，每个请求**不到 1 ns**——每个规则组一次 `is_empty()`；有一行、但匹配串挡掉了这个请求时 **4 ns**；有一行、且匹配串接受时 **11 ns**；而随后的规则匹配约 2.8 µs。

```
example.com  resBody://blocked  includeFilter://b:password
example.com  resBody://blocked  includeFilter://b:/"role"\s*:\s*"admin"/
```

比较方式是**包含**，不区分大小写，和头一样；`/re/` 值则拿原样到达的 body 来匹配。空 body 也是 body，所以对没有 body 的请求，`b:!x` 成立。如果没有任何东西让 body 被缓存下来——比如 `rulesFile://` 引入的规则里的 `b:`，它要到这个决定做完之后才匹配——这个条件就是未知，失败关闭，和上游在 `req._reqBody` 不是字符串时的做法一样（`rules.js:1903-1906`）。

为 `b:` 缓存 body 最多缓存到 2 MB，条件拿已读到的这段前缀来匹配——和上游在 `MAX_REQ_SIZE` 处的做法一样。和 body 类算子不同，`b:` 不能用 `reqMergeBigData` 调高这个上限：这个开关本身就是一条规则，而 `b:` 正在决定哪些规则生效。见[请求 body 有上限](#请求-body-有上限)。

#### 来源标记

`from:` 的值是一个固定列表里的单词——不是匹配串，也不能写 `/re/`：whistle 会把值转成小写再比较（`_original/lib/rules/rules.js:1608-1611, :1834-1859`）。每个标记在匹配规则之前就已经确定，所以取反的写法给出的是真实的答案，而不是失败关闭的筛选器。

| 标记 | 什么时候为真 |
|---|---|
| `tunnel` | 请求来自本代理拦截的一条隧道——`CONNECT` 或 SOCKS 连接 |
| `sni` | 被拦截的 TLS 握手里带了服务器名。跑明文 HTTP 的隧道算 `tunnel`，但不算 `sni` |
| `composer` | 内置控制台重放了这个请求（Replay 按钮 / `POST /api/replay`） |
| `test`、`httpserver`、`httpsserver`、`httpsport` | 在这里永远不为真——见下文 |

```
example.com  resHeaders://x-src=tunnel  includeFilter://from:tunnel
example.com  statusCode://403           includeFilter://from:!composer
```

后面四个能被识别，并给出确定的 **`false`**，所以 `from:!httpserver` 成立。`test` 需要 whistle 的测试头，本项目既不发也不认这个头；三个服务器标记需要 whistle 能在代理端口之外另开的 HTTP/HTTPS 监听（`config.httpPort`/`httpsPort`，`_original/lib/index.js:96-111`），本项目没有。启动时没开这些监听的 whistle，给出的也是同样的 `false`。

`from:composer` 靠回环那一跳上的 `x-whistle-composer` 请求头来标记，这个头一到就被取下，所以 `reqH.` 条件和源站都看不到它。和 `x-whistle-internal-req`（[`LINE_PROPS.md`](LINE_PROPS.md)）一样，这个名字是固定的，不是每个进程各不相同：这个标记只是给流量贴标签，并不守护任何东西，而名字固定，客户端才能有意地去触发这个条件。

有两处上游行为是**照搬、没有修正**的：

- `from:internalPath` 永远匹配不上。whistle 比较之前先把值转成小写，所以它自己的 `'internalPath'` 分支永远走不到。
- 不认识的标记**无论怎么写**，都满足不了任何筛选器。上游那串判断在看 `!` 之前就 `return false` 了，所以 `from:!nonsense` 也为假。这里把它当成“未知”答案：包含筛选器因此不满足，排除筛选器则不起作用。

本项目能解析的其他所有条件，现在都会真正求值。

#### 筛选条件与上游的不同之处

| 上游 | 这里 | 原因 |
|---|---|---|
| `i:` 先匹配客户端 IP，再退回看服务端 IP | 只看客户端 IP | 上游的服务端 IP 分支走不到：只要 `req.clientIp` 为 null，`filterProp` 就会报告 ip 筛选器已处理，所以它下面那行 `req.hostIp` 对 ip 筛选器永远不会执行（`rules.js:1824-1830,:1875-1880`）。要看服务端地址，写 `serverIp:`。 |
| 两遍都匹配出同一个算子时，响应那一遍胜出 | 书写顺序在前的胜出 | 见[响应阶段](#响应阶段)：上游两遍读的算子互不相交，遇不到这种情况。 |
| `remoteAddress:`/`remotePort:` 是原始 socket 的，和 `clientIp:`/`clientPort:` 不同 | 同一个 socket | 两者在上游只有在请求由另一个 whistle 转发过来时才不同，而本项目不认那些覆盖客户端 IP 的头。 |
| `host` 条件从不决定规则是否生效 | 匹配请求的主机 | 对 whistle 2.10.8 实测：`host=`/`host.` 被归到 `hostFilter` 下，而只有 `util.checkProxyHost` 会读它——它决定 `proxy://` 对哪些主机生效。`host:`（带冒号）上游根本不认，会被当成一个不可能匹配上的 URL 匹配串。这里两种写法都匹配请求自己的主机。 |
| 头的值还会和 `encodeURIComponent(value)` 比较 | 不比较 | 这个分支在上游走不到：被搜索的字符串已经转成了小写，而 `encodeURIComponent` 输出的是大写的十六进制。 |

有些筛选器会被**丢掉**，规则随后就当没有它们一样生效：内容为空或只有一个 `!`（`includeFilter://`、`includeFilter://!`）；头的键名被它自己的 `!` 弄空了（`reqH.!!=v`——第一个 `!` 算值的）；以及值既不是地址、也不是正则的 `i:`/`ip:`/`clientIp:`/`serverIp:`（`i:localhost`）。

被丢掉的条件**失败开放**（fail open）：就像从来没写过一样，所以不管它写在哪种筛选器里，这一行的生效范围都会变大。这一点值得弄清楚，因为它和写错的[匹配串](#匹配串)正好相反——没通过自身检查的匹配串什么也匹配不上，只是让它那一条规则失效；而没通过这些检查的条件，会把它本来把守的规则放出来。同一类笔误，波及范围却正好相反。

最要命的是拿它做豁免的情况。`excludeFilter://i:127.0.0.1` 让一条规则不作用于本机流量；要是写成 `excludeFilter://i:localhost`，条件被丢掉，这条规则就作用于*所有*流量，本机流量也在内。而且没有任何提示。

只是**永远不成立**的条件是另一回事，区别也只在包含那一侧：它会把包含筛选器彻底卡死，对排除筛选器则和被丢掉的条件一样不起作用。只差一个字符的两种写法，恰好落在这条线的两边——一开始就是空的头键名会被保留（`reqH.=v` 要找一个名为 `""` 的头，而没有哪个消息有这样的头），而分隔符后面什么都没有的名字根本不算条件（`includeFilter://reqH.` 是一个匹配不了任何 URL 的 URL 匹配串）。两者都是上游的答案，实测过。
### 禁用算子

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `ignore` | 一个或多个协议名，或 `all` | 对命中的请求，从解析出的算子集合里去掉这些算子 |

```
.example.com   host://10.0.0.1
static.example.com   ignore://host        # 这个域名保留它真实的目标地址
example.com/health   ignore://all         # 这个路径绕过所有规则
```

`ignore://` 后面如果跟的是**[筛选条件](#筛选条件)**而不是协议名，那它就是一个
*排除筛选器*，不是这个算子——`ignore://m:POST` 让这条规则对 POST 请求不生效，和
`excludeFilter://m:POST` 完全一样。上游让这两种写法走同一个解析器
（`_original/lib/rules/rules.js:57`）。

#### 按原文屏蔽一条规则

第三种读法按规则*写出来的原样*点名。你想关掉的规则偏偏改不了的时候——它在被引入的
文件里，或者是插件合并进来的——用的就是这种。

| 值 | 屏蔽什么 |
|-------|----------|
| `pattern=<text>` | 所有**匹配串片段**恰好是 `<text>` 的规则 |
| `matcher=<text>` | 每一个恰好是 `<text>` 的**算子片段** |
| `operator=` / `operation=` | 和 `matcher=` 一样 |

```
# 不动被引入的规则文件，关掉它里面的一行。
*   ignore://pattern=static.example.com
*   ignore://matcher=host://10.0.0.1
```

`:` 可以代替 `=`（`ignore://pattern:example.com`）。文本必须和片段*完全*一致，前缀也
算在内——`$example.com` 和 `example.com` 是两个不同的匹配串。

点名算子要用它**展开后**的形式。简写在这一行被拆开之前就已经展开了，所以
`example.com /local/path` 要用 `matcher=file:///local/path` 来屏蔽，
`matcher=/local/path` 不行。（上游两种都认；本项目只认展开后的那种——等算子生成出来，
原来写的那段文本已经找不回来了。）

和协议名那种写法不同，这种可以写在**文件里的任何位置**——在被屏蔽的规则上面或下面
都行——因为整套规则是先全部读完、再开始生效的。

三种读法实际上不会撞车，但原因值得说准确，因为原因*并不是*它们的形状互不重叠：
筛选条件和 `pattern=` 的值都可以带 `:`、`.` 和 `=`。真正把它们分开的，是各自靠一套
自己的词汇来识别：开头是 `m:`/`s:`/`b:`… 的是筛选条件，开头是上表四个键之一的是按
原文屏蔽，两者都不是的，就当成一串协议名来读。

> **`skip://` 对不带键的值读法不同。** 在这里 `skip://` 和 `ignore://` 是同一个算子，
> 只有一处例外：在 `skip://` 下，值里只要出现协议名不可能包含的字符，整个值就被*整体*
> 当成 `matcher=`。所以 `skip://example.com/path` 屏蔽的是这个算子片段，而
> `ignore://example.com/path` 会去找叫这些名字的协议，结果一个也找不到。上游也做了
> 同样的区分（`rules.js:1129-1141`）；如果你并不依赖这一点，优先用明确的 `matcher=`
> 写法。
>
> **而且 `skip://` 屏蔽得更早。** `ignore://` 能做的它都做，另外它在*遍历*规则的过程中
> 就把算子去掉，而不是遍历完之后（`checkSkip`，`_original/lib/util/index.js:2004-2013`）。
> 对每个有自己协议键的算子，两者结果一样，都是什么也不剩。但在
> [共享槽位](#短路不向源站发请求)上，两者给出的答案正好相反：
> `skip://` 把槽位让给下一条写出来的规则，`ignore://` 让它空着。还有一个后果：
> `skip://` 的名字列表只用 `|` 分隔，`ignore://` 还认 `&`。

### 短路（不向源站发请求）

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `redirect` | 一个 URL | 返回 `302 Found`，带 `Location: <url>` |
| `statusCode` | 一个状态码数字 | 返回这个状态码和空 body（mock） |
| `file` / `rawfile` | 本地路径**或一个 URL** | 返回文件的字节，`Content-Type` 靠猜 |

```
old.example.com/legacy   redirect://https://new.example.com/
/\/track\b/              statusCode://204
example.com/app.js       file:///Users/me/dev/app.js
```

**来源可以是 URL**，这时会去抓取它，把抓到的字节当作 mock 返回——
`pluginMgr.resolveKey` 会把 `util.isUrl` 认可的任何条目变成一次 HTTP 请求，而不是当成
路径（`_original/lib/plugins/index.js:1521-1529`）。

```
example.com/api/flags   file://http://mocks.internal/flags.json
example.com/api         file:///srv/cache|http://mocks.internal/api    # 本地优先
```

这是**抓取，不是转发**：请求自己的头不会带过去，答复带的是 file 这一族的 `Server` 头，
请求剩下的路径也*不会*拼到 URL 后面——`file:///srv/static` 会往目录里延伸，
`file://http://host/x` 不会。`|` 列表里的条目是一个一个判定的，所以上面第二行在本地有
副本时就返回本地的，没有时才去抓取。来源最大 256 KB（`MAX_URL_VAL_LEN`）；来源返回
`404` 时，给出的是这一族自己的 404；返回其他非 `200` 状态时，给出一个写明该状态码的
`502`，因为那说明 mock 服务器坏了，而不是文件不存在。`<…>` 表示的是路径，永远不是 URL。

注意第一行没有 `*`。路径前缀本来就会在路径段的边界上匹配它下面的所有内容，而普通
匹配串路径里的 `*` 是**字面字符**——`old.example.com/legacy/*` 只匹配含有 `*` 这个
字符的 URL，别的都不匹配。需要带捕获的路径通配时，写
`^http://old.example.com/legacy/**`。

**file 永远不会答复 WebSocket 或隧道。** 正在解析的 URL 不是 `http(s)://` 的时候——
`ws://`、`wss://`、`tunnel://`——file 这一族的每个候选，连同 `locationHref://`，都会被
跳过，槽位落到下一条规则（`notHttp && protoMgr.isFileProxy(rule.matcher)`，
`_original/lib/rules/rules.js:920,:977`）。file 是一个完整的 HTTP 响应，而升级请求要的
是 `101`，拿目录列表去答复它，就是一次顶着 mock 状态行的握手失败。`statusCode://` 和
`redirect://` 在同一个槽位里，却*不会*被跳过：这两种答复都可以在客户端升级之前给它。

`statusCode://101` 用在 WebSocket 上，就是一个背后没人的 WebSocket 端点：代理自己完成
握手——按 key 算出的 `Sec-WebSocket-Accept`、客户端请求的第一个子协议、`Upgrade`、
`Connection`——然后保持连接，读取并丢弃客户端发来的内容，和上游一样。客户端能连上、
能往里发，但不会有任何回应。

```
chat.example.com   file:///srv/mock.json       # WebSocket 会无视这一行……
chat.example.com   127.0.0.1:9000              # ……但这一行照样能把它转走
```

**这些算子彼此共用一个槽位，也和裸目标地址 URL 共用。** `file`、`rawfile`、`tpl`、
`jsonp`、`dust`、`redirect`、`statusCode` 和转发用的 URL，没有一个是上游 `protocols`
数组里的名字，所以 `parseRule` 把它们全都归到同一个 `rule` 列表下
（`_original/lib/rules/rules.js:1313-1316`），而 `getRule` 返回**第一个**命中的
（`:799-800`）。它们没法共存：谁先写谁来答，其余的都不生效。

```
example.com            http://localhost:5173
example.com/api/flags  file://({"beta":true})     # 永远不会返回——转发那条先赢了
```

把窄的规则写在宽的上面，或者给它标上 `lineProps://important`，这样不管行序如何它都
排第一：

```
example.com/api/flags  file://({"beta":true})
example.com            http://localhost:5173
```

在*同一行*里也没有协议优先级：先写的赢，因为上游是按输入顺序把一行的算子压进共享
列表的（`matchers.forEach(parseRule)`，`rules.js:1785-1789`）。所以
`file://({"id":7}) statusCode://201` 返回文件内容，而
`statusCode://201 file://({"id":7})` 返回 `201` 和**空 body**。想让 mock 的 body 换一个
状态码返回，用 [`replaceStatus://`](#改写响应)；它是改写一个响应，而不是凭空
造一个。

**屏蔽其中一个，不等于选中另一个。** `ignore://` 在槽位已经决出唯一赢家之后才执行，
所以它只能把这个赢家拿掉——绝不会把下一行提上来：

```
example.com  statusCode://204  redirect://http://elsewhere/  ignore://statusCode
```

返回的是源站的响应，而不是重定向。点名一个*输掉*的成员什么也不会发生，因为它根本不在
解析结果里，无从点名；而且名字必须是赢家**写出来时**用的那个：`ignore://rule` 能命中
占着槽位的任何成员，`ignore://http` 命中裸的 `http://…` 目标地址，别名什么也命中不了
——写成 `status://204` 的规则，`ignore://status` 和 `ignore://statusCode` 都屏蔽不了，
只有 `ignore://rule` 可以。这些全是上游 `ignoreForwardRule`
（`_original/lib/util/index.js:2047-2059`）的行为，它是从赢家的 URL 里把协议名读回来的。

[`skip://`](#按原文屏蔽一条规则) 才是**会**落到下一个的写法：它在遍历规则的
过程中就屏蔽算子，而不是遍历完之后，所以同一行写成 `skip://statusCode` 就会重定向。
在其他所有算子上，两者没有区别——只有在槽位这里，"落到下一个"才有地方可落。

### 请求改写

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `reqHeaders` | `name=value` 对（用 `&` 分隔）或 `{json}` | 设置/替换请求头。值为空时发出去的是一个**空头**，不是删除——删除用 `delete://reqHeaders.x`。多行会累加。 |
| `ua` | user-agent 字符串 | 设置 `User-Agent` 头 |
| `referer` | URL | 设置 `Referer` 头 |
| `method` | HTTP 方法 | 覆盖请求方法。不管有没有规则，**每个**请求的方法都会转成大写；不可用的值回退成 `GET` |
| `reqType` | MIME 类型或简称 | 设置请求的 `Content-Type`（`reqType://json`、`reqType://form`、…） |
| `reqCharset` | 字符集 | 设置请求 `Content-Type` 里的 charset |
| `reqCors` | origin URL、`*`，或 `method=…&headers=…` | 设置请求的 `Origin`，以及预检用的 `Access-Control-Request-Method` / `-Headers` 头。URL 只保留它的 origin 部分。`enable` 是*响应*侧的写法，在这里不起作用。 |
| `auth` | `user:pass`、`username=…&password=…` 或 `{json}` | 加一个 HTTP Basic `Authorization` 头——见下文 |
| `forwardedFor` | IP | 设置 `X-Forwarded-For` 头 |
| `reqWrite` | 文件路径 | 把请求 body 写入文件，只写一次——见[转储文件](#转储文件) |

```
example.com   reqHeaders://x-token=abc
example.com   reqHeaders://x-a=1&x-b=2
example.com   reqHeaders://{"x-a":"1","x-b":"2"}
example.com   ua://MyBot/1.0
api.test/*    method://POST
api.test      auth://admin:secret
api.test      forwardedFor://203.0.113.7
```

`ua://` 和 `referer://` 也是赋值，所以不带值地写它们，发出去的是一个空头。要去掉其中
一个，用的是 `disable://ua` 和 `disable://referer`。

#### `auth://` 的四种写法

| 值 | 发送 |
|-------|-------|
| `admin:secret` | `admin`/`secret` 对应的 `Authorization: Basic …` |
| `username=admin&password=secret` | 同上 |
| `{"username":"admin","password":"secret"}` | 同上 |
| `{"username":"admin","password":"secret","proxy":true}` | 改成发 **`Proxy-Authorization`** |
| 一个**位置**——`/etc/whistle/auth.json`、一个 URL | 它里面的内容，按 `username` / `password` / `proxy` 读取 |

只按第一个冒号拆分，所以密码里可以有冒号。可以只写其中一半，而且两半并不对称
（`getAuthBasic`，`_original/lib/util/index.js:3668-3685`）：只有密码没有用户名时，冒号
照样带上（`:secret`）；只有用户名没有密码时，不带冒号（`admin`）。两样都没写的值，什么
头都不发。

有两个边界情况是上游的，很容易踩坑：查询串写法里的 `proxy` 是按 `!!value` 读的，所以
`proxy=false` 是**真**——想表达"否"就用 JSON 写法；另外查询串的值是原样取的，所以密码
里的 `%2F` 到服务器那边还是 `%2F`。

**值里带斜杠就是位置，永远不会当成凭据。** `SLASH_RE`（`util/index.js:102,:3653`）检测
的是整个值，所以 `auth://admin:se/cret` **不**发任何头——在两个程序里，密码都不能含
斜杠，不管看起来多么应该可以。能扛住斜杠的两种写法，是在这个检测之前就判定掉的那两种：
`{"password":"p/q"}` 和 `username=u&password=p/q`。

表里最后一行，就是值里有斜杠时走的那条路；[官方文档](https://wproxy.org/docs/rules/auth.html)
讲到需要共享的凭据时，首先介绍的就是它。读回来的内容按数据对象解析——行格式也算在内，
所以文档里的这个文件

```
username: admin
password: my secret password
```

是两个字段，而不是一个很长的用户名。读不到的位置什么都不发。

> **本项目以前会把路径发出去。** 只要文件不存在，`auth:///Users/john/config/auth.json`
> 到源站时就成了 `Authorization: Basic base64("/Users/john/config/auth.json")`，因为当时
> 以"密码里可能有斜杠"为由跳过了斜杠检测；行格式的文件也被整个当成用户名发了出去。这两个
> 问题都是把文档自己的例子拿到 whistle 面前对照跑出来的——
> `tests/differential/cases-docs.js`。
>
> 那一页上有一种写法在**两个**程序里都不工作，下面这行记录的就是它：行格式里的内联
> ```` ``` ```` 块 `auth://{custom-key}` 会被读成 `user:pass`，因为块的内容是作为值本身
> 到达 `getAuthByRules` 的。两个代理都会把 `username` 当成用户名发出去。在块里请用
> 文件，或者 `{"username":…}` 这种 JSON 写法。

### 插件

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `plugin` | `name[/extra]` | 对请求执行一个已注册插件的钩子 |

三种写法，同一条规则——第二、第三种是上游的写法：

```
api.example.com   plugin://mock/extra
api.example.com   whistle.mock://extra
api.example.com   mock://extra
```

插件拿到的 `param` 就是 `extra`。短写法 `mock://` 只对**请求到达时已经注册**的名字有效：
本项目不认识的协议，在其他情况下都会被当成目标地址 URL
（`example.com http://localhost:5173`），没有叫 `mock` 的插件时，`mock://` 也一样——
于是请求会失败，报 `unsupported protocol mock:`。上游也是这样、在请求时判定的
（`getPluginByPluginRule`，`_original/lib/plugins/index.js:1406-1421`）。控制台的
Test Rules 知道已注册的名字；`whix explain` 不需要代理就能跑，只认识内置的那些。

在命令行注册插件（可以重复写），或者从脚本启动一个：

```bash
whix --plugin echo=127.0.0.1:9300 --plugin mock=127.0.0.1:9400
whix --node-plugin mock=./mock-plugin.js
```

插件会被问什么、怎么回答，见 [`PLUGINS.md`](PLUGINS.md)。在控制台里被关掉的插件，
对所有点它名的规则来说，就等于不存在——见[开关](API.md#开关https全部规则插件)。

插件答复了请求，也**不是**最终结果：这一行上的响应算子照样会作用在它的答复上，
[响应阶段](#响应阶段)也一样——和对待源站的答复相同，也和上游一致：在上游，
`plugin://` 规则是一跳通往插件自己服务器的代理，它的答复会经过普通的响应检查器回来
（`_original/lib/inspectors/res.js:825`）。

```
api.example.com   plugin://mock  resHeaders://x-mocked=1  replaceStatus://503
```

插件自己的响应钩子（`POST /response` 和流式的 `pipe://` 那些）也会作用在这个答复上，
和作用在源站答复上一样——包括产生这个答复的那个插件自己，因为上游会给每个命中的插件都
建立响应管道，不管字节是哪个插件写的。见
[`PLUGINS.md`](PLUGINS.md#本地产生的响应也走响应阶段)。唯一的例外是 `onAuth` 的拒绝：
上游用 `ignore://!…` 把它钉死，本项目则原样发出去，什么也不动。

### 选择中间人证书

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `sniCallback` | `name[(value)]` | 对一个被拦截的 TLS 连接，问插件该出示哪张证书——或者到底要不要拦截 |

```
api.example.com      sniCallback://certs(staging)
pinned.example.com   sniCallback://no-mitm
```

这个算子的解析时机和本页其他所有算子都不一样：在 **TLS 握手**期间，那时还没有请求。
所以它只能匹配那时已经有的东西——客户端 ClientHello 里的名字，以 `https://<那个名字>`
的形式——再加上客户端的地址和端口。没有方法、没有路径、没有头、没有 body，所以问到
这些的筛选器永远不会匹配 `sniCallback` 那一行。

插件有四种答法：出示 whix 自己生成的证书，出示插件自己的证书，复用上次它给的那张，
或者**干脆不拦截**——这时连接保持加密、原样转给源站，它的任何内容都不会被抓下来。
怎么写这个插件见 [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback)；内置的
`sniCallback://no-mitm` 完全不需要插件，总是不拦截。

有三个后果值得知道：

- **端口是匹配串的一部分**，因为规则匹配的 URL 带着端口：
  `localhost:9443 sniCallback://certs` 和 `localhost:9444 …` 是两条不同的规则，尽管
  ClientHello 一模一样。
- **不拦截的连接照样遵守隧道的路由规则。** SNI 这条路径会保留解析出来的目标，并应用
  `host://` 和上级代理那一组算子；必须走的路由不可用时，不会悄悄换成直连。它的负载对
  代理来说是不透明的，既不会被抓下来，也不会被 HTTP body 算子处理，因为 TLS 仍然在
  客户端和源站之间。
- **插件出错不等于不拦截。** 连不上、太慢、回的内容看不懂，都按"用 whix 本来就会生成
  的那张证书"处理，并打一条点名该插件的 `WARN`。为什么唯独这个钩子不像 `onAuth` 那样
  出错就拒绝（fail closed），见 [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback)。

### 脚本

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `resScript` | `.js` 文件路径（或内联 JS） | 对响应执行 JavaScript |
| `frameScript` | `.js` 文件路径、`{value}` 或内联 JS | 对每个 WebSocket 帧执行 JavaScript——配合 `enable://inspect` 时，也对普通隧道的每个数据块执行 |

脚本在一个内嵌的 JS 引擎里运行，有一个全局变量 `ctx`：

```js
// ctx = { req: { method, url }, res: { statusCode, headers, body } }
ctx.res.headers['x-scripted'] = 'yes';
ctx.res.body = ctx.res.body.replace(/foo/g, 'bar');
if (ctx.req.url.indexOf('/admin') >= 0) ctx.res.statusCode = 403;
```

改过的 `ctx.res.statusCode`、`ctx.res.headers` 和 `ctx.res.body` 会被应用。脚本出错时，
响应保持不变。

```
example.com   resScript:///abs/path/patch.js
```

这个钩子是本项目自己的，靠 `ctx` 这个词来识别。上游没有这个钩子：在上游看来，
`resScript://` 的文本就是**响应规则**——在这里也一样，只要文本里没提到 `ctx`：

````
```tps.rules
# rules
example.com jsAppend://(console.log('appended'))
```
example.com   resScript://{tps.rules}
````

值或路径什么也没指到时，什么也不执行。2026-09 之前，凡是不含 `rules`/`values` 的
`resScript` 文本都会被当成 JavaScript 执行，于是规则文本解析失败，悄无声息地什么也
没做。

**脚本也可以*产出规则*。** 这是上游给这一族算子的本意，现在已经实现：当脚本文本用括号
括着、不含 `#` 注释或 ``` `` ``` 围栏、并且提到了 `rules` 或 `values`
（`isRulesContent`，`_original/lib/rules/index.js:41-43`）时，它运行时会带上这两个
全局变量，往 `rules` 里 push 的内容都会作为额外的规则来解析。请求阶段的脚本能看到
`url`、`method`、`headers`、`body`、`ip` 和 `clientPort`；`resScript` 还能看到
`statusCode`、`serverIp` 和 `resHeaders`。抛了异常的脚本什么也不贡献，连抛异常之前
push 的行也不算。

不管多大的脚本，都放进一个 ``` 围栏块，再在规则行里写它的名字——两个代理都按空白拆分
规则行，所以内联的 `(…)` 脚本到第一个空格就断了，永远不是一个完整的程序。（本文档以前
举过 `reqScript://(rules.push(url + ' reqHeaders://x-seen=1'))` 这个例子。它会被解析成
`rulesFile://(rules.push(url` 外加另外两个算子，在 whistle 2.10.8 里和这里都一样。）

````
```probe.js
rules.push(url + ' reqHeaders://x-seen=1');
```
example.com   reqScript://{probe.js}
````

上下文就是上游的 `getScriptContext`（`_original/lib/rules/index.js:349-416`），名字
一个不差：

| 名字 | 是什么 |
|------|------------|
| `url` / `fullUrl`, `method`, `headers` / `reqHeaders`, `body` | 请求本身。`method` 已转成大写；`body` 最多是预览的那一段 |
| `ip` / `clientIp`, `clientPort` | 谁发的 |
| `httpVersion` | **客户端**用的版本：`1.0`、`1.1`、`2.0` |
| `pattern` | 脚本所在规则行的匹配串（`example.com/api reqScript://{x.js}` 里就是 `example.com/api`） |
| `port`, `uiPort`, `uiHost`, `version` | 代理本身：它的端口、控制台的端口（`-P`，没设就和代理相同）、`local.wproxy.org`、本次构建的版本号 |
| `rules`, `values` | 脚本产出的东西——见上文和下文 |
| `value` | `undefined`（上游：请求的 `G://` 值，本项目没有） |
| `reqScriptData` | 整个请求共用的一个对象：`reqScript` 往里放的东西，同一个请求的 `resScript` 能读到 |
| `statusCode`, `serverIp`, `resHeaders` | 在 `resScript` 里是响应的头部信息；在请求阶段那一遍是空字符串 |
| `getValue(name[, onlyValues])` | 同名的 ``` 块，没有就去 Values 里找；传 `true` 时只查 Values |
| `render(tpl, data)` / `tpl` | whistle 的 `<% … %>` / `<%= … %>` 微模板（`rules/index.js:304-347`），源码转换方式完全相同 |
| `isLocalAddress(ip)` | 回环地址、未指定地址（unspecified）、本机的主地址 |
| `parseUrl(url)` | Node 旧版的 `url.parse(url)` |
| `parseQuery(str)` | Node 的 `querystring.parse(str)` |
| `Buffer` | Node 的 `Buffer` |
| `decodeBuffer(buf, enc)`, `encodeString(str, enc)`, `encodingExists(enc)` | `iconv-lite` 的 `decode`、`encode` 和 `encodingExists` |

最后四行是 **Node 的行为本身，不是对它的概括**，因为
[`reqScript.md`](https://wproxy.org/docs/rules/reqScript.html) 写的是"同 Node.js
的 `url.parse`"，从 whistle 配置里抄过来的脚本会依赖这些细节：

```js
parseQuery('a=1&a=2&q=a+b')          // { a: ['1', '2'], q: 'a b' }   — not { a: '2', q: 'a+b' }
parseUrl('http://u:p@[::1]:81/a b#h') // auth 'u:p', host '[::1]:81', hostname '::1',
                                      // pathname '/a%20b', hash '#h', search null
Buffer.from('中').toString('hex')      // 'e4b8ad'
encodeString('中', 'gbk')              // <Buffer d6 d0>
```

它们是在引擎之上用 JavaScript 写的（`src/proxy/script_prelude.js`），并在
`tests/differential/core-bench.js` 里和 whistle 2.10.10 逐个用例做了对比——55 个脚本
对比，其中 24 个是 URL，全部一致。`Buffer` 具备规则脚本会用到的方法（`from`、`alloc`、
`concat`、`isBuffer`、`byteLength`，`toString` 支持 `utf8`/`hex`/`base64`/
`base64url`/`latin1`/`ascii`/`utf16le`，`slice`、`indexOf`、`write`、`copy`、
`equals`，以及定宽整数的 `read…`/`write…`）；它不是 Node `Buffer` 的全部。`iconv` 那三个
认识 Encoding Standard 里的那套编码——`gbk`、`gb18030`、`big5`、`shift_jis`、`euc-kr`，
以及 `windows-125x` 和 `iso-8859-x` 两个系列——名字按 iconv-lite 接受的写法来
（`GB2312`、`win1252`、`cp936`）；这套之外的编码（`cp437`、`utf7`）没有。

2026-09-30 之前，`Buffer` 和 `iconv` 那三个都不存在（脚本里一用到就抛异常，什么也产出
不了），`parseQuery` 和 `parseUrl` 是十行的近似实现，`pattern` 和 `port` 分别是 `''`
和 `0`。

还有一些也在，因为 whistle 脚本默认它们存在：`substr`、`escape` / `unescape`，以及
`RegExp.$1`…`$9` / `lastMatch` 这些静态属性。

**脚本能花多少时间。** whistle 在 60 ms 后停掉脚本；本项目是 **1 秒**，因为这里的引擎
比 V8 慢一个数量级，而在那边能跑完的脚本，在这边也必须能跑完。被停掉的脚本和抛异常的
一样，什么也不产出——它 push 的规则不算，对响应做的修改也不算——请求照常继续。它的
会话里会写明：一条 kind 为 `script-failed` 的 `unapplied` 记录，写明是哪个算子，以及是
抛了异常（附错误信息）还是超时。同样的 1 秒也适用于 `frameScript` 的顶层代码和它处理
函数的每一次调用（处理函数超时会结束该连接上的脚本，之后的每一帧都不经脚本直接通过），
以及 PAC 文件和每一次 `FindProxyForURL`。

另外还有两道限制，能更早拦住常见的失控情况，报错也更清楚：一次函数调用里的循环加起来
跑到 3,000,000 次迭代就会被停掉（空循环大约 20 ms），递归则在几百层栈帧后停掉。

这 1 秒管不到的地方：被*内置函数*回调的代码——`forEach`、`map`、`sort`、`replace`
的回调——以及 `frameScript` 单行 `ctx.frame` 写法每帧用 `eval` 执行的那段文本。这些会
一直跑到结束，只受每次调用的循环上限约束。脚本不在代理的工作线程上运行，所以一个停不下
来的脚本只会占住它自己的请求（和一个线程），不影响别的；2026-10-02 之前脚本是在工作
线程上跑的，一个调用了循环函数的循环——每次调用的循环上限看不到它——会永远占住它的
请求，这样的脚本有十个，整个代理就停了。

启动一个脚本大约花 0.5 ms；第一次用到 `Buffer`、`parseUrl`、`parseQuery` 或某个
`iconv` 辅助函数时，会再多花大约 3 ms，每次脚本运行只多这一次。

脚本写进 `values` 的内容，用来回答它 push 的规则里的 `{name}` 引用——见
[在规则文本里声明的 Values](#在规则文本里声明的值)。

仍然存在的差异：`isLocalAddress` 不会去查代理解析过的所有域名的缓存，whistle 的会查；
另外没有 `require`、`process` 或 `setTimeout`——上游也没有，`vm` 上下文里只有
JavaScript 本身，别的什么都没有。

`frameScript` 对 **WebSocket** 的帧和**普通 TCP 隧道**的数据块执行 JavaScript——
[`frameScript.md`](https://wproxy.org/docs/rules/frameScript.html)：
"操作 WebSocket 和普通 TCP 请求数据帧"。

```js
var seen = 0;                                     // 整个连接期间一直保留
ctx.sendToServer('hello');                        // 连接建立时发出
ctx.handleSendToServerFrame = function (buf, opts) {
  seen++;
  if (seen > 100) return null;                    // 什么也不发
  return String(buf).replace(/1/g, '***');
};
ctx.handleSendToClientFrame = function (buf, opts) {
  ctx.sendToServer('got ' + buf.length + ' bytes'); // 脚本自己发出的一帧
  return buf;                                     // 原样放行
};
```

```
chat.example.com        frameScript://{frame.js}
db.internal:5432        frameScript://{frame.js} enable://inspect
```

**每个连接一个脚本。** 连接建立时求值一次，之后每一帧都交给它的两个处理函数之一——
所以上面的 `seen` 能正常计数。2026-09-30 之前，脚本每一帧都重新求值一遍，计数器永远
是 1。

**处理函数拿到什么**：帧本身，是一个 `Buffer`（文本帧也是——要字符串就写
`String(buf)`），以及 `opts`：`{ opcode, mask, compressed, length }`，其中 `opcode`
为 1 是文本，为 2 是二进制。运行期间，脚本能看到 `reqScript` 能看到的东西——`url`、
`method`、`headers`、`getValue`、`parseUrl`、`Buffer` 等等——只是没有 `rules` 和
`values`。

**它返回什么**就发送什么，按上游 `util.toBuffer` 的读法来读
（`_original/lib/socket-mgr.js:303-323`）：

| 返回值 | 发送的内容 |
|----------|-----------|
| 字符串、数字 | 对应的文本 |
| 对象或数组 | 它的 JSON |
| `Buffer` | 这些字节 |
| `undefined`、`null`、`0`、`''` | **什么也不发**——这一帧被丢弃 |
| *（抛了异常）* | 错误信息，形如 `boom (handleSendToServerFrame)`——你就是靠它发现出错的，在 Frames 面板里和对端都能看到 |

**脚本自己发的帧**——`ctx.sendToServer(data, opts)`、`ctx.sendToClient(data, opts)`，
写在脚本顶层或处理函数里都行——会在正在处理的那一帧之前发出，并且会经过它传输方向
对应的处理函数，带着 `opts.frameScript === true`，这样处理函数可以把自己发的帧放过去。
`{ binary: true }` 发二进制帧。

**普通隧道需要 `enable://inspect`。** 本代理不读取内容的 `CONNECT` 隧道——既不是 HTTP、
也不是它要拦截的 TLS 握手的流量，或者是规则说了别碰的——以及升级到 WebSocket 以外
协议的 `Upgrade:`，都是按字节转发的。加上 `enable://inspect` 后，从任一侧读到的每个
数据块都会作为一帧显示在隧道那一行下面，并交给脚本。一个数据块就是一次读取返回的内容：
TCP 没有消息边界，需要完整消息的处理函数得自己拼起来，在上游也一样。
`enable://pauseSend` 和它的三个同类会隐含 `inspect`，在隧道上除此之外什么也不做。

和 whistle 2.10.10 不同的地方如下，每一条都由 `tests/differential/core-bench.js` 实测
（28 个帧和隧道用例，22 个一致）：

| | whistle | 这里 | 原因 |
|---|---|---|---|
| 处理函数里的 `ctx` 和 `Buffer` | `ReferenceError`，并被当作帧发出去——上游在脚本跑完后会清空它的全局变量，所以只有事先保存的引用（`var c = ctx`）能用 | 都能用 | 文档里的例子不在任何函数里读 `ctx.`，但实际会写的每个脚本都会这么读 |
| 处理函数返回 `Buffer` 的二进制帧 | 被当作**文本**帧重新发出（帧的选项写着 `opcode: 2`，而发送方读的是 `opts.binary`）——不是 UTF-8 的字节到对面就乱了 | 保持二进制 | 处理函数把 `opts.binary` 设成什么都会照办；没设时，字符串是文本，`Buffer` 保持原帧的类型 |
| 脚本顶层调用 `sendToServer`，同时又装了这个方向的处理函数 | 这一帧永远到不了 | 能到，会经过处理函数 | — |
| **隧道**脚本顶层调用 `sendToClient` | 写在回应 CONNECT 的 `200` 之前；客户端的 CONNECT 失败 | 写在它之后 | — |
| `typeof ctx.frame`、`typeof ctx.direction` | `undefined` | 一个对象和一个字符串 | 本项目的单行写法，见下文 |
| 分片的 WebSocket 消息 | 先重组，再交给脚本 | 每个分片原样转发 | 本项目逐帧转发；只有完整的消息才会交给处理函数 |
| 隧道上的 `enable://pauseSend` … | 暂停或丢弃数据块 | 只是显示，别的不做 | 没实现 |

客户端的帧交给 `handleSendToServerFrame`，和名字说的一样。在普通 WebSocket 上，
whistle 2.10.9 及之前是交给 `handleSendToClientFrame` 的；2.10.10 修好了
（avwo/whistle#1358），`tests/differential/ws-bench.js` 通过两个代理实测了这一点。

**本项目的单行写法**仍然可用：一个不装任何处理函数、但提到了 `ctx.frame` 的脚本，会对
每个*文本*帧求值一次，帧在 `ctx.frame.data` 里，方向在 `ctx.direction` 里。

```js
if (ctx.direction === 'send') ctx.frame.data = ctx.frame.data.toUpperCase();
```

每次都在同一个引擎里运行，所以它设的全局变量到下一帧还在。

**开销。** 带脚本的连接会为脚本单独占一个线程——引擎不能在线程间挪动，而一个连接的
两个方向是两个任务。没有 `frameScript` 的连接不占。处理函数里的循环跑到三百万次迭代
会被切断，和所有脚本一样。

### `log://` —— 页面的控制台，搬到这里

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `log` | 一个 id，或 `{name}` | 往命中的页面里注入一段脚本，把页面写到 `console` 的内容——以及未捕获的错误——发到本代理的 **Console** 面板 |

它是给没法打开开发者工具的页面用的：App 里的 WebView、手机上的浏览器。

```
m.example.com   log://shop
```

1. 在设备上通过代理打开页面。
2. 打开本代理的控制台，点工具栏里的 **Console**。
3. 页面传给 `console.log` / `info` / `warn` / `error` /
   `debug` 的所有内容都在那里，最新的在最下面，并带着页面地址。未捕获的异常（带调用栈）、
   未处理的 promise rejection、加载失败的 `<script>` 或 `<img>` 也都在——每一条都记为 `error`。

id（`shop`）是一个分组。多条规则用不同的 id，就会有多个分组，列在面板左侧；点其中一个
只显示它的条目。不带 id 的 `log://` 归到 `(no id)` 下。

**如果什么都没出来**，按值得检查的先后顺序：

| 你看到的 | 原因 |
|---|---|
| Network 里有这个页面的会话，但带一把锁、没有 body | 对这个域名的 HTTPS 没有被拦截，所以没有页面可以注入。要么设备没信任根证书，要么拦截是关着的 |
| 会话的 Rules 标签页里 `log://…` 显示为 "not applied" | body 超过了 `--body-rewrite-limit`，或者用了一种解不开的 `content-encoding`——原因就写在那里 |
| 响应是 `304` | 浏览器用了缓存的副本，里面没有脚本。刷新一次就好：`log://` 规则会去掉请求里的缓存校验头，所以下一次是完整的 `200` |
| `console` 的条目没有，但错误能收到 | 请求命中了 `disable://interceptConsole`——见下文 |
| 页面里有 `<meta http-equiv="Content-Security-Policy">` 标签 | 写在*响应头*里的 CSP 会自动帮你去掉；写进 HTML 里的不会，它会阻止内联脚本执行。用 `resReplace://` 把它去掉 |

**注入了什么、注入到哪。** 在 HTML 响应里，注入一个 `<script>` 元素，作为 `<head>` 里的
第一个东西，所以它比页面自己的任何脚本都先运行。在 JavaScript 响应里，把同样的源码放在
文件开头——这样规则即使没命中页面的 HTML、只命中了它的脚本，也照样能上报。别的都不动：
覆盖整个域名的规则也会命中它的图片和下载，这些既不会被采集，也不会被修改。这段脚本大约
4 KB，用 ES5 写，兼容老的 WebView，重复注入的第二份什么也不做。

它**只有一行，后面不带换行**，所以调用栈里的行号还是你源码的：`cart.js:41` 就是
`cart.js` 的第 41 行。只有第一行的列号会变。（你自己的 `log://{name}` 脚本——见下文——
你写了几行就占几行，它后面的所有内容都会往下挪这么多行。）

脚本通过向**页面自己的 origin** 上的 `/.whix/log` 发 `POST` 来上报。页面的请求都经过
本代理，所以代理自己答复这个路径（`204`），源站永远看不到它。这就是为什么它在
`https://` 页面上也不会报混合内容错误，也不需要 CORS。这也意味着这个路径被占用了：一个
真的提供 `/.whix/log` 的网站，通过本代理是访问不到这个路径的。

和 `html*`/`js*` 算子一样，注入会去掉响应的 `Content-Security-Policy` 头，并让它不可
缓存（`_original/lib/inspectors/log.js:47-48`）；`enable://keepCSP` 和
`enable://keepCache` 可以分别关掉这两项。

**只要错误，不要 `console`。** 同一个请求加上 `disable://interceptConsole`，就不碰
`console`，但仍然上报未捕获的错误：

```
m.example.com   log://shop disable://interceptConsole
```

**发送前修改或丢弃条目。** 在页面里定义 `window.onBeforeWhistleLogSend(args, level)`。
`args` 是页面传入的参数数组；直接原地修改它。把它清空，或者返回 `false`，这一条就不
发送。`log://{name}` 会把名为 `name` 的值作为第二段脚本，紧跟在采集脚本后面注入——想
在不改网站的前提下定义这个函数，就在这里定义：

````
``` strip-tokens
window.onBeforeWhistleLogSend = function (args, level) {
  if (level === 'debug') { return false; }
  for (var i = 0; i < args.length; i++) {
    if (typeof args[i] === 'string') { args[i] = args[i].replace(/token=\w+/g, 'token=***'); }
  }
};
```
m.example.com   log://{strip-tokens}
````

这时分组名就叫 `strip-tokens`。

**这些限制，全都是故意的。** 参数以文本形式发送：字符串原样发，`Error` 发它的调用栈，
DOM 节点写成 `<div#id.class>`，其他的发 JSON，重复出现的对象写成 `[Circular]`。单个
参数截断在 64 KiB，对象里的单个字符串截断在 8 KiB。代理保留最新的 2000 条，最多
8 MiB，**存在内存里**——重启后面板就清空了。页面关闭过程中写的条目，浏览器支持
`navigator.sendBeacon` 时用它发送，不支持就丢了。

**和 whistle 的不同。** 规则本身、id、`{name}`、`interceptConsole` 和
`onBeforeWhistleLogSend` 都是 whistle 的（[log](https://wproxy.org/docs/rules/log.html)）。
脚本是本项目自己写的，不是 whistle 的 `assets/js/log.js`：whistle 往它内部路径下的一个
`cgi-bin` 路由发送，把对象显示成可展开的树；本项目把每个参数显示成文本。whistle 把脚本
写在文档的最顶部、doctype 之前；本项目把它放在 `<head>` 里面。
`tests/differential/core-bench.js`（`CASES=log`）对照 whistle 检查了客户端能看到的
部分——命中规则的页面返回时带有采集脚本，同一页面不命中规则时不带，纯文本 body 不受
影响——`tests/page_log_e2e.rs` 检查了到 Console 面板 API 的完整往返。

同样的条目也可以通过 HTTP 读取：[`GET /api/logs`](API.md#页面日志)。

### weinre（HTML 调试注入）

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `weinre` | id，或脚本的 URL/路径 | 往 HTML 响应里注入一个 weinre `<script>` |

[weinre](https://www.npmjs.com/package/weinre) 是一个远程 DOM 检查器：你自己运行的一个
服务端、页面从它那里加载的一段脚本，以及你在那个服务端上打开的检查器页面。**whix 不包含
weinre**——whistle 把它整个打包进去，从自己的端口提供。所以在这里你得自己启动服务端，
再告诉 whix 它在哪：

```sh
npx weinre --boundHost -all- --httpPort 8080     # weinre 服务端
whix --weinre http://192.168.1.5:8080      # ……再告诉代理去哪找它
```

```
.example.com   weinre://mysession
```

页面随后会加载 `http://192.168.1.5:8080/target/target-script-min.js#mysession`，检查器
在 `http://192.168.1.5:8080/client/#mysession`。要用**设备**能访问到的地址，不要用
`127.0.0.1`。

没有 `--weinre` 时，单独一个 id 没地方加载脚本。这时什么都不注入，响应头保持原样（见下面
关于 CSP 的说明），会话里也会写明：它的 Rules 标签页把 `weinre://` 规则显示为
"not applied"，`unapplied` 里的 kind 是 `no-weinre-server`。（以前它会注入一个指向本代理
自己端口的 `<script>`，而那里返回 `404`：页面加载了，检查器永远连不上，也没有任何提示说
为什么。后来改成什么都不注入，但仍然会去掉页面的 CSP 和缓存头。）

规则也可以直接写脚本地址，这样就不需要 `--weinre`：

```
example.com    weinre://https://debug.example.com/target/target-script-min.js
```

> 规则行里的 `#` 会开始一段注释，所以 `weinre://https://…/script.js#id` 在规则被读取
> 之前就丢了 `#id`。要用完整 URL 又要带上 id，就把 URL 放进一个值里再引用它：
> `weinre://{agent}`。

标签注入在 `</head>` 之前（或 `<body>` 之后）。`https://` 页面会把来自 `http://` weinre
服务端的脚本当作混合内容拒绝；weinre 本身不支持 TLS，所以要么在它前面套一层支持 TLS 的
东西，要么用 `http://` 来调试页面。

注入会让响应失去 `Content-Security-Policy` 和可缓存性，和 `html*`/`js*`/`css*` 算子完全
一样：页面自己的 CSP 禁止的 agent 永远不会运行，被浏览器缓存下来的 agent 会比请求它的
规则活得更久（`_original/lib/inspectors/weinre.js:37-38`）。只有真正注入时才这样——什么
都没注入的 `weinre://` 两样都不动。`enable://keepCSP` 和 `enable://keepCache` 可以分别
关掉这两项。

**和 whistle 的不同**，由 `tests/differential/cases-compose.js` 对照 2.10.8 实测：whistle
追加的是它**自己打包的 agent**——整个 `assets/js/weinre.js`，内联，放在 body 的*末尾*——
指向 whistle 自己运行的 weinre 服务端。whix 两样都不打包，所以它输出一个 `<script src>`，
指向 `--weinre` 给出的服务端，并放在 `<head>` 里。由此还有两个后果：whistle 也会处理
**JavaScript** 响应，直接把 agent 追加进去（`weinre.js:33-35`），而在那里一个
`<script src>` 标签毫无意义；另外 whistle 会改写 **gzip 压缩**的 body，而本项目不动压缩
过的响应。

### `locationHref://` —— 自己跳转的页面

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `locationHref` | `[js:\|html:\|replace:]<url>` | 用一个把客户端导航到 `<url>` 的文档来**答复**请求 |

它是 mock，不是注入：whistle 把它和 `file://` 那些归为一类（`isFileProxy`，
`_original/lib/rules/protocols.js:282`），所以它和它们共用那一个目标地址槽位——先写的
那行胜出——而且完全不会联系源站。

| 值 | 答复 |
|-------|--------|
| `<url>` | `text/html`，`<script>window.location.href = "<url>";</script>` |
| `js:<url>` | `application/javascript`，只有那句赋值，外面不包标签 |
| `html:<url>` | 强制用 HTML 形式 |
| `replace:<url>` | `window.location.replace(…)`，不留历史记录 |
| 空 | `200`、`text/html`，body 为空 |

不带前缀时，浏览器*为了加载脚本*发出的请求（`Sec-Fetch-Dest: script`）会拿到
JavaScript 形式，这样为页面写的跳转就不会被套进另一个 `<script>` 里。如果值解析出来就是
请求**自己**的 URL，就什么也不答复——请求照常发出去，而不是没完没了地跳转到自己。

```
old.example.com    locationHref://https://new.example.com/
cdn.example.com    locationHref://js:https://cdn2.example.com/app.js
example.com/old    locationHref://replace:/new
```

### 开关、引入与 Values

| 算子 | 值 | 作用 |
|----------|-------|--------|
| `enable` | 开关（可多个） | `abort`/`abortReq`/`abortRes`（销毁连接，见下文）、`cors`（等同于 `resCors://enable`）、`captureStream`（让源站别压缩）、`gzip`/`br`/`deflate`（强制响应发出去时用这种编码）、`showHost`（把实际连到的地址写进 `x-host-ip`）、`ignoreSend`/`ignoreReceive`（丢掉 WebSocket 的一个方向）、`pauseSend`/`pauseReceive`（扣住 WebSocket 的一个方向，直到控制台放行）、`safeHtml`/`strictHtml`（每次注入前都先检查一道）、`keepCSP`/`keepCache`/`keepAllCache`（发生注入时照样保留）、`hide`/`show`（不让请求进抓包记录，或者把它放回来，见下文）、`websocket`（不管升级请求自称什么，都当 WebSocket 解析）、`h2`/`http2`/`httpsH2`（向 HTTPS 源站提供 HTTP/2，见下文） |
| `disable` | 开关（可多个） | 见下面两张表 |
| `trailers` | `name=value` / `{json}` | 给 HTTP 响应加 trailer 头（会强制使用 chunked），见下文 |
| `headerReplace` | `{"<scope>.<name>:<pattern>":"<repl>"}` | 改写某个头的值；scope 取 `req.`/`reqH.`/`res.`/`resH.` |
| `responseFor` | 一个名字，或 `name=<headers>` | 给**响应**加上 `x-whistle-response-for` 标注，见下文 |
| `rule` | Values 条目名 | 引入这个条目里的规则，一并应用 |
| `rulesFile` | 文件路径、`{value}` 或 `(inline)` | 引入规则，一并应用。也可以写成 `reqRules://`、`ruleFile://`、`ruleScript://`、`rulesScript://`、`reqScript://`，见下文 |
| `pipe` | 插件名 | 经由一个已注册的服务转发（和 `plugin` 类似） |

算子的值**整个**是 `{name}` 时，或者值里任意位置出现 `${name}` 时，会被替换成同名 Values 条目的内容（来自 `--value name=…` 或控制台的 Values 面板），见[算子的值可以是什么](#算子的值可以是什么)。

`disable://` 接一个或多个开关，用 `|` 分隔。它们在请求发出去的路上拿掉点东西，或者在响应回来的路上拿掉点东西：

| 开关 | 从请求里拿掉 |
|------|-------------------------|
| `ua` | `User-Agent` |
| `gzip` | `Accept-Encoding`，于是源站返回不压缩的内容 |
| `cookie` / `cookies` / `reqCookie` / `reqCookies` | `Cookie` |
| `referer` / `referrer` | `Referer`（两种拼法都认，因为头名本身用的就是那个错误拼法） |
| `ajax` | `X-Requested-With` |
| `cache` | `If-None-Match`、`If-Modified-Since`、`ETag`、`Last-Modified`，并设上 `Pragma`/`Cache-Control: no-cache` |
| `keepAlive` / `keepalive` | 设上 `Connection: close`，到源站的这一跳不进连接池 |

| 开关 | 对响应的改动 |
|------|-------------------------|
| `cookie` / `cookies` / `resCookie` / `resCookies` | 去掉 `Set-Cookie` |
| `cache` | `Cache-Control: no-cache`，外加一个已过期的 `Expires` 和 `Pragma` |
| `csp` | 去掉 `Content-Security-Policy` 这类头 |
| `301` | 把 `301 Moved Permanently` 改成 `302 Found`，浏览器就不会缓存这次重定向 |
| `userLogin` | `statusCode://401\|407`，或者改出来的 `replaceStatus://401\|407`，本来会带上 `WWW-Authenticate` / `Proxy-Authenticate` 质询，这个开关把它扣下不发（`enable://userLogin` 优先于它；只想对某一行生效，用 `lineProps://disableUserLogin`，见 [`LINE_PROPS.md`](LINE_PROPS.md)） |
| `trailers` / `trailer` | 完全不发 trailer 部分，源站发来的也不发 |
| `trailerHeader` | 发 trailer，但不发预告它们的 `Trailer:` 头 |
| `doctype` | HTML 前置插入（prepend）时，不在前面加 `<!DOCTYPE html>` |

`disable://tunnel` 不属于这两张表：它什么都不拿掉，而是直接拒绝这条连接，见[中断的是连接，不是请求](#中断的是连接不是请求)。`disable://h2`、`http2` 和 `httpsH2` 也不属于：它们让到 HTTPS 源站的这一跳停留在 HTTP/1.1，见 [`h2`](#h2--用哪个-http-版本连-https-源站)。

本项目不认识的开关**不起作用**：照样能解析，只是什么都不做，而不是让这条规则报错。

#### 写在请求头里的规则

请求可以自带规则，放在五个头里（`initHeaderRules`，`_original/lib/rules/index.js:576-638`）：

| 头 | 里面放什么 |
|---|---|
| `x-whistle-rule-value` | 规则文本 |
| `x-whistle-rule-host` | 再加一行，追加在规则文本后面 |
| `x-whistle-rule-key` | 一个 **Values** 条目的名字，条目内容加在最前面 |
| `x-whistle-rule-name` | 一个**规则组**的名字，组里的文本追加在后面——仅 `multiEnv` 下有效 |
| `x-whistle-key-value` | 一个 JSON 对象，放只供这段规则文本使用的 Values |

每个头都会先做百分号解码（`decodeURIComponent`；转义写坏了就保留原文，不会只解一半），然后按这个顺序拼起来：

```
<values[x-whistle-rule-key]>
<x-whistle-rule-value>
<x-whistle-rule-host>
<groups[x-whistle-rule-name]>
```

**读不读这些头取决于模式，删却不看模式。** `getValue` 里的 `delete req.headers[key]` 在它决定要不要返回值之前就执行了（`:558-570`），所以不管这个代理怎么配置，客户端写的规则文本都到不了源站，也不会被上级代理里的 whistle 执行。本项目也是这样，一直如此。

各模式下有什么不同：

| 启动参数 | 这五个头 | 谁优先 |
|---|---|---|
| *（什么都不加）* | 拿掉，内容丢弃 | — |
| `-M enableRequestHeaderRules` | 读取 | **存储的规则** |
| `-M multiEnv`（或 `nohost`、`multienv`，以及展开后包含它的 `-M multiple`） | 读取，包括 `x-whistle-rule-name` | **请求带的规则** |
| 在上面任一个之外再加 `-M strict` | 拿掉，内容丢弃 | — |

优先级照搬上游，就是一个 `if`（`initRules`，`:647-652`）：`multiEnv` 先解析存储的规则，再把请求带的规则合并上去、**覆盖**前者；`enableRequestHeaderRules` 正好反过来。

`-M multiEnv` 还连带两件事，都是上游的行为，也都实测过：

* 只有**默认**规则组生效。具名的规则组照样加载、照样能编辑，但选中它没有任何效果——这个模式下 `getSelectedRulesList()` 返回 `[]`（`_original/lib/rules/util.js:204-206`）。本项目的控制台干脆不让你切换，免得记下一个代理根本不理会的状态；
* 全局开关不再能打开 HTTPS 拦截。`isEnableCapture()` 一上来就是 `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`（`rules/util.js:547-550`），所以 `-M capture|multiEnv` 和 `-M multiEnv|capture` 都会原样放行 CONNECT。**规则**里写的 `enable://capture` 仍然有效：它是从规则里解析出来的，从不看那个全局开关。

> **`multiEnv` 让发请求的人自己决定请求去哪。** 它是给一个代理同时服务多套环境用的——每个请求自己点名用哪套，代理上什么都不存——不适合放在共享网络上的代理。正因如此，两边的代理默认都不开。

`x-whistle-rule-name` 是个例外：不在 `multiEnv` 下时，上游根本不对它调用 `getValue`，所以它既不被读取，**也不被删除**，会一路到达源站。这一点对照 whistle 2.10.8 实测过，本项目与之一致——包括一个边角情况：`-M strict|multiEnv` 会把它拿掉，却什么也不读，因为 `strict` 压掉的是调用的返回值，而不是调用本身。

以上每一条都由 `tests/differential/header-rules-bench.js` 逐个探测实测过（50 个探测，0 处不同），并由 `tests/header_rules_e2e.rs` 在不依赖 node 的情况下固定下来。

#### 前置代理声称的内容

一个代理如果躲在另一个代理后面，客户端的地址、协议（scheme）和 host 是通过请求头告诉它的。whistle 读下面这几个头（`handleForwardedProps`，`_original/lib/util/index.js:3697-3728`；`getFullUrl`，`lib/util/common.js:1231-1266`）：

| 头 | 声称的是什么 | 什么时候采信 |
|---|---|---|
| `x-forwarded-host` | 客户端请求的 host | `-M x-forwarded-host` |
| `x-forwarded-proto` | 客户端用的协议 | `-M x-forwarded-proto` |
| `x-forwarded-for` | 客户端的地址 | `-M keepXFF` |
| `x-whistle-real-host` | host，用 whistle 自己的写法 | 本项目在 **`-M x-forwarded-host`** 时；上游**总是**采信 |
| `x-whistle-forwarded-props` | *“帮我把这三道闸都打开”* | 本项目**从不**采信；上游**总是**采信 |

前三个头**只有被采信时才会被删掉**——上游的删除写在使用它们的那个分支里，所以没开对应模式时，前置代理写的这些头会照样到达源站，源站可能确实需要它们。

**后两个头，本项目从每个请求里删掉，并且不读。** 模式代表的是部署代理的人在启动时一次性认定：前面确实有个前置代理。头则是*发送方*说了算；代理分不清这是部署者配的前置代理，还是网络上随便哪个客户端，因为头是唯一的证据，而它正是发送方自己写的。在什么模式都不设的情况下实测：`x-whistle-real-host` 把请求送到了另一个源站，`x-whistle-forwarded-props: proto` 让一个普通的明文请求命中了 `https://…` 匹配串。`x-whistle-real-host` 在 `-M x-forwarded-host` 下会被采信，因为这个模式管的正是这件事。

**`x-forwarded-proto` 改变的是哪个匹配串命中，不是连接本身。** 标成 `https` 的请求会按 `https://…` 去匹配（没写端口时还按 443 端口匹配），但它离开这个代理时，跟进来时一模一样。实测：whistle 并不会为它发 ClientHello。所以 `tests/differential/forwarded-bench.js` 在源站一侧数握手次数，`tests/forwarded_e2e.rs` 则检查源站收到的第一个字节。

还有三个标记头和规则头一样处理，理由也一样——它们说的是关于*连接*的事实，而这些事实连接本身就能回答：

| 头 | whistle 在哪里丢掉它 |
|---|---|
| `x-whistle-client-port` | `_original/lib/init.js:181`，升级和隧道的路径上也各丢一次 |
| `x-whistle-alpn-protocol` | `init.js:224`，在那里被消费掉 |
| `x-whistle-client-id` | `res.js:717-723`——**除非**设了 `enable://keepClientId`；本项目也认这个开关，只用于这一个目的，别无他用 |

#### `websocket` —— 不自称 `websocket` 的升级请求

有些客户端说的是 WebSocket，名字却是自己起的：`Upgrade: ws`、某个厂商自定义的字符串，或者干脆拼错了。两边的代理都会把这种连接当成不透明的字节流走隧道，不解析出任何帧；也都把 `enable://websocket` 当作指令，照样按 WebSocket 去解析——上游的判断是 `socket.enable.websocket || util.isWebSocket(headers)`（`_original/lib/https/index.js:81`），本项目用的是同一个表达式。

#### 把 body 显示成帧

whistle 的 Frames 面板不只给 WebSocket 用：普通的 body 如果是事件流（event stream），或者有个头指定了分隔符，也会被切成帧（`handleResBody` / `parseFrame`，`_original/lib/inspectors/data.js:67-135,:323-345`）。本项目以前只把这种 body 显示成一整块预览，对一个永远不结束的流来说，等于什么都没显示。

* **`content-type: text/event-stream`** 按每个空行切开，一个 SSE 事件一帧。只看类型本身：`text/event-stream; charset=utf-8` 也算事件流。whistle 2.10.8 拿整个头去比较，把后者显示成一整块 body；2.10.9 修了这个问题，本项目跟随修复后的行为。
* **`x-whistle-custom-frame-separator`** 可以指定任意分隔符，请求和响应上都能用，对任何内容类型都有效——但**必须同时加上 `enable://captureStream`**，这个不能省：

  ```
  api.example.com enable://captureStream resHeaders://(x-whistle-custom-frame-separator=%0A)
  ```

  这样就能把按换行分隔的 JSON 流切成一行一帧。头的值会做百分号解码（`%0A` 是换行；FAQ 里印的是 `%A0`，那是另一个字节，什么也切不出来）；值以 `/` 开头时，分隔符会留在它结束的那一帧上。不管这个头能不能用，都会在另一端看到之前被删掉。

  之所以必须加这个开关，是因为这个头不一定是你加的：它可能来自源站，也可能来自上级代理里的 whistle，而别人发来的头不该决定这个代理要留存什么。whistle 2.10.8 也要求这两样同时出现——通过它自己的帧接口实测，只有分隔符、没有开关时，它一帧也不切，请求侧和响应侧都是这样。2.10.10 对**没有 body** 的请求（比如 GET）的响应，不加开关也会切帧，这是它调整了“何时记录请求已发出”带来的副作用；它的 changelog 和 FAQ 仍然要求加开关，本项目也一样。事件流是例外，会自动打开这个开关。
* **`disable://captureStream`** 把这两种都关掉。压缩过的 body 永远不切帧——在 deflate 流里找分隔符，什么也找不到。

从请求 body 切出来的帧标为 `send`，从响应切出来的标为 `receive`；在面板里，这是它们和 WebSocket 帧唯一的区别。被隐藏的请求（`enable://hide`）不产生帧。

#### `hide` —— 控制台根本不知道的请求

`enable://hide` 让请求照常发生，只是不进抓包记录。决定隐不隐藏的是四个开关，不是一个（`checkHideProp`，`_original/lib/util/index.js:3982-3987`）：`enable://hide` 和 `disable://show` 负责隐藏；`enable://show` 和 `disable://hide` 负责取消隐藏，两边冲突时取消隐藏的一方胜出。之所以成对存在，是因为两半通常来自不同的规则行——一条宽泛的 `enable://hide` 盖住整个域名，再用一条 `enable://show` 把你正在看的那个请求放出来。

被隐藏的请求不显示、不存储，也不能重放，本项目和上游都是如此——上游的数据服务也是靠同一个判断来把关的（`inspectors/data.js:59`）。上游另有只针对 Composer 的那一对（`enable://hideComposer`）和全局抓包开关，本项目没实现：这里的会话不记录它是不是 Composer 发出的。

#### `auto2http` —— https 那一段退回明文

把 `https://www.example.com` 指到一个只会说明文 HTTP 的开发服务器，几乎是每个人拿到调试代理做的第一件事，而单靠这一步是跑不通的：到源站这一段走的是 https，服务器却不是，握手失败。whistle 会去掉 TLS 把请求再发一次，[`host.md`](https://wproxy.org/docs/rules/host.html) 也写明了，`www.example.com 127.0.0.1:5173` 之所以能用，靠的就是这个。

这不是无条件的。`checkAuto2Http`（`_original/lib/util/index.js:3191-3198`）要求满足三个条件之一，而 `disable://auto2http` 能推翻全部三个：

* `enable://auto2http`——明说要；
* 这个请求命中了某条 `host://` 规则，不管它指向哪里；
* 连到的地址是**本地**的（回环地址、本机自己的地址，或者带了 host 覆盖的代理这一跳）。

这里有两处不同，都只关乎重试在什么时候发生，不改变重试做什么：

* **地址按写的来判断，而不是按解析结果。** whistle 拿刚查到的 IP 来判断，所以解析到 `127.0.0.1` 的 `dev.local` 在那边算本地，在这里不算。写在 `host://` 规则里的 IP、`localhost`，或者任何带了 `host://` 规则的请求——也就是那篇文档讲的这几种写法——两边都会走到重试。
* **重试来得更早。** whistle 只在错误看起来像 TLS 错误时（`checkTlsError`）才在第一次失败后就降级，否则会先再试一次 https。这里只要这一段没建立起来，不管什么原因，立刻降级。

这份文档的早期版本拒绝实现这个开关，理由是：悄悄把加密连接降级，和不校验证书是同一类问题。这个理由对它当时描述的情况依然成立——但它描述的范围比这个开关窄：这里说的是普通的请求路径，不是 `wss://` 的边角情况；拒绝实现，就意味着人人都会写的那条最常见的规则，在这里回 502，在 whistle 里回 200。所以现在按 whistle 的方式实现了，某个请求想退出，就用 `disable://auto2http`。

#### `h2` —— 用哪个 HTTP 版本连 HTTPS 源站

通过 **HTTP/2** 到达本代理的请求，如果 HTTPS 源站在 TLS 握手里提供 HTTP/2，就继续用 HTTP/2 发往源站；通过 HTTP/1.1 来的，就继续用 HTTP/1.1。这是 whistle 的默认行为（`checkH2`，`_original/lib/inspectors/res.js:174-195`）。代理解密的每个 HTTPS 站点，浏览器都会跟代理说 h2，所以对浏览器来说这是常态。下面的开关可以对命中的请求往两个方向扭转：

| 规则 | 到源站 |
|---|---|
| `enable://h2`（也可写 `http2`、`httpsH2`） | 不管客户端用的是什么，都向源站提供 HTTP/2 |
| `disable://h2`（也可写 `http2`、`httpsH2`） | 只用 HTTP/1.1；`disable` 优先于 `enable` |

```
# 源站在 h2 下有毛病：跟它说 HTTP/1.1
api.example.com disable://h2
```

源站通过 HTTP/2 看到的是：`Host` 头变成 `:authority`，不再作为普通头发送；只对单条 HTTP/1.1 连接有意义的那些头——`Connection`、`Keep-Alive`、`Proxy-Connection`、`Transfer-Encoding`、`Upgrade`、`HTTP2-Settings`，以及值不是 `trailers` 的 `TE`——都会被丢掉，和 whistle 的 `formatH2Headers` 丢的一样。所以 `reqHeaders://connection=close` 这条规则到了 h2 源站那里什么也不剩，两边都是如此。明文 `http://` 源站、WebSocket 升级请求，以及 `internal-proxy://` 这一跳（它会剥掉 TLS），都仍然走 HTTP/1.1。

同一条客户端连接发往同一个源站的所有 h2 请求，共用一条到源站的连接，所以一个有五十个资源的页面只需要一次 TLS 握手，而不是五十次；会话的耗时信息里会写明用的是哪条连接，并把第一个之后的请求都标成复用。和 whistle 有两处不同，都由 `tests/differential/h2-bench.js` 实测过：

* 这里的 `disable://http2` 只关掉**源站**那一半。whistle 的还会停止向客户端提供 h2，于是客户端也退回 HTTP/1.1；这里客户端仍然用 h2。两种情况下源站看到的都一样。
* `httpH2`——不带 TLS、用 HTTP/2 连明文 `http://` 源站——没有实现（见下文）。

#### 本项目没实现的开关

官方的 [`enable`](https://wproxy.org/docs/rules/enable.html) 和 [`disable`](https://wproxy.org/docs/rules/disable.html) 页面分别列了 55 项和 65 项（有几项是同一个开关的两种拼法）。每个名字都在本项目源码里查过；下面是哪里都找不到的那些，各附原因。它们能解析，但什么也不做。

| 开关 | 在上游做什么 | 本项目为什么不做 |
|---|---|---|
| `hideComposer`, `hideCaptureError`, `customParser`, `bigData` | 决定 whistle 自己的控制台显示什么——哪些行隐藏、由谁来渲染抓包内容，以及显示上限从 2 MB 提到 16 MB | 本项目有自己的控制台；抓包的大小上限用 `--body-preview-limit` 设。（`interceptConsole` **是**会读的，见 [`log://`](#log--页面的控制台搬到这里)） |
| `clientId`, `multiClient` | whistle 的 `x-whistle-client-id`——它盖上去的一个头，让上级代理能区分不同的客户端 | 本项目没有 client-id 这个概念，为了迁就一个开关去发明一个，是本末倒置。`keepClientId` **有**实现，用在它在这里唯一可能的含义上：保留*客户端*自己发来的 client-id，见[写在请求头里的规则](#写在请求头里的规则) |
| `useLocalHost`, `useSafePort` | 把 `log://` 和 `weinre://` 的 URL 改写成 whistle 自己内置的 host 和端口 | 这两条规则在本项目里都不指向本项目自己的服务：`log://` 上报到页面自己的 origin，`weinre://` 从 `--weinre` 指定的服务器加载 |
| `authCapture`, `tunnelHeadersFirst`, `tunnelAuthHeader` | 安排插件的 `auth` 钩子和 HTTPS 升级谁先谁后，以及插件通过隧道透传了一些头时，谁的头优先 | 这三个都属于 whistle 的插件 API；本项目的插件 API 是自己的一套，见 [`PLUGINS.md`](PLUGINS.md) |
| `flushHeaders`, `secureOptions` | Node 的底层细节——`response.flushHeaders()` 和 TLS socket 的 `secureOptions` | 这里没有 Node，无从 flush，也无从配置 |
| `httpH2` | 用不带 TLS 的 HTTP/2（h2c）连明文 `http://` 源站 | 没实现：到源站的 HTTP/2 只在 TLS 上提供，见 [`h2`](#h2--用哪个-http-版本连-https-源站) |
| `keepH2Session` | 以 `disable://keepH2Session` 的形式，让多条客户端连接共享同一个到源站的 h2 session，而不是每条连接各用一个 | 这里的 h2 session 总是一条客户端连接一个；跨连接共享，恰恰是连接池刻意不做的事，见 [`ARCHITECTURE.md`](ARCHITECTURE.md#复用源站连接) |
| `dnsCache` | 关掉 whistle 的 DNS 缓存 | 这里本来就没有 DNS 缓存可关，所以这个开关想要的效果已经是默认行为 |
| `clientCert`, `requestCert` | 让代理伪装出来的服务端向**客户端**索要证书（mTLS） | 没实现。配置了双向 TLS 的客户端，连 whistle 能通，连本项目会失败；缺的那一半是客户端证书的存储，而不是这个开关 |
| `forceResWrite` | 什么也不做：请求侧和响应侧**都**只读 `forceReqWrite`（`_original/lib/inspectors/req.js:604`、`res.js:1300`） | 这个开关只存在于文档里，程序里没有 |
| `timeout`（作为 `disable://timeout`） | 什么也不做：whistle 2.10.8 的源码里没有任何一个文件出现这个名字 | 同上——文档写了、程序从来不读的开关 |

> **响应 body 类算子会自动让请求绕过缓存。** `resBody`、`resPrepend`、`resAppend`、`resReplace`、`resMerge`、`html`/`js`/`css` 这几个变体、`attachment`、`resWrite` 或 `resWriteRaw`，只要用了其中任何一个，请求就会自动按 `disable://cache` 处理，不用你另外要求（`notAllowCache`，`_original/lib/inspectors/res.js:54-60,:1328`）。不这样的话，条件请求会得到一个没有 body 的 `304 Not Modified`，改写就悄悄失效了——而且时好时坏，因为这取决于客户端手里已经缓存了什么。
>
> **这是对 whistle 的有意改进，而不是向它看齐；这一条以前的说法正好相反。** whistle 有 `notAllowCache`，却永远走不到：它读的是 `req.rules`，而这十七个算子全在 `pureResProtocols` 里，*请求*阶段会跳过它们。对照真实的 whistle 2.10.8 实测，规则是 `resBody://(REWRITTEN)`，源站会处理 `If-None-Match`：
>
> ```
>              plain request        with If-None-Match (a browser reload)
> whistle      200 "REWRITTEN"      304 ""
> whix   200 "REWRITTEN"      200 "REWRITTEN"
> ```
>
> 也就是说，在 whistle 里一刷新，改写就没了。whix 照 whistle 代码写的意思做，而不是照 whistle 实际的表现做。
>
> `log://` 和 `weinre://` 也会让请求绕过缓存，而这两个 whistle *确实*走得到那段代码（`disableReqCache`，`_original/lib/inspectors/log.js:30`、`weinre.js:26`）——它们是请求阶段的算子。它们要往 HTML 响应里注入脚本，所以得先有一个响应可供注入。

#### Trailers（尾部头）

`trailers://` 是在源站发来的 trailer 部分上**追加**，不是替换（`extend(trailers, newTrailers)`，`_original/lib/inspectors/res.js:1264-1273`）。同名冲突时取规则里的值，`Trailer:` 头会预告后面要来的所有字段。

| 开关 | 作用 |
|------|--------|
| `disable://trailers` / `disable://trailer` | 完全不发 trailer 部分，源站发来的也不发 |
| `disable://trailerHeader` | 发 trailer，但不发预告它们的 `Trailer:` 头 |

HTTP trailer 部分不允许携带的名字会被丢掉，不管来自哪一边（`ILLEGAL_TRAILERS`，`_original/lib/util/common.js:34-53`）：`host`、`transfer-encoding`、`content-length`、`cache-control`、`te`、`max-forwards`、`authorization`、`set-cookie`、`content-encoding`、`content-type`、`content-range`、`trailer`、`connection`、`upgrade`、`http2-settings`、`proxy-connection`、`keep-alive`。在 body 之后才到的 `Content-Length`，和刚刚送完 body 的分帧方式自相矛盾；出现在那里的 `Set-Cookie` 是一份凭据，而客户端并没有义务去读它。

`resSpeed://` 和 trailer 可以同时生效，两者不是二选一。

`headerReplace` 的 scope 有 `req.` / `reqH.`（请求）、`res.` / `resH.`（响应）和 `trailer.`；写成 `resHeaders.` 的键一个都匹配不上，什么也不做。有三处细节继承自上游，很容易踩坑：

- **没写 scope 前缀**的键会沿用前一个键的 scope *和头名*，只用它自己的匹配模式——所以 `{"resH.location:/^http:/":"https:","x:/y/":"z"}` 两次替换都作用在 `location` 上，而不是 `x`。排在最前面、没有 scope 的键会被丢掉。
- 替换串里，`$&` 和 `$1`…`$9` 插入匹配到的整段和各个分组；把其中任意一种写成**双** `$`（`$$1`），插入的就是**百分号编码后**的内容。反斜杠用来转义引用（`\$1` 就是字面量 `$1`）；写两个反斜杠，则保留一个反斜杠，并且照常替换。
- 同一个头出现多次时：每个 `set-cookie` 各自改写，全部保留；其他头先拼成一个（用 `, ` 连接，`cookie` 用 `; `），再当作一个值改写——这正是 Node 交给上游的两种形态。

```
api.example.com     enable://cors
slow.example.com    enable://abort
static.example.com  disable://cache
example.com         trailers://x-checksum=abc123
example.com         headerReplace://{"resH.set-cookie:/Domain=[^;]+/":"Domain=example.com"}
example.com         headerReplace://{"resH.location:/^http:/":"https:"}
page.example.com    responseFor://name=x-served-by,req.x-request-id
example.com         resBody://{mockJson}        # {mockJson} 来自 Values 存储
example.com         rulesFile:///etc/whistle/extra.rules
```

#### `enable://abort` 是两道闸，不是一道

abort 会**销毁连接**——客户端看到的是连接被重置，永远拿不到状态码（上游的 `res.destroy()`，`_original/lib/inspectors/data.js:536` 和 `res.js:1178`）。它可以发生在两个时刻，落在哪个取决于你怎么写：

| 开关 | 何时触发 | 源站 |
|------|-------|------------|
| `abortReq` | 请求发出之前 | 完全不知道有这个请求 |
| `abortRes` | 响应头到达之后，并且在 `resDelay://` 之后 | 完整处理了这个请求 |
| `abort` | 两道闸都布下，所以请求那道先生效 | 完全不知道有这个请求 |

每道闸都能用同名的 `disable://` 撤掉，`disable://abort` 则两道都撤（`needAbortReq`/`needAbortRes`，`_original/lib/util/index.js:3893-3915`）。有了撤销，就可以大范围布下 abort，再给个别请求开口子：

```
example.com          enable://abort
example.com/health   disable://abort
```

想表达“让请求到达源站，然后掐断客户端”，又不改变源站看到的内容，就写 `enable://abort disable://abortReq`。

> 上游还能通过一行 `filter://abort` 布下这两道闸；在 whix 里 `filter://` 只是匹配条件，所以这里只能用 `enable://`。

#### 同一个开关两边都写，等于没写

`enable://x disable://x` 会互相抵消：上游判断开关是否打开用的是 `enable[name] && !disable[name]`（`isEnable`，`_original/lib/util/index.js:678-680`），判断是否关闭则反过来镜像一遍。两者谁先写谁后写不影响结果。本项目原来只实现了镜像那一半，直到实测才发现，所以以前两边都写的开关，在这里是*开*的，在上游却不起作用。

有三个名字不守这条规矩，这些例外来自上游，不是本项目图省事：**`userLogin`** 是 `enable` 优先于 `disable`（`util/index.js:3557-3562`）；**`showHost`** 是直接读取，从不看 `disable`（`res.js:1193`）；**`cors`** 在上游根本没有读 `enable` 的地方。

#### 两处开关上的偏离（实测）

* **`enable://responseWithMatchedRules`** 把命中的规则行写进响应的 `x-whistle-matched-rules` 头：每条规则是 `rawPattern + ' ' + rawMatcher`，用 `\n` 连接，整体做 URL 编码（`addMatchedRules`，`util/index.js:3879-3888`）。顺序按**算子表**，不按书写顺序——whistle 是在遍历 `protocols.js` 时给 `req.rules` 赋键的，所以 `enable://` 排在 `resHeaders://` 前面，`file://` 又排在这两个前面。它在请求侧的孪生开关 `requestWithMatchedRules` 在**两边**的代理里都是死的：上游在响应检查器里调用它（`res.js:770`），那时请求头早就发出去了，所以源站永远看不到这个头。
* **上游在 `disable://trailers` 时仍然预告 trailer。** 请求带 `TE: trailers` 时，whistle 发出 `Trailer: x-t`，然后根本不发 trailer 部分；whix 把预告和 trailer 部分一起去掉。预告一个永远不会到的字段，是在协议层面撒谎，不值得照搬。

#### 中断的是连接，不是请求

`CONNECT` 隧道和进来的 SOCKS 连接没有属于自己的响应可以销毁，所以 abort 直接落在连接本身上，而且发生在**告诉客户端连接已建立之前**：`CONNECT` 根本得不到应答，SOCKS 请求则收到 *connection not allowed by ruleset*。上游不管哪道闸触发，销毁的都是同一个 socket（`_original/lib/tunnel.js:372-374`、`:748-750`）；它建立 SOCKS 连接的方式，是向自己的端口发一个 `CONNECT`，所以隧道被拒，SOCKS 客户端也就被拒了（`lib/index.js:174-193`）。

在这里，两种写法合成了一种。whix 在知道字节要发往哪里之前就得应答 `CONNECT`，所以 `abortRes` 没法像在请求路径上那样，先让源站被连上——两种写法的结果一样，都是不作应答。其余规则全都成立，包括 `disable://abort`。

连接本身不带路径，也不带头，所以一行规则要拒绝连接，只能依据在任何请求之前就已知的东西——地址和客户端：

```
blocked.test         enable://abort   # 隧道被拒绝
example.com/api      enable://abort   # 隧道照常放行；里面的请求不放行
```

`disable://tunnel` 也会拒绝连接，在别处则什么也不做：上游只在这里读这个开关（`_original/lib/util/index.js:3900,:3912`），而 `disable://abort` 撤销它的方式，和撤销另外两个完全一样。

被拒绝的连接仍然算一条会话。它在控制台里显示为一条没有状态码的 `CONNECT`，所以 abort 看起来就是 abort，而不像是客户端自己挂断了。

在 **WebSocket** 上，两道闸仍然是分开的，因为升级请求确实有自己的响应：`abortReq` 在握手发出之前触发——在那之前，升级请求就是一个普通请求；`abortRes` 在服务器的 `101` 到达之后触发，不再把它转发出去（`_original/lib/https/index.js:256-259,:783-786`）。所以服务器完成了握手，客户端却永远看不到协议切换。

#### 多行 `rulesFile://` 怎么合并

`rulesFile` 会累积，但在读文件之前，它的列表会先过一遍筛选（`_original/lib/rules/rules.js:2258-2272`），而筛选看的是这一行是*怎么写的*：

* `reqRules://<path>` 表示“这个文件就是规则”——这样的行**每一条**都保留；
* 其他写法（`rulesFile://`、`ruleFile://`、`ruleScript://`、`rulesScript://`、`reqScript://`）表示一个*候选脚本*，**只有第一条**留下。第二条会被悄悄丢掉。

留下来的文件按解析顺序拼接起来，当作**一份**规则文本解析——所以两个文件争同一个单值算子时，由它们被引入的顺序决定，而不是看它出自哪个文件。

```
example.com   reqRules:///etc/whistle/a.rules     # 保留
example.com   reqRules:///etc/whistle/b.rules     # 保留
example.com   rulesFile:///etc/whistle/c.rules    # 保留（第一条不是 reqRules 的行）
example.com   rulesFile:///etc/whistle/d.rules    # 丢弃
```

> 如果留下来的候选内容看起来像 JavaScript 而不是规则，whistle 还会*执行*它（`isRulesContent`，`_original/lib/rules/index.js:41`），再把脚本输出的规则拼进去。whix 没有动态规则脚本：每个保留下来的文件都按规则文本读取。

规则文本不一定非得是文件。`reqRules://{extra}` 指向一个 **Values** 条目——来自 `--value`、控制台的 Values 面板，或者规则文件里的 ``` ``` ``` 代码块——`reqRules://(…)` 则是内联写法；两者都是 `readRuleValue` 还没碰磁盘就直接返回了 `rule.value`（`_original/lib/util/index.js:1177-1179`）。

#### 生成出来的规则能做什么、不能做什么

对照 whistle 2.10.8 实测（`tests/differential/cases-compose.js`）：

* **组合只有一层。** 写在生成出来的文本*里面*的 `reqRules://` 会被解析，但不会被跟进：`resolveRulesFile` 只读一次引入的内容并合并，之后没有谁再去问合并结果里有没有它自己的 `rulesFile`。所以自己引用自己，或者两步构成的循环，都会在应用一轮之后停下。
* **生成出来的规则优先**于引入它的那个文件，不管是在同一行还是在别的行——对单值算子，`mergeRule` 返回新规则；对可多次匹配的算子，它把新列表放在最前面（`lib/util/index.js:2147-2170`）。
* **`lineProps://important` 仍然比它优先。** 标了 important 的引入行能保住它的单值算子；对可多次匹配的算子，所有 important 的算子——不管来自哪一边——都排在所有普通算子前面。
* **生成出来的规则按请求的当前状态去匹配**，所以如果上面有一行改写了 URL，哪些生成的匹配串能命中就由它决定。
* 生成的文本如果不是规则、是空的、指向不存在的 Values 条目，或者指向不存在的文件，就什么也不贡献，也不算错误。

#### `resRules://` —— 给响应用的规则

`resRules://` 是它在响应阶段的孪生兄弟：whistle 把它和 `resScript://` 放在同一个累积列表里，等响应头到了，再解析这些行里的内容并合并（`getResRules`，`_original/lib/plugins/index.js:1337-1360`）。用 `resScript://` 写法给出的规则文本也按同样方式合并；只有用到了 `ctx` 的 `resScript://` 文本，在本项目里才会被当作[钩子](#脚本)。

生成的文本里只有**响应**那一半生效——上游的 `mergeRules(req, …, isResRules)` 只限于 `resProtocols`（`lib/util/index.js:2198-2203`）——所以里面的 `host://` 或 `reqHeaders://` 会被解析，然后丢掉：读到这段文本时，请求早已发出。真正生效的是所有响应侧的东西，包括 `replaceStatus://` 和各个 body 算子；针对响应的条件（`includeFilter://s:404`）也能判断，因为响应头已经拿到手了。

```
example.com   resRules://{late}          # 一个 Values 条目
example.com   resRules:///etc/whistle/response.rules
```

### 转储文件

`reqWrite://`、`reqWriteRaw://`、`resWrite://` 和 `resWriteRaw://` 把抓到的内容写到一个路径上。它们**不追加**，而且只写**一次**：whistle 先 stat 这个路径，文件已经存在就什么也不做（`checkWriterFile` / `getFileWriter`，`_original/lib/util/index.js:502-546`）。所以规则一直留着、页面刷新了，第一次抓到的内容也原样保留，而不会让文件越长越大，变成好几轮内容首尾相接、彼此没有分界。

| | |
|---|---|
| `enable://forceReqWrite` | 即使文件已存在也写——是**覆盖**，不是追加。别看名字，四个算子共用这一个开关（`req.js:601`、`res.js:1304`） |
| 以 `/` 结尾的路径 | 表示一个目录；转储内容以 `index.html` 落在里面 |
| 缺失的上级目录 | 自动创建 |
| 状态码不是 `200` 的响应 | 转储到 `<file>.<status>`，所以一连串 502 会写进 `dump.502`，和正常抓到的 `dump` 放在一起（`getWriterFile`，`res.js:147-153`） |
| `GET`/`HEAD`/`OPTIONS`/`CONNECT` 上的 `reqWrite://` | 不写——没有 body 可抓（`req.js:582-584`）。`reqWriteRaw://` 照样转储头部 |
| 没有 body 的响应上的 `resWrite://` | 同样的原因，不写。`resWriteRaw://` 照样转储头部 |

**路径会拼上 URL 里没被匹配掉的部分**，和 `file://` 一样——值是通过拼好尾部的 `rule.url` 读出来的（`getWriteFilePath`，`util/index.js:1461-1464`）。正因如此，一条规则才会**每个 URL 一个转储文件**，而不是整轮只有一个文件：

```
api.example.com   resWrite:///tmp/dump      # /users → /tmp/dump/users
                                            # /v2/orders/7 → /tmp/dump/v2/orders/7
api.example.com/users  resWrite:///tmp/dump # 匹配串吃掉了整段路径 → /tmp/dump
api.example.com   resWrite://</tmp/dump>    # <verbatim> 不做拼接
```

查询串不算进文件名——`/users?q=1` 和 `/users` 写的是同一个文件；请求 `/` 时没有可拼的东西，所以写的就是 `/tmp/dump` 本身。

值为**空**时没有路径可以拼接，上游的路径于是变成相对路径，whistle 会转储到它启动时所在的目录——对 `/users` 的请求用 `resWrite://`，会写出 `./users`。一条根本没写路径的规则，却往你的目录树里某个地方写文件，这种行为不值得照搬：whix 什么也不写。由 `tests/differential/write-bench.js` 实测。

```
api.example.com   reqWriteRaw:///tmp/api-request.http
api.example.com   resWrite:///tmp/api-body.json  enable://forceReqWrite
```

**原始（raw）转储里有一处偏离。** whistle 按每个头名到达时的原样写出，为此专门留了一份原始写法（`rawHeaderNames`，`_original/lib/util/file-writer-transform.js:33`）。hyper 在本项目拿到之前就把所有头名统一成了小写，所以这里的 `reqWriteRaw`/`resWriteRaw` 转储写的是 `connection: keep-alive`，whistle 的是 `Connection: keep-alive`。要恢复原始写法，就得为了一份调试转储，让每个头都带着第二份副本穿过整个代理。值、顺序、分帧和 body 都完全一致；由 `tests/differential/write-bench.js` 实测。
### 延迟与限速

| 算子 | 值 | 效果 |
|----------|-------|--------|
| `reqDelay` | 毫秒 | 转发请求前先等这么久 |
| `resDelay` | 毫秒 | 返回响应前先等这么久 |
| `reqSpeed` | **千比特**/秒 | 限制请求 body 的上传速度 |
| `resSpeed` | **千比特**/秒 | 限制响应 body 的下载速度 |

```
slow.example.com   reqDelay://500
slow.example.com   resDelay://1000
slow.example.com   resSpeed://800       # 800 kbit/s ≈ 100 kB/s 下载
```

> 限速会先把 body 缓存起来，再按节奏一块一块吐出去，所以长度已知的 body
> 会被强制改成 chunked 传输。

**速度单位是千比特（kilobit），不是千字节（kilobyte）**——上游文档写的是
千比特，实现是 `parseInt(speed * 1000 / 8)`。本项目直到最近都把这个值当千字节读，
所以按旧行为写的限速规则全都快了 8.192 倍；把这些值乘以 8 就对了。

**只写数字，不带单位。** 两类算子读值的方式不一样，这个差别是上游定的，不是
我们选的：

| | 读值用的是 | `600ms` | `600` | `0` 或 `-600` |
|---|---|---|---|---|
| `reqSpeed` / `resSpeed` | `parseFloat`——取最长的数字前缀 | 600，单位被丢掉 | 600 | **不限速** |
| `reqDelay` / `resDelay` | `Number`——整段文本都得是数字，否则什么都不算 | **完全不延迟** | 600 | **不延迟** |

速度的后缀是*直接丢掉，不做换算*：`resSpeed://20kb` 是 20 **千比特**，
`resSpeed://1mb` 是 1。延迟的后缀更糟——它会悄悄让整条规则失效。因为
`exports.delay` 根本不解析，它直接拿值的文本和 0 比较（`if (time > 0)`，
`_original/lib/util/index.js:3686-3691`），而在 JavaScript 里 `'600ms' > 0`
是 false。两个代理都是这个行为；在 `tests/differential/timing-bench.js` 上实测过。

这四个算子里，0 和负数都表示*不限制*，这是上游的 `> 0` 判断决定的。

### 改写响应

| 算子 | 值 | 效果 |
|----------|-------|--------|
| `replaceStatus` / `statusCode` | 状态码数字 | 替换源站响应的状态码。mock 出来的 `statusCode://401\|407`，以及确实把状态码**改成了**其中之一的 `replaceStatus://`，还会带上对应的认证质询——就是让浏览器弹框要账号密码的那个头；`disable://userLogin` 或 `lineProps://disableUserLogin` 可以不发它 |
| `resHeaders` | `name=value` 对（用 `&` 分隔）或 `{json}` | 设置/替换响应头。值为空会发出一个**空头**，而不是删掉这个头——要删请用 `delete://resHeaders.x`。`set-cookie` 是合并而不是替换，见下文。多行命中时会累加。 |
| `resType` | MIME 类型或简称 | 设置响应的 `Content-Type` |
| `resCharset` | 字符集 | 设置响应 `Content-Type` 上的 charset |
| `resCors` | origin、`*`、`enable`、`{json}` 或 `k=v&…` | 协商 CORS 响应头 |
| `attachment` | 文件名（可选） | 通过 `Content-Disposition: attachment` 强制下载 |
| `cache` | `no`/`no-cache`/`no-store`/秒数/`keep` | 设置 `Cache-Control`、`Expires` 和 `Pragma` |
| `resWrite` | 文件路径 | 把响应 body 写入文件，只写一次——见 [转储到文件](#转储文件) |

```
example.com        resHeaders://x-mitm=intercepted
example.com/api    resCors://*
cdn.example.com    resType://application/javascript
example.com/404    replaceStatus://200
example.com        cache://no
```

**`resHeaders://` 上的 `set-cookie` 是合并，不是替换**（`setCookies`，
`_original/lib/inspectors/res.js:89-122`）。规则里的 cookie 排在前面，后面跟着
源站发来的、*名字*没被规则提到的每一个 cookie——所以设置 `sid` 时，源站的 `csrf`
原样留在原处。有两种写法，效果不一样：

```
example.com   resHeaders://set-cookie=a=1,b=2            # 两个 cookie：按逗号拆开
example.com   resHeaders://{"set-cookie":["a=1,b=2"]}    # 一个 cookie：数组从不拆分
```

cookie 的属性里带逗号时（比如 `Expires=Wed, 21 Oct …`），只能用数组写法。对**任何**
头来说，JSON 数组都表示发多行这个头，不只是这一个。

**`resType` / `reqType`** 既接受完整的 MIME 类型，也接受简称：
`resType://json` 设成 `application/json`，`reqType://form` 设成
`application/x-www-form-urlencoded`，不认识的简称回落到
`application/octet-stream`。值里没有 `;` 时，头上原有的参数会保留，所以对一个
`text/html; charset=gbk` 的响应用 `resType://json`，结果是
`application/json; charset=gbk`。

**`cache`** 只接受开头的整数（`cache://600`；`cache://60s` 也是 60 秒——`parseInt`
的语义）或 `no`/`no-cache`/`no-store`；`keep` 和 `reserve` 不动源站返回的头，
**其他任何值都会被忽略**，和上游一致。不管设成什么，它都会同时写 `Expires` 和 `Pragma`。

**`resCors`** 照搬 whistle 的协商逻辑，而不是一股脑全放行：

| 值 | 效果 |
|-------|--------|
| `*` | `Access-Control-Allow-Origin: *`，不带凭据 |
| 一个 URL | 该 URL 的 origin，外加 `Access-Control-Allow-Credentials: true` |
| `enable` / `credentials` / `use-credentials` | 把请求自带的 `Origin` 原样回写，带凭据 |
| `{"methods":…,"headers":…,"credentials":…,"maxAge":…}` 或 `methods=…&maxAge=…` | 显式设置这些头 |

`headers` 在普通请求上变成 `Access-Control-Expose-Headers`，在预检请求上变成
`Access-Control-Allow-Headers`；如果是预检请求、值又是 `*`/`enable`，会把请求自带的
`Access-Control-Request-Headers` 原样回写。`enable://cors` **不是**上游的开关——
whix 把它留作 `resCors://enable` 的别名。

> 官方文档页把这句话写**反**了——它写的是"请求方法为 OPTIONS 时，
> access-control-allow-headers -> access-control-expose-headers"
> （<https://wproxy.org/docs/rules/resCors.html>），它的示例也给一个普通 `GET`
> 列出了 `access-control-allow-headers`。whistle 和 whix 的实际行为都正好相反，
> 而这也是唯一说得通的理解：`allow` 回应的是预检，`expose` 回应的是真正的响应。
> 上游自己的代码是 `var operate = isOptions ? 'allow' : 'expose'`
> （`_original/lib/util/index.js:2953`）。

### 删除

| 算子 | 值 | 效果 |
|----------|-------|--------|
| `delete` | 一个或多个 key，用 `\|` 或 `&` 分隔 | 删除头、cookie、查询参数、路径段、body 属性，或类型/字符集 |

key 只按一组固定的写法匹配；**其他写法一律悄悄忽略**，和上游完全一样。尤其是光写
`delete://server` 什么也删不掉——你得写上作用域。

| Key | 删除的是 |
|-----|---------|
| `resHeaders.x` / `res.headers.x` / `resH.x` / `res.h.x` | 这个响应头（作用域部分不区分大小写） |
| `reqHeaders.x` 及同样的几种变体 | 这个请求头 |
| `headers.x` | 请求和响应两边的这个头（这种写法**区分**大小写，而且必须是复数） |
| `reqCookies.x` / `cookies.x` | 请求 `Cookie` 头里的这个 cookie |
| `resCookies.x` / `cookies.x` | **客户端里**的这个 cookie——见下文 |
| `trailer.x` | 这个尾部头（trailer）（这个 key 不带 `req`/`res` 作用域；和 `headers.x` 一样，`trailer` 这个词**区分**大小写，必须小写） |
| `query.x` / `params.x` / `urlParams.x` / `url.Param.x` | 这个查询参数，重复出现几次就删几次 |
| `query` / `params` / `urlParams`（单独写） | 整个查询串，连 `?` 一起 |
| `pathname` | 整个路径，查询串保留 |
| `pathname.0` / `pathname.first`、`pathname.2`、`pathname.-1`、`pathname.last` | 对应的那一段路径，负数从末尾往前数 |
| `resType` / `res.type`、`reqType` / `req.type` | 媒体类型（`charset` 参数会保留） |
| `resCharset` / `res.charset`、`reqCharset` / `req.charset` | charset 参数 |
| `body`、`res.body`、`req.body` | 整个 body，包括算子注入的任何内容 |
| `resBody.a.b` / `resB.a.b`、`reqBody.a.b` | JSON body 里这个点分路径对应的字段 |

body 路径的读法和 whistle 一样：`reqBody.a\.b` 指的是名字里带点的一个 key
（反斜杠会先减半，所以 `a\\.b` 是两段），`reqBody."k[0]"` 把这一段按字面取，
`reqBody.a[0]` 是数组下标——和 `reqBody.a.0` 指的是同一个元素。

```
example.com   delete://resHeaders.server|resHeaders.x-powered-by
example.com   delete://reqCookies.tracking
example.com   delete://resBody.debug&resBody.internal.token
example.com   delete://query.utm_source|query.utm_medium
example.com   delete://pathname.first        # /v1/users → /users
```

URL 相关的这几类 key 有些边界情况值得知道，全都是从上游继承来的
（`parseDelQuery`/`parsePathReplace`/`deleteQuery`，
`_original/lib/util/index.js:2674-2721,1023-1058`）：

* 路径段是在**去掉**开头斜杠的路径里数的，所以在 `/v1/users` 里 `pathname.0`
  指的是 `v1`——和 `urlReplace://` 往里替换的是同一套分段；
* `pathname.last` 会在那一段原来的位置留下一个结尾斜杠（`/a/b/c` →
  `/a/b/`）；`pathname.-1` 指的是同一段，但不会留（`/a/b`）；
* 中间的点可以省（`pathname-1` ≡ `pathname.-1`），`pathname` 本身也不区分大小写——
  但 `first`/`last` **区分**。`delete://pathname.LAST` 能匹配上格式，然后什么也不做：
  凡是没被认成字面量 `last` 的 key，上游一律用 `+key` 强转成数字，而 `+'LAST'`
  是 `NaN`；
* 删查询参数这一步在 `params://` **之后**执行，所以同一行刚写进去的参数，
  它照样能删掉；
* 下标越界什么也不做，不会报错。

> **两处有意的偏离。**
>
> 在上游，对带查询串的 URL 单独写 `delete://pathname`，会把查询串输出**两遍**
> （`/a?x=1` → `/?x=1?x=1`，`util/index.js:1033,1057`）。whix 只输出一遍；
> 上游那种请求行，没有哪个源站能解析。
>
> 在真实的 whistle 里，`delete://body`（以及 `req.body` / `res.body`）并**不会**
> 清空 body，只会丢掉 `reqBody://`、`reqPrepend://` 和它们对应的响应版算子原本要
> 注入的内容。`removeBody` 赋的值是 `EMPTY_BUFFER`，而 `EMPTY_BUFFER` 是
> `toBuffer('')`——这个函数第一句就是 `if (!buf) return`
> （`util/common.js:1630-1632`），所以这个常量其实是 `undefined`，那次赋值对 body
> 毫无影响。whix 会把 body 清空：文档里这个 key 写的就是这个效果，上游自己的代码
> 本意也是这样。

响应没法伸手进浏览器删掉一个 cookie，所以 `delete://resCookies.x` 回送的是一个
**已经过期**的同名 cookie（`Max-Age=0` 加一个过去的 `Expires`）。每个名字发两条，
一条普通的、一条带 `Secure` 的，因为不带 `Secure` 的 cookie 覆盖不了带 `Secure`
的，而代理不知道浏览器里存的是哪一种。如果主机有一个值得写的父域，还会再发两条
限定在父域上的，用来对付设在 `.example.com` 上、而不是设在主机本身上的 cookie：
`a.b.example.com` 会加上 `Domain=b.example.com`，三段的主机名保留开头的点
（`.example.com`），`example.com` 没有父域，什么也不加。同一个请求上，如果
`resCookies://` 也设置了同名 cookie，删除**胜出**。

### Cookie

| 算子 | 值 | 效果 |
|----------|-------|--------|
| `reqCookies` | `name=value` 对（用 `&` 分隔）或 `{json}` | 合并进请求的 `Cookie` 头。多行命中时会累加。 |
| `resCookies` | `name=value` 对（用 `&` 分隔）或 `{json}` | 设置 `Set-Cookie` 头。多行命中时会累加。 |

查询串*里面*只写名字、不带 `=` 的项，得到的是一个**空值**——不会删掉这个 cookie；
要删请用 `delete://reqCookies.<name>`。如果整个值里一个 `=` 都没有，那它根本不是
查询串，而是一个**位置**（location，也就是文件或 URL），所以 `resCookies://sid`
会去读一个叫这个名字的文件，什么 cookie 也不设。`resCookies` 的条目会**替换**
响应里已经发出的同名 `Set-Cookie`，而不是再加一条。

把请求里的 cookie 全删光后，`Cookie:` 头仍然在，只是**为空**，不会被移除——这是
上游的 `setHeader(data, 'cookie', '')`。

```
example.com   reqCookies://sid=abc&locale=en
example.com   delete://reqCookies.tracking   # 删掉某个 cookie 要这么写
example.com   resCookies://theme=dark
```

#### Cookie 属性

`resCookies` 的 `{json}` 写法里，cookie 的值可以换成一个对象，对象的字段会变成
`Set-Cookie` 的属性：

```
example.com   resCookies://{"sid":{"value":"abc","httpOnly":true,"secure":true,"path":"/","sameSite":"Lax","maxAge":600}}
```

```
Set-Cookie: sid=abc; Expires=<now+600s>; Max-Age=600; Secure; HttpOnly; Path=/; SameSite=Lax
```

能识别的字段有 `value`、`maxAge`、`secure`、`httpOnly`、`partitioned`、`path`、
`domain` 和 `sameSite`，每个都支持上游接受的那几种写法（`maxAge` 也可以写成
`maxage` / `MaxAge` / `Max-Age` / `max-age`，其他字段同理）。字段缺失或为假值
（falsy）时不写出来；`maxAge` 会把 `Expires`/`Max-Age` 这一对一起写出。上面的
顺序就是上游 `getCookieItem` 的顺序。

用**数组**可以让一个名字对应多条 `Set-Cookie`，同一个 cookie 要设在多个作用域下
就这么写：

```
example.com   resCookies://{"sid":[{"value":"abc","path":"/a"},{"value":"abc","path":"/b"}]}
```

在**请求**这一侧，对象只贡献它的 `value`——`Cookie` 头没地方放属性，上游在这里
也是直接丢掉。

### Body

| 算子 | 值 | 效果 |
|----------|-------|--------|
| `reqBody` / `resBody` | 替换用的文本，或存着它的文件/URL | 替换整个 body |
| `reqReplace` / `resReplace` | `from=to` 对，用 `&` 分隔 | 在 body 内部做替换 |
| `reqPrepend` / `resPrepend` | 文本，或存着它的文件/URL | 插到 body 开头 |
| `reqAppend` / `resAppend` | 文本，或存着它的文件/URL | 插到 body 末尾 |
| `resMerge` | `{json}` | 把一个补丁深合并进 JSON 响应 body |
| `cssBody`/`cssPrepend`/`cssAppend` | CSS，或一个 URL | 要加到 **CSS 或 HTML** 响应里的 CSS |
| `htmlBody`/`htmlPrepend`/`htmlAppend` | HTML 片段 | 要加到 HTML 响应里的 HTML 片段 |
| `jsBody`/`jsPrepend`/`jsAppend` | JavaScript，或一个 URL | 要加到 **JS 或 HTML** 响应里的 JS |

只要有任何 body 算子生效，whix 就会把这个 body 缓存下来、做变换，再重新计算
`Content-Length`（同时去掉 `Transfer-Encoding`）。没有 body 算子的请求和响应
原样流式转发，不做任何改动。

**`GET`、`HEAD`、`OPTIONS` 和 `CONNECT` 请求永远不会被加上 body。**
在这些方法上，`reqBody`/`reqPrepend`/`reqAppend` 会被丢弃而不是生效，和 whistle
一致——带 payload 的 GET，有些源站和 CDN 会直接回 `400`。这里检查的是*转发出去*
的方法，所以同时写上 `method://post` 就能让注入恢复生效。`reqReplace` 和
`delete://reqBody.…` 不受影响：它们改写的是已经存在的 body，而这些方法上本来就
没有 body。

**压缩过的响应会先解码**，按文本做变换，出去时再用同样的编码压回去——`gzip`、
`deflate` 和 `br` 都能这样来回处理。没有这一步的话，对一个 gzip 过的页面用
`resReplace://`，会在 deflate 流里找匹配，结果悄悄什么也找不到——而大多数真实网站
都开了压缩，所以多数人都会撞上。本项目没法来回处理的编码（`compress`、双重编码的
`gzip, br`）原样不动，算子就在这些字节上跑，基本匹配不到有用的东西——和以前一样
没效果，但不会把 body 弄坏。`enable://gzip|br|deflate` 不管收到的是什么编码，都
强制指定*出去*时的编码（`br` 优先于 `gzip`，`gzip` 优先于 `deflate`），所以它也能
把源站明文发来的 body 压缩掉。

这也是为什么**每个**请求的 `Accept-Encoding` 在发出去时都会被收窄，只留下本代理
既能解开*又*能压回去的那几个——`gzip` 和 `br`
（`removeUnsupportsHeaders`，`_original/lib/util/index.js:1549-1570`，在
`req.js:579` 调用）。浏览器请求的是 `gzip, deflate, br, zstd`；如果不管，源站
会挑 zstd，这里没有任何东西能解码它，于是所有 body 算子都会悄无声息地失效。收窄这一步
来自上游，它的边界情况也一样：比较的是整个 token，所以 `gzip;q=1.0` 不算 `gzip`，
会被去掉；如果请求收窄后**一个**可接受的编码都不剩，就保留它原来的头，而不是塞给它
一个它根本没要过的编码。

这张表里的每个算子都会累加：同一个算子写在多条匹配的行上，每一行都会起作用，按各自
的类别拼接起来——见
[同一算子写了多行时怎么合并](#同一个算子写了多行怎么合并)。

值如果是一个**文件或 URL**，会在算子生效前先读出来（见
[从文件或 URL 读取的值](#从文件或-url-读取的值)）——这也是为什么在这里，
`jsAppend`/`cssAppend` 上的 URL 仍然表示 `<script src>`，永远不会被去抓取。

```
api.example.com/echo   reqBody://{"mocked":true}
example.com/app.js     resBody://console.log('patched')
example.com            resReplace://http://=https://
example.com            resReplace:///v\d+/g=vX         # 正则写法
example.com/page       resPrepend://<!-- via whix -->
example.com/page       jsAppend://https://cdn.test/debug.js
```

#### 各类算子分别作用于哪种响应

`jsXxx` 和 `cssXxx` **并不**只作用于 JS 和 CSS 响应：HTML 响应三类都接受，所以在
页面上写 `jsAppend://alert(1)` 才能生效。往 HTML 里放之前，值会先包一层——
JavaScript 包进 `<script>…</script>`，CSS 包进 `<style>…</style>`；如果值就是一个
URL（`https://…` 或 `//…`），就改成生成 `<script src="…">` / `<link rel="stylesheet">`。
`jsXxx` 规则上的行属性会变成生成的 `<script>` 的属性：`crossorigin`、`anonymous`、
`use-credentials`、`defer`、`async`、`nomodule`、`module`、`importmap`、
`speculationrules`。

```
example.com/page  jsAppend://https://cdn.test/a.js  lineProps://defer|module
```

#### 执行顺序

算子**不是**按书写顺序执行的。和 whistle 的处理流水线一致，响应按下面的顺序变换：

1. `resMerge` 和 `delete://resBody.…`
2. `resReplace`
3. 注入：`*Body` 替换 body，`*Prepend` 放在前面，`*Append` 放在后面——每个位置上的
   来源按 `res*`、`css*`、`html*`、`js*` 的顺序排列，用 CRLF 拼接。这些算子全都
   可以多行匹配，所以每个来源本身也可能是好几行；见
   [同一算子写了多行时怎么合并](#同一个算子写了多行怎么合并)。

所以替换永远看不到 prepend 或 append 进去的文本，而 `*Body` 会扔掉
`resMerge`/`resReplace` 产生的一切结果。**请求的顺序正好反过来：**
先注入，后跑 `reqReplace`，所以它*能*看到注入的文本。

和上游一样，往响应里注入会带来两个副作用：去掉 `Content-Security-Policy` 头
（免得注入的脚本被拦），并把响应设成不可缓存。`enable://keepCSP` 和
`enable://keepCache` 分别关掉这两项；显式写的 `cache://` 也会保留。
往 **HTML** 响应里做非空的 prepend 时，前面还会额外加一行 `<!DOCTYPE html>`，
用 `disable://doctype` 可以关掉。

响应*头部*有自己的一套顺序，其中有一点值得知道：`delete://resHeaders.x` 在上面那
两个副作用**之后**执行（`_original/lib/inspectors/res.js:1160-1165` 对比
`:1097-1104`），所以它能拿掉注入刚写进去的东西——

```
example.com   resAppend://<!-- x -->   delete://resHeaders.cache-control
```

——这样响应里就完全没有 `Cache-Control`，而不是带着注入打上的那个 `no-store`。

`Location` 在发出去时会做百分号编码（`encodeNonLatin1Char`，
`res.js:946-949`），时机在所有头算子都处理完之后，所以重定向到带非 ASCII 字符的
路径时，路径能完好到达。

#### `*Replace` 细节

值是一串 `pattern=replacement` 对，用 `&` 分隔（`resReplace://a=1&b=2` 是两处
替换）。左边的查找串如果严格写成 `/source/flags` 的形式——flags 取自 `igmu`，最多
四个——就是正则表达式；**其他任何写法都是字面字符串**，出现在哪里就替换哪里。正则
写法遵循 JavaScript，所以不带 `g` 标志时只替换*第一处*匹配。替换文本里可以用 `$&`
和 `$1`…`$9`，`/.*/ ` 或 `/.+/` 会替换整个 body。

对没有 `Content-Type` 或者是图片类型的响应，`resReplace` 整个跳过。对非 UTF-8
（二进制）的 body，`*Replace` 什么也不做。

SVG（`image/svg+xml`）在这里算**文本**，所以 `resReplace` 会作用于它——拿来给图标
换颜色很方便——而且 `file://` 提供的 SVG 会带上 `; charset=utf-8`。这是 whistle
2.10.8 的做法，它先判断 `xml` 再判断 `image/`。whistle 2.10.10 先判断 `image/`，
所以在那里 SVG 算图片，替换会悄悄失效；本项目有意保留旧的做法（STATUS，U1）。

多条匹配的行**不会**各自单独跑一遍：它们的替换对会先合并成一张映射表，所以同一个
查找串写了两次时，用的是第一行的替换值。见 [同一算子写了多行时
怎么合并](#同一个算子写了多行怎么合并)。

#### `resMerge` 细节

`resMerge` 只作用于 JavaScript、HTML、JSON 或没有 `Content-Type` 的响应。它合并进的
是 body 里**第一段看起来像 JSON 的子串**，而不是整个 body，所以 JSONP 的回调包裹会
保留：

```
api.test/jsonp   resMerge://{"ok":true}     # cb({"a":1}) → cb({"a":1,"ok":true})
```

HTML（或无类型）的 body 如果不是以 `{`/`[` *开头*，就不动它；空 body 会直接被补丁
整个替换掉。

多条匹配的行会先折叠成一个补丁再去合并，而这次折叠是**浅**的——`resMerge://true`
是 whistle 用来要求深折叠的标记行：

```
api.test/data  resMerge://{"n":{"y":8}}
api.test/data  resMerge://{"n":{"w":7}}   # 被丢掉：浅折叠，`n` 归第一行
api.test/data  resMerge://true            # ……除非这一行要求深折叠
```

> `statusCode` 有两种用途，和 whistle 一致：没有发往源站的请求时，它 mock 响应；
> 和转发出去的请求一起用时，它替换状态码。

---

### 第一条路是 JSON5

"按 JSON 读"其实是按 **JSON5** 读：`parseRawJson` 就是 `json5.parse`
（`evalJson`，`_original/lib/util/common.js:1673-1679`），而且每条通往对象的路
最先试的都是它——`_parseJSON` 先试它、再试查询串和行格式；`isJson` 用它判断一个值
是内容还是路径；读凭据的代码用它；两种 body 合并也用它，连 **body** 本身都用它来解析。

所以下面这些都是对象：

```
{a: 'one', b: 'two'}      unquoted keys, single quotes
{a: 'one',}               a trailing comma
{ /* or a comment */ }    comments, both kinds
{a: 0x1f, b: .5, c: +1}   hex, leading-dot and signed numbers
```

这就是为什么 [`reqCookies.md`](https://wproxy.org/docs/rules/reqCookies.html)
可以把 `{ key1: 'value1', key2: 'value2' }` 当成 cookie 对象打印出来。本项目以前把它
当文本读，结果设了一个名叫 `{` 的 cookie。

有一种写法看着应该能行，实际上两个程序都不行：带**横杠**的 key 不能不加引号，因为
`-` 会结束一个 JavaScript 标识符。`{x-a: 'b'}` 会落到行格式去解析，得到一个名叫
`{x-a` 的头；Node 会把它写到线上，hyper 拒绝构造它，所以 whistle 发出一个坏掉的头，
本项目则什么也不发。给 key 加上引号就行。

### 行格式的确切规则

**加载**来的值——来自 ``` 块、文件、URL 或 Values 存储——先按 JSON5 读；
没有空白字符的话再按查询串读；最后才逐行读（`_parseJSON`，
`_original/lib/util/index.js:1135-1143`）。第三条路有些细节和直觉不一样，每一条都是
对着 whistle 2.10.8 实测出来的，而不是读代码读出来的：

| 你写的 | 变成 | 原因 |
|---|---|---|
| `a: 123` | `{"a":123}` | 数字：首尾两个字符不一样 |
| `a: 1`、`a: 11`、`a: 121`、`a: 0` | `{"a":"1"}` … | **文本**：上游先问 `fv === lv`，数字分支是它的 `else`（`parseLine`，`common.js:1145-1157`） |
| `a: "1"` | `{"a":"1"}` | 带引号的值会去掉引号 |
| `solo`（没有分隔符） | `{"solo":""}` | 一个值为空的名字 |
| `solo:` | `{"solo:":""}` | **没有空白字符**，所以根本到不了行格式——查询串那条路把整个 token 当成名字，而名叫 `solo:` 的头不是合法 token，所以什么也不发 |

还有两种只有 `reqMerge://` / `resMerge://` 才看得到，因为 `RESOLVE_KEY_RE` 测的是
*原样书写的* matcher——同一个值放在 `params://` 下，点会原样保留：

| 你写的 | 变成 |
|---|---|
| `a.b.c: 1` | `{"a":{"b":{"c":"1"}}}` |
| `c\.d: 1` | `{"c.d":"1"}`——转义过的点是名字的一部分 |
| `a[0]: 1` | `{"a":["1"]}`——**方括号**下标会开出一个数组；点号形式的 `a.0` 开出的是对象 |

嵌套结构合并进**表单** body 时会被写成空（`a=`），因为 Node 的
`querystring.stringify` 就是这么处理它的；JSON body 拿到的则是结构本身。

> **还剩一处差异，而且是 JavaScript 造成的。** whistle 合并完 JSON 对象后，要经过
> 一个 JS 对象重新序列化，而 JS 会先枚举像整数的 key：给 `{"name":"x"}` 加一个 `0`
> 的补丁，在那边得到 `{"0":…,"name":"x"}`，在这里是 `{"name":"x","0":…}`。为了
> 模仿某种语言的属性顺序去重排用户的 JSON，比这个差异本身更糟。

### `^` 匹配串没有路径边界

`pattern.md` 的通配符一节把 `^wss://*.example.com/path/to` 列为不匹配
`wss://a.example.com/path/toxxx`，理由是"路径缺少 `/` 边界"。实际上能匹配。`^`
匹配串会被编译成一个前缀正则，里面任何地方都没有 `/` 边界——这个边界属于普通的
URL 片段写法——想禁止后面再跟尾巴，要用同一节里写过的结尾 `$`。在 whistle 2.10.8
上实测过，本项目与之一致；`cases-patterns.js` 里两种情况都有。

### 合并最多能读多大的 body

在上游，响应超过 2 MB 时会跳过 `resMerge://`；在这一行上加
`enable://resMergeBigData` 或 `lineProps://enableBigData` 可以把上限提到 16 MB
（`MAX_RES_SIZE` / `BIG_MAX_RES_SIZE`，
`_original/lib/inspectors/res.js:21-22,:1013`）。请求那边是同样的结构，用的是
`reqMergeBigData`（`req.js:19-20,:163`）。

本项目里，所有响应算子共用一个上限参数——`--body-rewrite-limit`，默认 16 MB，本来
就等于上游放宽后的上限——所以默认情况下，whistle 会跳过的 body，本项目照样会合并。
这两个开关仍然有用：它们把**这个请求**的上限提到 16 MB，正好满足那些把全局参数调低
了的用户。

### `socks://` 不写端口就是 1080

[`socks.md`](https://wproxy.org/docs/rules/socks.html) 说默认端口是 443，还说了
两次。其实是 1080：`proxyPort = isSocks ? 1080 : isHttpsProxy ? 443 : 80`
（`_original/lib/inspectors/res.js:284`），这也是其他所有地方通用的 SOCKS 默认端口。
那个页面看起来是照抄了 `https-proxy` 那一行。本项目和 whistle 一样用 1080。

### 属性列表里的转义

`delete://`、`enable://` 和 `disable://` 通过 `parseProps`
（`_original/lib/util/common.js:73,:111-127`）按 `|` 和 `&` 拆分值。它对整个值只跑
一个正则，做两件事：前面有**奇数**个反斜杠的分隔符算普通文本，不拆；`\s`、`\t`、
`\n`、`\r`、`\f` 和 `\v` 会变成它们代表的字符。所以 `delete.md` 自己的例子——

```
https://www.example.com/path delete://reqBody.\n\ \.p.test\|\&test
```

——指向两个 key：一个包含换行、空格和点，另一个包含竖线和 `&`。`lineProps://`
是例外，它只做普通拆分，完全不处理转义（`index.js:1898`），这一点
[`LINE_PROPS.md`](LINE_PROPS.md) 里有记录。

> 那个页面的表格把空格写成 `\ `，而代码读的是 `\s`。两个代理都会把 `\ ` 原样保留，
> 所以差异出在文档页上。

### 不是合法状态码的状态值

`statusCode://` 和 `replaceStatus://` 接受的是数字。给它别的东西——`abc`、`20x`、
`099`、`0`、`2000`、一个文件路径——上游会把它交给 Node 的 `res.writeHead`，后者抛
异常，客户端收到的是**连接重置**。上面每一种都对着 whistle 2.10.8 实测过。

这里没有可以照抄的行为，所以本项目沿用**空**值的结果，而空值上游是有定义的
（`var code = rule || 200`，`getStatusCodeFromRule`，
`_original/lib/util/index.js:3580`）：mock 回 `200`，`replaceStatus://` 不动响应。
写错一个字，不该成为丢掉一个已经到达的响应的理由。

确实是状态码的值，两边结果一致，包括注册范围之外的两个——`999` 和 `600`，两边都按
原样写出。

除 `101` 之外的**临时**状态码（interim，1xx）——比如 `statusCode://100`——不能当最终
响应：上游会把它写出去，然后客户端一直等一个永远不会来的最终响应；本项目的 HTTP
服务端拒绝发送它，改回 `500`。上游自己的测试集对这两种情况都期望报错
（`test/units/statusCode.test.js`，`statuscode4`/`statuscode5`）；这两个用例在
`tests/differential/upstream-suite.js` 里登记为已声明的差异，而不是要求两边一致。

### 不是合法 token 的方法值

同样的情况，换了一个算子。`method://GET;`、`method://{"method":"PUT"}` 以及一段
多行的内容，都会到达 Node 的 `http.request`，它抛出 `ERR_INVALID_HTTP_TOKEN`，
whistle 回它的 `502` 页面。本项目则不改方法。是合法 token 的值两边一致，包括不认识
的动词（`FROBNICATE` 原样发出）和数字。

### 不配置代理也能命中规则

以 **origin-form**（只有路径，不是完整 URL）直接发到代理端口的请求，由它的 `Host`
决定去向：

- **控制台的名字**——IP 地址、`localhost`、控制台主机名（内置的，或用 `-l` 加的）：
  由控制台来回答。正因如此，`http://127.0.0.1:8899/api` 拿到的是本程序的页面，而
  不是任何规则能碰到的东西；
- **其他任何名字**：当成发往这个名字的普通请求，规则照常生效——没设代理的客户端也能
  用上规则，靠的就是这一条，比如用 hosts 文件把 `api.example.com` 指到这台机器，
  再配上 `-p 80`。上游也是这么做的（`_original/biz/index.js:98-106`，
  `lib/upgrade.js:23-24`）。

```console
$ curl -H 'Host: api.example.com' http://127.0.0.1:8899/v1   # → api.example.com/v1, by the rules
```

解析回本代理的名字，不会在这个名字下拿到控制台——否则网页可以把自己的域名重新绑定
（rebind）到 `127.0.0.1`，然后读走一切——而是回一个 `302`，跳到控制台的地址，和上游
一样。

路径前面加 `/-/`（或 `/_/`）表示反过来：去掉这个前缀，剩下的当成普通请求处理
（`_original/biz/index.js:114-129`，FAQ 对同一个问题的回答也是这样）。这时请求指向
的是*本*代理，所以它去哪儿由规则决定：

```
http://127.0.0.1:8899/hop   https://api.example.com/hop
```

```console
$ curl http://127.0.0.1:8899/-/hop        # → api.example.com/hop
$ curl http://127.0.0.1:8899/hop          # → the console's 404
```

如果没有规则命中，请求的目标就是代理自己，会撞上防自环保护，回 `302`——上游也是这样。

## 优先级

对每个请求，whix 把规则走一遍，得出一组最终生效的结果：

1. **important 的先看。** 带 `lineProps://important` 的行先于普通行参与匹配。（`$` *不是*重要性标记，它表示精确匹配；见 [`$` —— 精确匹配串](#--精确匹配串)。）
2. **单值算子先匹配的赢**（`host`、`redirect`、`ua` ……）：第一条匹配上的规则（按重要性排过之后）决定取值。
3. **多值算子累加** —— 也就是 whistle 的 `multiMatchs` 列表，原样沿用：`enable`、`disable`、`ignore`、`filter`、`delete`、`plugin`、`style`、`cipher`、`trailers`、`urlParams`、`params`、`headerReplace`、`reqHeaders`、`resHeaders`、`reqCors`、`resCors`、`reqCookies`、`resCookies`、`reqReplace`、`urlReplace`、`resReplace`、`resMerge`、`reqBody`、`reqPrepend`、`reqAppend`、`resBody`、`resPrepend`、`resAppend`、`html`/`js`/`css` 这几个家族、`rulesFile`、`resScript`、`G`（再加上 `log` 和 `pipe`，本项目也让它们累加）。每个匹配到的值都保留，按从上到下的顺序排。

同一轮里，规则按**文件顺序**求值。所以更具体、优先级更高的规则要往前放（或者标上 `lineProps://important`）。

"文件顺序"的外面和里面还各有一层排序，很容易让人意外：

* **规则组。** 所有启用的*有名字的*组先走，顺序就是控制台列出它们的顺序，**默认组放最后** —— 所以有名字的组会盖过默认组。这是上游的顺序（先加有名字的组，之后才 `addRules(defaultRules, 'Default')`），也是上游控制台把 Default 列在最底下的原因。
* **同一行里的多个 token。** 有几种算子共用**同一个槽位**：目标地址（`http://…`、`example.com`、裸 host）、本地文件家族、`statusCode://` 和 `redirect://`。一个请求只由其中一个来应答，就是写得最早的那个 —— 在更前面的行上，或者在同一行里更靠前：

  ```
  example.com  file:///mock.json  statusCode://204   # 返回文件内容
  example.com  statusCode://204  file:///mock.json   # 应答 204
  ```

  在这场争夺里输掉的 `statusCode://` 就不出声了；它不会在响应阶段再回来，把赢家的状态码覆盖掉。

### 同一个算子写了多行，怎么合并

多值算子也仍然有一个*赢家*：第一个匹配上的，important 的行优先。凡是只读一个值的地方（`host`、文件路径、一个开关）用的都是它。会用到整个列表的算子，按家族各有各的合并方式：

| 家族 | 合并方式 |
|--------|-------------|
| `resBody` / `resPrepend` / `resAppend`、`reqBody` / `reqPrepend` / `reqAppend`，以及带类型的 `htmlBody`、`jsAppend`、`cssPrepend` …… | 按解析顺序**用 CRLF 拼接**。空行不参与拼接。带类型的每一行单独包装，所以两行 `jsAppend://` 就是两个 `<script>` 标签，各带各的 `lineProps` 属性。 |
| `reqReplace` / `resReplace` / `urlReplace` | 合并成**一张替换表**。表里每个查找串都会生效；同一个查找串写在两行里，取**第一行**的替换内容。表的顺序是：最后一行的查找串在前，然后依次是更早的每一行新加进来的 —— 替换就按这个顺序接力进行。 |
| `resMerge` | 合并成**一个补丁**，同一个键有冲突时第一行赢。多行合成补丁时默认是**浅**合并，除非其中某一行就是字面量 `resMerge://true` —— 这是 whistle 表示深合并的标记，这一行自己不提供任何数据。合好的补丁再深合并进 body。 |
| `params` / `urlParams` | 各自合并成一张表，同一个键有冲突时第一行赢；然后把 `urlParams` 叠在 `params` 上面。 |
| `reqHeaders` / `resHeaders` / `reqCookies` / `resCookies` / `reqCors` / `resCors` / `trailers` | 合并成**一张表**，同名有冲突时第一行赢。这些正是 `parseRuleJson` 自己处理的参数（`_original/lib/inspectors/req.js:459-468`、`res.js:845-855`），所以合并方式和 `resMerge`、`params` 一样。 |
| `headerReplace` | 从上到下依次执行。 |

```
example.com/x  resPrepend://<!--head-->
example.com/x  jsAppend://one()
example.com/x  jsAppend://two()
# → <!DOCTYPE html><!--head--><page><script>one()</script><script>two()</script>
```

`important` 的行排在列表最前面，所以它既能赢下有冲突的键，拼接时也排第一个：

```
example.com/x  resAppend://normal
example.com/x  resAppend://important lineProps://important
# → body + "important\r\nnormal"
```

---

## 速查表

每项一行。完整版 —— 它们做什么、哪里容易让人意外、不生效时该往哪查 —— 在 [`COOKBOOK.md`](COOKBOOK.md) 里。

| 任务 | 规则 |
|------|------|
| 把站点指到本地开发服务器 | `www.example.com  http://localhost:5173` |
| 把一个 host 转到别处，`Host` 头保持不变 | `.cdn.example.com  host://10.0.0.9` |
| 用假域名做本地开发 | `test.local  127.0.0.1:9099` |
| 用文件 mock 一个接口 | `api.example.com/users  file:///Users/me/mock/users.json` |
| 内联 mock 一个接口 | `api.example.com/health  file://({"status":"ok"})  resType://json` |
| 只返回一个状态码 | `/\/track\b/  statusCode://204` |
| 重定向旧路径（前缀不需要 `*`） | `example.com/old  redirect://https://example.com/new/` |
| ……并保留后面的部分 | `^http://example.com/old/**  redirect://https://example.com/new/$1` |
| 加一个请求头 | `example.com  reqHeaders://x-token=abc` |
| 加一个值里带空格的头 | `example.com  reqHeaders://authorization=${bearer}` |
| 删掉一个请求头 | `example.com  delete://reqHeaders.user-agent` |
| 给前端放开 CORS | `api.thirdparty.com  resCors://*` |
| 改 JSON 响应里的一个字段 | `api.example.com  resMerge://{"env":"staging"}` |
| 让响应变慢 | `slow.example.com  resDelay://2000  resSpeed://800` |
| 掐断连接 | `flaky.example.com  enable://abort` |
| 让一部分请求失败 | `api.example.com  statusCode://503  includeFilter://chance:5%` |
| 只对某一个方法生效 | `api.example.com  host://10.0.0.1  includeFilter://m:POST` |
| 从大范围规则里挖掉一条路径 | `example.com/health  ignore://all` |
| 压过前面的普通行 | `example.com  host://2.2.2.2 lineProps://important`（`$` 表示精确匹配，不表示重要性） |
| 做了证书固定的 host 不去碰 | `pinned.example.com  sniCallback://no-mitm` |
| 给每个解密过的响应打标记（确认 HTTPS 拦截在工作） | `/^https:/i  resHeaders://x-via=whix` |

---

## 算子覆盖情况

下面几组说的是已经实现的运行时路径，以及它们的限制。别把以前那个"注册表里名字的占比"当成语义上的覆盖率：别名、元数据、插件基础设施、按请求产生的效果，各需要不同的测试。当前的证据和有意的偏离都记在 STATUS 里。

### 运行时生效的算子

| 类别 | 算子 |
|----------|-----------|
| 路由 / 上级代理 | `host`、`proxy`、`http-proxy`、`https-proxy`、`internal-proxy`、`internal-http-proxy`、`internal-https-proxy`、`https2http-proxy`、`http2https-proxy`、`socks`、`pac`，以及带 `x`/`xs` 前缀的代理变体 |
| 改写请求 | `reqHeaders`、`reqCookies`、`reqType`、`reqCharset`、`reqCors`、`ua`、`referer`、`method`、`auth`、`forwardedFor`、`urlReplace`、`params`、`urlParams`、`reqBody`、`reqPrepend`、`reqAppend`、`reqReplace`、`reqDelay`、`reqSpeed`、`reqWrite`、`reqWriteRaw` |
| 改写响应 | `resHeaders`、`resCookies`、`resType`、`resCharset`、`resCors`、`replaceStatus`、`statusCode`、`attachment`、`cache`、`resBody`、`resMerge`、`resPrepend`、`resAppend`、`resReplace`、`resDelay`、`resSpeed`、`resWrite`、`resWriteRaw`、`trailers`、`headerReplace`、`responseFor` |
| 按内容类型改 body | `cssBody`/`cssPrepend`/`cssAppend`、`htmlBody`/`htmlPrepend`/`htmlAppend`、`jsBody`/`jsPrepend`/`jsAppend`（JS 和 CSS 家族也能作用到 HTML 响应上，包成对应的标签注入） |
| 短路 / 开关 | `redirect`、`locationHref`、`statusCode` mock、`enable`、`disable` |
| 本地文件 / 模板 | `file`、`rawfile`、`tpl`、`jsonp`、`dust`，以及它们带回退的 `x`/`xs` 变体（`xfile`、`xrawfile` ……） |
| 匹配 / 控制 | `filter`、`includeFilter`、`excludeFilter`、`ignore`、`delete`、`log`、`rule`、`rulesFile`（`reqRules`）、`resRules` |
| TLS | `cipher`（锁定连源站用的 TLS 版本 + 求值 OpenSSL cipher string），`sniCallback`（由插件挑选中间人证书，或者拒绝拦截） |
| 脚本 / 扩展 | `resScript`、`frameScript`、`plugin`、`pipe`、`weinre` |

**规则文件特性：** 算子值里的 `${port}` 和 `${version}` 会被替换（不区分大小写）。范围比上游宽：上游的 `CONFIG_VAR_RE`（`_original/lib/util/index.js:3262`）只有一个读取方，就是写在反引号里的 [`@` 引入](#引入另一份规则文本) 的来源；其他地方的 `${port}` 只有在 [反引号](#反引号模板) 里才会解析。那个唯一的读取方这里也有，而且不管来源带不带反引号都会替换。它永远碰不到**内容**：内联 `(…)` 载荷里的 `${port}`，或者 `{name}` 返回的内容里的 `${port}`，都是 mock 本来就想原样包含的文本。算子值如果是文件或 URL，会 [在算子执行前先读进来](#从文件或-url-读取的值)；包在反引号里的值会 [针对当前请求渲染](#反引号模板)；`locationHref://` 会直接用一个自己跳转的页面**应答**请求。

**别名算子**会被归一成标准写法，所以下面这些也都能用：`hosts→host`、`xhost→host`（是同一个算子，但 `x` 写法还会回退 —— 见 [目标地址](#目标地址)）、`html→htmlAppend`、`js→jsAppend`、`css→cssAppend`、`download→attachment`、`status→statusCode`、`skip→ignore`、`tlsOptions→cipher`、`pathReplace→urlReplace`、`reqMerge→params`、`resRules→resScript`、`ruleFile`/`ruleScript`/`rulesScript`/`reqScript`/`reqRules`→`rulesFile`、`P→G`。`ignore://` 里写的别名也会同样归一，所以 `ignore://hosts` 会去掉 `host://`，`ignore://xproxy` 会去掉整个上级代理家族。

说明：`http2https-proxy`/`https2http-proxy` 和 `internal-*` 家族确实会转换连源站的协议（scheme），去掉 TLS 的那一跳会带上 whistle 的 `x-whistle-https-request` 标记（见 [上级代理](#上级代理)）；`internal-*` 家族还缺的是 whistle 与 whistle 之间握手的其余部分，也就是 client-id 和拦截策略这两个头。**所有**上级代理名字都接受 `x` 前缀 —— `xproxy`、`xsocks`、`xhttp-proxy`、`xhttps-proxy`、`xinternal-proxy`、`xinternal-http-proxy`、`xinternal-https-proxy`、`xhttps2http-proxy`、`xhttp2https-proxy` —— 这对应上游给整个家族加的那一个可选的 `x?`（`PROXY_RE`，`_original/lib/rules/rules.js:37-38`），这里把它当作基础名字的别名来解析。和上游一样，带 `x` 前缀的代理如果**建立**不起来，就回退成直连；这次重试管什么、不管什么，见 [上级代理那一节](#上级代理)。`enable`/`disable` 在请求的两侧应用一组精选的开关（见 [开关](#开关引入与-values) 那几张表，其余的不生效）；`pipe` 像 `plugin` 一样把请求交给一个注册过的服务（不会在数据流中途接管）；**裸 URL** 会转发请求（见 [目标地址](#目标地址)），而同一个协议键写成 `rule://` 时，是从 Values 里拉进额外的规则，就像 `rulesFile://` 从文件里拉一样；任何算子值里的 `{name}` 都会用 Values 里的内容替换。`cipher` 承载的是 Node 的 TLS 选项，rustls 能表达的部分都会照办 —— 见 [`cipher://` 能锁定什么](#cipher-能锁定什么)。

### 给源站出示客户端证书（`tlsOptions://`）

`tlsOptions://` 就是 `cipher://` 的另一个名字。[`cipher.md`](https://wproxy.org/docs/rules/cipher.html) 讲它的第一个用途就是双向 TLS（mutual TLS）：源站要求*本代理*证明自己是谁。

```
# PEM：私钥和它的证书，分成两个文件……
api.example.com   tlsOptions://key=/certs/client.key&cert=/certs/client.crt

# ……或者作为文本，放在一个值里
api.example.com   tlsOptions://{client.json}

# PKCS#12（.pfx / .p12）和它的密码
api.example.com   tlsOptions://passphrase=123456&pfx=/certs/client.p12

# 还有：连这个源站时信任谁
internal.example.com   tlsOptions://ca=/certs/corp-root.pem
staging.example.com    tlsOptions://rejectUnauthorized=false
```

````
``` client.json
{ "key": "-----BEGIN PRIVATE KEY-----\n…", "cert": "-----BEGIN CERTIFICATE-----\n…" }
```
````

| 选项 | 作用 |
|--------|--------------|
| `key` + `cert` | 客户端证书：PEM 格式，每一项都可以写路径，也可以直接写文本（以 `-----` 开头的值）。`cert` 可以放一整条证书链，叶子证书在前。私钥必须是未加密的 |
| `pfx` + `passphrase`（或 `pwd`） | 同样的身份，换成 PKCS#12 文件。旧的（3DES）和现在的（AES、PBKDF2）加密方式都能读 |
| `base` | 一个目录，上面那些路径都相对它来算 |
| `ca` | PEM，写路径或文本都行。**源站**证书必须能链到的根证书，用来*替代*内置的那一套 —— 这是 Node 里这个选项的含义 |
| `rejectUnauthorized=false` | 不校验这个源站的证书 |
| `minVersion`、`maxVersion`、`secureProtocol`、`ciphers` | 见 [下文](#cipher-能锁定什么) |
| `crl`、`dhparam`、`ecdhCurve`、`sigalgs`、`secureOptions`、`sessionTimeout`、`sessionIdContext`、`honorCipherOrder`、`allowPartialTrustChain` | **不支持**：rustls 没有对应的东西。请求照常进行，会话的 `unapplied` 里会列出这个选项 |

和所有 `cipher://` 选项一样，多行会合并，所以证书可以写在一行，版本写在另一行。

**证书用不了，请求就失败**，而且在发起任何连接之前就失败，并给出原因：`502`、`x-whix-error: rules`，body 类似 `tlsOptions: cannot read key /certs/client.key: No such file or directory`、`tlsOptions: the private key does not belong to the certificate` 或 `tlsOptions: pfx could not be opened (wrong passphrase, or not PKCS#12)`。遇到这些情况，whistle 会不带证书直接连，让源站去拒绝；两边客户端看到的都是 502，但这里会告诉你是哪个文件出了问题。

**连接按身份隔开。** 一条被源站认证为某个客户端的连接，绝不会被复用到另一条规则发起的请求上，只要那条规则写的是另一张证书，或者根本没写证书。证书和信任配置都是连接池给连接分组的依据之一，而且带身份的规则有自己单独的一套 TLS 会话（用于会话恢复），所以不会恢复到别人的会话上去。

`ca` 和 `rejectUnauthorized` 在这里比在 whistle 里更要紧，因为 whistle 除非用 `--safe` 启动，否则根本不校验源站。有了这两个选项，你可以只用一条规则去连一个由私有 CA 签发证书的源站，而不必用 `--insecure-upstream` 把所有源站的校验都关掉。

2026-09-30 之前，前五行的选项一个都没被读取：选项能解析，但每条连源站的连接都不带客户端证书。`tests/differential/core-bench.js` 用九种方式去问两边的代理 —— 不带客户端证书、PEM 按路径和内联、一个 PFX、一张源站不信任的证书、一个和证书不配对的私钥、错误的密码、证书和版本分两行写、一个不存在的文件 —— 九种结果两边全部一致。

别和 `enable://clientCert` / `requestCert` 搞混：那两个是让*代理伪造的服务端*反过来向**客户端**要证书，这个仍然 [没有实现](#开关引入与-values)。

### `cipher://` 能锁定什么

`minVersion` / `maxVersion` / `secureProtocol`（或者直接写一个 `cipher://TLSv1.2`）锁定的是**连源站那一侧**的 TLS 协议版本。rustls 只支持 TLS 1.2 和 1.3，所以锁到比 1.2 更老的版本时，会被抬到 1.2。

这个值可以走数据值能走的每一条路，这也是 [`cipher.md`](https://wproxy.org/docs/rules/cipher.html) 开头就讲的：JSON、`minVersion=TLSv1.2&maxVersion=TLSv1.3`、行格式、文件、`{name}`。唯一的例外是上游定下的：只由 `[a-z0-9:!-]` 组成的值是一个 **cipher string**（OpenSSL 的密码套件字符串），而不是对象（`SEP_CIPHER_RE`，`_original/lib/rules/index.js:38`），所以 `cipher://ECDHE-RSA-AES128-GCM-SHA256` 不需要写 `ciphers=`。另外，多行 `cipher://` 会**合并**，同一个键有冲突时第一行赢 —— `getTlsOptions` 会遍历整个列表（`:684-691`）。本项目以前只读第一行，而且只认 JSON 写法，其余的都悄悄忽略了。

> **这是本项目有意比 whistle 多做一步的地方之一。**
> 用 `tests/differential/https-bench.js` 实测（它现在会报告源站协商出的 TLS 版本）：在**一条正常能连上的连接上，版本锁定在上游不生效**。whistle 在 `getTlsOptions`（`_original/lib/rules/index.js:680-733`）里构造这些选项，但只有在*因为 ciphers 出错而重试*时，才会把它们加进 socket 选项（`lib/inspectors/res.js:495-497`、`lib/util/common.js:1769-1771`）；第一次成功的握手根本见不到它们，所以 `tlsOptions://{"maxVersion":"TLSv1.2"}` 在那边仍然协商出 TLS 1.3。直接写的 `cipher://TLSv1.2` 连这一步都走不到：`SEP_CIPHER_RE = /[^a-z\d:!-]/i` 不接受点号，所以 whistle 不把它当 cipher string，而它又不是 JSON —— 于是这个值最后被当成一个*文件*去打开。whix 在第一次尝试时就应用锁定，这才是规则字面上说的行为。

`ciphers` 是一个 **OpenSSL cipher string**，whix 会真正对它求值。不是拿名字去查表，而是把这门小语言完整地算一遍：别名（`HIGH`、`DEFAULT`、`ECDHE`、`AESGCM`、`aRSA` ……）、中缀 `+` 表示"同时满足"（`ECDHE+AESGCM`）、`!` 和 `-` 表示排除、前缀 `+` 表示降低优先级、`@STRENGTH` 排序。和 OpenSSL 不同的不是语言，而是求值所在的**全集**：rustls 只带九个套件，所以 `3DES` 什么也选不出来，这是对的 —— 在没编译 3DES 的 OpenSSL 上结果一模一样。

有两个细节是照着复刻的，因为它们是**在 Node 26 / OpenSSL 3.6 上实测**出来的，不是推断的：

- **TLS 1.2 的套件名不约束 TLS 1.3。** `ciphers: "ECDHE-RSA-AES128-GCM-SHA256"` 照样会用默认套件协商出 TLS 1.3。如果把锁定也套到 1.3 的列表上，那边就没有可提供的套件了，连接会被**降级到 TLS 1.2** —— 一条本意是"优先用这个套件"的规则，反倒把连接变弱了。
- **只有明确写出 TLS 1.3 套件名，才约束 TLS 1.3。** `TLS_AES_128_GCM_SHA256` 会锁定它；别名 `CHACHA20` 不会，尽管它描述的也是一个 TLS 1.3 套件。

一个**什么都选不出来**的字符串，会让这次**锁定**作废，请求本身不受影响：连接照常建立、不带锁定，日志里会说明这一点，并点出哪些 token 什么都没匹配到。它*不会*让请求失败，原因是这里的"没有匹配"和 OpenSSL 里的不是一回事。OpenSSL 在一个字符串从它自己那个很大的全集里什么都选不出来时，会抛 `no cipher match`；而这里只是从九个套件里什么都选不出来。`cipher://3DES` 在编译了 3DES 的 OpenSSL 上是个完全正常的字符串，在这里如果让它失败，失败原因只跟*这个构建*有关，跟规则无关。让请求失败，就等于把这个限制强加到别人的流量上，还挂着一条说他们规则文件有问题的报错。

还有两点让这件事定了下来。一是 `cipher://` **在 whistle 2.10.8 里不生效** —— 每种写法都实测过 —— 所以没有可以忠实照搬的上游行为，只剩一个问题：一个真正实现了它的代理应该怎么做。二是本项目在别处早就回答过这个问题：`statusCode://abc`、`replaceStatus://1` 和 `method://GET;` 都是让算子不生效，而不是让什么东西失败。

值的两半是分开读的，所以一个用不了的 cipher string 不会把一个可用的 `maxVersion` 一起拖下水。存在、但没有任何允许的版本能用的套件 —— 比如 `maxVersion` 是 TLS 1.2 时只写了 TLS 1.3 的套件 —— 也按同样的方式丢掉，版本保留；以前为这种情况建连接会让请求 panic。

被丢掉的锁定会记在会话上，不只是在日志里：`unapplied` 会点名 `cipher://` 算子，kind 是 `cipher-unusable`，并写明原因（[`API.md`](API.md#没生效的规则)）。纯 HTTP 上什么都不会说，因为它根本没有握手，也就谈不上缺了锁定。**`cipher://` 锁定是调试辅助，不是安全策略**：用不了的时候，连接会带着默认套件照常进行，所以它不能保证源站到底是用什么连上的。

```
# 会被求值；源站真的从这个集合里协商
example.com cipher://{"ciphers":"ECDHE+AESGCM:!AES128"}
# 按名字锁定 TLS 1.3；TLS 1.2 的列表被清空，和 OpenSSL 清空它的方式一样
example.com cipher://{"ciphers":"TLS_AES_128_GCM_SHA256"}
# 能连上，但不带锁定；会话里写着 `no cipher match: 3DES names no cipher
# suite this build has` —— rustls 没有 3DES，怎么说它都不会有
example.com cipher://{"ciphers":"3DES"}
# ciphers 这一半被丢掉；版本那一半仍然有效
example.com cipher://{"ciphers":"3DES","maxVersion":"TLSv1.2"}
```

九个套件是三个 TLS 1.3 套件（AES-GCM ×2、ChaCha20-Poly1305），加上六个 TLS 1.2 的 ECDHE 套件（ECDSA/RSA × AES-128-GCM/AES-256-GCM/ChaCha20）。选择结果是和这个集合取**交集**，所以 `cipher://` 只能缩小代理会协商的范围，永远不能扩大。

**源站证书的校验方式和 whistle 不同。** whistle 默认设置 `rejectUnauthorized: false`（`_original/lib/config.js:74`），只有用 `--safe` 启动才校验，所以自签名、过期或私有 CA 证书的源站，它都能照常调试。本项目默认用 webpki 根证书库校验源站（以及 `https-proxy://`），所以这些源站在这里会返回 502，除非用 `--insecure-upstream` 启动。

本地文件家族从磁盘读内容返回：`file`/`rawfile` 返回字节（`rawfile` 解析的是一份完整的 HTTP 响应文件 —— 状态行 + 头 + body）；`x`/`xs` 变体（`xfile`、`xrawfile` ……）**文件存在时**返回文件，不存在就落到真实服务器上。

`tpl`、`dust` 和 `jsonp` 渲染模板 —— 而且三者**逐字节相同**，和上游完全一样：whistle 没有模板引擎，`jsonp` 自己也不做任何回调包装。渲染分两遍：先用查询字符串替换 `{name}`/`{{name}}`，再替换 `${var}` 运行时变量。变量表和坑见 [`TEMPLATES.md`](TEMPLATES.md)。

WebSocket 帧也会被抓下来：每个被拦截的 `ws://`/`wss://` 连接都记成一个会话（状态 `101`），每一帧（两个方向）都能看到 —— 在控制台里选中这个连接，打开它的 Frames 标签页，或者请求 `/frames.json?id=<session>`。

**经过代理时不协商任何扩展。** 客户端的 `Sec-WebSocket-Extensions` 提议（浏览器默认会发 `permessage-deflate`）不会转给服务器，所以帧以不压缩的形式传输，抓包、`frameScript` 和插件看到的每一帧，都是两端实际写出的那一帧。应用本身察觉不到，只是线路上的字节多了。上游会把这个提议转过去，再另外解压一份副本用来显示。（2026-09 之前本项目会把它转过去，却没保留帧的"已压缩"标志位，结果开了压缩的服务器发来的消息，到达时成了一堆二进制乱码。）

`enable://ignoreSend` 和 `enable://ignoreReceive` 让这种会话的某一个方向静音：帧仍然会被**抓下来并做标记**，只是永远不会送到对端，所以界面上显示的是丢掉了什么，而不是一段空白。控制帧不受影响 —— 扣下 `close` 会让两端对连接是否已经结束各执一词，扣下 `ping`/`pong` 会破坏两端约好的保活；whistle 同样只扣数据帧。

`enable://pauseSend` 和 `enable://pauseReceive` 则是把一个方向**扣住**，而不是丢掉。帧一到就被抓下来并标记，Frames 标签页会显示哪个方向被扣住、有多少帧在等，还有一个 **Release** 按钮把它们放出去 —— 按到达顺序，一次全部放出。whistle 也只有这个粒度：它自己的控制台是把这个方向的状态改回正常，整个控制台里没有"只放一帧"的功能。放行请求发到 `POST /api/ws/release`，带 `{"id": <session>, "dir": "send"|"receive"}`；`GET /api/ws/status?id=<session>` 返回当前扣住了什么。

暂停不等于"晚一点的忽略"，由此带来两点不同：

- 它也会扣住这个方向的**控制**帧 —— 上游暂停的是字节流，而不是里面的帧，所以和被扣的数据挤在同一个数据块里的 `ping` 会一起被扣住。为了不让两端在一条突然安静下来的连接上超时，暂停期间代理每 22 秒自己发一次保活，和 whistle 完全一样。发送方向被扣住时，`disable://pong` 会压掉发给**服务器**的那个保活；接收方向被扣住时，`disable://ping` 会压掉发给**客户端**的那个 —— 和 whistle 的分法一样。压掉它们，意味着一条安静的连接只能听凭两端各自的空闲超时处理，而这正是你要这么设置的目的。
- 同一个方向上两个开关都打开，并不构成一种状态：whistle 每个方向只记一个状态，而且先判断暂停，所以 `enable://pauseSend|ignoreSend` 的效果是暂停；放行之后，这个方向保持畅通，而不是开始丢帧。

被扣住的方向会预读，让控制台能显示有什么在等，最多 64 帧或 4 MiB；超过之后对端会被反压，直到放行为止，不会丢任何东西。连接结束时仍被扣着的帧，在抓包里保持标记 —— 它们从没到达对端，这时再放行也找不到东西了。

### 多个匹配串与多行块

一个算子可以在一行里服务多个匹配串（pattern），这一行会展开成每个匹配串一条规则。这需要用**算子在前**的写法；如果写成匹配串在前，只有第一个 token 是匹配串，其余都是算子（见 [匹配串放在哪](#匹配串的位置)）：

```
host://127.0.0.1:8080   www.example.com  api.example.com  static.example.com
```

列表更长时，用块写法更好读（whistle 的 `line\`` 语法）：

```
line`
proxy://127.0.0.1:8080
www.example.com
api.example.com
includeFilter://m:GET
excludeFilter:///admin/
`
```

块在解析前会被折叠成一个逻辑行，所以一行里合法的写法，放进块里也都合法。

### 注释

`#` 在**一行的任何位置**都会开始注释，不只是行首：

```
a.com  host://1.1.1.1        # 这一整段尾巴都会被忽略
```

这和上游完全一致，包括它那个容易割手的地方：URL 片段（fragment）里的 `#` 也会被当成注释，所以 `example.com/a#b file:///x` 会丢掉 `#b`。

### 元数据与只有上游才有的基础设施

| 算子 | 原因 / 说明 |
|-------------|-----------|
| `G` | 上游的全局插件基础设施在本项目里没有对应物；它不是改请求 body/头的算子，也不是重要性标记 |
| `style` | 元数据，不改写流量；保留它是为了在控制台里按 `style:` 筛选。不保证和上游界面的视觉效果完全一样 |

### 相比上游做了简化的地方

whistle 的插件变量（`%name=…`）和它基于 Node 对象的插件 API 没有实现 —— 这里的插件是讲 whix 自有协议的外部 HTTP 服务（见 [`PLUGINS.md`](PLUGINS.md)）。模板变量和 `lineProps` *是*实现了的；具体做到哪一步，见 [`TEMPLATES.md`](TEMPLATES.md) 和 [`LINE_PROPS.md`](LINE_PROPS.md)。文档写法之外的匹配串/算子也许能解析，但行为不一定和上游 whistle 完全一致。

算子层里已知、而且有意留着的缺口：

- **引入插件规则的 `@` 没有实现。** 指向插件的两种来源写法 —— `@whistle.<name>[/path]` 和 `@$<key>/…` —— 在上游会去请求插件自己的 UI 服务（`getRemoteRules`，`_original/lib/util/index.js:3271-3290`）。这里的插件是讲本项目协议的外部 HTTP 服务，没有这样的接口，所以这一行只记日志，不贡献任何东西。其他所有来源写法都能用，对所有规则文本都一样 —— 见 [引入另一份规则文本](#引入另一份规则文本)。
- **`@` 来源里的 `${port}` 要等代理绑定端口之后才能解析。** 它取的是*正在监听*的端口，而 `--port 0` 要等 socket 建好才确定，所以在那之前拉取的来源会带着没替换的变量去拉 —— 日志里会说明，而不是去拉 0 端口。实际上走不到这一步：第一次拉取发生在绑定之后。
- **没有声明 charset 的响应不做嗅探。** 有 `charset=` 时，响应算子会遵守它：先把 body 解码再做文本变换，之后再编码回去，注入的值也按这个字符集写入，和 whistle 一样。没有的话，whistle 会读前 25 KB，猜是 UTF-8 还是 GB18030；whix 把 body 当 UTF-8 处理，不是 UTF-8 就不动它。所以一个不是 UTF-8、又从不声明字符集的页面，whistle 会改写，这里会原样放过。
- **请求 body 的字符集不会被还原。** whistle 给 `reqReplace://` 套上和响应同样的一对解码/编码；whix 直接处理字节，所以在非 UTF-8 的请求 body 上，这个算子什么也不做。
- **HTTP/2 请求的 `:authority` 按原样转发。** 把 h2 转成 HTTP/1.1 发给纯 HTTP 源站时，本项目发送的是客户端请求的那个 `Host`；whistle 发的则是隧道当初打开时用的 authority。所以一个先 `CONNECT host:80`、再请求 `:authority: host` 的客户端，在这里看到的是 `host`，在那边是 `host:80`。两者指的是同一台服务器，按 `Host` 匹配的规则也不受影响 —— 匹配串是拿请求 URL 来匹配的，而 URL 两边都带着端口。
- **没有 body、但方法允许带 body 的请求，body 长度的标示方式（framing）不同。** 客户端发 `POST`（或任何可能带 body 的方法），又完全不带 `Content-Length` 和 `Transfer-Encoding` 时，whistle 会转发 `content-length: 0`，whix 两个头都不发。两种写法都表示"没有 body"，所有源站读起来都一样；差别来自 Node 的 HTTP 客户端和 hyper 的不同，不是规则造成的。在普通代理路径上看不出来，因为客户端自己的库已经选好了标示方式；只有在承载明文的 `CONNECT` 隧道里才会显现，那里的字节就是客户端写出的样子。
- **响应的 trailer 部分只发给要了它的客户端。** 源站的 trailer 和 `trailers://` 都只在客户端请求带了 `TE: trailers` 时才发 —— 否则 hyper 的 HTTP/1 服务端会丢掉 trailer 部分（`Conn::write_trailers`，hyper 1.10.1 `src/proto/h1/conn.rs:729-733`，依据的是在 `conn.rs:328-332` 读到的 `TE` 头）。whistle 则不管怎样都发。响应的其他部分不变；用 `curl --raw -H 'TE: trailers'` 能看到完整行为。
- **`params://` 写进 body 时是先缓冲再处理，不是流式的。** whistle 逐个 part 改写 multipart body，所以上传的内容永远不会整个落进内存；whix 手里本来就已经有完整的 body（其他请求 body 算子也都要缓冲），直接按 boundary 切分。格式正确的 body 结果一样，大 body 会多占内存。大小上限*是*实现了的 —— 见 [请求 body 有上限](#请求-body-有上限)。
- **非 UTF-8 的请求 body**，`params://` 合并时**不去动它**。whistle 会尝试 GB18030，之后再编码回去；本项目保持 UTF-8，和其他所有文本变换一样。
- **`{{whistlePluginName}}` / `{{whistlePluginPackage.x}}` 不会被替换**，而且这是有意不做，不算缺口。上游会在从已安装 npm 包目录里读出的 `rules.txt` / `_rules.txt` / `resRules.txt` / `_values.txt` 文件里替换它们，数据来源是这个包自己的 `package.json`（`renderPluginRules`，`_original/lib/util/index.js:3533-3542`；`lib/plugins/get-plugins-sync.js:184-206`）。这里的插件是讲本项目自有协议的外部 HTTP 服务：没有包目录、没有 `package.json`，也没有静态规则文件 —— 插件要注入规则，是从它的请求钩子里返回，而那时它本来就知道自己叫什么。没有可以拿来替换的东西。

如果某条规则没按你想的那样工作，加 `-v`（debug 日志）运行：每个请求都会记下它最终解析出的目标地址，或者短路的决定。


### wproxy.org 文档和 whistle 实际行为不一致的地方

下面是官方文档里写了、但 whistle 2.10.8 实际并不这么做的地方。每一条都对着运行中的程序实测过，**以程序为准** —— 本项目跟的是 whistle，不是文档里的文字。之所以记下来，是因为从那些页面过来的读者，不然会以为是 whix 有 bug。

| 页面上说 | whistle 实际上 | 在哪 |
|---|---|---|
| 对 `OPTIONS` 请求，`access-control-allow-headers` 会变成 `access-control-expose-headers` | 正好相反 —— 预检请求上是 `allow`，其他情况是 `expose` | 上文的 [`resCors`](#改写响应) |
| 不带 `: ` 的行格式值"在第一个冒号处切分" | 写在规则行上的值，只有带 `=` 时才会交给行解析器，而且那时它是查询字符串，不是多行文本。不带 `=` 就**什么都不产生**：`reqHeaders://x-a:1` 和 `reqHeaders://bare` 都不设置任何头，`urlParams://test1:1` 也不加任何查询参数 —— 而同样的文字写在 `{value}` 的某一行上，就会变成条目，因为加载进来的内容走的是另一条路。用五种方式实测过；whix 一致 | 见上文"数据值的三种写法，以及两条路"那一段 |
| `ws://` / `wss://` / `tunnel://` 对纯 HTTP 请求"返回 502" | 确实如此，页面是对的 —— 但只在这一行被*读成*目标地址的时候。`127.0.0.1:8080 ws://host/x` 就不是：裸 host 在 `indexOfPattern` 看来不是匹配串，`ws://` URL 才是，于是这一行会互换成"匹配串 `ws://host/x`、算子 `host://127.0.0.1:8080`"（`_original/lib/rules/rules.js:1449-1467,:1774-1789`），而纯 HTTP 请求永远匹配不上它 | `cases.js` 里那两个 "swaps into pattern and host" 用例 |
| `delete://pathname`"删除请求路径（不包含请求参数）" | 它删掉路径之后，**查询串会重复一遍** | 已记录在 [删除](#删除) 一节 |
| [`socks`](https://wproxy.org/docs/rules/socks.html) 说默认端口是 **443** | 是 `1080`，出自同时给三者赋值的那一行 —— `isSocks ? 1080 : isHttpsProxy ? 443 : 80`（`_original/lib/inspectors/res.js:284`）。那个 443 看起来是从 `https-proxy` 页面抄过来的 | whix 用 1080；`src/proxy/upstream.rs` |
| [`enable`](https://wproxy.org/docs/rules/enable.html) 把 `forceResWrite` 和 `forceReqWrite` 并列，一侧一个 | 程序里根本没有 `forceResWrite`。`forceReqWrite` 在**两侧**都会读 —— 响应的转储听的也是这个按请求命名的名字（`_original/lib/inspectors/req.js:604`、`res.js:1300`） | [开关](#本项目没实现的开关) 下面的那张开关表 |
| [`socks`](https://wproxy.org/docs/rules/socks.html)、[`https-proxy`](https://wproxy.org/docs/rules/https-proxy.html) 等页面把 `enable://captureIp` 写成解密发往 IP 的 HTTPS 请求的办法 | 确实是，但前提是 whistle 本来就在解密：单独一个 `enable://captureIp` 不会打开拦截，所以在默认安装下，这个连接怎么都是原样转发。`enable://capture` 才能两件事一起做。两边代理都在控制台开关关闭和打开两种状态下实测过 | [不解密某个连接](#不解密某个连接) |
| [`auth`](https://wproxy.org/docs/rules/auth.html) 的第 2 种写法：一个 ```` ``` ```` 块里写 `username: admin` / `password: …`，用 `auth://{custom-key}` 引用 | 等 `getAuthByRules` 看到它时，块里的内容已经*就是*值了，而它里面没有斜杠，所以按冒号切分：用户名变成字面量 `username`，密码是文件剩下的全部内容。同样格式的**文件**就没问题，因为路径里有斜杠，走的是另一条路。两边代理都实测过；whix 一致 | 上文的 [`auth://`](#auth-的四种写法)；`cases-docs.js` |

`ws://` 那一行最值得记住：页面是对的，而最显而易见的测试方法却不对 —— 写成 `<host:port> ws://…` 的 bench 用例在两边都不生效，对它名义上要测的那条规则什么也证明不了。

行格式那一行以前声称 whistle 会设置一个字面上名叫 `x-a:1` 的头。并不会；它什么都不设，本项目也一样。那一行本身就是一次测错，而且错在一张专门用来记录"说错了"的表里 —— 这件事值得留在记录上，而不是悄悄改掉。


### 代理自己生成的响应带 `x-server`

whistle 自己生成（而不是转发）的每个响应都带 `x-server`（`wrapResponse`，`_original/lib/util/index.js:1080-1090`）：`statusCode://`、`redirect://`、`file://` mock、它直接应答的预检。它说清了一件 mock 响应本来说不清的事：这个响应来自代理，不是源站。

whix 也这么做，写的值是 `whix`，因为它不是 whistle。依赖上游那个确切值的工具会匹配不上，这正是对的结果 —— 它面对的本来就不是 whistle。


### 不解密某个连接

`disable://intercept` 会原样转发 TLS 连接，而不是读取它 —— 客户端拿到的是**源站自己的证书**，不是本代理伪造的。做了证书固定（pinning）的客户端需要的就是它，不想被解密的 host 也该用它。`disable://https` 和 `disable://capture` 是同一个开关（`disable.intercept || disable.https || disable.capture`，`_original/lib/tunnel.js:167-169`）。

```
pinned.example.com disable://intercept
```

连接仍然会被**路由**：`host://` 和代理家族照常作用于它，因为路由不需要明文。它失去的是所有需要明文的东西 —— 会话里没有请求、没有头、没有 body，任何请求或响应算子都不会在它上面执行。

它的优先级高于 `sniCallback://`：一个没人会为它伪造证书的连接，再去问插件该伪造哪张证书，答案毫无用处，所以这个钩子不会被调用。

`--no-intercept-https` 是对所有连接一次性说同样的话。

客户端也可以自己为某一条隧道这么要求：在 `CONNECT` 上带一个请求头 `x-whistle-policy: tunnel`（或 `connect`，或 `weakTunnel`）。这是 whistle 自己的约定，它的插件和串在前面的另一个 whistle 都在用（`_original/lib/tunnel.js:143-147`）。它优先于 `enable://capture`，和在那边一样。要求相反效果的值 `intercept` 和 `capture` 不予理会：拦截开着时（默认）它们什么也不改变；拦截关着时隧道仍然原样转发，而 whistle 会去读它。

**先连上远端，再告诉客户端隧道已打开。** 当规则匹配的是 `CONNECT` 本身里的地址时（或者拦截关着，或者请求头要求了），whix 先拨号，等远端应答之后才回 `200`，和 whistle 一样（`_original/lib/tunnel.js:637-695`）。名字解析不出来，或者端口拒绝连接，`CONNECT` 就**完全得不到回复**：浏览器报 `ERR_TUNNEL_CONNECTION_FAILED`，控制台里有一条状态为 0 的 `CONNECT` 行，失败阶段是 `dns` 或 `connect`。如果规则只匹配 ClientHello 里的名字，那要等 `200` 发出去之后才能判断，所以这种情况下客户端看到的是隧道先打开、再关闭，控制台里是同样的一行。

**两个更窄的开关，各管一半连接。** 分到哪一半，看 ClientHello 有没有写服务器名，这是客户端那边的事实，跟规则无关：

| 开关 | 原样转发的是 |
|---|---|
| `disable://captureSNI` | ClientHello **写了**服务器名的连接 |
| `disable://captureNoSNI` | ClientHello **什么都没写**的连接 |

**还有一个不用写的默认行为。** 打开到**裸 IP 地址**、而且 ClientHello 没写名字的隧道，*不会*被解密 —— `net.isIP(servername) &&
!isCaptureIp()`（`_original/lib/https/index.js:1287`）。TLS 禁止在 SNI 里放 IP 字面量，所以 `https://10.0.0.5/` 正好就是这种形态，会原封不动地通过。有三种写法可以要求重新解密它，还有一种写法即便如此也拒绝：

```
10.0.0.5   enable://capture      # ……或 enable://captureIp，或 enable://captureIP
10.0.0.5   enable://capture disable://captureIp   # 仍然原样转发
```

`enable://capture` 是通用的那个：在 whistle 里，它也是把拦截整体打开的开关，因为 whistle 的全局开关默认是关的。这里拦截默认开着，所以这个开关只在这一种情况下才有作用。以上全部对着 whistle 2.10.8 实测过 —— `tests/differential/https-bench.js` 对十二种连接形态比较**证书是谁签的**，只有这样才能分清一条连接是被读了，还是被直接放过去了。

> whistle 不管规则怎么写都会拦截**本地**主机名，所以 `localhost` 上的 `disable://intercept` 在那边被忽略，在这里会被遵守。见 [`CERTIFICATES.md`](CERTIFICATES.md#哪些连接会被解密)。


### 调整发给上级代理的 CONNECT

`disable://proxyUA` 会从本代理发给上级代理的 CONNECT 里去掉客户端的 `User-Agent`；`disable://proxyConnection` 会要求那个代理关闭连接而不是保持 —— 发 `Proxy-Connection: close` 而不是 `keep-alive`（`_original/lib/inspectors/res.js:314-318,:329-333`）。两者都直接从 `disable` 读取，不受 `enable://` 抵消的影响，和上游的读法一样。


### 响应 body 也有上限

whistle 用**流式变换**改写响应（`addTextTransform` / `addZipTransform`，`_original/lib/inspectors/res.js`），所以一条规则永远不会让它把整个 body 攒在手里。本项目的 body 层是缓冲式的，所以会：任何匹配上的 body 算子，都要先把整个响应收齐才动手。

拿一个 800 MB 的下载实测，只匹配了一条 `resReplace://`，常驻内存从 9.9 MB 涨到 **1.97 GB** —— 只是一条普通规则加一个大文件。

现在上限是 **16 MiB**（`--body-rewrite-limit`），这是上游自己的"大数据"数字（`BIG_MAX_RES_SIZE`，`res.js:22`），对改写主要针对的页面、打包产物和 JSON 载荷来说足够宽裕。超过上限，响应会**原封不动**地流过去：body 算子、`enable://gzip` 和任何插件的 `responseBody` 钩子都不执行。会话上会说明这一点：它的 `unapplied` 列表点出每个没执行的算子，kind 是 `body-over-limit`，并写明上限（[`API.md`](API.md#没生效的规则)），控制台的 Rules 标签页会把它们标成 "not applied"。还会有一条 `WARN` 点出是哪个请求。同样的 800 MB 下载，现在峰值只有 **33 MB**，而且逐字节完整到达。

上限按线路上的字节计算，而且**解压也算在内**：一个解压后会超过上限的 gzip 不会被解压，而是按到达时的样子转发，记为 `decoded-over-limit` —— 一个由同一个字节重复构成的 16 MiB gzip，解开后有好几个 GB。`content-encoding` 根本解不开的 body —— 字节和头说的不一致（`undecodable`），或者是 `zstd` 和叠加编码（`unsupported-coding`）—— 也会原样转发，而不是让算子在压缩过的字节上跑：以前在这种情况下，`resAppend` 会把纯文本写到 gzip 流的结尾后面，没有哪个客户端能读。

`--body-rewrite-limit` 的值会出现在 `/api/status`（`body_rewrite_cap`）和控制台的 Status 面板上；把 whix 当库嵌入的程序用 `body_rewrite_cap` 设置它。`enable://resMergeBigData`，或者在 `resMerge://` 那一行上写 `lineProps://enableBigData`，会把单个请求的上限提高到至少 16 MiB —— 只有在这个参数被调低过时才有意义。

这是本项目少数几个需要一个上游没有的参数的地方之一，原因在架构上，不是偏好 —— 见 [`ROADMAP.md`](ROADMAP.md)。


### 跨域 mock：自动 CORS

用 `file://`（以及 `rawfile`/`tpl`/`dust`/`jsonp` 和它们的 `x`/`xs` 变体）mock 一个
API，而发起请求的页面在**另一个源**上时，whistle 会自己补上 CORS 头 —— 否则浏览器
在任何代码看到响应之前就把它拒了。whix 现在同样如此
（`isAutoCors`，`_original/lib/handlers/file-proxy.js:178-191`）。

触发条件就是请求带了 `Origin` 头。补的是 `resCors://enable` 那一套：回显请求自己的
`Origin`，并带 `access-control-allow-credentials: true`。

**预检也被直接应答。** 浏览器在真实请求之前先发 `OPTIONS`，而 whistle 对 file 规则的
预检**答 200 + CORS 头，根本不打开文件**（`file-proxy.js:249-252`）。这一半不可省：
文件不存在就会 404 掉预检，规则只对 `POST` 写也会答出错误的东西，真实请求于是永远
不会发生。

```
# 页面在 http://app.test 上，API mock 在 http://api.test 上
api.test/data file:///srv/mock.json
```

关掉它：`disable://autoCors`，或行级属性 `lineProps://disableAutoCors`
（原版的拼写错误别名 `disabledAutoCors` 一并接受）。

只作用于 file 家族。`redirect://` 与 `statusCode://` 在上游由另一个 handler 应答，
不带自动 CORS，这里也一样。


### 请求 body 有上限

改写请求 body 的算子需要把 body 放进内存，而 body 是客户端想发什么就发什么。whistle 把上限定在 **2 MB**，可以用 `enable://reqMergeBigData`，或者在 `reqMerge://` 那一行写 `lineProps://enableBigData`，提到 **16 MB**（`MAX_REQ_SIZE` / `BIG_MAX_REQ_SIZE`，`_original/lib/inspectors/req.js:19-20,:163,:564`）。whix 也一样。

超过上限，请求**不会**失败，也**不会**被截断：body 逐字节流向源站，只是改写停了 —— `reqBody`、`reqReplace`、`params`、`reqWrite`/`reqWriteRaw` 和 `reqSpeed` 都不执行。这就是上游的 `interrupt`（`handleParams`，`req.js:169-185`）。对调试代理来说这是正确的失败方式：不能因为检查流量而把流量弄坏。whix 会在会话上记录 —— `unapplied`，kind 是 `request-body-over-limit`，点出那些算子（`params://` 只在它本来会改写表单或 JSON body 时才列出）—— 并记一条 `WARN`。这样，一条在 body 超过某个大小后就不再生效的规则，不会看起来像一条从没匹配过的规则。`content-encoding` 解不开的请求 body 也一样，按发来的样子到达源站。

`b:` body 筛选器也要读 body，用来决定*哪些*规则生效，所以它们没法参考某条规则来提高上限 —— 它们总是用普通的 2 MB，并且只在读到的那段前缀上匹配，和上游的 `resolveBodyFilter` 一样。


### 事件流

`text/event-stream` 响应永远不会被收齐。收齐它不只是让它变慢，而是把它整个扣住：body 什么时候结束由服务器决定，对 SSE 来说通常是永远不结束，那客户端就什么都收不到。

`resReplace://` 仍然生效。它是唯一不需要完整 body 的 body 算子 —— 它只需要一个窗口 —— 所以它跟着流走，事件一到就替换。whix 只扣住一小段尾巴（刚好够保证跨数据块边界的匹配不会漏掉），每遇到一个完整事件的结尾，就把到那里为止的内容放出去，这正是上游自己的机制（`_original/lib/util/replace-string-transform.js`、`replace-pattern-transform.js`）。写成 `\r\n\r\n` 的空行在这里也算事件边界，上游只认 `\n\n`。

有两种情况直接拒绝、不去尝试，流原样通过：

- **压缩过的事件流** —— 在 deflate 流里搜明文字符串什么都找不到，改写它又会破坏头里承诺的格式；
- **真正需要结尾的算子**：`resMerge://`、`resScript://`，以及带类型的注入（`htmlPrepend`、`jsAppend` ……）。后者是按响应是不是 HTML/JS/CSS 来选的，所以本来就永远匹配不到事件流。

  声明了 `responseBody` 的插件也会同样被跳过，并记一条 `WARN`，免得这个钩子看起来莫名其妙没跑。改用流式钩子（`pipe://`）—— 见 [`PLUGINS.md`](PLUGINS.md)。

`resPrepend://` 和 `resAppend://` **会**生效：一个在源站第一个字节之前发出，另一个在最后一个字节之后。在一个永远不结束的流上，`resAppend://` 永远不会触发 —— 一个不结束的 body 没有"之后"，这是如实的答案，不是缺功能。

`resBody://` 也生效，而且意味着不用等源站的 body：值发出去，流就结束。这让它可以用来 mock 一个本来会永远流下去的接口。不会加 doctype，`safeHtml`/`strictHtml` 也不限制这三个中的任何一个，因为这些都属于上游 HTML 注入那一套机制，而事件流不是 HTML。

`disable://trailers` 对事件流生效；`resWriteRaw://` 和 `trailers://` 不生效。

会话会点出哪些没执行，记为 `unapplied`，kind 是 `event-stream`：`resMerge`、带类型的 `html*`/`js*`/`css*` 家族、`resSpeed`、`resScript`、`weinre`、`resWrite`/`resWriteRaw`、`trailers` 和 `enable://gzip`，以及流被压缩时的 `resReplace`。跟着流一起走的那四个不会列出，因为它们执行了。


## 源站证书校验

whistle **不**校验源站服务器的证书：`rejectUnauthorized` 默认是 `false`，只有 `--safe` 才会打开（`_original/lib/config.js:74`）。whix 把这个默认值反过来 —— 默认校验，用 `--insecure-upstream` 关掉：

```bash
whix --insecure-upstream      # 接受自签名 / 私有 CA 证书的源站
```

不加这个参数，自签名或私有 CA 证书的源站会返回 **502**，而 whistle 会照常代理。

这个反转是有意的，也是本项目唯一不复刻上游默认值的地方。其他地方都以忠实为先 —— 同一份规则文件在两个实现里必须解析出相同的结果。但一个默默接受任何源站证书的调试代理，在它正在检查的连接本身已经被别人拦截时，没法告诉用户。这个特性值得默认保留，为它多花一个参数也值得。
