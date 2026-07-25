# 模板与本地文件 / Templates

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [规则](RULES.md)

用本地文件 mock 响应，并在其中插入请求相关的变量。

```
example.com/api    tpl:///tmp/mock/api.json
example.com/page   file:///tmp/mock/page.html
example.com/raw    rawfile:///tmp/mock/raw.http
```

---

## 先说一件重要的事：whistle 没有模板引擎

原版 whistle 里 **`tpl`、`dust`、`jsonp` 是同一个东西的三个名字** —— 字节级等价，没有任何分支区分它们：

```js
// _original/lib/handlers/file-proxy.js:14
var TPL_RE = /(?:dust|tpl|jsonp):$/;
```

这个正则在整个文件里只被用了两次，两处都走同一条渲染路径。`package.json` 里也没有任何模板引擎依赖 —— 没有 dust.js，没有 handlebars，没有 mustache。

所以：

- **没有** `{#section}` / 循环 / 条件 / 局部模板
- **没有** `{.}`、嵌套 block、自定义 helper
- `dust://` 和 `jsonp://` 是未文档化的历史别名，whistle 自己的 WebUI 协议列表里都没有它们

whistle-rs 忠实对齐了这个行为。

> **`jsonp://` 不会自动包裹 callback。** 上游没有任何 callback 嗅探逻辑 —— JSONP 是靠模板自己写出来的，见下文。

---

## 渲染：两遍替换

模板渲染是**两遍有序替换**，外面套一个整体开关。

### 触发开关

```js
var VAR_RE = /\{\S+\}/;   // file-proxy.js:15
```

**整个文件里必须至少出现一处 `{…}`（花括号之间不含空白），否则两遍都不执行。**

这是个容易踩的坑：

- `${ now }`（`{` 后有空格）→ 永远不会渲染
- 文件里完全没有 `{` → 即使写了 `${method}` 也不会替换

### 第一遍：查询字符串插值

```
{name}     {{name}}
```

- 数据来源**只有 URL 查询字符串**，不是请求头、不是 body、不是 values 存储
- 变量名限定为 `[\w$-]+` —— **不含点号**，所以 `{a.b}` 不是第一遍的变量
- 解析规则同 Node `querystring`：按 `&`/`=` 拆分，`+` 转空格，百分号解码
- **重复的键会变成 JSON 数组**：`?a=1&a=2` 配 `{a}` → `["1","2"]`
- **未知的名字原样保留**，不会被替换成空串
- 前面紧挨一个 `$` 可以抑制替换：`${name}` 会完整留给第二遍

URL 里**没有** `?` 时第一遍整个跳过，但**第二遍照常执行**。

### 第二遍：`${var}` 运行时变量

变量名是一个**封闭白名单**，不在表内的名字原样保留。

| 写法 | 含义 |
|------|------|
| `${var}` | 普通替换 |
| `${{var}}` | 结果做 `encodeURIComponent` 编码 |
| `$${var}` | 原始模式：查询串/cookie 的值**不做**百分号解码 |
| `${var.key}` | 子路径，如 `${query.foo}`、`${reqHeaders.user-agent}`、`${env.PATH}` |
| `${var.replace(a,b)}` | 对解析结果再做一次替换，见下节 |

变量名**大小写不敏感**（`${reqHeaders}` 与 `${reqheaders}` 等价）。

---

## `.replace(pattern,replacement)` 修饰符

变量名（或子路径）末尾可以跟一个 `.replace(...)`，对**解析出来的值**再做一次替换
（`resolveTplVar`，`_original/lib/rules/rules.js:725-752`）。它在 `${{...}}` 的
URI 编码**之前**生效。

| 写法 | 结果 |
|------|------|
| `${query.v.replace(a,b)}` | 普通子串替换，**只替换第一处**（JS `String.replace` 的字符串形式） |
| `${url.replace(/a/gi,b)}` | `/…/flags` 会被编译成真正的正则；`g` 全部替换，`i`/`m` 同 JS，`u` 无需转换 |
| `${v.replace(/(\d+)-(\d+)/,$2/$1)}` | 反向引用 `$&`、`$0`..`$9` |
| `${v.replace(/(.+)/,$$1)}` | `$$n` 把该分组做 `encodeURIComponent` |
| `${v.replace(/(x)/,\$1)}` | `\$n` 原样输出 `$n`；`\\$n` 输出一个反斜杠加值 |
| `${v.replace(a\,b,-)}` | `\,` 是参数里的字面逗号；`\\,` 是字面 `\,` |
| `${v.replace(/x/g)}` | 没有第二个参数 = 删除 |
| **`${query.absent.replace(,默认值)}`** | **pattern 为空时不做替换，而是给空值兜底** |

最后一行容易漏掉：上游是 `val = pattern ? val : val || replacement`
（`rules.js:744-746`）。所以

- pattern 为空 + 值为空 → 输出 `replacement`
- pattern 为空 + 值非空 → 输出原值
- pattern **非**空 + 值为空 → 输出空串（**不会**兜底）

反向引用只有在 pattern 是正则时才展开：字符串 pattern 没有捕获组，JS 会把 `$1`
原样留下（`$&` 仍然生效）。

> **不支持的正则会整体保留原样。** JS 的断言 `(?=…)`、反向引用 `\1` 在 Rust 的
> `regex` 里没有对应实现，此时 whistle-rs 输出完整的 `${...}` 占位符，而不是
> 假装替换过了。

---

## 变量表

### 已实现

| 变量 | 说明 |
|------|------|
| `${method}` | 请求方法 |
| `${url}` | 完整 URL；支持 `.protocol` / `.host` / `.hostname` / `.port` / `.path` / `.pathname` / `.search` / `.query` 等子路径 |
| `${path}` / `${pathname}` / `${search}` | 路径（含查询）/ 纯路径 / 查询串（含 `?`） |
| `${queryString}` / `${searchString}` | 同 `${search}`，但为空时返回 `?` |
| `${query}` / `${query.<键>}` | 查询串整体 / 单个查询参数 |
| `${reqHeaders.<名>}` | 请求头（别名 `reqH`、`reqHeader`） |
| `${reqCookies.<名>}` | 请求 cookie（别名 `reqCookie`） |
| `${ip}` / `${clientIp}` | 客户端 IP |
| `${host}` / `${realHost}` | **代理自身的绑定地址**（绑定全部接口时为空），不是请求的 Host |
| `${port}` / `${realPort}` | 代理监听端口 |
| `${version}` | whistle-rs 版本 |
| `${hostname}` | 本机主机名 |
| `${env.<名>}` | 环境变量 |
| `${now}` | 毫秒时间戳 |
| `${random}` | `[0,1)` 随机小数 |
| `${randomInt(n)}` / `${randomInt(a-b)}` | 随机整数 |
| `${randomUUID}` | 随机 UUID |

> `${host}` / `${port}` 的语义容易误解：原版读的是 whistle 自己的配置
> （`resolveVarValue`，`_original/lib/rules/rules.js:657-668`），
> 想要请求的主机名请用 `${url.hostname}`。

### 解析为空字符串

`tpl://` 在**上游响应产生之前**就短路了，所以响应侧的变量必然为空 —— 返回空串而非留下占位符，与上游一致：

`${statusCode}`、`${serverIp}`、`${serverPort}`、`${resHeaders.*}`、`${resCookies.*}`、`${id}` / `${reqId}`、`${clientId}`、`${clientPort}`、`${remoteAddress}`、`${remotePort}`、`${realUrl}`

### 未实现（原样保留）

| 变量 | 原因 |
|------|------|
| `${localClientId}` | 需要客户端身份体系 |
| `${whistle.<插件名>}` | 需要插件运行时耦合 |

---

## JSONP 怎么写

上游不做任何 callback 处理，所以**由模板自己写**：

```js
// /tmp/mock/api.js
{callback}({"ok":1,"id":"${randomUUID}"})
```

```
example.com/api   jsonp:///tmp/mock/api.js
```

```
GET http://example.com/api?callback=cb123
→ cb123({"ok":1,"id":"3f2a…"})
```

`{callback}` 走第一遍的查询串插值，`${randomUUID}` 走第二遍。Content-Type 来自**文件扩展名**（`.js`），与协议名无关。

---

## Content-Type

按上游的回退链推断（`file-proxy.js:255-258`）：

1. **命中的那个文件的扩展名**（不是规则里写的值 —— 见「文件查找」）
2. 都没有时，看**请求 URL 的扩展名**
3. 再没有则 `text/html`

第 2 步是为什么 `example.com/a.json file:///tmp/mock` 能返回 JSON —— 即使 mock 文件没有扩展名。

模板响应的状态码**恒为 200**，`content-length` 在渲染**之后**重新计算，且**不支持 Range 请求**
（`file://` 目前也不支持，见「文件查找」末尾）。

响应侧算子（`resHeaders://`、`resType://`、`resCors://` 等）**对模板/文件响应同样生效** ——
和上游一样，短路产生的响应也会走一遍响应侧规则：

```
example.com/api   tpl:///tmp/mock.json  resHeaders://x-mock=1
```

但插件的 `onResponse` **不会**对短路响应触发：那个钩子的语义是「上游响应到达之后」，
而短路时根本没有上游。插件想影响这类响应，请用 `onRequest` 里的 `ctx.setRules(...)`。

---

## 协议家族

| 协议 | 行为 |
|------|------|
| `file://` | 原样返回文件内容，按扩展名推断类型 |
| `tpl://` `dust://` `jsonp://` | 渲染模板（三者等价） |
| `rawfile://` | 文件是**一个完整的 HTTP 响应**（状态行 + 响应头 + 空行 + body），解析后返回 |
| `xfile://` `xtpl://` … | 文件**不存在时回落到真实服务器**，而不是返回 404 |
| `xsfile://` `xstpl://` … | 同上，且把 `http:` 回落改写为 `https:` |

`x` / `xs` 前缀**只在文件找不到时**才有意义。

### `rawfile://` 示例

```
HTTP/1.1 404 Not Found
Content-Type: application/json

{"error":"nope"}
```

分隔头和 body 的空行**接受任意 CR/LF 组合**（`HEADERS_SEP_RE`，`file-proxy.js:12`）：
`\r\n\r\n`、`\n\n`、`\r\r`、`\n\r` 等八种写法都算，手写的 `.http` fixture 不必纠结换行符。

两个边界行为：

- **前 256 KB 内找不到空行就不当作 raw 响应**（`MAX_HEADERS_SIZE`，`file-proxy.js:13,151-158`），
  整个文件按普通文件返回，而不是把第一行误当成状态行。
- body 按**字节**切分并原样返回，二进制内容（图片等）不会被 UTF-8 转换损坏。

---

## 文件查找

规则的值不是一个路径，而是一串候选：按下面的顺序展开成列表，**第一个 `stat()` 结果是普通文件的候选生效**
（`getRuleFiles`，`_original/lib/util/index.js:1420-1444`；`readFiles`，`file-proxy.js:38-58`）。

| 写法 | 展开成 |
|------|--------|
| `a\|b\|c` | `a`、`b`、`c` —— 多路径回退 |
| `~/mock.json` | `$HOME/mock.json`（全角 `～/` 同样生效；单独一个 `~` 不展开） |
| `/tmp/site/` | `/tmp/site`，然后 `/tmp/site/index.html` |
| `tmp/x`（缺少前导 `/`） | `tmp/x`，然后 `/tmp/x` —— whistle-rs 自己的兜底 |

含 `..` 路径段的候选会被**拒绝**（`UP_PATH_REGEXP`，`_original/lib/util/common.js:29`），
不参与查找；如果整条规则最终没找到文件，404 的正文里显示的就是这个标记：

```
$ curl -x http://127.0.0.1:8899 'http://mock.test/up'
whistle-rs: file not found <strong>(Path contains parent directory notation &#39;..&#39;)</strong>
```

被拒绝的候选不会中断整条规则 —— `file://../escape|/tmp/ok.txt` 仍然会服务 `/tmp/ok.txt`。
`x` / `xs` 规则则照旧回落到真实服务器。

`a..b` 这样的文件名不受影响：只有**独立成段**的 `..` 才算越级。

> **上游怪癖：`xs` 前缀不拆 `|`。** 拆分用的正则（`rules.js:96`）写的是 `^x?(...)`，
> 只允许**单个** `x`，所以 `xsfile://a|b` 在原版里就不会被拆开，整串会被当成一个文件名。
> whistle-rs **刻意复刻**了这个行为：`|` 在 POSIX 文件名里是合法字符，"修好"它会让同一份规则文件在两边解析出不同的路径。

Content-Type 取的是**命中的那个候选**的扩展名，不是规则里写的值 ——
所以 `file:///tmp/site/` 命中 `index.html` 时会返回 `text/html`。

`file://` 的定位是在开发机上服务任意本地路径，因此除了上面的 `..` 校验**不做沙箱限制** ——
上游对绝对路径同样不加限制。

**尚未移植**：

| 上游行为 | 现状 |
|----------|------|
| 路径先 `decodeURIComponent`，并截掉 `?`/`#` 之后的部分（`decodePath`，`util/index.js:1403-1418`） | 未实现。上游需要它是因为目录规则会把请求路径拼到值后面，whistle-rs 不拼；代价是 `file:///tmp/a%20b.json` 这种写法目前不会解码 |
| 从 values 存储 / 远程 URL / 插件 key 解析文件 | 未实现 |
| `file://` 的 Range 请求（206 + `content-range`，`file-proxy.js:102,160-172`） | 未实现，整份文件以 200 返回。Range 是可选的，客户端会自行处理；另外上游 `parseRange` 对 `bytes=-500` 这类后缀区间算错（`util/index.js:3358-3366`），复刻与否都需要额外决策 |
| `rawfile://` 的**内联值**形式会删掉 `content-encoding`（`file-proxy.js:71-73`） | 无法触发：whistle-rs 的规则解析器不支持 `<...>` 内联值，文件族的值永远是路径 |

### 文件缓存

文件内容会被缓存，但每次请求仍会 `stat` 一次，只有 mtime 与长度都未变才复用 —— mock 文件在开发时改动频繁，缓存绝不能返回过期内容。超过 1 MB 的文件不缓存。

唯一的缝隙：一次改写既保持字节长度不变、又落在文件系统 mtime 精度内，此时可能返回一次旧内容。

---

## 与 values 存储的关系

规则算子的值里写 `{name}` 会被 [values 存储](RULES.md)替换，这是**规则层**的替换，发生在模板渲染之前，两者互不干扰：

```
# {mock} 是 values 里的一个条目名，值为文件路径
example.com   tpl://{mock}
```
