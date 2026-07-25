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

变量名**大小写不敏感**（`${reqHeaders}` 与 `${reqheaders}` 等价）。

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
| `${var.replace(a,b)}` | `.replace()` 修饰符未移植。引擎会识别该后缀并**整体保留原样**，而不是错误地渲染成半成品 |
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

1. **文件自身的扩展名**
2. 都没有时，看**请求 URL 的扩展名**
3. 再没有则 `text/html`

第 2 步是为什么 `example.com/a.json file:///tmp/mock` 能返回 JSON —— 即使 mock 文件没有扩展名。

模板响应的状态码**恒为 200**，`content-length` 在渲染**之后**重新计算，且**不支持 Range 请求**。

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

---

## 文件查找

值先按原样当作路径，找不到再尝试补一个前导 `/`。

**尚未移植**（写文档时逐条核对过实现）：

| 上游行为 | 现状 |
|----------|------|
| `a\|b\|c` 多路径回退，第一个存在的文件生效 | 未实现，`\|` 会被当作路径的一部分 |
| 路径含 `..` 时返回带特定文案的 404 | 未实现，不做校验 |
| 结尾 `/` 展开为「目录本身」和「目录 + index.html」两个候选 | 未实现 |
| 从 values 存储 / 远程 URL / 插件 key 解析文件 | 未实现 |

`file://` 的定位是在开发机上服务任意本地路径，因此**不做沙箱限制** —— 上游对绝对路径同样不加限制。

> 顺带一提，上游拆分 `|` 的正则只允许**单个** `x` 前缀，所以即使在原版里，`xsfile://a|b` 的多路径回退也不生效。

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
