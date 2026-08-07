# 规则行级属性 / Line properties (`lineProps://`)

[English README](../README.md) · [简体中文 README](../README.zh-CN.md) · [规则总览](RULES.md)

`lineProps://` 是 whistle 的**行作用域修饰符**：它声明的开关只影响**同一行**上写的算子，
是全局 `enable://` / `disable://` 的行内对应物。

对应原版实现：`resolveMatchFilter`（`lib/rules/rules.js:1552`）、
`parseLineProps`（`lib/util/index.js:1877`）。

---

## 语法

```
pattern  op1 op2 …  lineProps://<action>[|&<action>…]  [更多 lineProps:// …]
```

```
example.com  host://1.2.3.4  lineProps://important
example.com  htmlAppend:///tmp/x.html  lineProps://safeHtml&important
```

已实现并测试的解析语义（与原版一致）：

| 行为 | 说明 |
|------|------|
| 分隔符 | `\|` **和** `&` 都是分隔符（原版 `SEP_RE = /[\|&]/`），且**不支持转义** —— 这一点刻意不同于 `enable://` |
| 多次出现 | 一行上多个 `lineProps://` 令牌会合并 |
| 空载荷 | `lineProps://`、`lineProps://\|` 均为 no-op，不会产生空动作 |
| 未知属性 | 原样保留，不校验、不告警（原版同样不校验） |
| 非算子 | `lineProps://` 本身不是算子；只有它的行不构成规则 |
| 旧别名 | `includeFilter://safeHtml` / `includeFilter://strictHtml` 等价于对应的 `lineProps://`，不是过滤条件（原版 `formatShorthand`，`rules.js:224-229`） |
| 每算子携带 | 行属性会复制到该行的**每个**算子上，因为解析结果会混合来自多行的算子 |

> **注意**：原版把一行的 `lineProps` 对象**按引用**共享给该行生成的所有规则，因此为某个算子
> 写的属性会静默作用于同行的其它算子。本移植复制而非共享，语义等价但没有原版
> `IS_JSON` 备忘缓存那个跨算子串味的 bug。

---

## 属性状态表

诚实标注两种状态：**已接线**（真实影响流量，且有测试）、**仅暴露**（已解析，可通过
`Resolved::props(protocol)` 读取，但无运行时效果 —— 每一条都注明了为什么）。

| 属性 | 状态 | 说明 |
|------|------|------|
| `important` | ✅ **已接线** | 该行算子优先于普通行的同名协议，不论文件位置。**这是唯一的拼法** —— 此前 `$` 前缀也被当作它的简写，那是本移植自己发明的，上游的 `$` 是精确匹配，见 [`RULES.md`](RULES.md#--exact-patterns) |
| `internal` | ✅ **已接线** | 使规则对 whistle 自身发出的请求同样生效。判定见下节[「什么算内部请求」](#什么算内部请求) |
| `internalOnly` | ✅ **已接线** | 使规则**仅**对内部请求生效 |
| `safeHtml` | ✅ **已接线** | 响应体不像标记语言（首字符是 `{`/`[`）时，拒绝把**该行**的内容注入进去 |
| `strictHtml` | ✅ **已接线** | 同上，但只接受真正的标记语言（首字符 `<` 或空体）。优先级高于 `safeHtml` |
| `proxyFirst` | ✅ **已接线** | `host` 与 `proxy` 同时命中时优先 `proxy`（默认优先 `host`） |
| `proxyHost` | ✅ **已接线** | 让 `host` 与 `proxy` 同时生效：走代理，但代理连的是 `host://` 指定的地址 |
| `proxyHostOnly` | ✅ **已接线** | 同上，但无 `host` 命中时丢弃 `proxy` |
| `weakRule` | ✅ **已接线** | 反转默认优先级，使 `file` 族规则给命中的 `proxy`/`host` 让路 |
| `originUrl` | ✅ **已接线** | **原版未文档化**：域名型 pattern（无自带路径）命中时，拼到转发/file 值后面的路径强制为 `/`，即只要目标自己的根（`lib/rules/rules.js:1105`）。带路径的 pattern 不受影响 —— 上游同样以 `rule.isDomain` 为前提 |
| `disableAutoCors` | ✅ 已生效 | 关掉本地文件响应上的**自动 CORS**（`isAutoCors`，`_original/lib/handlers/file-proxy.js:178-191`）。此前这里写着「本移植没有可抑制的对象……为了能关掉它而先实现自动 CORS 是本末倒置」——结论写反了：自动 CORS 本身就是那个功能，见 [`RULES.md`](RULES.md#跨域-mock自动-cors) |
| `disabledAutoCors` | ✅ 已生效 | 原版接受的拼写错误别名，同上 |
| `enableBigData` | 仅暴露 | **本移植没有可抬高的上限**：`reqMerge`/`resMerge` 对整个已缓冲的 body 生效，不设 2MB 门槛（原版 `MAX_RES_SIZE`/`BIG_MAX_RES_SIZE`，`lib/inspectors/res.js:25-26,:1017`），等价于该开关恒为开 |
| `internalProxy` | 仅暴露 | 本移植没有「经上游代理明文转发 https」这一模式：`internal-proxy://` 与 `proxy://` 走同一条 HTTP 代理路径，没有可切换的行为（原版 `isInternalProxy`，`lib/util/index.js:3799-3809`） |
| `proxyTunnel` | 仅暴露 | 需要在 `upstream::Target` 上增加「明文请求也先 CONNECT」的开关，而 `src/proxy/upstream.rs` 不在本次改动范围内；且无法在没有上游代理的情况下做端到端验证 |
| `enableUserLogin` | 不适用 | 本移植没有登录框，也没有 `disable://userLogin` |
| `disableUserLogin` | 不适用 | 同上 |


`LINE_PROP_ACTIONS` 常量列出全部已知动作，仅作文档用途 —— 它**不是过滤器**，未列出的动作
同样会被保留。

---

## 与匹配的关系

绝大多数行属性**不影响匹配**，只影响算子的行为。唯一的例外是 `internal` / `internalOnly`：
它们是对整行的**可见性硬门禁**。

原版在主扫描循环里对**每个协议**都执行 `checkInternal`（`lib/rules/rules.js:910`），
而不是上游文档所暗示的仅限 proxy/socks/host 族 —— 本移植遵循实际代码而非文档。

```rust
// 客户端请求（默认）
manager.resolve(&req);                      // internalOnly 的行不可见
// 已知来源的请求
manager.resolve_scoped(&req, is_internal);  // is_internal = true 时反转
```

代理管线（`src/proxy/mod.rs` 的 `serve()`）用后者，并把同一个作用域传给
`rule://` / `rulesFile://` / 插件注入的子规则集，所以嵌套规则里的
`internalOnly` 与顶层行为一致。

### 什么算内部请求

原版用**每进程随机**的标记头识别自己发出的请求
（`config.PROXY_ID_HEADER = 'x-whistle-proxy-id-' + uid`，`lib/config.js:89`；
由 `setInternalOptions` 写入、`checkPluginReqOnce` 在入口删除）。

本移植改用固定且公开的头名 —— **`x-whistle-internal-req`**（任意非空值即可）：
这里没有需要保护的内部服务，而固定名字才让 whistle-rs 自己的工具（以及开发者本人）
能主动触发一条 `internal` 规则。该头在规则匹配**之前**就被摘掉，因此既不会被
`includeFilter://reqH.` 看到，也不会写进抓包记录或发到源站。

```console
$ curl -x 127.0.0.1:8899 http://demo.test/api            # 客户端请求
$ curl -x 127.0.0.1:8899 -H 'x-whistle-internal-req: 1' \
       http://demo.test/api                              # 内部请求
```

> **注意**：普通行对内部请求是不可见的（原版同样如此）。一旦给某个请求打上标记，
> 想让它命中的每一行都必须写 `lineProps://internal` 或 `lineProps://internalOnly`。

目前 whistle-rs 自身还没有任何走完整代理管线的出站请求：`responseFor` 预取与
`rulesFile://` 读取都绕开了管线，而 `/api/replay` 的自回环刻意不打标记 —— 原版的
composer/replay 同样不是内部请求。等到有了这类调用方（例如插件回环），
只需在发请求时带上该头即可。

---

## 注入门禁（`safeHtml` / `strictHtml`）

对应原版 `WhistleTransform#allowInject` + `filterHtml`
（`lib/util/whistle-transform.js:66-89`）。三个容易踩空的点：

1. 判定只看**原始响应体**的第一个非空白字节，且在任何算子改写它**之前**做出；
2. 只有 **HTML 响应**会被门禁 —— 其余类型 `allowInject` 直接返回 true，所以给
   JS 响应的 `jsAppend` 写 `safeHtml` 是没有意义的；
3. 门禁是**逐行**的：同一个请求里，带 `safeHtml` 的 `htmlAppend` 被丢弃，
   不带的 `htmlPrepend` 照常注入。

| 响应体首字符 | 无属性 | `safeHtml` | `strictHtml` |
|---|---|---|---|
| `<` 或空体 | 注入 | 注入 | 注入 |
| `{` / `[` | 注入 | 拒绝 | 拒绝 |
| 其它（纯文本） | 注入 | 注入 | 拒绝 |

被门禁的算子包括通用的 `resBody`/`resPrepend`/`resAppend` 与 `htmlBody`/`htmlPrepend`/
`htmlAppend`（原版把它们放进同一个 `injectRules` 列表）。请求侧算子不受影响。
全局的 `enable://safeHtml` / `enable://strictHtml` 会叠加到每一行上
（`lib/inspectors/res.js:970-987`）。

---

## host 与 proxy 的优先级

原版默认 **`host` 压过 `proxy`**：两者同时命中时代理被丢弃，直连 host 指定的地址
（`lib/rules/index.js:220-237`）。行属性用来反转这个默认值：

| 写法 | 结果 |
|------|------|
| 只有 `proxy://` | 走代理 |
| `host://` + `proxy://` | **只用 host**，代理被丢弃 |
| 任一行加 `proxyHost` / `proxyFirst` | 两者都生效：走代理，代理连 host 地址 |
| `proxy://` 加 `proxyHostOnly` | 同上；但若本次没有 `host://` 命中，代理被丢弃 |

`enable://proxyHost` / `enable://proxyFirst` 是同语义的请求级开关；
代理 URL 自带的 `?proxyHost` 查询标记同样有效（原版 `PROXY_HOSTS_RE`），
且该查询串不会混进代理地址。

`weakRule` 处理的是另一半优先级：默认 `file` 族规则会短路整个请求，写上它之后，
只要同时命中了 `host://`（或非 `proxyHostOnly` 的 `proxy://`），本地文件就让路
（原版 `filterWeakRule`，`lib/util/index.js:3733-3745`）。

---

## 尚未移植

- `rawProps`（原版仅用于 WebUI 回显原始令牌）。
- 原版的 `lineProps` 对象按引用共享所导致的 `IS_JSON` 跨算子备忘缓存行为 —— 刻意不复刻。
