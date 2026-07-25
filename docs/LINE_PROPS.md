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
| 每算子携带 | 行属性会复制到该行的**每个**算子上，因为解析结果会混合来自多行的算子 |

> **注意**：原版把一行的 `lineProps` 对象**按引用**共享给该行生成的所有规则，因此为某个算子
> 写的属性会静默作用于同行的其它算子。本移植复制而非共享，语义等价但没有原版
> `IS_JSON` 备忘缓存那个跨算子串味的 bug。

---

## 属性状态表

诚实标注三种状态：**已接线**（真实影响流量）、**已实现待接入**（逻辑与测试就绪，缺调用方）、
**仅暴露**（已解析，可通过 `Resolved::props(protocol)` 读取，但无运行时效果）。

| 属性 | 状态 | 说明 |
|------|------|------|
| `important` | ✅ **已接线** | 该行算子优先于普通行的同名协议，不论文件位置。与本移植已有的 `$` 前缀简写合流于 `Rule::is_important()` |
| `internal` | ⚠️ **已实现待接入** | 使规则对 whistle 自身发出的请求同样生效。`matcher::resolve_refs_scoped` 已实现并测试，但目前**没有调用方传入 `is_internal_req = true`** |
| `internalOnly` | ⚠️ **已实现待接入** | 使规则**仅**对内部请求生效。同上：当前效果等价于该行对所有客户端请求不可见 |
| `safeHtml` | ⚠️ **已实现待接入** | `LineProps::allows_injection()` 已实现并测试；`apply.rs` 的 `htmlXxx`/`jsXxx`/`cssXxx` 注入路径尚未调用它 |
| `strictHtml` | ⚠️ **已实现待接入** | 同上。优先级高于 `safeHtml` |
| `disableAutoCors` | 仅暴露 | 原版用于抑制 `file`/`tpl`/`rawfile` 响应的自动 CORS |
| `disabledAutoCors` | 仅暴露 | 原版接受的拼写错误别名，本移植一并接受 |
| `enableUserLogin` | 仅暴露 | 原版中优先于 `disableUserLogin` 和全局 `disable://userLogin` |
| `disableUserLogin` | 仅暴露 | |
| `internalProxy` | 仅暴露 | 经上游代理明文转发 |
| `proxyFirst` | 仅暴露 | `host` 与 `proxy` 同时命中时优先 `proxy`（默认优先 `host`） |
| `proxyHost` | 仅暴露 | 让 `host` 与 `proxy` 同时生效 |
| `proxyHostOnly` | 仅暴露 | 同上，但无 `host` 命中时丢弃 `proxy` |
| `proxyTunnel` | 仅暴露 | 上游代理再 CONNECT 到更上游 |
| `weakRule` | 仅暴露 | 反转默认优先级，使 `proxy`/`host` 不被 `file` 族规则压制 |
| `enableBigData` | 仅暴露 | 把 `reqMerge`/`resMerge` 的缓冲上限从 2MB 提到 16MB |
| `originUrl` | 仅暴露 | **原版未文档化**：域名型 pattern 按域名命中时，强制拼接路径为 `/` |

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

---

## 后续接入指引

要让「已实现待接入」的属性真正生效，需要在本移植中补上调用方：

1. **`internal` / `internalOnly`** —— 在 `src/proxy/mod.rs` 的 `serve()` 里把
   `state.rules.read().unwrap().resolve(&info)` 换成 `resolve_scoped(&info, is_internal)`，
   并判定何为内部请求（插件回环、`/api/replay` 自回环等）。
2. **`safeHtml` / `strictHtml`** —— 在 `src/proxy/apply.rs` 的 HTML/JS/CSS 注入分支中，
   用 `resolved.props("htmlAppend")`（等）取出行属性，注入前调用
   `props.allows_injection(body)` 判定。
3. **其余属性** —— 均可通过 `Resolved::props(protocol)` 读到，在对应算子的处理点消费即可。

---

## 尚未移植

- 原版把 `includeFilter://safeHtml` / `includeFilter://strictHtml` 在 `formatShorthand`
  阶段改写为 `lineProps://`（`rules.js:224-229`）；本移植暂未支持这两个旧别名。
- `rawProps`（原版仅用于 WebUI 回显原始令牌）。
- 原版的 `lineProps` 对象按引用共享所导致的 `IS_JSON` 跨算子备忘缓存行为 —— 刻意不复刻。
