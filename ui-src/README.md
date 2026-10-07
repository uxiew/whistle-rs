# whix 控制台

代理端口上提供的网页控制台：一个 Vue 3 应用，构建出来是**单个自包含的 HTML 文件** `dist/index.html`。

## 先构建控制台，再构建代理

`dist/index.html` **不在**仓库里：它是一个 445 KB 的打包产物，每次构建都会从头到尾重写一遍，放进仓库的话，控制台的每一处改动都会变成一份没法读的 diff。在这个目录里构建它，Rust 构建会把它内联进去。

```sh
npm ci          # 只需一次；严格按 package-lock.json 锁定的版本安装
npm run build   # 生成 dist/index.html
```

话虽如此，为了编译一个 Rust 代理而要求装 Node，仍然是笔不划算的交易，所以 Node 不是必需的。`dist/index.html` 存在时，`build.rs` 把它复制到 `OUT_DIR`（Cargo 给构建脚本用的输出目录）；不存在时，就在那里写一张占位页——两种情况下 `cargo build` 都会成功，只是会给出一条警告，写明缺了什么。没带控制台编出来的二进制，所有 API 路由照常工作；只有 `/` 是占位页，页面上也会写明这一点。

控制台是在**编译**时内联进去的，所以如果你先构建了代理、后构建控制台，在重新构建代理之前什么都不会变。`cargo build` 自己会发现新文件（`rerun-if-changed`）；你要记得的，是再跑一次 `cargo build`。

产物完全不引用外部资源：没有分块（chunk）、没有 CDN、没有字体、没有图片。哪怕它正在检查的那个网络断了，它也得能加载出来，这也是整个编辑器都内联进来、而不是另外去拉取的原因。如果哪次构建产出了第二个文件，或者 HTML 里多出一个指向页面之外的 `src=`/`href=`，那就是 bug——去查 `vite.config.ts`。

## 开发

```sh
npm run dev       # localhost:5199，连的是代理 API 的 mock
npm run preview   # 构建好的 dist/index.html，连的是同一个 mock
npm run typecheck # vue-tsc
```

`mock/api.ts` 是一个 Vite 插件，`src/proxy/webui.rs` 能回答的每个路由它都回答，用的是一套专门挑来覆盖各种边角情况的测试数据（fixture）：一个失败的请求；一个超时、状态码为 0 的请求；一个带帧的 WebSocket（其中一帧被 `enable://ignoreSend` 丢掉，两帧被 `enable://pauseSend` 扣住，好让 Release 按钮有东西可放）；一个被截断的 body；一个不是 JSON 的 body；一张图片；一个既不是文本也不是图片、而且同样被截断的二进制 body；一个禁用的规则组；还有一个从没应答过的插件。它只在开发时用——`apply: 'serve'` 让它不进构建产物。它的状态跟着服务进程走：放行扣住的帧之后，想让它们回来，就重启 `npm run dev`。


## 目录结构

| 路径 | 是什么 |
| --- | --- |
| `index.html` | 页面外壳，带着 `__VERSION__`、`__HOST__`、`__PORT__` 占位，代理返回页面时填上 |
| `src/main.ts` | 先定主题，再挂载 |
| `src/App.vue` | 工具栏 + 左侧栏 + 工作区，以及键盘快捷键 |
| `src/api.ts` | 代理 API 的每个接口，带类型 |
| `src/store.ts` | 唯一的响应式 store（文件开头有说明） |
| `src/columns.ts` | 请求表格的列 |
| `src/format.ts` | 字节、时间、主机名、JSON 的格式化 |
| `src/curl.ts` | 把请求转成 curl 命令 |
| `src/sidebar/*.vue` | 左侧栏的 6 个列表：请求来源、Composer 历史、Console 日志分组、规则组、Values、插件 |
| `src/panes/*.vue` | 7 个面板（Requests、Composer、Console、Rules、Values、Test Rules、Status），请求详情的各个标签页，耗时瀑布图 |
| `src/components/*.vue` | 工具栏、侧栏条目、卡片、编辑器、导入导出 |
| `src/editor/` | 给 CodeMirror 6 用的规则语言 |
| `src/styles/app.css` | 配色，以及所有用到配色的样式 |

## Composer

`panes/ComposerPane.vue` 让你手写一个请求，再把它 POST 到 `/api/composer`，由后者**经代理自己的端口**发出去——和 Replay 走的是同一条本机回环（`send_through_self`，`src/proxy/webui.rs`）。所以手写的请求和其他请求一样会被匹配、改写、抓取，`from:composer` 也能匹配到它。这里没有任何东西直接跟源站通信，也不应该有：一个直接连源站的 Composer，不过是第二个 `curl` 而已。

详情面板里的 "Edit & Resend" 用一个抓到的请求来预填 Composer——正好是 `curl.ts` 的反方向，也是大多数手写请求的来由。草稿和最近发出的二十个请求存在 `localStorage` 里，因为你正在重新加载的这个页面，就是由你正在改配置的那个代理提供的。

## 规则编辑器

`src/editor/whistle-classify.js` 决定一行里哪一段（token）是*匹配串*（pattern）——也就是代理真正拿来匹配的那部分。它故意写成朴素的脚本式 JavaScript：不 import 任何东西，也不依赖 CodeMirror，因为它要在两个地方跑：一是在这里被打包进控制台，二是被一个 Rust 测试当作脚本执行，把它的结果和解析器自己的 `split_line` 逐一对照。别把它改成模块，也别复制它：有两份就会慢慢走样，而这种走样正是它存在要防止的那个 bug。

`whistle-language.ts` 把它包成一个 CodeMirror 6 的 `StreamLanguage`。注意那里记下的一条限制：它输出的 token 名不能是 CodeMirror 5 的旧名字（`def`、`keyword`、`variable-2`、`error`……），因为 6 版会先拿这些名字去查一张内置表，语言自己的定义排在后面。
