# 拦截 HTTPS 与根证书

要看到（以及改写）HTTPS 流量，whix 得当一回**中间人**：对每个域名，它都现场生成一张证书交给你的客户端，这张证书由 whix 第一次运行时创建的**根证书**签发。你先安装并信任这张根证书，客户端才会信任它签出来的证书。

- [根证书放在哪](#根证书放在哪)
- [下载根证书](#下载根证书)
- [安装根证书](#安装根证书)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Linux](#linux)
  - [iOS](#ios)
  - [Android](#android)
  - [Firefox](#firefox所有平台)
- [移除根证书](#移除根证书)
- [验证](#验证)
- [改为出示真实证书](#改为出示真实证书)
- [工作原理](#工作原理)
- [安全须知](#安全须知)

---

## 根证书放在哪

whix 第一次启动时生成根证书，存进数据目录（默认 `~/.whix`，用 `--dir` 改）：

```
~/.whix/certs/root.crt   # 根证书（要安装的是这个）
~/.whix/certs/root.key   # 它的私钥（别外传；在 Unix 上创建时权限为 0600）
```

把这两个文件都删掉，下次启动就会重新生成一张新的根证书（之前装过的地方都得重装一遍）。

## 下载根证书

whix 运行时，打开它自带的页面下载证书：

```
http://127.0.0.1:8899/           # 状态页，上面有下载链接
http://127.0.0.1:8899/rootCA.crt # 证书本身
```

**或者，在已经设好代理的设备上：** 打开 <http://rootca.pro/>。这个域名由代理自己应答，不往外转发，而且不管路径是什么都返回证书——所以不用在手机键盘上敲地址和端口。这是 whistle 原有的做法，本项目保留了。如果你希望这个域名像别的域名一样被转发，用 `-M pureProxy` 关掉它。

也可以直接从磁盘上拷：`~/.whix/certs/root.crt`。

```bash
# 比如不开浏览器，直接存到本地
curl -o whix-rootCA.crt http://127.0.0.1:8899/rootCA.crt
```

> 如果你的 shell 导出了 `http_proxy`/`https_proxy`，加上 `--noproxy '*'`，让 curl 直接连 whix，而不是绕到另一个代理上。

## 安装根证书

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.whix/certs/root.crt
```

也可以走图形界面：双击 `root.crt` → 会打开“钥匙串访问” → 在 *系统* 钥匙串里找到 **whix Root CA** → *显示简介* → *信任* → 把 **使用此证书时** 设为 **始终信任**。

### Windows

```powershell
# 以管理员身份运行
Import-Certificate -FilePath "$env:USERPROFILE\.whix\certs\root.crt" `
  -CertStoreLocation Cert:\LocalMachine\Root
```

或者：双击 `root.crt` → **安装证书** → *本地计算机* → *将所有的证书都放入下列存储* → **受信任的根证书颁发机构**。

### Linux

```bash
# Debian / Ubuntu
sudo cp ~/.whix/certs/root.crt /usr/local/share/ca-certificates/whix.crt
sudo update-ca-certificates

# Fedora / RHEL
sudo cp ~/.whix/certs/root.crt /etc/pki/ca-trust/source/anchors/whix.crt
sudo update-ca-trust
```

> **用哪个 IP？** 代理启动时加了 `-H 0.0.0.0`（或某个局域网地址），手机才连得上——默认是 `127.0.0.1`，只有本机能连。这样启动后，whix 会打印出同一网络里的设备能用来连它的地址：启动时打印一遍，`GET /api/status` 里也有。监听那一行里的 `0.0.0.0` 不算——它的意思是“所有网卡”，而手机要的是具体某一个地址。如果一个地址都没打印，说明内核报不出这台机器的任何私有地址；那就自己从 `ifconfig` / `ipconfig` 的输出里找。

### iOS

1. 把设备 Wi-Fi 的 HTTP 代理设成你电脑的 IP，端口 `8899`。
2. 用 Safari 打开 **<http://rootca.pro/>**（或 `http://<your-ip>:8899/rootCA.crt`），允许下载描述文件。
3. **设置 → 通用 → VPN与设备管理** → 安装描述文件。
4. **设置 → 通用 → 关于本机 → 证书信任设置** → 为 **whix Root CA** 启用完全信任。（iOS 上这最后一步不能省。）

### Android

1. 把 Wi-Fi 代理设成你电脑的 IP，端口 `8899`。
2. 从 **<http://rootca.pro/>**（或 `http://<your-ip>:8899/rootCA.crt`）下载证书，然后在 **设置 → 安全 → 加密与凭据 → 安装证书 → CA 证书** 里安装。
3. 注意：从 Android 7 起，App 要在网络安全配置（network security config）里主动声明，才会信任**用户**装的 CA 证书。要拦截某个 App，可能得把证书装到系统级（设备要 root），或者给这个 App 单独配置。
4. 根证书装在**系统**证书库里时，Chrome 和 WebView 会像检查公网证书一样检查代理签发的站点证书，有效期超过 CA/Browser Forum 上限的一律拒绝（2026-03-15 起签发的证书，上限是 200 天）：页面报 `ERR_CERT_VALIDITY_TOO_LONG`。whix 签的站点证书有效期 43 天——往前 7 天、往后 36 天，和 whistle 2.10.10 一样——快到期前会重新签，所以不会碰到这个错误。更早的某个版本签的有效期是一年多一点；如果你看到这个错误，升级就行。

### Firefox（所有平台）

Firefox 用自己的信任库，不用系统的：

**设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → 导入** → 选择 `root.crt` → 勾选 *信任由此证书颁发机构来标识网站*。

---

## 移除根证书

不调试了，或者准备删数据目录之前，先做这一步：一张受信任的根证书，只要私钥还在磁盘上，谁读到 `root.key`，谁就能对这台客户端冒充任何网站。先撤销信任，再删文件。每一张 whix 根证书都叫 **whix Root CA**，所以如果你重新生成过，可能装了不止一张；下面的命令会把它们全部移除。

```bash
# macOS —— 反复执行，直到它回答 "Unable to delete certificate matching"
sudo security delete-certificate -c "whix Root CA" /Library/Keychains/System.keychain

# Debian / Ubuntu
sudo rm /usr/local/share/ca-certificates/whix.crt
sudo update-ca-certificates --fresh

# Fedora / RHEL
sudo rm /etc/pki/ca-trust/source/anchors/whix.crt
sudo update-ca-trust
```

```powershell
# Windows，以管理员身份运行
Get-ChildItem Cert:\LocalMachine\Root |
  Where-Object Subject -like '*CN=whix Root CA*' | Remove-Item
```

- **iOS：** 设置 → 通用 → VPN与设备管理 → whix 的描述文件 → 移除描述文件。
- **Android：** 设置 → 安全 → 加密与凭据 → 受信任的凭据 → 用户 → whix Root CA → 移除。
- **Firefox：** 设置 → 隐私与安全 → 证书 → 查看证书 → 证书颁发机构 → whix Root CA → 删除或不信任。

另外记得把客户端的代理设置改回去。上面这些命令本项目的测试一条都没跑过，测试从不碰信任库。

---

## 验证

让客户端走代理、并信任这张根证书，请求一个 HTTPS 地址：

```bash
curl -x http://127.0.0.1:8899 \
     --cacert ~/.whix/certs/root.crt \
     https://example.com/ -D - -o /dev/null
```

应该得到 `HTTP/1.1 200 OK`。再加一条规则，比如 `example.com resHeaders://x-mitm=1`，就能看到注入的头出现在响应里——这就证明隧道被解密了。

**如果客户端不信任它**，curl 会报 `curl: (60) SSL certificate problem: self signed certificate in certificate chain`（macOS 自带的 curl 实测如此；别的 TLS 库措辞不一样，浏览器则显示它自己的警告页），控制台里会出现一行带 `client-tls` 标签的 `CONNECT`，原因写着 "the client refused this proxy's certificate … it does not trust the whix root certificate, or it pins the server's own"。前半句的情况，在那个客户端上装好根证书就解决了；后半句——App 做了证书固定（pinning）——只能干脆不拦截这个域名（见下一节）。客户端在握手中途断开、什么也没说的，也会打上同样的标签，原因写着 "hung up during the TLS handshake"。

---

## 改为出示真实证书

有些客户端只认它预期的那张证书，你的根证书信任得再彻底也没用——这是 App 固定了服务器的证书（pinning）。这不是装个什么就能解决的：代理必须出示客户端要找的那张证书，也就是说，你手里得有这张证书。

```sh
whix -z ./certs      # 目录里放着 api.example.com.key 和 api.example.com.crt
```

每一对 `<name>.key` 加 `<name>.crt`（或 `.cer`、`.pem`），会用在**证书里带的每一个名字**上——看的是证书的 `subjectAltName`，不是文件名。在同一个目录里放 `root.key` 加 `root.crt`，会替换掉根证书本身，这也是自己提供根证书的唯一办法。完整规则见 [`docs/CLI.md`](CLI.md#手动提供证书)。

也可以让插件按连接逐个决定，包括决定完全不拦截——见 [`RULES.md`](RULES.md) 里的 `sniCallback://`。

## 工作原理

1. 客户端向代理发送 `CONNECT example.com:443`。
2. whix 回复 `200`，升级这个 socket，然后读取客户端的 **ClientHello**——只读不消费，所以之后这些字节还能原样用来开始握手。
3. whix 以 TLS 服务端的身份**接受**这个连接，出示的站点证书签给 ClientHello 请求的那个名字，由根证书现场签发（按域名缓存）。
4. 解密后的请求拿去匹配你的规则，再通过一条**新的** TLS 连接转发给真实服务器。即使某条 `host://` 规则改了目标 IP，发往源站的 SNI 和对源站证书的校验用的仍是**原来的**域名，所以真实服务器看到的还是一次合法的握手。

实现：`src/ca.rs`（根证书和签发）、`src/proxy/sni.rs`（解析 ClientHello、决定出示哪张证书）、`src/proxy/tunnel.rs`（`handle_connect`、`serve_tunnel`）。

### 证书签给哪个名字

第 3 步按 **ClientHello** 里的名字签证书，而不是按打开隧道时用的地址，因为客户端要核对的是 ClientHello 里的那个名字。两者几乎总是一样；不一样的时候，以前按隧道地址签出来的证书会被客户端拒绝：

```
$ curl --socks5 127.0.0.1:1080 https://localhost:9443/     # curl 自己解析域名
   certificate served: subject=CN=127.0.0.1  san=IP Address:127.0.0.1   <- before
   certificate served: subject=CN=localhost  san=DNS:localhost          <- now
```

`--socks5`（区别于 `--socks5-hostname`）让 curl 自己做 DNS 解析、对着地址打开隧道，而它的 ClientHello 里请求的仍然是域名。把 IP 写死的客户端走 `CONNECT` 时也是这样。如果客户端根本不发 SNI——老客户端，或者直接连一个 IP——就退回用隧道自己的地址，跟以前一样。

### 隧道里装的是什么

隧道是对一个**地址**打开的，不是对某种协议，客户端往里放什么都行。在第 2 步之前，会先嗅探开头的几个字节，做法和 whistle 完全一样（`_original/lib/https/index.js:1176-1221`）：

| 开头的字节 | 怎么处理 | 想改的话用 |
|---|---|---|
| 一条 TLS 记录（`0x16`） | 解密，过程如上 | `enable://forHttp`、`disable://captureHttps` |
| 明文的 `HTTP/1.x` 请求行 | 当 HTTP 读——规则对它完全生效 | `enable://forHttps`、`disable://captureHttp` |
| 明文的 HTTP/2 前导（`PRI * HTTP/2.0`） | 当 HTTP/2 读 | 同上 |
| **其他任何内容** | **原样转发** | — |

最后一行最要紧，而且不需要任何开关：跑着 SSH、游戏协议，或者某种没人叫得出名字的二进制协议的隧道，会被直接放过去。whix 以前假定每条隧道都是 TLS，一律拿去做 TLS 握手，结果这些客户端收到的是一个 TLS alert，而在 whistle 那里它们的连接好好的。

判断请求方法用的是上游的 `/^(\w+)\s+(\S+)\s+HTTP\/1.\d$/im`——什么方法都认，不是查一张列表——所以 `PROPFIND`、`MKCOL`，或者今天早上才发明的方法，照样当 HTTP 读。

### 哪些连接会被解密

不是每条隧道都会被打开。在第 3 步之前，会对连接问三个问题，任何一个都可能让它原样通过——照样按它的规则路由，但绝不解密。这样的隧道在控制台里只有一行 `CONNECT`，目标地址后面跟着 `(tunnel)`，里面什么都没有：

| 连接 | 解密？ | 想改的话用 |
|---|---|---|
| 目标是域名，不管 ClientHello 带没带 SNI | 是 | `disable://intercept`、`disable://https`、`disable://capture` |
| ClientHello 指明了服务器名 | 是 | `disable://captureSNI` |
| ClientHello 什么名字都没带 | 是 | `disable://captureNoSNI` |
| **目标（authority）是裸 IP，并且 ClientHello 什么名字都没带** | **否** | `enable://capture`、`enable://captureIp`、`enable://captureIP`——不过就算有这些，`disable://captureIp` 也照样不让解密 |

最后一行是默认行为，不是一条规则，而且照搬上游：`net.isIP(servername) && !isCaptureIp()`（`_original/lib/https/index.js:1287`）。TLS 不允许在 SNI 里放 IP，所以 `https://10.0.0.5/` 产生的正是这种形态——对着一个地址开隧道，里面不带任何名字——两个代理都不会为它伪造证书。因此，把 IP 写死的客户端不用你做任何设置，就能保住端到端的连接。

> **whix 默认解密，whistle 默认不解密。** whistle 的控制台有个 `Enable HTTPS` 开关，初始是**关**的；关着的时候，`isEnableIntercept` 只拦截已经配了自定义证书的域名（`_original/lib/tunnel.js:187-199`）。本项目只要没被告知不解密就解密，`--no-intercept-https` 是全局关闭的开关。这是两者在默认立场上唯一的不同。上表的每一行都是在打开 whistle 这个开关的情况下实测的——不然比的就是“whistle 什么都不拦截”和“本项目拦截”，对哪条规则都说明不了什么。
>
> 还有一件 whistle 会做、本项目不做的事：不管规则怎么写，它都会拦截**本地**域名。`localhost` 上的 `disable://intercept` 在那边被忽略，在这边生效。这是实测的结果，也是 `tests/differential/https-bench.js` 把证书相关的用例放在 `probe.test` 加一行 `host://` 下跑、而不放在 `localhost` 下跑的原因。

### 让插件决定

`sniCallback://` 规则把第 3 步交给插件：插件可以提供自己的证书，也可以干脆不拦截（让连接保持端到端加密）。见 [`RULES.md`](RULES.md#choosing-the-mitm-certificate) 和 [`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback)。

---

## 安全须知

- 装了根证书，谁拿着 `root.key`，谁就能对那台机器冒充**任何**网站。只在你自己掌控的设备上装，并且别让 `root.key` 外泄。
- 根证书在本地生成，永远不会离开你的机器。
- 用完就卸载：把证书从信任库里移除，再删掉 `~/.whix/certs/`。
- whix 用系统的 webpki 根证书库校验**源站**的服务器证书，所以不会悄悄接受伪造的源站证书。
