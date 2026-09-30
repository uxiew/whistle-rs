# 安装、升级与卸载

[快速开始](../README.md) · [证书](CERTIFICATES.md) · [安全运行与数据边界](OPERATIONS.md) · [当前状态](STATUS.md)

whistle-rs 是单个可执行文件：没有安装程序，不注册服务，不改系统代理，不装证书。"安装"就是把它放进 `PATH`，"卸载"就是把下面列出的东西删掉。

## 下载

还没有正式发布（GitHub Releases 是空的）。每次推到 main，CI 会给五个平台各打一个包：在仓库的 **Actions → CI → 那次运行 → Artifacts** 里，名字是 `whistle-rs-<target>`，保留 14 天，要登录 GitHub 才能下载。下载到的是 GitHub 包的一层 zip，解开才是下面这三样：

| 文件 | 是什么 |
| --- | --- |
| `whistle-rs-<版本>-<target>.tar.gz`（Windows 是 `.zip`） | 二进制、`LICENSE`、`NOTICE.md`、`THIRD-PARTY-LICENSES.md`、`BUILD-INFO.txt`、`SHA256SUMS` |
| 同名加 `.sha256` | 压缩包本身的 SHA-256 |
| `smoke-<target>.json` | 这个二进制在 CI 那台机器上跑冒烟测试的逐步结果（见 [DEVELOPMENT](DEVELOPMENT.md#在一台机器上实际用一遍)） |

| 平台 | target |
| --- | --- |
| Linux x86_64 | `x86_64-unknown-linux-gnu` |
| Linux arm64 | `aarch64-unknown-linux-gnu` |
| macOS Apple 芯片 | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Windows x86_64 | `x86_64-pc-windows-msvc` |

最低系统版本写在包里 `BUILD-INFO.txt` 的 `runs on:` 一行，由 CI 从二进制本身读出来：Linux 是它链接的最高 glibc 符号版本，glibc 更老的发行版上启动就报 `version 'GLIBC_2.xx' not found`；macOS 是 `minos`；Windows 不需要另装 Visual C++ 运行库。各平台实测到的值和 CI 结果记在 [STATUS](STATUS.md)。Windows ARM、32 位系统、musl（Alpine）没有包。

也可以自己构建，见 [README](../README.md#从源码构建)。

## 校验

```sh
sha256sum -c whistle-rs-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sha256    # macOS 用 shasum -a 256 -c
tar -xzf whistle-rs-0.1.0-x86_64-unknown-linux-gnu.tar.gz
cd whistle-rs-0.1.0-x86_64-unknown-linux-gnu && sha256sum -c SHA256SUMS
```

```powershell
Get-FileHash .\whistle-rs-0.1.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256   # 和 .sha256 文件里的比，不分大小写
Expand-Archive .\whistle-rs-0.1.0-x86_64-pc-windows-msvc.zip -DestinationPath .
```

校验和只能证明下载没坏、和 CI 当时产出的一致；它不是签名，能替换压缩包的人也能替换 `.sha256`。二进制没有代码签名，macOS 版也没有公证。

## 安装

```sh
install -m 755 whistle-rs ~/.local/bin/      # 或任何在 PATH 里的目录
whistle-rs --version
```

Windows 上把 `whistle-rs.exe` 放进一个目录（比如 `%LOCALAPPDATA%\Programs\whistle-rs`），再把这个目录加进用户的 `Path` 环境变量。

- **macOS 拒绝运行**（提示无法验证开发者，或者进程直接被杀）：浏览器下载的文件带隔离属性，而这个二进制只有链接器自动加的 ad-hoc 签名。确认来源后去掉隔离属性：`xattr -d com.apple.quarantine whistle-rs`。
- **Windows**：从资源管理器双击未签名的 exe 可能弹 SmartScreen；监听本机以外的地址（`-H 0.0.0.0`）时防火墙可能询问是否放行。这两处本项目都没有在 Windows 上实际点过，CI 的 Windows 虚拟机只从命令行启动、只监听 127.0.0.1。

第一次启动（`whistle-rs -p 8899`）会建数据目录、生成根证书。要解密 HTTPS，再按 [CERTIFICATES](CERTIFICATES.md#install-it) 让客户端信任根证书。

## 数据目录

默认 `~/.whistle-rs`，即 macOS/Linux 的 `$HOME/.whistle-rs`、Windows 的 `%USERPROFILE%\.whistle-rs`；`--dir` 可以换地方。里面是：

| 路径 | 内容 | 什么时候写 |
| --- | --- | --- |
| `certs/root.crt` | 根证书，可以给客户端 | 第一次启动 |
| `certs/root.key` | 根证书的私钥。拿到它的人可以对信任这个根证书的客户端冒充任何网站 | 第一次启动 |
| `rules/groups.json`、`rules/<组名>.rules` | 规则组的顺序和开关、每组的文本 | 控制台保存规则时 |
| `values.json` | Values | 控制台保存 Values 时 |
| `sessions/sessions-YYYY-MM-DD.jsonl` | 历史会话，一行一条，按 UTC 日期分文件，默认留 7 天 | 每条会话完成时；`--no-persist` 时不写 |
| `values.json.unreadable-<毫秒>` 等 | 启动时读不懂的 `groups.json`/`values.json`，挪到这里而不是覆盖，日志里有 WARN | 启动时，只在读不懂时 |

目录外面它只写规则明确要求写的文件（`reqWrite://`、`resWrite://` 等，写到规则给的路径）。`--cert-dir` 里的证书是你自己放的，它只读不写。Node 插件自己写什么由插件决定。

保存规则和 Values 时先写一个新文件再改名换上，进程在写的过程中被杀，留下的也是完整的旧文件或新文件。同一个目录同时只跑一个实例：它不加锁也不检查，两个实例共用一个目录时，后保存规则的会覆盖先保存的。

**谁能读：** Unix 上私钥、规则、Values、会话文件是 `0600`，本项目自己的子目录是 `0700`（见 [OPERATIONS](OPERATIONS.md#采集与保留)）。Windows 上不单独设权限，文件继承所在目录的 ACL：放在默认的 `%USERPROFILE%` 下时，Windows 默认只有你自己、SYSTEM 和 Administrators 能读；`--dir` 指到别处（比如 `D:\whistle`）时，要自己确认那个目录别人读不到。

## 升级

1. 停掉旧的：Ctrl+C，或 `kill <pid>`。它会先把已完成的会话写完、结束自己拉起的 Node 插件，再以退出码 0 退出。
2. 换掉二进制。
3. 用同一个目录启动。

新版本读得懂旧版本写的数据：0.1.0 写下的历史、规则组（顺序、开关、文本）、Values，换成之后的版本都要原样读回来，根证书不变，客户端不用重新信任。这一条由测试守着（`tests/data_compat.rs`，用 0.1.0 实际写出的目录 `tests/data/0.1.0/`）：以后哪个版本读不回来，测试就失败，要么写迁移，要么在这里写明哪些数据不再兼容。

**降级**（换回旧版本）不保证，但不会悄悄丢数据：

- 旧版本不认识的字段直接跳过（有测试确认新增字段不会让读取失败）；
- 整个 `groups.json`/`values.json` 都读不懂时，挪成 `*.unreadable-<毫秒>`，日志里 WARN 写明两个路径，再以空的开始。2026-09-29 之前构建的二进制没有这层保护，读不懂就当空的，下一次保存会覆盖掉；
- 历史文件里读不懂的行跳过，文件本身不改，到保留期按日期删除。

## 卸载

1. **停掉它**，确认没有留下插件进程：用 `kill -9` 或任务管理器强杀、而插件又没用 SDK 时，插件可能还在（见 [PLUGINS](PLUGINS.md#注册插件)）。
2. **撤销对根证书的信任**，每个信任过它的客户端都要做，命令见 [CERTIFICATES 的 Remove it](CERTIFICATES.md#remove-it)。只删私钥不够：备份或别的拷贝里可能还有它。
3. **把客户端的代理设置改回去。** whistle-rs 从不改系统代理，改过的是你自己。
4. **删数据目录**：

   ```sh
   rm -rf ~/.whistle-rs                                         # 用过 --dir 的，删那个目录
   ```

   ```powershell
   Remove-Item -Recurse -Force "$env:USERPROFILE\.whistle-rs"
   ```

   规则写出的文件在规则指定的地方，不在这里。
5. **删二进制**，Windows 上顺手把它的目录从 `Path` 里去掉。

除此之外它没在系统里留下别的：没有服务、开机项、注册表项或系统级配置。
