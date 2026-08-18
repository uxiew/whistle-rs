# HTTPS interception & the root CA

To read (and rewrite) HTTPS traffic, whistle-rs performs a **man-in-the-middle**: it
presents your client a certificate it generates on the fly for each host, signed by a
**root CA** that whistle-rs creates on first run. Your client will only trust those
certificates after you install and trust that root CA.

- [Where the CA lives](#where-the-ca-lives)
- [Download it](#download-it)
- [Install it](#install-it)
  - [macOS](#macos)
  - [Windows](#windows)
  - [Linux](#linux)
  - [iOS](#ios)
  - [Android](#android)
  - [Firefox](#firefox-all-platforms)
- [Verify](#verify)
- [How it works](#how-it-works)
- [Security notes](#security-notes)

---

## Where the CA lives

On first start whistle-rs generates and persists the root CA under the storage dir
(default `~/.whistle-rs`, override with `--dir`):

```
~/.whistle-rs/certs/root.crt   # the root certificate (install this)
~/.whistle-rs/certs/root.key   # its private key (keep secret)
```

Delete both files to regenerate a fresh CA on the next start (you'll need to
re-install it everywhere).

## Download it

With whistle-rs running, open the built-in page and download the certificate:

```
http://127.0.0.1:8899/           # status page with a download link
http://127.0.0.1:8899/rootCA.crt # the certificate itself
```

**Or, from a device that already has the proxy set:** open <http://rootca.pro/>.
The proxy answers for that name itself instead of forwarding it, and hands over
the certificate whatever the path is — so there is no address and no port to type
on a phone keyboard. It is whistle's own arrangement, kept here. `-M pureProxy`
turns it off, if you would rather that name were forwarded like any other.

Or copy it straight from disk: `~/.whistle-rs/certs/root.crt`.

```bash
# e.g. save it locally without a browser
curl -o whistle-rs-rootCA.crt http://127.0.0.1:8899/rootCA.crt
```

> If your shell exports `http_proxy`/`https_proxy`, add `--noproxy '*'` so curl talks
> to whistle-rs directly instead of through another proxy.

## Install it

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.whistle-rs/certs/root.crt
```

Or via the GUI: double-click `root.crt` → it opens Keychain Access → find
**whistle-rs Root CA** under *System* → *Get Info* → *Trust* → set **When using this
certificate: Always Trust**.

### Windows

```powershell
# Run as Administrator
Import-Certificate -FilePath "$env:USERPROFILE\.whistle-rs\certs\root.crt" `
  -CertStoreLocation Cert:\LocalMachine\Root
```

Or: double-click `root.crt` → **Install Certificate** → *Local Machine* → *Place all
certificates in the following store* → **Trusted Root Certification Authorities**.

### Linux

```bash
# Debian / Ubuntu
sudo cp ~/.whistle-rs/certs/root.crt /usr/local/share/ca-certificates/whistle-rs.crt
sudo update-ca-certificates

# Fedora / RHEL
sudo cp ~/.whistle-rs/certs/root.crt /etc/pki/ca-trust/source/anchors/whistle-rs.crt
sudo update-ca-trust
```

### iOS

1. Set the device's Wi-Fi HTTP proxy to your machine's IP and port `8899`.
2. Visit **<http://rootca.pro/>** in Safari (or `http://<your-ip>:8899/rootCA.crt`)
   and allow the profile download.
3. **Settings → General → VPN & Device Management** → install the profile.
4. **Settings → General → About → Certificate Trust Settings** → enable full trust
   for **whistle-rs Root CA**. (This last step is required on iOS.)

### Android

1. Set the Wi-Fi proxy to your machine's IP and port `8899`.
2. Download the certificate from **<http://rootca.pro/>** (or
   `http://<your-ip>:8899/rootCA.crt`) and install it under **Settings → Security → Encryption &
   credentials → Install a certificate → CA certificate**.
3. Note: since Android 7, apps only trust **user** CAs if they opt in via a network
   security config. System-level install (rooted devices) or an app-specific config
   may be required to intercept a given app.

### Firefox (all platforms)

Firefox uses its own trust store, not the OS one:

**Settings → Privacy & Security → Certificates → View Certificates → Authorities →
Import** → select `root.crt` → check *Trust this CA to identify websites*.

---

## Verify

Point a client at the proxy and fetch an HTTPS URL, trusting the CA:

```bash
curl -x http://127.0.0.1:8899 \
     --cacert ~/.whistle-rs/certs/root.crt \
     https://example.com/ -D - -o /dev/null
```

You should get `HTTP/1.1 200 OK`. Add a rule like `example.com resHeaders://x-mitm=1`
and you'll see the injected header appear — proof the tunnel was decrypted.

---

## How it works

1. The client sends `CONNECT example.com:443` to the proxy.
2. whistle-rs replies `200`, upgrades the socket, and reads the client's
   **ClientHello** — without consuming it, so the same bytes can still start a
   handshake afterwards.
3. It **TLS-accepts** the connection using a leaf certificate for the name the
   ClientHello asked for, signed on the fly by the root CA (cached per host).
4. The now-decrypted request is matched against your rules and forwarded to the real
   server over a **new** TLS connection. The upstream SNI and certificate check use
   the **original** hostname even if a `host://` rule changed the destination IP, so
   real servers still see a valid handshake.

Implementation: `src/ca.rs` (CA + signing), `src/proxy/sni.rs` (the ClientHello and
the certificate decision) and `src/proxy/mod.rs` (`handle_connect`, `serve_tunnel`).

### Which name the certificate is for

Step 3 signs for the name in the **ClientHello**, not the address the tunnel was
opened to, because the ClientHello name is the one the client will check. The two
are the same almost always, and where they are not, using the tunnel's address
produced a certificate the client rejected:

```
$ curl --socks5 127.0.0.1:1080 https://localhost:9443/     # curl resolves the name itself
   certificate served: subject=CN=127.0.0.1  san=IP Address:127.0.0.1   <- before
   certificate served: subject=CN=localhost  san=DNS:localhost          <- now
```

`--socks5` (as opposed to `--socks5-hostname`) makes curl resolve DNS and open the
tunnel to an address, while its ClientHello still asks for the hostname. A client
that pins an IP does the same thing over `CONNECT`. When the client sends no SNI at
all — an old client, or a connection to a literal IP — the tunnel's own address is
still the fallback, which is what it always was.

### What the tunnel is carrying

A tunnel is opened to an **address**, not to a protocol, and a client may put
anything through it. Before step 2 the first bytes are sniffed, exactly as
whistle sniffs them (`_original/lib/https/index.js:1176-1221`):

| First bytes | What happens | Say otherwise with |
|---|---|---|
| a TLS record (`0x16`) | decrypted, as above | `enable://forHttp`, `disable://captureHttps` |
| a cleartext `HTTP/1.x` request line | read as HTTP — rules apply to it in full | `enable://forHttps`, `disable://captureHttp` |
| the cleartext HTTP/2 preface (`PRI * HTTP/2.0`) | read as HTTP/2 | as above |
| **anything else** | **relayed untouched** | — |

The last row is the one that matters most and it needs no flag: a tunnel
carrying SSH, or a game protocol, or a binary nobody has named, is passed
through. whistle-rs used to assume every tunnel was TLS and hand it to the
acceptor, so those clients got a TLS alert where whistle gave them their
connection.

The method test is upstream's `/^(\w+)\s+(\S+)\s+HTTP\/1.\d$/im` — any method,
not a list — so `PROPFIND`, `MKCOL` or something invented this morning is still
read as HTTP.

### Which connections are read at all

Not every tunnel is opened. Before step 3, three questions are asked of the
connection, and any one of them can send it through untouched — routed by its
rules, but never decrypted:

| The connection | Read? | Say otherwise with |
|---|---|---|
| a name, whether or not the ClientHello carried SNI | yes | `disable://intercept`, `disable://https`, `disable://capture` |
| the ClientHello named a server | yes | `disable://captureSNI` |
| the ClientHello named nothing | yes | `disable://captureNoSNI` |
| **the authority is a bare IP and the ClientHello named nothing** | **no** | `enable://capture`, `enable://captureIp`, `enable://captureIP` — and `disable://captureIp` refuses even then |

The last row is a default rather than a rule, and it is upstream's:
`net.isIP(servername) && !isCaptureIp()`
(`_original/lib/https/index.js:1287`). TLS forbids an IP literal in SNI, so
`https://10.0.0.5/` produces exactly that shape — a tunnel to an address, with
nothing named inside it — and neither proxy forges a certificate for it. A client
that pins an IP therefore keeps its end-to-end connection without being asked.

> **whistle-rs reads by default; whistle does not.** whistle's console has an
> `Enable HTTPS` switch that starts **off**, and with it off `isEnableIntercept`
> only touches hosts that already have a custom certificate
> (`_original/lib/tunnel.js:187-199`). This port reads unless told not to, and
> `--no-intercept-https` is the global opt-out. It is the one difference of
> posture here, and everything in the table above is measured with whistle's
> switch turned on — otherwise the comparison is between "whistle intercepts
> nothing" and "this port intercepts", which says nothing about either rule.
>
> One more thing whistle does that this port does not: it intercepts a **local**
> hostname whatever the rules say. `disable://intercept` on `localhost` is
> ignored there and honoured here. Measured, and the reason
> `tests/differential/https-bench.js` runs its certificate cases under
> `probe.test` and a `host://` line rather than under `localhost`.

### Letting a plugin choose

A `sniCallback://` rule hands step 3 to a plugin, which may supply its own
certificate or decline the interception entirely (leaving the connection encrypted
end to end). See [`RULES.md`](RULES.md#choosing-the-mitm-certificate) and
[`PLUGINS.md`](PLUGINS.md#证书钩子--snicallback).

---

## Security notes

- Installing a root CA lets whatever holds `root.key` impersonate **any** website to
  that machine. Only install it on devices you control, and keep `root.key` private.
- The CA is generated locally and never leaves your machine.
- Uninstall when you're done: remove the certificate from the trust store and delete
  `~/.whistle-rs/certs/`.
- whistle-rs verifies **upstream** server certificates against the system webpki root
  store, so it won't silently accept a forged upstream cert.
