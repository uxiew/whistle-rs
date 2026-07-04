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
2. Visit `http://<your-ip>:8899/rootCA.crt` in Safari and allow the profile download.
3. **Settings → General → VPN & Device Management** → install the profile.
4. **Settings → General → About → Certificate Trust Settings** → enable full trust
   for **whistle-rs Root CA**. (This last step is required on iOS.)

### Android

1. Set the Wi-Fi proxy to your machine's IP and port `8899`.
2. Download `root.crt` and install it under **Settings → Security → Encryption &
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
2. whistle-rs replies `200`, upgrades the socket, and **TLS-accepts** it using a leaf
   certificate for `example.com` signed on the fly by the root CA (cached per host).
3. The now-decrypted request is matched against your rules and forwarded to the real
   server over a **new** TLS connection. The upstream SNI and certificate check use
   the **original** hostname even if a `host://` rule changed the destination IP, so
   real servers still see a valid handshake.

Implementation: `src/ca.rs` (CA + signing) and `src/proxy/mod.rs` (`handle_connect`,
`mitm_serve`).

---

## Security notes

- Installing a root CA lets whatever holds `root.key` impersonate **any** website to
  that machine. Only install it on devices you control, and keep `root.key` private.
- The CA is generated locally and never leaves your machine.
- Uninstall when you're done: remove the certificate from the trust store and delete
  `~/.whistle-rs/certs/`.
- whistle-rs verifies **upstream** server certificates against the system webpki root
  store, so it won't silently accept a forged upstream cert.
