//! Runtime configuration, ported from `_original/lib/config.js` (the subset that
//! the Rust core currently honours). Values mirror whistle's defaults so the CLI
//! behaves the same way from the user's point of view.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Package defaults taken verbatim from `_original/package.json`.
pub const DEFAULT_PORT: u16 = 8899;
pub const DEFAULT_TIMEOUT_MS: u64 = 360_000;
pub const DATA_DIRNAME: &str = ".whistle-rs";
pub const NAME: &str = "whistle-rs";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The whole running configuration. In the original this is a giant mutable
/// singleton; here it is an immutable value built once from CLI args.
#[derive(Debug, Clone)]
pub struct Config {
    /// Main proxy port (HTTP proxy + CONNECT). whistle default: 8899.
    pub port: u16,
    /// Bind address, as given with `-H`. `None` binds loopback — see
    /// [`Config::bind_ip`]; every interface has to be asked for.
    pub host: Option<IpAddr>,
    /// Socket idle timeout.
    pub timeout_ms: u64,
    /// Storage directory (root CA, rules, etc.). whistle: `~/.whistle`.
    pub storage_dir: PathBuf,
    /// Whether HTTPS interception (MITM) is enabled by default. whistle only
    /// intercepts when told to; we expose a global switch for the core.
    pub intercept_https: bool,
    /// Which origins may call the console's API from a page on another site —
    /// whistle's `--allowOrigin`. Empty means none, which is the default in both.
    pub allow_origins: AllowedOrigins,
    /// A directory of certificates supplied by hand — whistle's `-z/--certDir`.
    ///
    /// Each `<name>.key` paired with `<name>.crt` (or `.cer`, `.pem`) is served
    /// **instead of a forged one** for every name the certificate carries, which
    /// is how a client that pins its server's certificate can still be read.
    /// `root.key` + `root.crt` there replaces the root CA itself, which is the
    /// only way to supply one: `gui/https.md` says the console will not accept a
    /// root through its upload form.
    pub cert_dir: Option<PathBuf>,
    /// Inline rules text loaded at startup (`-r`/`--rules`), whistle's
    /// `config.rules`.
    pub rules: Option<String>,
    /// Console login — whistle's `-n/--username` and `-w/--password`.
    ///
    /// With neither set the console is open, which is upstream's default and
    /// its own test: `if (!username && !password) return true`
    /// (`_original/biz/webui/lib/index.js:161-163`).
    pub ui_username: Option<String>,
    pub ui_password: Option<String>,
    /// The read-only account — `-N/--guestName` and `-W/--guestPassword`. It
    /// may `GET`; anything that writes needs the full login
    /// (`GET_METHOD_RE`, `biz/webui/lib/index.js:520-525`).
    pub guest_username: Option<String>,
    pub guest_password: Option<String>,
    /// Optional separate port for the console — whistle's `-P/--uiport`.
    ///
    /// `None` (or the proxy's own port) means the console is served on the
    /// proxy port, which is upstream's default: `config.uiport = config.port`
    /// unless the flag moved it, and only a *different* value starts a second
    /// server (`customUIPort`, `_original/biz/init.js:8-19`).
    pub ui_port: Option<u16>,
    /// Whether the console answers at all — `-M headless` (and
    /// `shadowRulesOnly`) turn it off. The root certificate and the PAC file
    /// still answer, because a client that cannot fetch them cannot be
    /// configured to use the proxy: upstream keeps `/cgi-bin/rootca` and
    /// `/cgi-bin/status` answering under `headless` too, measured.
    pub console: bool,
    /// Whether the hostnames in [`crate::proxy::webui::BUILTIN_UI_HOSTS`] open
    /// the console — `-M pureProxy` (and `proxyOnly`, `httpProxy`) turn it off,
    /// which is upstream's own `if (config.pureProxy) return false` inside
    /// `isWebUIHost`. Without a way to say no there is no way to run this as a
    /// plain proxy that forwards those names like any other.
    pub console_hostnames: bool,
    /// Whether a client's own `x-forwarded-for` survives to the origin —
    /// `-M keepXFF`. Off by default in both proxies, so a client cannot hand
    /// the origin an address the proxy appears to vouch for.
    pub keep_client_xff: bool,
    /// Whether this proxy reads rules out of a request's **own headers**, and
    /// whose rules win when it does — `-M enableRequestHeaderRules` and
    /// `-M multiEnv`/`nohost`. Off in both proxies by default; see
    /// [`HeaderRules`] for what each setting means and why the default matters.
    pub header_rules: HeaderRules,
    /// Was `-M multiEnv` (or `nohost`, or `multienv`) named?
    ///
    /// Separate from [`header_rules`](Self::header_rules) because `-M strict`
    /// takes away the *reading* and nothing else: `getValue` still runs for
    /// `x-whistle-rule-name` — `config.multiEnv && ... getValue(...)`
    /// (`_original/lib/rules/index.js:586`) — and the delete inside it is
    /// unconditional, so the header is consumed under `strict|multiEnv` and
    /// forwarded to the origin under `strict` alone. Measured, and the two-line
    /// difference the bench found when this was one field.
    ///
    /// The other two things the mode does — resolving the default group alone,
    /// and taking the HTTPS switch away — read it for the same reason: they
    /// check `config.multiEnv` directly and have never heard of `strict`.
    pub multi_env: bool,
    /// Believe `x-forwarded-host` (and whistle's `x-whistle-real-host`) about
    /// where the request was addressed — `-M x-forwarded-host`.
    ///
    /// Off in both proxies by default. See [`crate::proxy::forwarded`], which
    /// is also where this port's one divergence in that family is named.
    pub trust_forwarded_host: bool,
    /// Believe `x-forwarded-proto` about the scheme the client used, which
    /// decides whether `https://` patterns match — `-M x-forwarded-proto`.
    pub trust_forwarded_proto: bool,
    /// Whether a mode has taken the global HTTPS switch away.
    ///
    /// `-M multiEnv` and `-M notAllowedEnableHTTPS` do not *set*
    /// [`intercept_https`](Self::intercept_https) — they make it unanswerable:
    /// upstream's `isEnableCapture()` opens with
    /// `if (config.multiEnv || config.notAllowedEnableHTTPS) return false`
    /// (`_original/lib/rules/util.js:547-550`), so it is false whatever the
    /// stored property says and whatever order the tokens came in. Measured:
    /// `-M capture|multiEnv` passes CONNECT through, and so does
    /// `-M multiEnv|capture`.
    ///
    /// A rule may still ask for one host — `enable://capture` is resolved from
    /// the rules and never consults this, exactly as upstream's per-rule
    /// enable does.
    pub capture_locked_off: bool,
    /// Extra hostnames that **are** the console rather than somewhere to
    /// forward to — whistle's `-l/--localUIHost`, which appends to a built-in
    /// list rather than replacing it (`uiHostList`,
    /// `_original/lib/config.js:1040-1054`). Lower-cased on the way in; the
    /// built-in three live in [`crate::proxy::webui::BUILTIN_UI_HOSTS`].
    pub local_ui_hosts: Vec<String>,
    /// Optional inbound SOCKS5 port (whistle's `socksPort`).
    pub socks_port: Option<u16>,
    /// Registered plugin servers: name → `host:port` (whistle plugin servers).
    pub plugins: HashMap<String, String>,
    /// Named values (whistle's Values store): name → content. Referenced by
    /// `{name}` in operator values and by `rule://name`.
    pub values: HashMap<String, String>,
    /// The names `--value` gave. Those beat a ``` block of the same name, where
    /// the rest of the store loses to one — see
    /// [`crate::proxy::apply::yield_to_overrides`].
    pub value_overrides: HashSet<String>,
    /// Max bytes of each captured body kept for the inspection preview.
    pub body_preview_cap: usize,
    /// Max bytes of a **response** body this proxy will hold in memory in order
    /// to rewrite it. See [`DEFAULT_BODY_REWRITE_CAP`].
    pub body_rewrite_cap: usize,
    /// Whether to persist captured sessions to disk (JSONL).
    pub persist_sessions: bool,
    /// Number of days of session JSONL files to retain.
    pub persist_days: u32,
    /// How many captured transactions to keep in memory — whistle's
    /// `-R/--reqCacheSize`. Floored at 600 there and here
    /// (`_original/lib/util/data-server.js:10-12`).
    pub req_cache_size: usize,
    /// How many captured WebSocket frames to keep in memory — whistle's
    /// `-F/--frameCacheSize`. Upstream's floor is the odd one: anything under
    /// **720** becomes 600 (`data-server.js:14-16`), so the flag can only ever
    /// raise the number.
    pub frame_cache_size: usize,
}

impl Config {
    /// The address every listener binds: `-H` if given, else `127.0.0.1`.
    ///
    /// It used to be every interface, which is upstream's default and meant a
    /// fresh start was an open proxy to the whole network, with a console any
    /// device on it could rewrite — and rules read and write files. A proxy
    /// for this machine's own debugging needs nothing more than loopback; a
    /// phone or a second machine is a decision, made with `-H 0.0.0.0` (or an
    /// address), and startup says how. A deliberate divergence from whistle.
    pub fn bind_ip(&self) -> IpAddr {
        self.host
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
    }

    /// Can anything but this machine reach the listeners?
    pub fn listens_beyond_loopback(&self) -> bool {
        !self.bind_ip().is_loopback()
    }

    pub fn data_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// Path of the persisted root CA certificate (PEM).
    pub fn root_ca_cert_path(&self) -> PathBuf {
        self.storage_dir.join("certs").join("root.crt")
    }

    /// Path of the persisted root CA private key (PEM).
    pub fn root_ca_key_path(&self) -> PathBuf {
        self.storage_dir.join("certs").join("root.key")
    }

    /// Directory for persisted session JSONL files.
    pub fn sessions_dir(&self) -> PathBuf {
        self.storage_dir.join("sessions")
    }
}

impl Default for Config {
    fn default() -> Self {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        Config {
            port: DEFAULT_PORT,
            host: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            storage_dir: base.join(DATA_DIRNAME),
            intercept_https: true,
            allow_origins: AllowedOrigins::default(),
            cert_dir: None,
            rules: None,
            ui_username: None,
            ui_password: None,
            guest_username: None,
            guest_password: None,
            ui_port: None,
            console: true,
            console_hostnames: true,
            keep_client_xff: false,
            header_rules: HeaderRules::Off,
            multi_env: false,
            trust_forwarded_host: false,
            trust_forwarded_proto: false,
            capture_locked_off: false,
            local_ui_hosts: Vec::new(),
            socks_port: None,
            plugins: HashMap::new(),
            values: HashMap::new(),
            value_overrides: HashSet::new(),
            body_preview_cap: DEFAULT_BODY_PREVIEW_CAP,
            body_rewrite_cap: DEFAULT_BODY_REWRITE_CAP,
            persist_sessions: true,
            persist_days: DEFAULT_PERSIST_DAYS,
            req_cache_size: DEFAULT_REQ_CACHE_SIZE,
            frame_cache_size: DEFAULT_FRAME_CACHE_SIZE,
        }
    }
}

/// Default preview cap: 16 KB of each body kept for inspection.
/// The `--allow-origin` list, parsed once.
///
/// whistle's own shape (`_original/lib/config.js:612-634`): the value is split
/// on `|`, `,` or `&` and lower-cased; a `*` **anywhere in the list** means every
/// origin and the rest is ignored; any other entry containing a star becomes a
/// domain pattern, and the rest are literal hostnames.
///
/// The star vocabulary is the one the pattern layer already speaks — `*` is one
/// label, `**` is any number, `***.` makes the label optional — because it is
/// the same function upstream uses in both places, and this reuses the same one
/// here rather than growing a second dialect.
#[derive(Debug, Clone, Default)]
pub struct AllowedOrigins {
    /// `--allow-origin '*'`: every origin, which is the only way to say "any".
    pub all: bool,
    /// Literal hostnames, lower-cased.
    pub hosts: Vec<String>,
    /// Hostnames written with a star, compiled.
    pub patterns: Vec<regex::Regex>,
}

impl AllowedOrigins {
    /// Parse a `--allow-origin` value.
    pub fn parse(list: &str) -> Self {
        let mut out = AllowedOrigins::default();
        for raw in list.split(['|', ',', '&']) {
            let entry = raw.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            if entry == "*" {
                // Upstream checks for `*` before compiling anything, so a list
                // that contains one is simply "all".
                return AllowedOrigins {
                    all: true,
                    ..Default::default()
                };
            }
            match entry.contains('*') {
                true => {
                    if let Some(re) = crate::rules::wildcard::domain_pattern(&entry) {
                        out.patterns.push(re);
                    }
                }
                false => out.hosts.push(entry),
            }
        }
        out
    }

    /// Whether `host` — an origin's hostname, without its port — is on the list.
    pub fn allows(&self, host: &str) -> bool {
        if self.all {
            return true;
        }
        let host = host.to_ascii_lowercase();
        self.hosts.iter().any(|h| h == &host) || self.patterns.iter().any(|re| re.is_match(&host))
    }

    /// Nothing was configured, which is the default and means no cross-origin
    /// caller is named.
    pub fn is_empty(&self) -> bool {
        !self.all && self.hosts.is_empty() && self.patterns.is_empty()
    }
}

/// What a `-M/--mode` list did, so the launch can say so out loud.
///
/// A whistle command line that names a mode this port cannot honour should not
/// look like it worked. Upstream's parser silently ignores anything it does not
/// recognise (its `forEach` has no `else`), which is fine for a program where
/// every token means something; here the same silence would hide the difference
/// between "applied" and "there is no such thing here".
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ModeReport {
    /// Tokens that changed something.
    pub honoured: Vec<String>,
    /// Tokens upstream has and this port has nothing to apply them to.
    pub inert: Vec<String>,
    /// Tokens neither program knows — almost certainly a typo.
    pub unknown: Vec<String>,
}

/// Upstream's composite modes, expanded before anything else looks at the list
/// (`_original/lib/config.js:766-773`). `admin`'s expansion differs under
/// `debug`, and this takes the non-debug one; the extra tokens it adds are all
/// inert here, so the difference is not reachable.
/// Whether a request may carry its **own rules**, in its own headers.
///
/// whistle reads five headers off an arriving request and, when a mode says so,
/// parses their contents as a rules text that applies to that request alone
/// (`initHeaderRules`, `_original/lib/rules/index.js:576-638`):
///
/// | header | what it carries |
/// |---|---|
/// | `x-whistle-rule-value` | the rules text |
/// | `x-whistle-rule-host` | one more line, appended |
/// | `x-whistle-rule-key` | the name of a **values** entry, whose content is prepended |
/// | `x-whistle-rule-name` | the name of a **rule group**, whose text is appended — `multiEnv` only |
/// | `x-whistle-key-value` | a JSON object of values private to that text |
///
/// Each is percent-decoded, and each is **removed from the request either way**
/// — the delete in `getValue` (`:558-570`) is unconditional and only the
/// *reading* is gated. This port has always done the removing; what follows is
/// the reading.
///
/// **Why it is off by default, in both proxies.** These headers let whoever
/// sends the request choose where it goes and what it carries — a proxy that
/// honours them by default is one any client on the network can redirect. The
/// deployment they exist for is the opposite of accidental: one whistle serving
/// many environments, each request naming its own
/// (`nohost`/`multiEnv` — hence the name).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum HeaderRules {
    /// The headers are removed and their contents dropped. The default, and
    /// what `-M strict` forces regardless of the other tokens
    /// (`config.strict ||` in `getValue`, `rules/index.js:561`).
    #[default]
    Off,
    /// `-M enableRequestHeaderRules`: the headers are read, but **the console's
    /// rules win** — upstream resolves the header rules first and merges the
    /// stored ones over them (`initRules`, `rules/index.js:647-652`), and the
    /// merge is what decides. `x-whistle-rule-name` is neither read nor removed
    /// under this one; measured, it reaches the origin.
    Console,
    /// `-M multiEnv` (also spelled `nohost`, `multienv`, and reached through
    /// `-M multiple`): the headers are read and **they win**, because upstream
    /// merges them the other way round. Two things come with it, both measured
    /// and both upstream's:
    ///
    ///   * the console's **named** rule groups stop applying — `multiEnv` makes
    ///     `getSelectedRulesList()` return `[]` and refuses select/unselect
    ///     (`rules/util.js:94,:149,:164,:204`). The **default** group still
    ///     applies; only selection is gone;
    ///   * HTTPS is no longer intercepted from the switch — see
    ///     [`Config::capture_locked_off`].
    Request,
}

impl HeaderRules {
    /// Are the five headers read at all?
    pub fn reads_headers(self) -> bool {
        self != HeaderRules::Off
    }

    /// Do the rules a request brought beat the ones the console holds?
    pub fn beats_stored_rules(self) -> bool {
        self == HeaderRules::Request
    }
}

fn expand_mode(token: &str) -> Option<&'static [&'static str]> {
    match token {
        "multiple" => Some(&[
            "multiEnv",
            "disableUpdateTips",
            "keepXFF",
            "x-forwarded-proto",
        ]),
        "admin" => Some(&[
            "proxyServer",
            "master",
            "x-forwarded-proto",
            "strict",
            "rules",
            "disableUpdateTips",
            "proxifier",
            "notAllowedDisablePlugins",
        ]),
        _ => None,
    }
}

/// Every mode token upstream recognises and this port has nothing to do with.
///
/// Written out rather than left to fall through to `unknown`, because the two
/// answers are different advice: "whistle has this and whistle-rs does not" is
/// something to look up, and "no such mode" is a typo to fix. Grouped by why.
const INERT_MODES: &[&str] = &[
    // Console options: which switches the web UI offers, and how it looks.
    "disableAuthUI",
    "disableUIAuth",
    "keepProxyUI",
    "hideLeftBar",
    "hideLeftMenu",
    "allowMultipleChoice",
    "useMultipleRules",
    "enableMultipleRules",
    "disableMultipleRules",
    "notAllowDisableRules",
    "notAllowedDisableRules",
    "disableBackOption",
    "disabledBackOption",
    "disableMultipleOption",
    "disabledMultipleOption",
    "disableRulesOptions",
    "disabledRulesOptions",
    "notAllowDisablePlugins",
    "notAllowedDisablePlugins",
    "disableUpdateTips",
    "disableCustomCerts",
    "showPluginReq",
    // Which subsystem the instance is for. This port has one shape.
    "rules",
    "rulesOnly",
    "plugins",
    "pluginsOnly",
    "network",
    "shadowRules",
    "socks",
    "master",
    "client",
    "agent",
    "proxyServer",
    "proxifier",
    "proxifier2",
    "diagnose",
    "encrypted",
    "captureData",
    "noGzip",
    "INADDR_ANY",
    "buildIn",
    "build-in",
    // DNS resolution order — `gui/online.md`'s three radio buttons.
    "ipv6Only",
    "ipv6only",
    "ipv4First",
    "ipv4first",
    "ipv6first",
    "verbatim",
    "dnsResolve",
    "dnsResolve4",
    "dnsResolve6",
    // Node's own inspector and process shape.
    "debug",
    "safe",
    "rejectUnauthorized",
];

impl Config {
    /// Is HTTPS intercepted from the switch, for connections no rule speaks for?
    ///
    /// upstream's `isEnableCapture()` (`_original/lib/rules/util.js:547-554`),
    /// whose first line refuses outright under two modes and whose second
    /// consults the stored property. Both halves are asked here rather than
    /// folded into one field, so that `/api/status` can still report what the
    /// switch says *and* that a mode has taken it away — and so the answer does
    /// not depend on the order `-M capture|multiEnv` came in. Measured: it does
    /// not, either way round.
    pub fn intercepts_https(&self) -> bool {
        self.intercept_https && !self.capture_locked_off
    }

    /// Apply a `-M/--mode` list: `|`, `,` or `&` separated, as upstream splits
    /// it (`newConf.mode.trim().split(/\s*[|,&]\s*/)`, `config.js:763`).
    ///
    /// Only the tokens a *proxy client* can tell apart are honoured, and that
    /// set was measured rather than chosen: `tests/differential/mode-bench.js`
    /// runs one whistle per token and reports which ones move any of nine
    /// probes. Fifteen of the fifty-six do; they collapse into six behaviours,
    /// four of which this port has something to apply them to.
    pub fn apply_modes(&mut self, list: &str) -> ModeReport {
        let mut report = ModeReport::default();
        let mut saw_strict = false;
        let mut tokens: Vec<String> = Vec::new();
        for raw in list.split(['|', ',', '&']) {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            // A composite is fully represented by what it expands to, so the
            // name itself is not carried forward — reporting `multiple` as a
            // thing that did nothing would be less true than reporting the four
            // tokens it actually stands for.
            match expand_mode(token) {
                Some(parts) => tokens.extend(parts.iter().map(|p| p.to_string())),
                None => tokens.push(token.to_string()),
            }
        }
        for token in tokens {
            let honoured = match token.as_str() {
                // A plain proxy: the console stays on its own port and the three
                // hostnames go back to being ordinary names to forward.
                "pureProxy" | "proxyOnly" | "httpProxy" => {
                    self.console_hostnames = false;
                    true
                }
                // No console at all. The certificate and the PAC still answer.
                "headless" | "shadowRulesOnly" => {
                    self.console = false;
                    true
                }
                // The HTTPS switch, at launch. This port intercepts by default,
                // so the `on` spellings are the default and say so; the `off`
                // ones are `--no-intercept-https` under whistle's name.
                "capture" | "intercept" | "enable-capture" | "enableCapture" | "enableHttps"
                | "enableHTTPS" | "persistentCapture" => {
                    self.intercept_https = true;
                    true
                }
                "disable-capture" | "disableCapture" => {
                    self.intercept_https = false;
                    true
                }
                // Keep the client's own `x-forwarded-for` instead of dropping
                // it. Both proxies drop it by default so a client cannot claim
                // an address; this is how upstream opts back in globally, and
                // it is `enable://clientIp` for every request.
                "keepXFF" | "forwardedFor" | "x-forwarded-for" => {
                    self.keep_client_xff = true;
                    true
                }
                // A request may bring its own rules, and they lose to the
                // console's.
                "enableRequestHeaderRules" => {
                    // `multiEnv` is the stronger of the two and upstream checks
                    // it first everywhere, so a list naming both means
                    // `multiEnv` whichever order it came in.
                    if self.header_rules != HeaderRules::Request {
                        self.header_rules = HeaderRules::Console;
                    }
                    true
                }
                // A request may bring its own rules, and they win. HTTPS
                // interception goes with it — see `capture_locked_off`.
                "multiEnv" | "multienv" | "nohost" => {
                    self.header_rules = HeaderRules::Request;
                    self.multi_env = true;
                    self.capture_locked_off = true;
                    true
                }
                // Believe a front proxy about the host the client asked for.
                // `x-whistle-real-host` rides on this gate too — upstream reads
                // that one with no gate at all, which is the divergence named
                // in `crate::proxy::forwarded`.
                "x-forwarded-host" => {
                    self.trust_forwarded_host = true;
                    true
                }
                // Believe it about the scheme, which decides whether `https://`
                // patterns match a request that arrived in the clear.
                "x-forwarded-proto" => {
                    self.trust_forwarded_proto = true;
                    true
                }
                // "do not let anyone switch HTTPS on": the same lock, without
                // the rules half.
                "notAllowEnableHTTPS" | "notAllowedEnableHTTPS" => {
                    self.capture_locked_off = true;
                    true
                }
                // Handled after the loop: what `strict` does is take away what
                // another token gave, so whether it did anything cannot be
                // known until every token has been read.
                "strict" => {
                    saw_strict = true;
                    false
                }
                _ => false,
            };
            // Bucketed after the loop instead: what it did is not knowable yet.
            if token == "strict" {
                continue;
            }
            let bucket = if honoured {
                &mut report.honoured
            } else if INERT_MODES.contains(&token.as_str()) {
                &mut report.inert
            } else {
                &mut report.unknown
            };
            if !bucket.contains(&token) {
                bucket.push(token);
            }
        }
        // `strict` is the one token whose effect is entirely negative: it makes
        // `getValue` refuse to return a header's contents
        // (`config.strict || ...`, `_original/lib/rules/index.js:561`), which is
        // visible only if something else asked for them. Reported as honoured
        // when it took something away and as inert when there was nothing to
        // take — the two are different advice, and the token is the same.
        if saw_strict {
            let bucket = if self.header_rules.reads_headers() {
                self.header_rules = HeaderRules::Off;
                &mut report.honoured
            } else {
                &mut report.inert
            };
            bucket.push("strict".to_string());
        }
        report
    }
}

pub const DEFAULT_BODY_PREVIEW_CAP: usize = 16 * 1024;

/// Default ceiling on a response body held in memory to rewrite it: 16 MiB.
///
/// **This bound exists because this port's body layer is buffered and whistle's
/// is not.** whistle rewrites a response with stream transforms
/// (`addTextTransform` / `addZipTransform`, `_original/lib/inspectors/res.js`),
/// so a rule never costs it the body; the one place it accumulates —
/// `resMerge://` — carries an explicit ceiling of its own (`MAX_RES_SIZE`,
/// `res.js:21-22`). Here any body operator collects the whole response, and
/// measured against an 800 MB download with a single `resReplace://` matching,
/// resident memory went from 9.9 MB to **1.97 GB**.
///
/// 16 MiB is upstream's own "big data" number (`BIG_MAX_RES_SIZE`), which is
/// generous for the pages, bundles and JSON payloads rewriting is actually
/// aimed at, and far below the point where a download costs the proxy its life.
/// Past it the response streams through untouched — see
/// `crate::proxy::body::collect_capped`.
pub const DEFAULT_BODY_REWRITE_CAP: usize = 16 * 1024 * 1024;

/// Default number of days to retain persisted session files.
pub const DEFAULT_PERSIST_DAYS: u32 = 7;

/// The largest request body the console reads, 16 MiB: far above any rules
/// text, values store or bundle a person writes, and a ceiling on what one
/// request can make the proxy hold. Every console route used to read its body
/// with no limit at all, so one request could exhaust memory. Over it is a
/// `413`.
pub const CONSOLE_BODY_LIMIT: usize = 16 * 1024 * 1024;

/// Captured transactions kept in memory, and whistle's own default and floor
/// (`-R/--reqCacheSize`, `_original/lib/util/data-server.js:10-12`). This port
/// used to keep 500, so the console showed a shorter history than whistle's for
/// the same traffic.
pub const DEFAULT_REQ_CACHE_SIZE: usize = 600;

/// Captured WebSocket frames kept in memory (`-F/--frameCacheSize`,
/// `data-server.js:14-16`). 600 is upstream's default; its floor is written
/// against **720**, so a smaller flag value lands back on 600 rather than on
/// itself — see [`Config::frame_cache_size`].
pub const DEFAULT_FRAME_CACHE_SIZE: usize = 600;

/// Apply whistle's floor to a `-R` value: under its default, the default wins.
pub fn clamp_req_cache_size(n: usize) -> usize {
    n.max(DEFAULT_REQ_CACHE_SIZE)
}

/// Apply whistle's floor to a `-F` value. The comparison is against 720 and the
/// result is 600 — upstream's own asymmetry, kept because a user who copies a
/// `-F 700` from one proxy to the other should get the same buffer.
pub fn clamp_frame_cache_size(n: usize) -> usize {
    match n >= 720 {
        true => n,
        false => DEFAULT_FRAME_CACHE_SIZE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two capture caps, and the floors whistle applies to them
    /// (`_original/lib/util/data-server.js:10-16`). The `-F` floor is written
    /// against 720 and answers 600, which is upstream's own asymmetry rather
    /// than a transcription slip.
    #[test]
    fn a_capture_cap_cannot_be_set_below_its_floor() {
        assert_eq!(clamp_req_cache_size(0), 600);
        assert_eq!(clamp_req_cache_size(1), 600);
        assert_eq!(clamp_req_cache_size(599), 600);
        assert_eq!(clamp_req_cache_size(600), 600);
        assert_eq!(clamp_req_cache_size(5000), 5000);

        assert_eq!(clamp_frame_cache_size(0), 600);
        assert_eq!(clamp_frame_cache_size(600), 600);
        assert_eq!(clamp_frame_cache_size(719), 600);
        assert_eq!(clamp_frame_cache_size(720), 720);
        assert_eq!(clamp_frame_cache_size(5000), 5000);
    }

    /// The four modes this port honours, and that each is honoured for every
    /// spelling upstream gives it.
    #[test]
    fn the_modes_that_change_something_do() {
        let with = |list: &str| {
            let mut c = Config::default();
            let r = c.apply_modes(list);
            (c, r)
        };
        for token in ["pureProxy", "proxyOnly", "httpProxy"] {
            let (c, r) = with(token);
            assert!(!c.console_hostnames, "{token}");
            assert!(c.console, "{token}: only the hostnames go");
            assert_eq!(r.honoured, [token]);
        }
        for token in ["headless", "shadowRulesOnly"] {
            let (c, r) = with(token);
            assert!(!c.console, "{token}");
            // Not the hostnames: upstream still routes them and answers 404.
            assert!(c.console_hostnames, "{token}");
            assert_eq!(r.honoured, [token]);
        }
        for token in [
            "capture",
            "intercept",
            "enableCapture",
            "enableHttps",
            "persistentCapture",
        ] {
            let (c, _) = with(token);
            assert!(c.intercept_https, "{token}");
        }
        for token in ["disableCapture", "disable-capture"] {
            let (c, _) = with(token);
            assert!(!c.intercept_https, "{token}");
        }
        for token in ["keepXFF", "forwardedFor"] {
            let (c, _) = with(token);
            assert!(c.keep_client_xff, "{token}");
        }
    }

    /// A list is split on any of the three separators upstream splits on, and a
    /// token it has that this port cannot apply is reported rather than
    /// swallowed — the whole point of the report is that a copied command line
    /// says what happened to it.
    #[test]
    fn a_mode_list_is_split_and_triaged() {
        let mut c = Config::default();
        let r = c.apply_modes(" pureProxy , nohost | notAThing & keepXFF | noGzip ");
        assert_eq!(r.honoured, ["pureProxy", "nohost", "keepXFF"]);
        assert_eq!(r.inert, ["noGzip"]);
        assert_eq!(r.unknown, ["notAThing"]);
        assert!(!c.console_hostnames && c.keep_client_xff);
        assert_eq!(c.header_rules, HeaderRules::Request);

        // An empty list changes nothing and reports nothing.
        let mut c = Config::default();
        assert_eq!(c.apply_modes(""), ModeReport::default());
        assert_eq!(c.apply_modes("  |  , "), ModeReport::default());
    }

    /// `multiple` and `admin` are composites upstream expands before reading
    /// (`config.js:766-773`), so the parts have to be honoured too — `multiple`
    /// carries `keepXFF`, and a port that only matched the composite name would
    /// silently drop it.
    #[test]
    fn a_composite_mode_expands_to_its_parts() {
        let mut c = Config::default();
        let r = c.apply_modes("multiple");
        assert!(c.keep_client_xff, "multiple carries keepXFF");
        assert!(r.honoured.contains(&"keepXFF".to_string()));
        // `multiple` carries `multiEnv`, which is a behaviour and not just
        // vocabulary: a request may bring its own rules, and they win.
        assert!(r.honoured.contains(&"multiEnv".to_string()));
        assert_eq!(c.header_rules, HeaderRules::Request);
        assert!(c.multi_env && c.capture_locked_off && !c.intercepts_https());
        // The composite's own name is not reported: it stands for its parts and
        // they are what happened.
        assert!(!r.inert.contains(&"multiple".to_string()));
        assert!(r.unknown.is_empty(), "{r:?}");

        let mut c = Config::default();
        let r = c.apply_modes("admin");
        assert!(r.unknown.is_empty(), "admin expands to known tokens: {r:?}");
        // `admin` carries `strict`, and there is nothing for it to suppress —
        // so it is reported as the inert token it was in that list.
        assert!(r.inert.contains(&"strict".to_string()), "{r:?}");
        assert_eq!(c.header_rules, HeaderRules::Off);
    }

    /// The three settings of [`HeaderRules`], and the two facts `-M multiEnv`
    /// carries that `-M strict` does not take back. Every line here was
    /// measured against whistle 2.10.8 by
    /// `tests/differential/header-rules-bench.js` before it was written.
    #[test]
    fn the_header_rules_modes_are_read_the_way_upstream_reads_them() {
        // Off unless asked, in both proxies.
        assert_eq!(Config::default().header_rules, HeaderRules::Off);

        let mut c = Config::default();
        c.apply_modes("enableRequestHeaderRules");
        assert_eq!(c.header_rules, HeaderRules::Console);
        assert!(!c.multi_env, "this one is not multiEnv");
        assert!(c.intercepts_https(), "and it does not touch the switch");

        // Three spellings of the same mode.
        for token in ["multiEnv", "multienv", "nohost"] {
            let mut c = Config::default();
            c.apply_modes(token);
            assert_eq!(c.header_rules, HeaderRules::Request, "{token}");
            assert!(c.multi_env, "{token}");
        }

        // `multiEnv` is the stronger of the two whichever order they come in —
        // upstream checks `config.multiEnv` first at every site.
        for list in [
            "multiEnv|enableRequestHeaderRules",
            "enableRequestHeaderRules|multiEnv",
        ] {
            let mut c = Config::default();
            c.apply_modes(list);
            assert_eq!(c.header_rules, HeaderRules::Request, "{list}");
        }

        // `strict` takes the reading away and leaves everything else standing:
        // the name header is still consumed, the named groups still stop, and
        // the HTTPS switch is still gone.
        for list in ["strict|multiEnv", "multiEnv|strict"] {
            let mut c = Config::default();
            let r = c.apply_modes(list);
            assert_eq!(c.header_rules, HeaderRules::Off, "{list}");
            assert!(c.multi_env && c.capture_locked_off, "{list}");
            assert!(r.honoured.contains(&"strict".to_string()), "{list}: {r:?}");
        }
    }

    /// `isEnableCapture()` refuses under two modes before it consults anything,
    /// so the token order cannot decide it. Measured: `-M capture|multiEnv` and
    /// `-M multiEnv|capture` both pass CONNECT through.
    #[test]
    fn a_mode_can_take_the_https_switch_away_whatever_the_order() {
        for list in [
            "capture|multiEnv",
            "multiEnv|capture",
            "capture|notAllowedEnableHTTPS",
        ] {
            let mut c = Config::default();
            c.apply_modes(list);
            assert!(c.intercept_https, "{list}: the switch itself is still on");
            assert!(!c.intercepts_https(), "{list}: and it no longer answers");
        }
        // Without one of those modes the switch is the whole answer.
        let mut c = Config::default();
        c.apply_modes("capture");
        assert!(c.intercepts_https());
    }

    /// The last word wins when two tokens in one list disagree, which is what
    /// reading them left to right means.
    #[test]
    fn a_later_mode_overrides_an_earlier_one() {
        let mut c = Config::default();
        c.apply_modes("capture|disableCapture");
        assert!(!c.intercept_https);
        let mut c = Config::default();
        c.apply_modes("disableCapture|capture");
        assert!(c.intercept_https);
    }

    /// `--allow-origin` takes whistle's list: split on any of three separators,
    /// lower-cased, and a `*` anywhere in it means every origin.
    #[test]
    fn the_allowed_origin_list_is_parsed_like_upstreams() {
        let a = AllowedOrigins::parse("good.test, Other.TEST|third.test");
        assert!(!a.all);
        assert!(a.allows("good.test"));
        assert!(a.allows("other.test"), "lower-cased on the way in");
        assert!(a.allows("OTHER.test"), "and on the way out");
        assert!(a.allows("third.test"));
        assert!(!a.allows("evil.test"));

        // One star is one label — the same vocabulary a rule pattern speaks,
        // because it is the same function upstream calls in both places.
        let w = AllowedOrigins::parse("*.wild.test");
        assert!(w.allows("api.wild.test"));
        assert!(!w.allows("wild.test"), "a star is a label, not nothing");
        assert!(!w.allows("deep.api.wild.test"), "and one label, not two");
        assert!(AllowedOrigins::parse("**.wild.test").allows("deep.api.wild.test"));
        assert!(
            AllowedOrigins::parse("***.wild.test").allows("wild.test"),
            "three makes it optional"
        );

        // A `*` anywhere is "all", and the rest of the list stops mattering.
        for list in ["*", "good.test|*", "*|good.test"] {
            let all = AllowedOrigins::parse(list);
            assert!(all.all, "{list}");
            assert!(all.allows("anything.at.all"), "{list}");
        }

        // Nothing configured is nothing allowed, which is the default.
        assert!(AllowedOrigins::default().is_empty());
        assert!(AllowedOrigins::parse("").is_empty());
        assert!(AllowedOrigins::parse("  |  ,").is_empty());
        assert!(!AllowedOrigins::default().allows("good.test"));
    }
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    fn loopback_unless_told_otherwise() {
        let c = Config::default();
        assert_eq!(c.bind_ip(), IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(!c.listens_beyond_loopback());
        let lan = Config {
            host: Some("0.0.0.0".parse().unwrap()),
            ..Config::default()
        };
        assert!(lan.listens_beyond_loopback());
        let v6 = Config {
            host: Some("::1".parse().unwrap()),
            ..Config::default()
        };
        assert!(!v6.listens_beyond_loopback());
    }
}
