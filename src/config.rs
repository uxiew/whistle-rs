//! Runtime configuration, ported from `_original/lib/config.js` (the subset that
//! the Rust core currently honours). Values mirror whistle's defaults so the CLI
//! behaves the same way from the user's point of view.

use std::collections::HashMap;
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
    /// Bind address. `None` => all interfaces (INADDR_ANY).
    pub host: Option<IpAddr>,
    /// Socket idle timeout.
    pub timeout_ms: u64,
    /// Storage directory (root CA, rules, etc.). whistle: `~/.whistle`.
    pub storage_dir: PathBuf,
    /// Whether HTTPS interception (MITM) is enabled by default. whistle only
    /// intercepts when told to; we expose a global switch for the core.
    pub intercept_https: bool,
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
            rules: None,
            ui_username: None,
            ui_password: None,
            guest_username: None,
            guest_password: None,
            ui_port: None,
            console: true,
            console_hostnames: true,
            keep_client_xff: false,
            local_ui_hosts: Vec::new(),
            socks_port: None,
            plugins: HashMap::new(),
            values: HashMap::new(),
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
fn expand_mode(token: &str) -> Option<&'static [&'static str]> {
    match token {
        "multiple" => Some(&["multiEnv", "disableUpdateTips", "keepXFF", "x-forwarded-proto"]),
        "admin" => Some(&[
            "proxyServer", "master", "x-forwarded-proto", "strict", "rules",
            "disableUpdateTips", "proxifier", "notAllowedDisablePlugins",
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
    // Reading rules out of request headers — a real feature, not done here.
    // `nohost`/`multiEnv` deployments serve many environments from one proxy by
    // letting each request carry its own rules; measured, upstream honours
    // `x-whistle-rule-value` under any of these three.
    "multiEnv", "multienv", "nohost", "enableRequestHeaderRules",
    // Trusting a front proxy's forwarded headers. Measured: with these on,
    // upstream *consumes* `x-forwarded-proto` / `x-forwarded-host` and lets them
    // decide the scheme and the destination. Off — which is the default in both
    // — the headers travel on untouched, which is what this port does.
    "x-forwarded-proto", "x-forwarded-host",
    // Console options: which switches the web UI offers, and how it looks.
    "disableAuthUI", "disableUIAuth", "keepProxyUI", "hideLeftBar", "hideLeftMenu",
    "allowMultipleChoice", "useMultipleRules", "enableMultipleRules",
    "disableMultipleRules", "notAllowDisableRules", "notAllowedDisableRules",
    "disableBackOption", "disabledBackOption", "disableMultipleOption",
    "disabledMultipleOption", "disableRulesOptions", "disabledRulesOptions",
    "notAllowDisablePlugins", "notAllowedDisablePlugins",
    "notAllowEnableHTTPS", "notAllowedEnableHTTPS", "disableUpdateTips",
    "disableCustomCerts", "showPluginReq",
    // Which subsystem the instance is for. This port has one shape.
    "rules", "rulesOnly", "plugins", "pluginsOnly", "network", "shadowRules",
    "socks", "master", "client", "agent", "proxyServer", "proxifier",
    "proxifier2", "diagnose", "encrypted", "captureData", "strict", "noGzip",
    "INADDR_ANY", "buildIn", "build-in",
    // DNS resolution order — `gui/online.md`'s three radio buttons.
    "ipv6Only", "ipv6only", "ipv4First", "ipv4first", "ipv6first", "verbatim",
    "dnsResolve", "dnsResolve4", "dnsResolve6",
    // Node's own inspector and process shape.
    "debug", "safe", "rejectUnauthorized",
];

impl Config {
    /// Apply a `-M/--mode` list: `|`, `,` or `&` separated, as upstream splits
    /// it (`newConf.mode.trim().split(/\s*[|,&]\s*/)`, `config.js:763`).
    ///
    /// Only the tokens a *proxy client* can tell apart are honoured, and that
    /// set was measured rather than chosen: `tests/differential/mode-probe.js`
    /// runs one whistle per token and reports which ones move any of nine
    /// probes. Fifteen of the fifty-six do; they collapse into six behaviours,
    /// four of which this port has something to apply them to.
    pub fn apply_modes(&mut self, list: &str) -> ModeReport {
        let mut report = ModeReport::default();
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
                "capture" | "intercept" | "enable-capture" | "enableCapture"
                | "enableHttps" | "enableHTTPS" | "persistentCapture" => {
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
                _ => false,
            };
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
        for token in ["capture", "intercept", "enableCapture", "enableHttps", "persistentCapture"] {
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
        let r = c.apply_modes(" pureProxy , nohost | notAThing & keepXFF ");
        assert_eq!(r.honoured, ["pureProxy", "keepXFF"]);
        assert_eq!(r.inert, ["nohost"]);
        assert_eq!(r.unknown, ["notAThing"]);
        assert!(!c.console_hostnames && c.keep_client_xff);

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
        // The rest of the expansion is real vocabulary, so it is inert and not
        // unknown — the distinction is the advice the report gives.
        assert!(r.inert.contains(&"multiEnv".to_string()));
        // The composite's own name is not reported: it stands for its parts and
        // they are what happened.
        assert!(!r.inert.contains(&"multiple".to_string()));
        assert!(r.unknown.is_empty(), "{r:?}");

        let mut c = Config::default();
        let r = c.apply_modes("admin");
        assert!(r.unknown.is_empty(), "admin expands to known tokens: {r:?}");
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
}
