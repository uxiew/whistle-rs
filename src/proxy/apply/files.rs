//! Finding a file rule's file: the candidate paths a value names (`|` lists,
//! directories, `~`, `..` refused), a URL source fetched before the rule is
//! applied, and the mtime-keyed cache files are read through.

use super::*;

/// May this rule's entries name a URL, or are they all paths?
///
/// The `<…>` form is paths only, which is a measurement rather than a design:
/// `file://http://host/x` is fetched by whistle and `file://<http://host/x>` is
/// opened as a path and 404s. The brackets are documented as *do not append the
/// request's path*, and nothing says they also mean *do not fetch* — but they
/// do, and a port that fetched both would answer `200` where whistle answers
/// `404`.
///
/// One shape is not covered: against a pattern that leaves no path to append —
/// `^http://host/echo <http://host/x>` — upstream fetches after all. That is
/// recorded in `tests/differential/cases.js` rather than reproduced, because no
/// reading of `file-proxy.js` explained why the pattern's leftover should decide
/// whether a value is a URL, and encoding an unexplained correlation is how a
/// port acquires bugs it cannot maintain.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum Sources {
    PathsOnly,
    PathsAndUrls,
}

/// The marker whistle reports instead of a path it refused to resolve
/// (`INVALID_PATH`, `_original/lib/handlers/file-proxy.js:29,52`).
pub(super) const INVALID_PATH: &str = "(Path contains parent directory notation '..')";

/// The paths a file rule may resolve to, in the order whistle tries them.
///
/// A rule value is not simply a path: it can list several with `|`, name a
/// directory, start at the home directory, and — in whix — omit the
/// leading slash. Building the whole list up front keeps the "first one that is
/// a file wins" rule (`readFiles`, `file-proxy.js:38-58`) a single loop, and
/// keeps the 404 able to name what was actually tried.
pub(super) struct FileCandidates {
    pub(super) paths: Vec<FileSource>,
    /// What a 404 should blame: the last path the user actually wrote, or
    /// [`INVALID_PATH`] when that entry was refused for containing `..`.
    pub(super) blame: String,
}

/// Where one candidate's bytes come from.
///
/// A file rule may name a URL instead of a path, and then the bytes are fetched
/// rather than opened — see [`names_a_remote_file`](crate::rules::matcher) for
/// the upstream reader that does this and why such an entry keeps its own path.
/// The two are kept in one ordered list because upstream tries them in the order
/// written and stops at the first that answers: `file:///srv/cache|http://host/x`
/// serves the local copy when it exists and fetches only when it does not.
#[derive(Debug, Clone, PartialEq)]
pub(super) enum FileSource {
    Path(String),
    Url(String),
}

/// A file rule's URL source, already fetched.
///
/// The fetch happens before [`short_circuit`], not inside it: everything that
/// answers a request without contacting the origin is synchronous, and the one
/// piece of I/O here that is not the filesystem should not be the reason to make
/// all of it async. [`prefetch_remote_file`] walks the same candidate list the
/// serving code walks, so the URL it fetched is the URL that will be asked for.
pub struct RemoteFile {
    pub(super) url: String,
    /// The bytes, or `None` when the fetch did not produce any.
    pub(super) data: Option<Arc<Vec<u8>>>,
    /// What the URL answered, or `0` when nothing did. It outlives a failed
    /// fetch because upstream distinguishes two kinds: a `404` is *this file is
    /// not there*, and anything else is the file server itself being broken,
    /// which it reports as a `502` rather than hiding behind a not-found
    /// (`is502 = err.code > 0 && err.code != 404`,
    /// `_original/lib/handlers/file-proxy.js:302`). A transport failure has no
    /// numeric code there, so it falls to the 404 — and to `0` here.
    pub(super) status: u16,
}

/// Fetch a file rule's URL source, if the rule has one that is reached.
///
/// "Reached" is what the walk is for: an entry only matters when no earlier
/// candidate is a readable local file, which is upstream's `readFiles` order
/// (`_original/lib/handlers/file-proxy.js:39-59`). Returns `None` for the
/// overwhelmingly common case — a rule that is not a file rule, or one whose
/// sources are all paths — and costs nothing there.
///
/// A remote source is capped at `MAX_URL_VAL_LEN`
/// (`_original/lib/plugins/index.js:1496`), and a fetch that fails is not an
/// answer: the rule falls through to its next candidate, then to the 404 — or,
/// for an `x` variant, to the origin.
pub async fn prefetch_remote_file(resolved: &Resolved) -> Option<RemoteFile> {
    let op = resolved.slot()?;
    let proto = op.protocol.as_str();
    if !crate::rules::protocols::is_file_protocol(proto) {
        return None;
    }
    let (value, sources) = file_location(op)?;
    if sources != Sources::PathsAndUrls {
        return None;
    }
    for source in FileCandidates::of(proto, &value, sources).paths {
        match source {
            FileSource::Path(p) if read_cached(Path::new(&p)).is_some() => return None,
            FileSource::Path(_) => {}
            FileSource::Url(url) => {
                let answer = super::super::upstream::simple_get(&url).await;
                let (status, body) = match answer {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!("file://{url}: {err}");
                        return Some(RemoteFile {
                            url,
                            data: None,
                            status: 0,
                        });
                    }
                };
                // Over the cap is this port's own refusal, not a measurement of
                // upstream's: whistle passes `maxLength` into its reader and
                // what that does at the boundary was never put in front of it.
                // Refusing loudly beats serving a body that is silently short.
                if status != 200 || body.len() > MAX_URL_FILE {
                    tracing::warn!("file://{url}: answered {status}, {} bytes", body.len());
                    return Some(RemoteFile {
                        url,
                        data: None,
                        status,
                    });
                }
                return Some(RemoteFile {
                    url,
                    data: Some(Arc::new(body.to_vec())),
                    status,
                });
            }
        }
    }
    None
}

/// How much of a URL-sourced file is served — `MAX_URL_VAL_LEN`
/// (`_original/lib/plugins/index.js:1496`).
pub(super) const MAX_URL_FILE: usize = 1024 * 256;

impl FileCandidates {
    pub(super) fn of(proto: &str, value: &str, sources: Sources) -> FileCandidates {
        let mut paths = Vec::new();
        let mut blame = String::new();
        for entry in split_paths(proto, value) {
            // A URL is not a path and none of what follows applies to it: there
            // is no home directory to expand, no `index.html` to append and no
            // leading slash to restore. It is also the one entry that can carry
            // a `?query`, which `decode_path` would cut off.
            if sources == Sources::PathsAndUrls && crate::rules::url::has_web_protocol(entry) {
                blame = entry.to_string();
                paths.push(FileSource::Url(entry.to_string()));
                continue;
            }
            // Home first, then the separators — `convertSlash`'s own order.
            let entry = convert_slash(&expand_home(&decode_path(entry)));
            if has_parent_ref(&entry) {
                // `joinPath` refuses the path outright (`util/index.js:1847-1849`)
                // and `readFiles` reports it with a fixed marker; it contributes
                // no candidate, so a later `|` alternative can still win.
                blame = INVALID_PATH.to_string();
                continue;
            }
            for candidate in expand_index(&entry) {
                // whix also accepts a value whose leading slash the rule
                // parser dropped (`file://tmp/x`), which upstream resolves
                // against the rule file's root instead. It is a fallback, so it
                // is tried after the path as written and never blamed in a 404.
                let rooted = format!("/{}", candidate.trim_start_matches('/'));
                blame = candidate.clone();
                if rooted != candidate {
                    paths.push(FileSource::Path(candidate));
                }
                paths.push(FileSource::Path(rooted));
            }
        }
        FileCandidates { paths, blame }
    }

    /// The first candidate that answers: a readable regular file, or the URL
    /// source [`prefetch_remote_file`] already fetched.
    pub(super) fn read(&self, remote: Option<&RemoteFile>) -> Option<(String, Arc<Vec<u8>>)> {
        self.paths.iter().find_map(|source| match source {
            FileSource::Path(p) => read_cached(Path::new(p)).map(|data| (p.clone(), data)),
            // Matched by URL rather than taken on trust: the prefetch walked
            // this same list, but a `|` value can name two URLs and only the
            // one that was fetched may answer.
            FileSource::Url(url) => remote
                .filter(|r| &r.url == url)
                .and_then(|r| r.data.as_ref())
                .map(|data| (url.clone(), Arc::clone(data))),
        })
    }
}

/// Split a `a|b|c` multi-path value (`getFiles`, `_original/lib/rules/rules.js:290`).
///
/// whistle only splits when the protocol matches `FILE_PROTO_RE`
/// (`rules.js:96`), whose `x?` prefix admits a *single* `x` — so `xsfile://` and
/// its siblings are never split. whix reproduces the quirk rather than
/// tidying it up: `|` is a legal character in a POSIX filename, so "fixing" it
/// would change what an existing rule file resolves to.
pub(super) fn split_paths<'a>(proto: &str, value: &'a str) -> Vec<&'a str> {
    match proto.starts_with("xs") {
        true => vec![value],
        false => value.split('|').collect(),
    }
}

/// Turn a candidate into a filesystem path — upstream's `decodePath`
/// (`_original/lib/util/index.js:1403-1418`, reached from `getTempFilePath`).
///
/// Two things happen there, and both matter once a rule maps a directory: the
/// query string and fragment come off (`getPureUrl`), because
/// `/static/app.js?v=2` names the file `app.js`; and the rest is
/// percent-decoded, because a request for `/a%20b.js` is asking for `a b.js`.
/// Undecodable escapes are left as written, which is upstream's fallback too.
pub(super) fn decode_path(path: &str) -> String {
    let pure = match path.find(['?', '#']) {
        Some(i) => &path[..i],
        None => path,
    };
    if !pure.contains('%') {
        return pure.to_string();
    }
    let mut out = Vec::with_capacity(pure.len());
    let bytes = pure.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(h), Some(l)) if let Some(byte) = from_hex(*h, *l) => {
                out.push(byte);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| pure.to_string())
}

/// Two hex digits → the byte they spell, or `None` if they do not.
pub(super) fn from_hex(high: u8, low: u8) -> Option<u8> {
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    Some(digit(high)? << 4 | digit(low)?)
}

/// `~/x` (and the full-width `～/x`) start at the home directory
/// (`getHomePath`, `_original/lib/util/common.js:557-564`). A bare `~` is left
/// alone: upstream's `/^[~～]\//` requires the slash.
pub(super) fn expand_home(path: &str) -> String {
    let Some(rest) = path.strip_prefix("~/").or_else(|| path.strip_prefix("～/")) else {
        return path.to_string();
    };
    match dirs::home_dir() {
        // Upstream falls back to a literal `~` when the OS has no home
        // directory; leaving the path untouched has the same effect.
        Some(home) => format!("{}/{rest}", home.to_string_lossy().trim_end_matches('/')),
        None => path.to_string(),
    }
}

/// A backslash is a path separator **everywhere except on Windows**, which is
/// the opposite of how it reads.
///
/// `convertSlash` is `isWin32 ? filePath : formatPathSep(filePath)`
/// (`_original/lib/util/file-mgr.js:13-16`), and `formatPathSep` replaces every
/// `\` with `/` (`util/common.js:178-180`). So a rule written on Windows —
/// `file://D:\mock.json`, or a path pasted out of Explorer — keeps working when
/// the same rules file is opened on a Mac, which is the point: rules travel
/// between machines and paths in them are written in the local dialect.
///
/// On Windows itself nothing is converted, because the OS takes either
/// separator and a `/` in a path is already a `/`.
///
/// The cost is a file whose **name** contains a backslash, which is legal here
/// and unreachable through a rule. It is unreachable in upstream too, and a
/// path that cannot be written on the platform the rule was written for is the
/// cheaper thing to give up.
pub(crate) fn convert_slash(path: &str) -> String {
    match cfg!(windows) {
        true => path.to_string(),
        false => path.replace('\\', "/"),
    }
}

/// whistle's `UP_PATH_REGEXP` (`_original/lib/util/common.js:29`): a `..` that
/// stands alone as a path segment. A file named `a..b` is perfectly fine.
pub(super) fn has_parent_ref(path: &str) -> bool {
    path.split(['/', '\\']).any(|segment| segment == "..")
}

/// A trailing slash means "a directory", which whistle expands into two
/// candidates: the directory name itself, then its `index.html`
/// (`getRuleFiles`, `_original/lib/util/index.js:1433-1437`). The first only
/// ever wins for a *file* that happens to be named like the directory.
pub(super) fn expand_index(path: &str) -> Vec<String> {
    match path.ends_with(['/', '\\']) {
        true => vec![
            path[..path.len() - 1].to_string(),
            format!("{path}index.html"),
        ],
        false => vec![path.to_string()],
    }
}

/// whistle's `encodeHtml` (`_original/lib/util/common.js:619-635`), so a path
/// echoed into the 404 body cannot inject markup.
pub(super) fn encode_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '`' => out.push_str("&#96;"),
            _ => out.push(c),
        }
    }
    out
}

/// Cached file contents, valid only while the file's mtime and length are
/// unchanged. Mock files are edited constantly during development, so the
/// cache must never be able to serve a stale body.
pub(super) struct CachedFile {
    pub(super) mtime: std::time::SystemTime,
    pub(super) len: u64,
    pub(super) data: Arc<Vec<u8>>,
}

/// Files at or below this size are cached; larger ones are streamed from disk
/// every time so a big fixture cannot pin memory.
pub(super) const MAX_CACHED_FILE: u64 = 1 << 20;

/// Cap on distinct cached paths. Rule files reference a handful of mocks, so a
/// small map suffices; on overflow we clear rather than track recency.
pub(super) const MAX_CACHE_ENTRIES: usize = 64;

pub(super) static FILE_CACHE: Lazy<Mutex<HashMap<PathBuf, CachedFile>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Read one candidate path through the mtime-keyed cache.
///
/// Every call still `stat`s the file, so an edit is picked up immediately; only
/// the read of an unchanged file is skipped. The one gap is a rewrite that both
/// preserves the byte length *and* lands within the filesystem's mtime
/// resolution of the previous one — a second-granularity filesystem can then
/// serve the previous body once.
///
/// Beyond the `..` check in [`FileCandidates`] there is no sandboxing:
/// `file://` exists to serve arbitrary local paths on the developer's own
/// machine, and the original imposes no restriction on absolute paths either.
pub(super) fn read_cached(path: &Path) -> Option<Arc<Vec<u8>>> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let len = meta.len();
    let mtime = meta.modified().ok();

    // A file we cannot stat for mtime is never cached — correctness first.
    if let (Some(mtime), true) = (mtime, len <= MAX_CACHED_FILE)
        && let Ok(mut cache) = FILE_CACHE.lock()
    {
        if let Some(hit) = cache.get(path)
            && hit.mtime == mtime
            && hit.len == len
        {
            return Some(Arc::clone(&hit.data));
        }
        let data = Arc::new(std::fs::read(path).ok()?);
        if cache.len() >= MAX_CACHE_ENTRIES {
            cache.clear();
        }
        cache.insert(
            path.to_path_buf(),
            CachedFile {
                mtime,
                len,
                data: Arc::clone(&data),
            },
        );
        return Some(data);
    }
    std::fs::read(path).ok().map(Arc::new)
}
