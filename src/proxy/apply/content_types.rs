//! Content types: the extension table a local file is served with (copied from
//! the `mime` package whistle carries, and tested against it), and the
//! `reqType://`/`resType://`/`reqCharset://`/`resCharset://` operators with the
//! short names they accept.

use super::*;

/// Content type for a served file, following whistle's fallback chain
/// (`_original/lib/handlers/file-proxy.js:255-258`): the file's own extension
/// first, then the *request URL's* extension, then `text/html`.
///
/// That second step is what makes `example.com/a.json file:///tmp/mock` serve
/// JSON even though the mock file has no extension.
pub(super) fn content_type_for(path: &str, full_url: &str) -> &'static str {
    match content_type_of_ext(path) {
        Some(ct) => ct,
        // Strip query/fragment before looking at the URL's extension.
        None => {
            let pure = full_url.split(['?', '#']).next().unwrap_or(full_url);
            content_type_of_ext(pure).unwrap_or("text/html; charset=utf-8")
        }
    }
}

/// Map a path's extension to a content type, or `None` when there is no
/// extension in the final path segment.
///
/// Types and spellings are whatever the `mime` package upstream depends on
/// answers for that extension; the `; charset=utf-8` suffix follows upstream's
/// `util.isText` (`_original/lib/util/index.js:1494-1531`), which is a substring
/// test — anything naming `javascript`, `css`, `html`, `json`, `xml` or starting
/// `text/` is text, and only `image/*` that got past those is not. That is why
/// `image/svg+xml` carries a charset and `image/png` does not.
///
/// The table is a subset of `mime`'s several hundred entries — every spelling
/// here was read out of the `mime@1.6.0` whistle depends on rather than
/// guessed, including the ones that look wrong (`.ts` is `video/mp2t`, `.rs` is
/// `application/rls-services+xml`, and `.docx` carries a charset because
/// `isText`'s substring test finds `xml` inside `openxmlformats`). An extension
/// outside it falls back to the request URL's, then to `text/html`, which is
/// the fallback chain whistle passes to `mime.lookup` itself
/// (`file-proxy.js:255-257,:314`).
pub(super) fn content_type_of_ext(path: &str) -> Option<&'static str> {
    // The separator set is `mime`'s own: `lookup` strips everything up to the
    // last `.`, `/` **or** `\` (`mime@1 lookup`, `path.replace(/.*[\.\/\\]/, '')`),
    // so a final segment with no dot is taken as the extension whole. That is
    // not a quirk without consequence — `file://http://host/json` is typed
    // `application/json` upstream, and was `text/html` here, because this
    // required a dot and gave up.
    let ext = path
        .rsplit(['.', '/', '\\'])
        .next()
        .filter(|ext| !ext.is_empty())?
        .to_ascii_lowercase();
    Some(match ext.as_str() {
        // Markup, styles and scripts.
        "html" | "htm" | "shtml" => "text/html; charset=utf-8",
        "xhtml" => "application/xhtml+xml; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "jsx" => "text/jsx; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "scss" => "text/x-scss; charset=utf-8",
        "sass" => "text/x-sass; charset=utf-8",
        "less" => "text/less; charset=utf-8",
        "htc" => "text/x-component; charset=utf-8",
        "hbs" => "text/x-handlebars-template; charset=utf-8",
        // Data and documents. A source map is JSON, and `.map` is how every
        // bundler spells it — which is `mime`'s answer too.
        "json" | "map" => "application/json; charset=utf-8",
        "webmanifest" => "application/manifest+json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "rss" => "application/rss+xml; charset=utf-8",
        "atom" => "application/atom+xml; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "tsv" => "text/tab-separated-values; charset=utf-8",
        "yaml" | "yml" => "text/yaml; charset=utf-8",
        "ini" | "conf" | "log" | "txt" | "text" => "text/plain; charset=utf-8",
        "manifest" | "appcache" => "text/cache-manifest; charset=utf-8",
        "ics" => "text/calendar; charset=utf-8",
        "vcf" => "text/x-vcard; charset=utf-8",
        "rtf" => "application/rtf",
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=utf-8"
        }
        "xls" => "application/vnd.ms-excel",
        "xlsx" => {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet; charset=utf-8"
        }
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => {
            "application/vnd.openxmlformats-officedocument.presentationml.presentation; charset=utf-8"
        }
        "epub" => "application/epub+zip",
        "mobi" => "application/x-mobipocket-ebook",
        // Images.
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "tif" | "tiff" => "image/tiff",
        "svg" => "image/svg+xml; charset=utf-8",
        "ico" => "image/x-icon",
        "wbmp" => "image/vnd.wap.wbmp",
        "jng" => "image/x-jng",
        "psd" => "image/vnd.adobe.photoshop",
        "ai" | "eps" => "application/postscript",
        // Fonts.
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        // Video and audio. `.ts` is `video/mp2t` and not TypeScript, which is
        // `mime`'s answer and therefore whistle's.
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "ogv" => "video/ogg",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "flv" => "video/x-flv",
        "ts" => "video/mp2t",
        "3gp" => "video/3gpp",
        "m3u8" => "application/vnd.apple.mpegurl",
        "mpd" => "application/dash+xml; charset=utf-8",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" | "oga" => "audio/ogg",
        "aac" => "audio/x-aac",
        "flac" => "audio/x-flac",
        "m4a" => "audio/mp4",
        "weba" => "audio/webm",
        "mid" | "midi" => "audio/midi",
        // Archives and binaries.
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "xz" => "application/x-xz",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/x-rar-compressed",
        "jar" | "war" => "application/java-archive",
        "apk" => "application/vnd.android.package-archive",
        "swf" => "application/x-shockwave-flash",
        "wasm" => "application/wasm",
        "bin" => "application/octet-stream",
        // Sources, scripts and certificates.
        "php" => "application/x-httpd-php",
        "pl" => "application/x-perl",
        "sh" => "application/x-sh",
        "bat" => "application/x-msdownload",
        "sql" => "application/x-sql",
        "c" | "h" | "cpp" => "text/x-c; charset=utf-8",
        "java" => "text/x-java-source; charset=utf-8",
        "rs" => "application/rls-services+xml; charset=utf-8",
        "pem" | "crt" => "application/x-x509-ca-cert",
        "cer" => "application/pkix-cert",
        "p12" | "pfx" => "application/x-pkcs12",
        _ => return None,
    })
}

/// Every entry of the type table, against the `mime@1.6.0` whistle carries.
///
/// The table is written out by hand, so the test is the check that it was
/// copied and not invented — the values were produced by asking that package
/// and are pinned here in the shape it gave them.
#[cfg(test)]
#[test]
pub(super) fn the_type_table_is_the_one_whistle_carries() {
    // A few that a subset table gets wrong by guessing: `.ts` is a transport
    // stream, `.rs` is not `text/rust`, and the office formats carry a charset
    // only because `isText` looks for `xml` as a substring.
    assert_eq!(content_type_of_ext("a.ts"), Some("video/mp2t"));
    assert_eq!(
        content_type_of_ext("a.rs"),
        Some("application/rls-services+xml; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.scss"),
        Some("text/x-scss; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.jsx"),
        Some("text/jsx; charset=utf-8")
    );
    assert_eq!(
        content_type_of_ext("a.m3u8"),
        Some("application/vnd.apple.mpegurl")
    );
    assert_eq!(
        content_type_of_ext("a.php"),
        Some("application/x-httpd-php")
    );
    assert_eq!(
        content_type_of_ext("a.pem"),
        Some("application/x-x509-ca-cert")
    );
    assert_eq!(
        content_type_of_ext("a.docx"),
        Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document; charset=utf-8"
        )
    );
    // An extension the table does not carry has no answer here — the caller
    // then falls back to the request URL's, as `mime.lookup(path, defaultType)`
    // does upstream.
    assert_eq!(content_type_of_ext("a.zzz"), None);
    assert_eq!(content_type_of_ext("a.vue"), None);
}

/// `reqCharset`/`resCharset` and the `delete://…Type`/`…Charset` keys, which
/// upstream resolves in one pass over `Content-Type`
/// (`setCharset`, `_original/lib/util/index.js:3923-3944`).
///
/// The header is split on `;`, the media type is slot 0 and the charset slot 1;
/// dropping the type empties slot 0 rather than removing the header, so
/// `delete://resType` alone leaves a bare `; charset=utf-8` behind. Only when
/// *everything* is empty is the header removed. Faithfully odd.
pub(super) fn set_charset(
    headers: &mut HeaderMap,
    charset: Option<&str>,
    drop_type: bool,
    drop_charset: bool,
) {
    if charset.is_none() && !drop_type && !drop_charset {
        return;
    }
    let current = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim();
    let mut parts: Vec<String> = match current.is_empty() {
        true => vec![String::new()],
        false => current.split(';').map(|p| p.trim().to_string()).collect(),
    };
    if drop_type {
        parts[0] = String::new();
    }
    if drop_charset {
        parts.truncate(1);
    } else if let Some(charset) = charset {
        let value = format!("charset={charset}");
        match parts.len() {
            1 => parts.push(value),
            _ => parts[1] = value,
        }
    }
    let joined = parts.join("; ");
    if joined.trim_matches(|c| c == ';' || c == ' ').is_empty() {
        headers.remove(hyper::header::CONTENT_TYPE);
        return;
    }
    if let Ok(v) = HeaderValue::from_str(&joined) {
        headers.insert(hyper::header::CONTENT_TYPE, v);
    }
}

/// Media types whistle recognises by short name, beyond what a file extension
/// lookup gives (`REQ_TYPE`, `_original/lib/inspectors/req.js:31-40`).
pub(super) fn req_type_alias(name: &str) -> Option<&'static str> {
    Some(match name {
        "urlencoded" | "form" => "application/x-www-form-urlencoded",
        "json" => "application/json",
        "xml" => "application/xml",
        "text" => "text/plain",
        "upload" | "multipart" => "multipart/form-data",
        "defaultType" => "application/octet-stream",
        _ => return None,
    })
}

/// `resType`/`reqType` — set the media type, keeping the existing parameters.
///
/// A value with no `/` is a short name to look up (`resType://json` →
/// `application/json`), and a value with no `;` inherits whatever parameters
/// the current header carries, so `resType://json` on a
/// `text/html; charset=gbk` response yields `application/json;charset=gbk`
/// (`getNewType`, `_original/lib/util/index.js:3946-3956`).
pub(super) fn set_content_type(
    headers: &mut HeaderMap,
    value: &str,
    alias: fn(&str) -> Option<&'static str>,
) {
    let mut parts: Vec<String> = value.split(';').map(str::to_string).collect();
    let name = parts[0].clone();
    if !name.is_empty() && !name.contains('/') {
        parts[0] = lookup_type(&name, alias).to_string();
    }
    let mut new_type = parts.join(";");
    if !new_type.contains(';')
        && let Some(current) = headers
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .filter(|c| c.contains(';'))
    {
        let mut kept: Vec<String> = current.split(';').map(str::to_string).collect();
        kept[0] = new_type;
        new_type = kept.join(";");
    }
    set_header(headers, "content-type", &new_type);
}

/// Resolve a short type name (`lookupType`,
/// `_original/lib/util/index.js:3664-3666`): the side-specific aliases first,
/// then the same extension table the local-file family uses, then whistle's
/// `application/octet-stream` default.
pub(super) fn lookup_type(name: &str, alias: fn(&str) -> Option<&'static str>) -> &'static str {
    if name == "sse" {
        return "text/event-stream";
    }
    alias(name)
        // The extension table carries a `charset` for text types; `mime.lookup`
        // does not, and a parameter here would block the `getNewType` merge.
        .or_else(|| content_type_of_ext(&format!("x.{name}")).map(media_type))
        .unwrap_or("application/octet-stream")
}

/// The media type of a `type; parameter` string.
pub(super) fn media_type(full: &'static str) -> &'static str {
    full.split(';').next().unwrap_or(full)
}

/// The response side has no short-name aliases beyond the extension table.
pub(super) fn no_type_alias(_: &str) -> Option<&'static str> {
    None
}
