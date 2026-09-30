// The part of Node a whistle script is written against, in JavaScript.
//
// whistle runs a rule's script in a Node `vm` context that it fills by hand
// (`getScriptContext`, `_original/lib/rules/index.js:349-416`): `Buffer`,
// `parseUrl` (Node's legacy `url.parse`), `parseQuery` (`querystring.parse`)
// and three `iconv` helpers. The engine here is not Node, so those are built
// in this file, to the behaviour of the originals rather than to a summary of
// it — `reqScript.md` promises "同 Node.js 的 url.parse", and a script copied
// from a whistle setup depends on the details.
//
// This file is one function expression. `script.rs`'s bootstrap evaluates it
// the first time a script reaches for one of these names and calls it with
// `host`: the `Buffer` function that already exists (a stub until now), and
// `define`, which puts the real functions where the stubs were. Compiling
// these twelve hundred lines costs about 3 ms, and most scripts never need
// them.
//
// The natives it leans on (`__utf8Encode`, `__utf8Decode`, `__iconvEncode`,
// `__iconvDecode`, `__encodingExists`) are registered by `script.rs`; bytes
// cross that boundary as "binary strings" — one character per byte, code
// units 0-255 — which is the one representation both sides can hold without a
// copy of the typed-array API on the Rust side.
(function (global, host) {
  'use strict';

  var U8 = Uint8Array;
  // The function object the bootstrap made, its prototype already a
  // `Uint8Array`'s: filled in here rather than replaced, so a script that took
  // a reference to `Buffer` before this ran holds the real one.
  var Buffer = host.Buffer;
  var native = {
    utf8Encode: global.__utf8Encode,
    utf8Decode: global.__utf8Decode,
    iconvEncode: global.__iconvEncode,
    iconvDecode: global.__iconvDecode,
    encodingExists: global.__encodingExists
  };

  // ── Buffer ──────────────────────────────────────────────────────────────
  //
  // A `Uint8Array` whose prototype is `Buffer.prototype`, which is what Node's
  // own is. `buf[0]`, `buf.length`, `instanceof Uint8Array` and the inherited
  // typed-array methods therefore all work without being written here.

  function wrap(u8) {
    Object.setPrototypeOf(u8, Buffer.prototype);
    return u8;
  }

  function alloc(size) {
    size = Number(size);
    if (!(size >= 0) || size === Infinity) {
      throw new RangeError('The value "' + size + '" is invalid for option "size"');
    }
    return wrap(new U8(Math.floor(size)));
  }

  function binToBuf(bin) {
    var len = bin.length;
    var buf = alloc(len);
    for (var i = 0; i < len; i++) {
      buf[i] = bin.charCodeAt(i) & 255;
    }
    return buf;
  }

  function bufToBin(buf, start, end) {
    var out = '';
    // In pieces: `apply` spreads its array onto the stack.
    for (var i = start; i < end; i += 4096) {
      out += String.fromCharCode.apply(null, buf.subarray(i, Math.min(end, i + 4096)));
    }
    return out;
  }

  function normalizeEncoding(encoding) {
    if (encoding == null || encoding === '') {
      return 'utf8';
    }
    switch (String(encoding).toLowerCase()) {
      case 'utf8':
      case 'utf-8':
        return 'utf8';
      case 'hex':
        return 'hex';
      case 'base64':
        return 'base64';
      case 'base64url':
        return 'base64url';
      case 'latin1':
      case 'binary':
        return 'latin1';
      case 'ascii':
        return 'ascii';
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return 'utf16le';
    }
  }

  function checkEncoding(encoding) {
    var enc = normalizeEncoding(encoding);
    if (!enc) {
      throw new TypeError('Unknown encoding: ' + encoding);
    }
    return enc;
  }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var B64_VALUE = {};
  (function () {
    for (var i = 0; i < 64; i++) {
      B64_VALUE[B64.charAt(i)] = i;
      B64_VALUE[B64URL.charAt(i)] = i;
    }
  })();

  // Node's decoder is forgiving: either alphabet, padding optional, and any
  // character outside both is skipped rather than refused.
  function base64ToBin(str) {
    var out = '';
    var bits = 0;
    var have = 0;
    for (var i = 0; i < str.length; i++) {
      var c = str.charAt(i);
      if (c === '=') {
        break;
      }
      var v = B64_VALUE[c];
      if (v === undefined) {
        continue;
      }
      bits = (bits << 6) | v;
      have += 6;
      if (have >= 8) {
        have -= 8;
        out += String.fromCharCode((bits >> have) & 255);
      }
    }
    return out;
  }

  function binToBase64(bin, url) {
    var table = url ? B64URL : B64;
    var out = '';
    var len = bin.length;
    for (var i = 0; i < len; i += 3) {
      var a = bin.charCodeAt(i);
      var b = i + 1 < len ? bin.charCodeAt(i + 1) : NaN;
      var c = i + 2 < len ? bin.charCodeAt(i + 2) : NaN;
      out += table.charAt(a >> 2);
      out += table.charAt(((a & 3) << 4) | (isNaN(b) ? 0 : b >> 4));
      if (isNaN(b)) {
        out += url ? '' : '==';
        break;
      }
      out += table.charAt(((b & 15) << 2) | (isNaN(c) ? 0 : c >> 6));
      if (isNaN(c)) {
        out += url ? '' : '=';
        break;
      }
      out += table.charAt(c & 63);
    }
    return out;
  }

  var HEX = '0123456789abcdef';

  function hexToBin(str) {
    var out = '';
    // Node stops at the first pair that is not two hex digits.
    for (var i = 0; i + 1 < str.length; i += 2) {
      var hi = HEX.indexOf(str.charAt(i).toLowerCase());
      var lo = HEX.indexOf(str.charAt(i + 1).toLowerCase());
      if (hi < 0 || lo < 0) {
        break;
      }
      out += String.fromCharCode((hi << 4) | lo);
    }
    return out;
  }

  function stringToBin(str, enc) {
    switch (enc) {
      case 'utf8':
        return native.utf8Encode(str);
      case 'hex':
        return hexToBin(str);
      case 'base64':
      case 'base64url':
        return base64ToBin(str);
      case 'latin1':
      case 'ascii':
        var out = '';
        for (var i = 0; i < str.length; i++) {
          out += String.fromCharCode(str.charCodeAt(i) & 255);
        }
        return out;
      case 'utf16le':
        var wide = '';
        for (var j = 0; j < str.length; j++) {
          var unit = str.charCodeAt(j);
          wide += String.fromCharCode(unit & 255, unit >> 8);
        }
        return wide;
    }
  }

  function binToString(bin, enc) {
    switch (enc) {
      case 'utf8':
        return native.utf8Decode(bin);
      case 'hex':
        var hex = '';
        for (var i = 0; i < bin.length; i++) {
          var byte = bin.charCodeAt(i);
          hex += HEX.charAt(byte >> 4) + HEX.charAt(byte & 15);
        }
        return hex;
      case 'base64':
        return binToBase64(bin, false);
      case 'base64url':
        return binToBase64(bin, true);
      case 'latin1':
        return bin;
      case 'ascii':
        var ascii = '';
        for (var j = 0; j < bin.length; j++) {
          ascii += String.fromCharCode(bin.charCodeAt(j) & 127);
        }
        return ascii;
      case 'utf16le':
        var wide = '';
        for (var k = 0; k + 1 < bin.length; k += 2) {
          wide += String.fromCharCode(bin.charCodeAt(k) | (bin.charCodeAt(k + 1) << 8));
        }
        return wide;
    }
  }

  function isArrayBuffer(value) {
    return Object.prototype.toString.call(value) === '[object ArrayBuffer]';
  }

  function fromArrayLike(list) {
    var len = list.length >>> 0;
    var buf = alloc(len);
    for (var i = 0; i < len; i++) {
      buf[i] = list[i] & 255;
    }
    return buf;
  }

  // What `Buffer(...)` and `new Buffer(...)` do. Also the species constructor
  // of the inherited typed-array methods, which call it as `new Buffer(length)`
  // or `new Buffer(arrayBuffer, offset, length)`.
  host.construct = function (value, encodingOrOffset, length) {
    if (typeof value === 'number') {
      return alloc(value);
    }
    return Buffer.from(value, encodingOrOffset, length);
  };

  Buffer.from = function (value, encodingOrOffset, length) {
    if (typeof value === 'string') {
      return binToBuf(stringToBin(value, checkEncoding(encodingOrOffset)));
    }
    if (value == null || typeof value !== 'object') {
      throw new TypeError(
        'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.'
      );
    }
    if (isArrayBuffer(value)) {
      // A view, not a copy — as in Node.
      var offset = encodingOrOffset >>> 0;
      var size = length === undefined ? value.byteLength - offset : length >>> 0;
      return wrap(new U8(value, offset, size));
    }
    if (value.type === 'Buffer' && Array.isArray(value.data)) {
      return fromArrayLike(value.data);
    }
    if (typeof value.length === 'number') {
      return fromArrayLike(value);
    }
    throw new TypeError(
      'The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.'
    );
  };

  Buffer.alloc = function (size, fill, encoding) {
    var buf = alloc(size);
    if (fill !== undefined && fill !== 0) {
      buf.fill(fill, 0, buf.length, encoding);
    }
    return buf;
  };

  Buffer.allocUnsafe = Buffer.allocUnsafeSlow = function (size) {
    return alloc(size);
  };

  Buffer.isBuffer = function (value) {
    return value != null && value instanceof Buffer;
  };

  Buffer.isEncoding = function (encoding) {
    return typeof encoding === 'string' && encoding.length > 0 && !!normalizeEncoding(encoding);
  };

  Buffer.byteLength = function (value, encoding) {
    if (typeof value !== 'string') {
      return value.byteLength === undefined ? value.length : value.byteLength;
    }
    return stringToBin(value, checkEncoding(encoding)).length;
  };

  Buffer.concat = function (list, totalLength) {
    if (!Array.isArray(list)) {
      throw new TypeError('The "list" argument must be an instance of Array');
    }
    var i;
    if (totalLength === undefined) {
      totalLength = 0;
      for (i = 0; i < list.length; i++) {
        totalLength += list[i].length;
      }
    }
    var out = alloc(totalLength);
    var at = 0;
    for (i = 0; i < list.length && at < totalLength; i++) {
      var piece = list[i];
      if (at + piece.length > totalLength) {
        piece = piece.subarray(0, totalLength - at);
      }
      out.set(piece, at);
      at += piece.length;
    }
    return out;
  };

  Buffer.compare = function (a, b) {
    var len = Math.min(a.length, b.length);
    for (var i = 0; i < len; i++) {
      if (a[i] !== b[i]) {
        return a[i] < b[i] ? -1 : 1;
      }
    }
    return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
  };

  function clamp(value, fallback, len) {
    if (value === undefined) {
      return fallback;
    }
    value = Math.trunc(Number(value)) || 0;
    if (value < 0) {
      value += len;
    }
    return Math.min(Math.max(value, 0), len);
  }

  var proto = Buffer.prototype;

  proto.toString = function (encoding, start, end) {
    var len = this.length;
    start = start === undefined ? 0 : Math.min(Math.max(start | 0, 0), len);
    end = end === undefined ? len : Math.min(Math.max(end | 0, 0), len);
    if (end <= start) {
      return '';
    }
    return binToString(bufToBin(this, start, end), checkEncoding(encoding));
  };

  proto.toLocaleString = proto.toString;

  proto.toJSON = function () {
    return { type: 'Buffer', data: Array.prototype.slice.call(this) };
  };

  proto.equals = function (other) {
    return Buffer.compare(this, other) === 0;
  };

  proto.compare = function (other) {
    return Buffer.compare(this, other);
  };

  // Both share memory with the original, as Node's do.
  proto.subarray = proto.slice = function (start, end) {
    var len = this.length;
    start = clamp(start, 0, len);
    end = clamp(end, len, len);
    return wrap(new U8(this.buffer, this.byteOffset + start, Math.max(end - start, 0)));
  };

  function toNeedle(value, encoding) {
    if (typeof value === 'string') {
      return binToBuf(stringToBin(value, checkEncoding(encoding)));
    }
    if (typeof value === 'number') {
      return fromArrayLike([value]);
    }
    return value;
  }

  proto.indexOf = function (value, byteOffset, encoding) {
    if (typeof byteOffset === 'string') {
      encoding = byteOffset;
      byteOffset = 0;
    }
    var needle = toNeedle(value, encoding);
    var len = this.length;
    var from = clamp(byteOffset, 0, len);
    if (needle.length === 0) {
      return from;
    }
    outer: for (var i = from; i + needle.length <= len; i++) {
      for (var j = 0; j < needle.length; j++) {
        if (this[i + j] !== needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  };

  proto.lastIndexOf = function (value, byteOffset, encoding) {
    if (typeof byteOffset === 'string') {
      encoding = byteOffset;
      byteOffset = undefined;
    }
    var needle = toNeedle(value, encoding);
    var len = this.length;
    var from = Math.min(clamp(byteOffset, len, len), len - needle.length);
    outer: for (var i = from; i >= 0; i--) {
      for (var j = 0; j < needle.length; j++) {
        if (this[i + j] !== needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  };

  proto.includes = function (value, byteOffset, encoding) {
    return this.indexOf(value, byteOffset, encoding) !== -1;
  };

  proto.write = function (string, offset, length, encoding) {
    if (typeof offset === 'string') {
      encoding = offset;
      offset = 0;
      length = undefined;
    } else if (typeof length === 'string') {
      encoding = length;
      length = undefined;
    }
    offset = offset >>> 0;
    var room = this.length - offset;
    if (length === undefined || length > room) {
      length = room;
    }
    var bin = stringToBin(String(string), checkEncoding(encoding));
    var count = Math.min(bin.length, Math.max(length, 0));
    for (var i = 0; i < count; i++) {
      this[offset + i] = bin.charCodeAt(i);
    }
    return count;
  };

  proto.copy = function (target, targetStart, sourceStart, sourceEnd) {
    targetStart = targetStart >>> 0;
    sourceStart = sourceStart >>> 0;
    sourceEnd = sourceEnd === undefined ? this.length : Math.min(sourceEnd >>> 0, this.length);
    var count = Math.min(sourceEnd - sourceStart, target.length - targetStart);
    if (!(count > 0)) {
      return 0;
    }
    target.set(new U8(this.buffer, this.byteOffset + sourceStart, count), targetStart);
    return count;
  };

  var fillBytes = U8.prototype.fill;
  proto.fill = function (value, start, end, encoding) {
    if (typeof start === 'string') {
      encoding = start;
      start = undefined;
      end = undefined;
    } else if (typeof end === 'string') {
      encoding = end;
      end = undefined;
    }
    if (typeof value !== 'string') {
      return fillBytes.call(this, value & 255, start, end);
    }
    var bin = stringToBin(value, checkEncoding(encoding));
    var len = this.length;
    var from = clamp(start, 0, len);
    var to = clamp(end, len, len);
    if (bin.length === 0) {
      return fillBytes.call(this, 0, from, to);
    }
    for (var i = from; i < to; i++) {
      this[i] = bin.charCodeAt((i - from) % bin.length);
    }
    return this;
  };

  // The fixed-width readers and writers a binary protocol is picked apart
  // with. `DataView` does the byte order; these only name it Node's way.
  function view(buf) {
    return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  [
    ['UInt8', 'Uint8', 1],
    ['Int8', 'Int8', 1],
    ['UInt16', 'Uint16', 2],
    ['Int16', 'Int16', 2],
    ['UInt32', 'Uint32', 4],
    ['Int32', 'Int32', 4],
    ['Float', 'Float32', 4],
    ['Double', 'Float64', 8]
  ].forEach(function (kind) {
    var name = kind[0];
    var method = kind[1];
    var size = kind[2];
    var orders = size === 1 ? [['', false]] : [['LE', true], ['BE', false]];
    orders.forEach(function (order) {
      var read = function (offset) {
        return view(this)['get' + method](offset >>> 0, order[1]);
      };
      var write = function (value, offset) {
        offset = offset >>> 0;
        view(this)['set' + method](offset, value, order[1]);
        return offset + size;
      };
      proto['read' + name + order[0]] = read;
      proto['write' + name + order[0]] = write;
      // Node spells the unsigned ones both ways.
      if (name.indexOf('UInt') === 0) {
        proto['read' + name.replace('UInt', 'Uint') + order[0]] = read;
        proto['write' + name.replace('UInt', 'Uint') + order[0]] = write;
      }
    });
  });

  // ── the three iconv helpers ─────────────────────────────────────────────

  function toBuffer(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    if (typeof value === 'string') {
      return Buffer.from(value);
    }
    return Buffer.from(value);
  }

  // The encodings iconv-lite hands to `Buffer` itself — its "internal" codecs.
  // `latin1` and `ascii` are deliberately not among them: there they are real
  // single-byte tables, under which a character the table lacks is a `?`,
  // where `Buffer` would keep its low byte.
  function internalCodec(encoding) {
    if (encoding == null || encoding === '') {
      return 'utf8';
    }
    switch (String(encoding).toLowerCase().replace(/[^0-9a-z]/g, '')) {
      case 'utf8':
        return 'utf8';
      case 'ucs2':
      case 'utf16le':
        return 'utf16le';
      case 'binary':
        return 'latin1';
      case 'base64':
        return 'base64';
      case 'hex':
        return 'hex';
    }
  }

  // `iconv.decode(buf, encoding || 'utf8')`. Everything that is not one of the
  // internal codecs is asked of the native side, which knows the WHATWG set
  // (gbk, gb18030, big5, shift_jis, euc-kr, the windows-125x and iso-8859
  // families, …) and iconv-lite's spellings of their names.
  function decodeBuffer(buf, encoding) {
    buf = toBuffer(buf);
    var own = internalCodec(encoding);
    if (own) {
      return buf.toString(own);
    }
    var text = native.iconvDecode(bufToBin(buf, 0, buf.length), String(encoding));
    if (text === null) {
      throw new Error('Encoding not recognized: \'' + encoding + '\'');
    }
    return text;
  }

  function encodeString(str, encoding) {
    str = String(str == null ? '' : str);
    var own = internalCodec(encoding);
    if (own) {
      return Buffer.from(str, own);
    }
    var bin = native.iconvEncode(str, String(encoding));
    if (bin === null) {
      throw new Error('Encoding not recognized: \'' + encoding + '\'');
    }
    return binToBuf(bin);
  }

  function encodingExists(encoding) {
    if (encoding == null || encoding === '') {
      return false;
    }
    return !!internalCodec(encoding) || native.encodingExists(String(encoding));
  }

  // ── querystring.parse ───────────────────────────────────────────────────

  function isHexDigit(code) {
    return (code >= 48 && code <= 57) || (code >= 65 && code <= 70) || (code >= 97 && code <= 102);
  }

  // `querystring.unescape`: `decodeURIComponent`, and when that throws — a
  // stray `%`, or escapes that are not UTF-8 — decode what can be decoded and
  // leave the rest as written.
  function qsUnescape(str) {
    try {
      return decodeURIComponent(str);
    } catch (e) {
      var bin = native.utf8Encode(str);
      var out = '';
      for (var i = 0; i < bin.length; i++) {
        var code = bin.charCodeAt(i);
        if (
          code === 37 &&
          i + 2 < bin.length &&
          isHexDigit(bin.charCodeAt(i + 1)) &&
          isHexDigit(bin.charCodeAt(i + 2))
        ) {
          out += String.fromCharCode(parseInt(bin.substring(i + 1, i + 3), 16));
          i += 2;
        } else {
          out += bin.charAt(i);
        }
      }
      return native.utf8Decode(out);
    }
  }

  function parseQuery(qs, sep, eq, options) {
    var obj = Object.create(null);
    if (typeof qs !== 'string' || qs.length === 0) {
      return obj;
    }
    sep = typeof sep === 'string' && sep ? sep : '&';
    eq = typeof eq === 'string' && eq ? eq : '=';
    var maxKeys = 1000;
    if (options && typeof options.maxKeys === 'number') {
      maxKeys = options.maxKeys;
    }
    var decode = qsUnescape;
    if (options && typeof options.decodeURIComponent === 'function') {
      decode = options.decodeURIComponent;
    }
    var safeDecode = function (text) {
      // A `+` is a space, and is one before the escapes are read: `%2B` stays
      // a plus.
      text = text.replace(/\+/g, ' ');
      if (text.indexOf('%') === -1) {
        return text;
      }
      try {
        return decode(text);
      } catch (e) {
        return qsUnescape(text);
      }
    };
    var parts = qs.split(sep);
    var taken = 0;
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i];
      if (part === '') {
        continue;
      }
      if (maxKeys > 0 && taken >= maxKeys) {
        break;
      }
      taken++;
      var at = part.indexOf(eq);
      var key = safeDecode(at === -1 ? part : part.substring(0, at));
      var value = at === -1 ? '' : safeDecode(part.substring(at + eq.length));
      if (!(key in obj)) {
        obj[key] = value;
      } else if (Array.isArray(obj[key])) {
        obj[key].push(value);
      } else {
        obj[key] = [obj[key], value];
      }
    }
    return obj;
  }

  // ── url.parse (the legacy one) ──────────────────────────────────────────

  var SLASHED = { http: 1, https: 1, ftp: 1, gopher: 1, file: 1, ws: 1, wss: 1 };
  function isSlashed(protocol) {
    return !!protocol && SLASHED[protocol.replace(/:$/, '')] === 1;
  }
  function isScript(protocol) {
    return protocol === 'javascript' || protocol === 'javascript:';
  }

  // RFC 3492, the encoding half: what `url.parse` does to a label that is not
  // ASCII.
  function punycode(label) {
    var input = [];
    var i;
    for (i = 0; i < label.length; i++) {
      var unit = label.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < label.length) {
        var low = label.charCodeAt(i + 1);
        if ((low & 0xfc00) === 0xdc00) {
          input.push(((unit & 0x3ff) << 10) + (low & 0x3ff) + 0x10000);
          i++;
          continue;
        }
      }
      input.push(unit);
    }
    var digit = function (d) {
      return String.fromCharCode(d + 22 + 75 * (d < 26 ? 1 : 0));
    };
    var adapt = function (delta, points, first) {
      delta = first ? Math.floor(delta / 700) : delta >> 1;
      delta += Math.floor(delta / points);
      var k = 0;
      for (; delta > 455; k += 36) {
        delta = Math.floor(delta / 35);
      }
      return Math.floor(k + (36 * delta) / (delta + 38));
    };
    var out = '';
    for (i = 0; i < input.length; i++) {
      if (input[i] < 128) {
        out += String.fromCharCode(input[i]);
      }
    }
    var basic = out.length;
    var handled = basic;
    if (basic) {
      out += '-';
    }
    var n = 128;
    var delta = 0;
    var bias = 72;
    while (handled < input.length) {
      var m = Infinity;
      for (i = 0; i < input.length; i++) {
        if (input[i] >= n && input[i] < m) {
          m = input[i];
        }
      }
      delta += (m - n) * (handled + 1);
      n = m;
      for (i = 0; i < input.length; i++) {
        if (input[i] < n) {
          delta++;
        }
        if (input[i] === n) {
          var q = delta;
          for (var k = 36; ; k += 36) {
            var t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
            if (q < t) {
              break;
            }
            out += digit(t + ((q - t) % (36 - t)));
            q = Math.floor((q - t) / (36 - t));
          }
          out += digit(q);
          bias = adapt(delta, handled + 1, handled === basic);
          delta = 0;
          handled++;
        }
      }
      delta++;
      n++;
    }
    return out;
  }

  function toASCII(hostname) {
    return hostname
      .split('.')
      .map(function (label) {
        return /[^\x00-\x7f]/.test(label) ? 'xn--' + punycode(label) : label;
      })
      .join('.');
  }

  // `escape`d on the way into `pathname`/`search`/`hash`: the characters the
  // legacy parser calls "auto escape".
  var AUTO_ESCAPE = {
    '\t': '%09',
    '\n': '%0A',
    '\r': '%0D',
    ' ': '%20',
    '"': '%22',
    "'": '%27',
    '<': '%3C',
    '>': '%3E',
    '\\': '%5C',
    '^': '%5E',
    '`': '%60',
    '{': '%7B',
    '|': '%7C',
    '}': '%7D'
  };

  function autoEscape(rest) {
    return rest.replace(/[\t\n\r "'<>\\^`{|}]/g, function (c) {
      return AUTO_ESCAPE[c];
    });
  }

  function validHostChar(code) {
    return (
      (code >= 97 && code <= 122) || // a-z
      code === 46 || // .
      (code >= 65 && code <= 90) || // A-Z
      (code >= 48 && code <= 57) || // 0-9
      code === 45 || // -
      code === 43 || // +
      code === 95 || // _
      code > 127
    );
  }

  function Url() {
    this.protocol = null;
    this.slashes = null;
    this.auth = null;
    this.host = null;
    this.port = null;
    this.hostname = null;
    this.hash = null;
    this.search = null;
    this.query = null;
    this.pathname = null;
    this.path = null;
    this.href = null;
  }

  function formatUrl(u) {
    var auth = u.auth || '';
    if (auth) {
      auth = encodeURIComponent(auth).replace(/%3A/gi, ':') + '@';
    }
    var protocol = u.protocol || '';
    var pathname = u.pathname || '';
    var hash = u.hash || '';
    var host = '';
    if (u.host) {
      host = auth + u.host;
    } else if (u.hostname) {
      host = auth + (u.hostname.indexOf(':') !== -1 ? '[' + u.hostname + ']' : u.hostname);
      if (u.port) {
        host += ':' + u.port;
      }
    }
    var search = u.search || '';
    if (protocol && protocol.charAt(protocol.length - 1) !== ':') {
      protocol += ':';
    }
    pathname = pathname.replace(/[?#]/g, function (c) {
      return c === '?' ? '%3F' : '%23';
    });
    if (u.slashes || isSlashed(protocol)) {
      if (u.slashes || host) {
        if (pathname && pathname.charAt(0) !== '/') {
          pathname = '/' + pathname;
        }
        host = '//' + host;
      } else if (protocol.length >= 4 && protocol.indexOf('file') === 0) {
        host = '//';
      }
    }
    search = search.replace(/#/g, '%23');
    if (hash && hash.charAt(0) !== '#') {
      hash = '#' + hash;
    }
    if (search && search.charAt(0) !== '?') {
      search = '?' + search;
    }
    return protocol + host + pathname + search + hash;
  }

  // `Url.prototype.parse(url, false, false)` from Node's `lib/url.js`, step
  // for step. The quirks are the point: the host is lower-cased and the path
  // is not, a space in the path becomes `%20`, `auth` is percent-decoded, an
  // IPv6 host keeps its brackets in `host` and loses them in `hostname`, and a
  // URL with no `?` has `search: null` rather than `''`.
  function nodeUrlParse(url) {
    if (typeof url !== 'string') {
      throw new TypeError('The "url" argument must be of type string.');
    }
    var out = new Url();

    // Leading and trailing whitespace goes; a backslash before the query is a
    // slash.
    var hasHash = false;
    var hasAt = false;
    var trimmed = url.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, '');
    var question = trimmed.indexOf('?');
    var rest = '';
    for (var i = 0; i < trimmed.length; i++) {
      var ch = trimmed.charAt(i);
      if (ch === '#') {
        hasHash = true;
      } else if (ch === '@') {
        hasAt = true;
      }
      rest += ch === '\\' && (question === -1 || i < question) ? '/' : ch;
    }

    if (!hasHash && !hasAt) {
      // A bare path: nothing to find but where the query starts.
      var simple = /^(\/\/?(?!\/)[^?\s]*)(\?[^\s]*)?$/.exec(rest);
      if (simple) {
        out.path = rest;
        out.href = rest;
        out.pathname = simple[1];
        if (simple[2]) {
          out.search = simple[2];
          out.query = out.search.slice(1);
        }
        return out;
      }
    }

    var proto = /^[a-z0-9.+-]+:/i.exec(rest);
    var lowerProto;
    if (proto) {
      proto = proto[0];
      lowerProto = proto.toLowerCase();
      out.protocol = lowerProto;
      rest = rest.slice(proto.length);
    }

    var slashes;
    if (proto || /^\/\/[^@\/]+@[^@\/]+/.test(rest)) {
      slashes = rest.charAt(0) === '/' && rest.charAt(1) === '/';
      if (slashes && !(lowerProto && isScript(lowerProto))) {
        rest = rest.slice(2);
        out.slashes = true;
      }
    }

    if (!isScript(lowerProto) && (slashes || (lowerProto && !isSlashed(lowerProto)))) {
      // The host runs to the first `/`, `?` or `#`; the last `@` before that
      // ends the auth; and a character a host cannot hold ends the host early.
      var hostEnd = -1;
      var atSign = -1;
      var nonHost = -1;
      for (var j = 0; j < rest.length; j++) {
        var c = rest.charAt(j);
        if ('\t\n\r "%\';<>\\^`{|}'.indexOf(c) !== -1) {
          if (nonHost === -1) {
            nonHost = j;
          }
        } else if (c === '#' || c === '/' || c === '?') {
          if (nonHost === -1) {
            nonHost = j;
          }
          hostEnd = j;
          break;
        } else if (c === '@') {
          atSign = j;
          nonHost = -1;
        }
      }
      var start = 0;
      if (atSign !== -1) {
        out.auth = decodeURIComponent(rest.slice(0, atSign));
        start = atSign + 1;
      }
      if (nonHost === -1) {
        out.host = rest.slice(start);
        rest = '';
      } else {
        out.host = rest.slice(start, nonHost);
        rest = rest.slice(nonHost);
      }

      // The port comes off the end of the host.
      var port = /:[0-9]*$/.exec(out.host);
      if (port) {
        port = port[0];
        if (port !== ':') {
          out.port = port.slice(1);
        }
        out.host = out.host.slice(0, out.host.length - port.length);
      }
      out.hostname = out.host;

      var hostname = out.hostname;
      var ipv6 = hostname.charAt(0) === '[' && hostname.charAt(hostname.length - 1) === ']';
      if (!ipv6) {
        for (var k = 0; k < hostname.length; k++) {
          if (!validHostChar(hostname.charCodeAt(k))) {
            // What follows the first character a hostname cannot hold is path.
            out.hostname = hostname.slice(0, k);
            rest = '/' + hostname.slice(k) + rest;
            break;
          }
        }
      }
      if (out.hostname.length > 255) {
        out.hostname = '';
      } else {
        out.hostname = out.hostname.toLowerCase();
      }
      if (out.hostname !== '') {
        if (ipv6) {
          if (/[\0\t\n\r #%\/<>?@\\^|]/.test(out.hostname)) {
            throw new TypeError('Invalid URL');
          }
        } else {
          out.hostname = toASCII(out.hostname);
          if (/[\0\t\n\r #%\/:<>?@[\\\]^|]/.test(out.hostname)) {
            throw new TypeError('Invalid URL');
          }
        }
      }
      out.host = (out.hostname || '') + (out.port ? ':' + out.port : '');
      if (ipv6) {
        out.hostname = out.hostname.slice(1, -1);
        if (rest.charAt(0) !== '/') {
          rest = '/' + rest;
        }
      }
    }

    if (!isScript(lowerProto)) {
      rest = autoEscape(rest);
    }

    var hashAt = rest.indexOf('#');
    var queryAt = rest.indexOf('?');
    if (hashAt !== -1 && queryAt > hashAt) {
      queryAt = -1;
    }
    if (queryAt !== -1) {
      out.search = hashAt === -1 ? rest.slice(queryAt) : rest.slice(queryAt, hashAt);
      out.query = out.search.slice(1);
    }
    var first = queryAt !== -1 ? queryAt : hashAt;
    if (first === -1) {
      if (rest.length > 0) {
        out.pathname = rest;
      }
    } else if (first > 0) {
      out.pathname = rest.slice(0, first);
    }
    if (isSlashed(lowerProto) && out.hostname && !out.pathname) {
      out.pathname = '/';
    }
    if (out.pathname || out.search) {
      out.path = (out.pathname || '') + (out.search || '');
    }
    if (hashAt !== -1) {
      out.hash = rest.slice(hashAt);
    }
    out.href = formatUrl(out);
    return out;
  }

  // What whistle falls back to when `url.parse` throws (`parseUrlSafe`,
  // `_original/lib/util/parse-url-safe.js:148-212`): a parser that accepts
  // anything.
  function lenientUrlParse(addr) {
    addr = String(addr || '').replace(
      /^[\n\r\t\x00-\x20\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/,
      ''
    );
    var match = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\\\/]+)?([\S\s]*)/i.exec(addr);
    var protocol = match[1] ? match[1].toLowerCase() : '';
    var forward = match[2] || '';
    var other = match[3] || '';
    var count = forward.length + other.length;
    var rest = forward + other + match[4];
    if (protocol === 'file:') {
      if (count >= 2) {
        rest = rest.slice(2);
      }
    } else if (protocol && forward) {
      rest = rest.slice(2);
    }
    var url = { slashes: !!forward, protocol: protocol };
    var at = rest.indexOf('#');
    if (at !== -1) {
      url.hash = rest.substring(at);
      rest = rest.substring(0, at);
    }
    at = rest.indexOf('?');
    if (at !== -1) {
      url.search = rest.substring(at);
      url.query = rest.substring(at + 1);
      rest = rest.substring(0, at);
    }
    if (
      (protocol === 'file:' && (count !== 2 || /^[a-zA-Z]:/.test(rest))) ||
      (!url.slashes && (protocol || count < 2))
    ) {
      url.pathname = rest;
      url.host = url.hostname = '';
    } else {
      at = rest.indexOf('/');
      if (at !== -1) {
        url.pathname = rest.substring(at);
        rest = rest.substring(0, at);
      } else {
        url.pathname = '/';
      }
      url.path = url.pathname + (url.search || '');
      at = rest.lastIndexOf('@');
      if (at !== -1) {
        url.auth = rest.substring(0, at);
        rest = rest.substring(at + 1);
      }
      url.host = rest;
      var port = /:(\d*)$/.exec(rest);
      if (port) {
        url.port = port[1];
        rest = rest.substring(0, port.index);
      }
      url.hostname =
        rest.charAt(0) === '[' && rest.charAt(rest.length - 1) === ']' ? rest.slice(1, -1) : rest;
    }
    if (url.pathname.charAt(0) !== '/') {
      url.pathname = '/' + url.pathname;
    }
    var defaults = { http: 80, ws: 80, https: 443, wss: 443, ftp: 21, gopher: 70 };
    var scheme = protocol.split(':')[0];
    var portNumber = +url.port;
    var keepPort =
      !!portNumber && scheme !== 'file' && (defaults[scheme] ? portNumber !== defaults[scheme] : true);
    if (!keepPort) {
      url.host = url.hostname;
      url.port = '';
    }
    var encode = function (str) {
      try {
        return encodeURIComponent(decodeURIComponent(str));
      } catch (e) {
        return '';
      }
    };
    url.username = url.password = '';
    if (url.auth) {
      var colon = url.auth.indexOf(':');
      if (colon !== -1) {
        url.username = encode(url.auth.slice(0, colon));
        url.password = encode(url.auth.slice(colon + 1));
      } else {
        url.username = encode(url.auth);
      }
      url.auth = url.password ? url.username + ':' + url.password : url.username;
    }
    url.origin = protocol !== 'file:' && url.host ? protocol + '//' + url.host : 'null';
    var href = protocol + (protocol && url.slashes ? '//' : '');
    if (url.username) {
      href += url.username + (url.password ? ':' + url.password : '') + '@';
    } else if (url.password) {
      href += ':' + url.password + '@';
    }
    url.href = href + url.host + url.pathname + (url.search || '') + (url.hash || '');
    return url;
  }

  function parseUrl(url) {
    try {
      return nodeUrlParse(url);
    } catch (e) {
      return lenientUrlParse(url);
    }
  }

  host.define({
    decodeBuffer: decodeBuffer,
    encodeString: encodeString,
    encodingExists: encodingExists,
    parseQuery: parseQuery,
    parseUrl: parseUrl
  });
})
