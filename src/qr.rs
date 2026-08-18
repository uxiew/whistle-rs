//! A QR encoder, for the one thing this proxy needs one for.
//!
//! `gui/mobile.md` is a page about typing a proxy address into a phone, and
//! upstream's console shortens that by drawing a QR code for each address the
//! machine answers on: point the camera at the screen, and the phone opens the
//! page that hands it the root certificate. It is the difference between
//! reading four numbers off a screen and not.
//!
//! whistle gets this from `qrcode@1.2.0`. This is the same thing in about four
//! hundred lines, because the alternative was a dependency for one dialog —
//! and because a QR code is checkable: every matrix this produces is compared
//! bit for bit against that package by
//! `tests/differential/qr-bench.js`, over the payloads the console actually
//! draws and a few hundred it never will.
//!
//! **What it does, and only that.** Byte mode, error-correction level **M**,
//! versions 1 to 10 — up to 213 bytes, where the longest thing the console
//! draws is about forty. Anything longer returns `None` and the console shows
//! the link on its own, which is what it did before this existed.
//!
//! Numeric, alphanumeric and Kanji modes are not here, and `qrcode` splits a
//! URL across all of them to save space. What that costs is measured rather
//! than waved away: over the twelve addresses `qr-bench.js` draws, **one** comes
//! out a version larger — `http://192.168.100.200:8899/` is 29×29 here and
//! 25×25 there. Both are read by the same camera at the same distance.
//!
//! The reference throughout is ISO/IEC 18004. Where a constant looks arbitrary
//! it is from a table there, and the table is named.

/// The error-correction level this encoder emits. See the module note.
const EC_LEVEL_BITS: u32 = 0b00;

/// Per version (1-based, index 0 is version 1), at level **M**:
/// `(ec_codewords_per_block, group1_blocks, group1_data, group2_blocks, group2_data)`.
///
/// ISO/IEC 18004 table 9 (block structure) and table 13 (error-correction
/// characteristics). Every row is checked by `qr-bench.js`, which encodes a
/// payload that lands on each version and compares the whole matrix.
const BLOCKS_M: [(usize, usize, usize, usize, usize); 10] = [
    (10, 1, 16, 0, 0),  // 1
    (16, 1, 28, 0, 0),  // 2
    (26, 1, 44, 0, 0),  // 3
    (18, 2, 32, 0, 0),  // 4
    (24, 2, 43, 0, 0),  // 5
    (16, 4, 27, 0, 0),  // 6
    (18, 4, 31, 0, 0),  // 7
    (22, 2, 38, 2, 39), // 8
    (22, 3, 36, 2, 37), // 9
    (26, 4, 43, 1, 44), // 10
];

/// Alignment-pattern centre coordinates per version — ISO/IEC 18004 table E.1.
/// Version 1 has none; the rest are the cross product of these, minus the three
/// that would sit on a finder pattern.
const ALIGNMENT: [&[usize]; 10] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
];

/// The highest version this encoder knows, and so the longest payload it takes.
pub const MAX_VERSION: usize = 10;

/// A finished symbol: `size × size` modules, `true` where the module is dark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matrix {
    pub size: usize,
    modules: Vec<bool>,
    /// 1..=[`MAX_VERSION`]. Reported because a caller sizing an image wants it.
    pub version: usize,
}

impl Matrix {
    pub fn get(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.size + x]
    }

    /// Render as an SVG, at `scale` pixels per module plus the four-module
    /// quiet zone the specification requires (§6.3.8 — a symbol without it is
    /// one many scanners will not find).
    ///
    /// One `<path>` for every dark module, because a decoder cares about the
    /// modules and nothing else, and a rect-per-module SVG of a version-3
    /// symbol is under 8 KB.
    pub fn to_svg(&self, scale: usize) -> String {
        let quiet = 4;
        let side = (self.size + quiet * 2) * scale;
        let mut path = String::new();
        for y in 0..self.size {
            for x in 0..self.size {
                if self.get(x, y) {
                    let (px, py) = ((x + quiet) * scale, (y + quiet) * scale);
                    path.push_str(&format!("M{px} {py}h{scale}v{scale}h-{scale}z"));
                }
            }
        }
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{side}\" height=\"{side}\" \
             viewBox=\"0 0 {side} {side}\" shape-rendering=\"crispEdges\">\
             <rect width=\"{side}\" height=\"{side}\" fill=\"#fff\"/>\
             <path fill=\"#000\" d=\"{path}\"/></svg>"
        )
    }
}

/// Encode `text` as a QR symbol, or `None` if it does not fit in
/// [`MAX_VERSION`] at level M.
///
/// The bytes are taken as they are — UTF-8 for a Rust string, which is what a
/// phone camera will read back.
pub fn encode(text: &str) -> Option<Matrix> {
    let data = text.as_bytes();
    let version = smallest_version(data.len())?;
    let (ec_per_block, g1_blocks, g1_data, g2_blocks, g2_data) = BLOCKS_M[version - 1];
    let total_data = g1_blocks * g1_data + g2_blocks * g2_data;

    // ── the bit stream: mode, length, payload, terminator, padding ──
    let mut bits = BitBuffer::default();
    bits.push(0b0100, 4); // byte mode
    // The character-count indicator is 8 bits for versions 1-9 in byte mode and
    // 16 from version 10 (ISO/IEC 18004 table 3). Getting this wrong shows up
    // only at version 10, which is why `qr-bench.js` reaches one.
    bits.push(data.len() as u32, if version <= 9 { 8 } else { 16 });
    for b in data {
        bits.push(*b as u32, 8);
    }
    // Terminator: up to four zero bits, then pad to a byte boundary.
    let capacity = total_data * 8;
    let terminator = 4.min(capacity - bits.len());
    bits.push(0, terminator);
    while bits.len() % 8 != 0 {
        bits.push(0, 1);
    }
    // Pad bytes alternate 0xEC / 0x11 (§7.4.10).
    let mut codewords = bits.into_bytes();
    for pad in [0xECu8, 0x11].iter().cycle() {
        if codewords.len() >= total_data {
            break;
        }
        codewords.push(*pad);
    }

    // ── split into blocks, compute error correction for each ──
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut ec_blocks: Vec<Vec<u8>> = Vec::new();
    let mut at = 0;
    for (count, size) in [(g1_blocks, g1_data), (g2_blocks, g2_data)] {
        for _ in 0..count {
            let block = codewords[at..at + size].to_vec();
            at += size;
            ec_blocks.push(reed_solomon(&block, ec_per_block));
            blocks.push(block);
        }
    }

    // ── interleave: one codeword from each block in turn (§7.6) ──
    let mut stream: Vec<u8> = Vec::new();
    let widest = blocks.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..widest {
        for block in &blocks {
            if let Some(b) = block.get(i) {
                stream.push(*b);
            }
        }
    }
    for i in 0..ec_per_block {
        for block in &ec_blocks {
            stream.push(block[i]);
        }
    }

    // ── lay it out, mask it, stamp the format information ──
    let size = 17 + 4 * version;
    let mut canvas = Canvas::new(size, version);
    canvas.place_function_patterns();
    // Before the mask is chosen, not after: the version blocks are thirty-six
    // modules of the symbol, and every penalty rule counts them. Upstream
    // writes them at the same point, above `setupData`
    // (`qrcode/lib/core/qrcode.js:440-442`). Writing them afterwards picked a
    // different mask for exactly the payloads that reach version 7, which is
    // one case in `qr-bench.js` and would have been none in a bench that only
    // drew URLs.
    if version >= 7 {
        canvas.place_version();
    }
    canvas.place_data(&stream);
    let mask = canvas.pick_mask();
    canvas.apply_mask(mask);
    canvas.place_format(mask);
    Some(Matrix {
        size,
        modules: canvas.dark,
        version,
    })
}

/// The smallest version whose level-M byte capacity holds `len` bytes.
fn smallest_version(len: usize) -> Option<usize> {
    (1..=MAX_VERSION).find(|&v| {
        let (_, g1b, g1d, g2b, g2d) = BLOCKS_M[v - 1];
        let data_bits = (g1b * g1d + g2b * g2d) * 8;
        let overhead = 4 + if v <= 9 { 8 } else { 16 };
        len * 8 + overhead <= data_bits
    })
}

// ── the bit stream ─────────────────────────────────────────────────────────

#[derive(Default)]
struct BitBuffer {
    bytes: Vec<u8>,
    bits: usize,
}

impl BitBuffer {
    fn push(&mut self, value: u32, width: usize) {
        for i in (0..width).rev() {
            let bit = (value >> i) & 1 == 1;
            if self.bits.is_multiple_of(8) {
                self.bytes.push(0);
            }
            if bit {
                let at = self.bits / 8;
                self.bytes[at] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
    }

    fn len(&self) -> usize {
        self.bits
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

// ── Reed–Solomon over GF(256) ──────────────────────────────────────────────

/// Log and antilog tables for GF(256) with the QR primitive polynomial
/// `x^8 + x^4 + x^3 + x^2 + 1` (0x11D) and generator 2 (§7.5.2).
fn gf_tables() -> &'static ([u8; 256], [u8; 512]) {
    use std::sync::OnceLock;
    static TABLES: OnceLock<([u8; 256], [u8; 512])> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut log = [0u8; 256];
        let mut exp = [0u8; 512];
        let mut x: u16 = 1;
        for (i, slot) in exp.iter_mut().take(255).enumerate() {
            *slot = x as u8;
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11D;
            }
        }
        // The second half repeats the first, so a product of two logs indexes
        // it without a modulo.
        exp.copy_within(0..257, 255);
        (log, exp)
    })
}

fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (log, exp) = gf_tables();
    exp[log[a as usize] as usize + log[b as usize] as usize]
}

/// The generator polynomial for `n` error-correction codewords:
/// `(x - α⁰)(x - α¹)…(x - αⁿ⁻¹)`.
fn generator_poly(n: usize) -> Vec<u8> {
    let (_, exp) = gf_tables();
    let mut poly = vec![1u8];
    for root in exp.iter().take(n) {
        // Multiply by `(x - α^i)`, which in GF(2) is `(x + α^i)`.
        let mut next = vec![0u8; poly.len() + 1];
        for (j, c) in poly.iter().enumerate() {
            next[j] ^= *c;
            next[j + 1] ^= gf_mul(*c, *root);
        }
        poly = next;
    }
    poly
}

/// The `n` error-correction codewords for one block: the remainder of the
/// message polynomial divided by the generator.
fn reed_solomon(data: &[u8], n: usize) -> Vec<u8> {
    let poly = generator_poly(n);
    let mut remainder = vec![0u8; data.len() + n];
    remainder[..data.len()].copy_from_slice(data);
    for i in 0..data.len() {
        let lead = remainder[i];
        if lead == 0 {
            continue;
        }
        for (j, g) in poly.iter().enumerate() {
            remainder[i + j] ^= gf_mul(*g, lead);
        }
    }
    remainder[data.len()..].to_vec()
}

// ── the matrix ─────────────────────────────────────────────────────────────

struct Canvas {
    size: usize,
    version: usize,
    dark: Vec<bool>,
    /// A module belonging to a function pattern, which data skips and the mask
    /// does not touch.
    reserved: Vec<bool>,
}

impl Canvas {
    fn new(size: usize, version: usize) -> Self {
        Canvas {
            size,
            version,
            dark: vec![false; size * size],
            reserved: vec![false; size * size],
        }
    }

    fn set(&mut self, x: usize, y: usize, dark: bool, reserved: bool) {
        self.dark[y * self.size + x] = dark;
        self.reserved[y * self.size + x] = reserved;
    }

    fn is_dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.size + x]
    }

    fn is_reserved(&self, x: usize, y: usize) -> bool {
        self.reserved[y * self.size + x]
    }

    /// Finders, separators, timing, alignment, the dark module, and the areas
    /// the format and version information will occupy (§6.3).
    fn place_function_patterns(&mut self) {
        let n = self.size;
        // Three finder patterns, each with its separator.
        for (ox, oy) in [(0, 0), (n - 7, 0), (0, n - 7)] {
            for dy in 0..7 {
                for dx in 0..7 {
                    let edge = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                    let core = (2..=4).contains(&dx) && (2..=4).contains(&dy);
                    self.set(ox + dx, oy + dy, edge || core, true);
                }
            }
        }
        // The one-module light separator around each finder: the row and column
        // that face the rest of the symbol.
        //
        // Written out per corner rather than derived from the finder's origin.
        // The derived version was wrong by a handful of modules, and the way it
        // was wrong is instructive: data still fitted, the symbol still had
        // three finders, and every bit after the mistake was **shifted** — so it
        // looked like a QR code and decoded to nothing. `qr-bench.js` found it
        // by reading the codewords back out.
        for i in 0..8 {
            // top-left
            self.set(i, 7, false, true);
            self.set(7, i, false, true);
            // top-right
            self.set(n - 1 - i, 7, false, true);
            self.set(n - 8, i, false, true);
            // bottom-left
            self.set(i, n - 8, false, true);
            self.set(7, n - 1 - i, false, true);
        }
        // Timing patterns: alternating modules along row 6 and column 6.
        for i in 8..n - 8 {
            let dark = i % 2 == 0;
            self.set(i, 6, dark, true);
            self.set(6, i, dark, true);
        }
        // Alignment patterns, at every crossing except the three that would
        // land on a finder.
        let centres = ALIGNMENT[self.version - 1];
        for &cy in centres {
            for &cx in centres {
                // A centre sits on a finder when it falls inside one of the
                // three corners the finders occupy — top-left, bottom-left,
                // top-right. There is no finder in the fourth corner, which is
                // why an alignment pattern lives there.
                let (left, top) = (cx < 8, cy < 8);
                let on_finder = (left && (top || cy >= n - 8)) || (top && cx >= n - 8);
                if on_finder {
                    continue;
                }
                for dy in 0..5isize {
                    for dx in 0..5isize {
                        let edge = dx == 0 || dx == 4 || dy == 0 || dy == 4;
                        let centre = dx == 2 && dy == 2;
                        self.set(
                            (cx as isize + dx - 2) as usize,
                            (cy as isize + dy - 2) as usize,
                            edge || centre,
                            true,
                        );
                    }
                }
            }
        }
        // The dark module, which is always dark and never anything else.
        self.set(8, n - 8, true, true);
        // Reserve the format-information strips: nine modules around the
        // top-left finder, eight along the top-right, and **seven** down the
        // bottom-left — seven, not eight, because the eighth is the dark module
        // set just above. Reserving it as light was the first bug this file's
        // finder test caught.
        for i in 0..9 {
            if !self.is_reserved(i, 8) {
                self.set(i, 8, false, true);
            }
            if !self.is_reserved(8, i) {
                self.set(8, i, false, true);
            }
        }
        for i in 0..8 {
            self.set(n - 1 - i, 8, false, true);
        }
        for i in 0..7 {
            self.set(8, n - 1 - i, false, true);
        }
        // And the version-information blocks, from version 7.
        if self.version >= 7 {
            for i in 0..6 {
                for j in 0..3 {
                    self.set(n - 11 + j, i, false, true);
                    self.set(i, n - 11 + j, false, true);
                }
            }
        }
    }

    /// Walk the symbol in the two-module-wide zigzag from the bottom right,
    /// skipping the timing column, and drop one bit in each free module
    /// (§7.7.3).
    fn place_data(&mut self, stream: &[u8]) {
        let n = self.size;
        let mut bit = 0usize;
        let mut upward = true;
        let mut col = n as isize - 1;
        while col >= 0 {
            // Column 6 is the vertical timing pattern; the pairs step over it.
            if col == 6 {
                col -= 1;
                continue;
            }
            for i in 0..n {
                let y = if upward { n - 1 - i } else { i };
                for dx in 0..2 {
                    let x = (col - dx) as usize;
                    if self.is_reserved(x, y) {
                        continue;
                    }
                    let dark = stream
                        .get(bit / 8)
                        .is_some_and(|byte| byte & (0x80 >> (bit % 8)) != 0);
                    self.dark[y * self.size + x] = dark;
                    bit += 1;
                }
            }
            upward = !upward;
            col -= 2;
        }
    }

    /// Is this module inverted by mask pattern `m`? ISO/IEC 18004 table 10.
    fn mask_at(m: u8, x: usize, y: usize) -> bool {
        let (i, j) = (y, x); // the specification's row/column names
        match m {
            0 => (i + j) % 2 == 0,
            1 => i % 2 == 0,
            2 => j % 3 == 0,
            3 => (i + j) % 3 == 0,
            4 => (i / 2 + j / 3) % 2 == 0,
            5 => (i * j) % 2 + (i * j) % 3 == 0,
            6 => ((i * j) % 2 + (i * j) % 3) % 2 == 0,
            _ => ((i + j) % 2 + (i * j) % 3) % 2 == 0,
        }
    }

    fn apply_mask(&mut self, m: u8) {
        for y in 0..self.size {
            for x in 0..self.size {
                if !self.is_reserved(x, y) && Self::mask_at(m, x, y) {
                    self.dark[y * self.size + x] ^= true;
                }
            }
        }
    }

    /// Try all eight masks and keep the one with the lowest penalty (§7.8.3).
    ///
    /// The trial masks and un-masks in place rather than cloning the canvas:
    /// masking is its own inverse.
    ///
    /// **The format information for the candidate is written before it is
    /// scored.** Those thirty-one modules are part of the symbol, and the
    /// penalty rules count runs, blocks and the dark ratio over all of it —
    /// so scoring with the format area left blank scores a symbol that will
    /// never exist. Upstream does the same, and says why in one line
    /// (`getBestMask`, `qrcode/lib/core/mask-pattern.js:208-231`, which calls
    /// `setupFormatInfo(p)` before each trial). Leaving it out picked a
    /// different mask for a third of the payloads `qr-bench.js` tries: a
    /// readable symbol every time, and not the one whistle draws.
    fn pick_mask(&mut self) -> u8 {
        let mut best = (0u8, u32::MAX);
        for m in 0..8 {
            self.place_format(m);
            self.apply_mask(m);
            let score = self.penalty();
            self.apply_mask(m);
            if score < best.1 {
                best = (m, score);
            }
        }
        best.0
    }

    /// The four penalty rules (§7.8.3.1), which together prefer a symbol that
    /// does not look like its own function patterns.
    fn penalty(&self) -> u32 {
        let n = self.size;
        let mut score = 0u32;

        // 1. Runs of five or more same-coloured modules, in each direction.
        for line in 0..n {
            for horizontal in [true, false] {
                let (mut run, mut prev) = (0u32, false);
                for i in 0..n {
                    let dark = match horizontal {
                        true => self.is_dark(i, line),
                        false => self.is_dark(line, i),
                    };
                    if i > 0 && dark == prev {
                        run += 1;
                        if run == 5 {
                            score += 3;
                        } else if run > 5 {
                            score += 1;
                        }
                    } else {
                        run = 1;
                    }
                    prev = dark;
                }
            }
        }

        // 2. Every 2×2 block of one colour.
        for y in 0..n - 1 {
            for x in 0..n - 1 {
                let c = self.is_dark(x, y);
                if c == self.is_dark(x + 1, y)
                    && c == self.is_dark(x, y + 1)
                    && c == self.is_dark(x + 1, y + 1)
                {
                    score += 3;
                }
            }
        }

        // 3. The finder-like sequence 1:1:3:1:1 with four light modules before
        //    or after it — the thing a scanner hunts for, appearing where it
        //    should not.
        //
        //    An eleven-module sliding window, which is how the specification
        //    states it and how `qrcode@1.2.0` implements it: `10111010000` and
        //    `00001011101`. The first version of this walked the seven-module
        //    core and then looked outward, and scored a different mask for the
        //    same symbol — a symbol that still scanned, and still was not the
        //    one whistle draws.
        const AFTER: u32 = 0b101_1101_0000;
        const BEFORE: u32 = 0b000_0101_1101;
        for line in 0..n {
            let (mut row_bits, mut col_bits) = (0u32, 0u32);
            for i in 0..n {
                row_bits = ((row_bits << 1) & 0x7FF) | self.is_dark(i, line) as u32;
                col_bits = ((col_bits << 1) & 0x7FF) | self.is_dark(line, i) as u32;
                if i >= 10 {
                    if row_bits == AFTER || row_bits == BEFORE {
                        score += 40;
                    }
                    if col_bits == AFTER || col_bits == BEFORE {
                        score += 40;
                    }
                }
            }
        }

        // 4. How far the proportion of dark modules is from half, in steps of
        //    five per cent. The rounding is the specification's:
        //    `|ceil(percent / 5) - 10|`, which is not the same as measuring the
        //    distance from fifty and dividing — they disagree at the boundaries,
        //    and disagreeing there picks a different mask.
        let dark = self.dark.iter().filter(|d| **d).count();
        let percent = dark as f64 * 100.0 / (n * n) as f64;
        let k = ((percent / 5.0).ceil() - 10.0).abs();
        score += k as u32 * 10;

        score
    }

    /// The 15-bit format information — EC level and mask — written twice, with
    /// its BCH(15,5) check bits and the fixed XOR mask (§7.9).
    fn place_format(&mut self, mask: u8) {
        let data = (EC_LEVEL_BITS << 3) | mask as u32;
        let mut bch = data << 10;
        while bits_len(bch) >= 11 {
            bch ^= 0b101_0011_0111 << (bits_len(bch) - 11);
        }
        let format = ((data << 10) | bch) ^ 0b101_0100_0001_0010;

        let n = self.size;
        for i in 0..15 {
            let dark = (format >> i) & 1 == 1;
            // Copy one, around the top-left finder, stepping over the timing row
            // and column at index 6.
            let (x1, y1) = match i {
                0..=5 => (8, i),
                6 => (8, 7),
                7 => (8, 8),
                8 => (7, 8),
                _ => (14 - i, 8),
            };
            self.dark[y1 * n + x1] = dark;
            // Copy two, split between the other two finders.
            let (x2, y2) = match i {
                0..=7 => (n - 1 - i, 8),
                _ => (8, n - 15 + i),
            };
            self.dark[y2 * n + x2] = dark;
        }
    }

    /// The 18-bit version information, twice, for version 7 and up (§7.10).
    fn place_version(&mut self) {
        let mut bch = (self.version as u32) << 12;
        while bits_len(bch) >= 13 {
            bch ^= 0b1_1111_0010_0101 << (bits_len(bch) - 13);
        }
        let info = ((self.version as u32) << 12) | bch;
        let n = self.size;
        for i in 0..18 {
            let dark = (info >> i) & 1 == 1;
            let (row, col) = (i / 3, i % 3);
            self.dark[row * n + (n - 11 + col)] = dark;
            self.dark[(n - 11 + col) * n + row] = dark;
        }
    }
}

/// Position of the highest set bit, counted from one — the length of `v` in
/// bits. Used by both BCH divisions above.
fn bits_len(v: u32) -> u32 {
    32 - v.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two ends of what this encoder claims, so a change to the capacity
    /// arithmetic cannot pass quietly.
    #[test]
    fn it_takes_what_it_says_it_takes() {
        assert!(encode("").is_some(), "an empty payload still makes a symbol");
        // 213 bytes is the level-M byte capacity of version 10.
        assert_eq!(encode(&"a".repeat(213)).map(|m| m.version), Some(10));
        assert!(encode(&"a".repeat(214)).is_none(), "and one more does not fit");
    }

    /// Each version is one module wider than the last by four, and the payload
    /// picks the smallest that holds it.
    #[test]
    fn the_version_grows_with_the_payload() {
        for (len, version, size) in [(14, 1, 21), (15, 2, 25), (26, 2, 25), (27, 3, 29)] {
            let m = encode(&"a".repeat(len)).expect("fits");
            assert_eq!((m.version, m.size), (version, size), "{len} bytes");
        }
    }

    /// The three finder patterns, which are the same in every symbol ever made
    /// and are what a scanner looks for first.
    #[test]
    fn the_finders_are_where_a_scanner_expects_them() {
        let m = encode("http://192.168.1.5:8899/rootCA.crt").expect("fits");
        for (ox, oy) in [(0, 0), (m.size - 7, 0), (0, m.size - 7)] {
            for dy in 0..7 {
                for dx in 0..7 {
                    let expected = dx == 0
                        || dx == 6
                        || dy == 0
                        || dy == 6
                        || ((2..=4).contains(&dx) && (2..=4).contains(&dy));
                    assert_eq!(m.get(ox + dx, oy + dy), expected, "{dx},{dy} of {ox},{oy}");
                }
            }
        }
        // The dark module, which the specification fixes.
        assert!(m.get(8, m.size - 8));
    }

    /// A field's own arithmetic: `α^i · α^(255-i)` is one, and the log tables
    /// are inverses.
    #[test]
    fn the_field_multiplies() {
        let (log, exp) = gf_tables();
        for a in 1..=255u8 {
            assert_eq!(exp[log[a as usize] as usize], a, "log/exp disagree at {a}");
        }
        assert_eq!(gf_mul(0, 7), 0);
        assert_eq!(gf_mul(1, 7), 7);
        // The reduction itself: `0x80 · 2` overflows into bit 8 and comes back
        // as the primitive polynomial's low byte, `0x11D & 0xFF`.
        assert_eq!(gf_mul(0x80, 2), 0x1D);
        // A field is commutative and associative, and this one is checked
        // against `qrcode@1.2.0` end to end by `qr-bench.js`.
        for a in [1u8, 3, 0x53, 0x9F, 0xFF] {
            for b in [2u8, 7, 0x11, 0xC4, 0xFE] {
                assert_eq!(gf_mul(a, b), gf_mul(b, a), "{a}·{b}");
                assert_eq!(
                    gf_mul(gf_mul(a, b), 5),
                    gf_mul(a, gf_mul(b, 5)),
                    "({a}·{b})·5"
                );
            }
        }
    }

    /// The generator polynomial for ten error-correction codewords, which the
    /// specification prints in full (annex A, table A.1) as
    /// α^0 … in exponent form — here as the coefficients they stand for.
    #[test]
    fn the_generator_matches_the_published_one() {
        let (_, exp) = gf_tables();
        let expected: Vec<u8> = [0u32, 251, 67, 46, 61, 118, 70, 64, 94, 32, 45]
            .iter()
            .map(|e| exp[*e as usize])
            .collect();
        assert_eq!(generator_poly(10), expected);
    }

    /// The SVG carries the quiet zone, without which many scanners never find
    /// the symbol at all.
    #[test]
    fn the_svg_leaves_room_around_it() {
        let m = encode("hello").expect("fits");
        let svg = m.to_svg(4);
        let side = (m.size + 8) * 4;
        assert!(svg.contains(&format!("width=\"{side}\"")), "{svg:.120}");
        assert!(svg.starts_with("<svg xmlns="));
        assert!(svg.contains("<path fill=\"#000\""));
    }

    /// Every mask is tried and the best is kept, so at least one of the eight
    /// must be reachable for some payload — a picker stuck on zero would still
    /// produce readable symbols and would be a real defect.
    #[test]
    fn more_than_one_mask_gets_chosen() {
        let masks: std::collections::HashSet<u8> = (0..60)
            .filter_map(|i| {
                let text = format!("http://192.168.{i}.{}:8899/rootCA.crt", i * 3 % 200);
                let m = encode(&text)?;
                // Read the mask back out of the format information: the three
                // low bits of the first copy, un-XORed.
                let mut format = 0u32;
                for i in 0..15u32 {
                    let (x, y) = match i {
                        0..=5 => (8, i as usize),
                        6 => (8, 7),
                        7 => (8, 8),
                        8 => (7, 8),
                        _ => (14 - i as usize, 8),
                    };
                    if m.get(x, y) {
                        format |= 1 << i;
                    }
                }
                Some(((format ^ 0b101_0100_0001_0010) >> 10 & 0b111) as u8)
            })
            .collect();
        assert!(masks.len() > 1, "only ever picked {masks:?}");
    }
}
