//! Simple scanner for non-overlapping, known references of Nix store paths in a
//! given string.
//!
//! This is used for determining build references (see
//! //snix/eval/docs/build-references.md for more details).
//!
//! The scanner itself is using the Wu-Manber string-matching algorithm, using
//! our fork of the `wu-mamber` crate.
use pin_project::pin_project;
use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Poll, ready};
use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};
use wu_manber::TwoByteWM;

/// A searcher that incapsulates the candidates and the Wu-Manber searcher.
/// This is separate from the scanner because we need to look for the same
/// pattern in multiple outputs and don't want to pay the price of constructing
/// the searcher for each build output.
pub struct ReferencePatternInner<P> {
    candidates: Vec<P>,
    longest_candidate: usize,
    // FUTUREWORK: Support overlapping patterns to be compatible with cpp Nix
    searcher: Option<TwoByteWM>,
}

#[derive(Clone)]
pub struct ReferencePattern<P> {
    inner: Arc<ReferencePatternInner<P>>,
}

impl<P> ReferencePattern<P> {
    pub fn candidates(&self) -> &[P] {
        &self.inner.candidates
    }

    pub fn longest_candidate(&self) -> usize {
        self.inner.longest_candidate
    }
}

impl<P: AsRef<[u8]>> ReferencePattern<P> {
    /// Construct a new `ReferencePattern` that knows how to scan for the given
    /// candidates.
    pub fn new(candidates: Vec<P>) -> Self {
        let searcher = if candidates.is_empty() {
            None
        } else {
            Some(TwoByteWM::new(&candidates))
        };
        let longest_candidate = candidates.iter().fold(0, |v, c| v.max(c.as_ref().len()));

        ReferencePattern {
            inner: Arc::new(ReferencePatternInner {
                searcher,
                candidates,
                longest_candidate,
            }),
        }
    }
}

impl<P> From<Vec<P>> for ReferencePattern<P>
where
    P: AsRef<[u8]>,
{
    fn from(candidates: Vec<P>) -> Self {
        Self::new(candidates)
    }
}

/// Represents a "primed" reference scanner with an automaton that knows the set
/// of bytes patterns to scan for.
pub struct ReferenceScanner<P> {
    pattern: ReferencePattern<P>,
    matches: Vec<AtomicBool>,
}

impl<P: AsRef<[u8]>> ReferenceScanner<P> {
    /// Construct a new `ReferenceScanner` that knows how to scan for the given
    /// candidate bytes patterns.
    pub fn new<IP: Into<ReferencePattern<P>>>(pattern: IP) -> Self {
        let pattern = pattern.into();
        let mut matches = Vec::new();
        for _ in 0..pattern.candidates().len() {
            matches.push(AtomicBool::new(false));
        }
        ReferenceScanner { pattern, matches }
    }

    /// Scan the given buffer for all non-overlapping matches and collect them
    /// in the scanner.
    pub fn scan<S: AsRef<[u8]>>(&self, haystack: S) {
        if haystack.as_ref().len() < self.pattern.longest_candidate() {
            return;
        }

        if let Some(searcher) = &self.pattern.inner.searcher {
            for m in searcher.find(haystack) {
                self.matches[m.pat_idx].store(true, Ordering::Release);
            }
        }
    }

    pub fn pattern(&self) -> &ReferencePattern<P> {
        &self.pattern
    }

    pub fn matches(&self) -> Vec<bool> {
        self.matches
            .iter()
            .map(|m| m.load(Ordering::Acquire))
            .collect()
    }

    pub fn candidate_matches(&self) -> impl Iterator<Item = &P> {
        let candidates = self.pattern.candidates();
        self.matches.iter().enumerate().filter_map(|(idx, found)| {
            if found.load(Ordering::Acquire) {
                Some(&candidates[idx])
            } else {
                None
            }
        })
    }
}

impl<P: Clone + Ord + AsRef<[u8]>> ReferenceScanner<P> {
    /// Finalise the reference scanner and return the resulting matches.
    pub fn finalise(self) -> BTreeSet<P> {
        self.candidate_matches().cloned().collect()
    }
}

const DEFAULT_BUF_SIZE: usize = 8 * 1024;

#[pin_project]
pub struct ReferenceReader<'a, P, R> {
    scanner: &'a ReferenceScanner<P>,
    buffer: Vec<u8>,
    consumed: usize,
    #[pin]
    reader: R,
}

impl<'a, P, R> ReferenceReader<'a, P, R>
where
    P: AsRef<[u8]>,
{
    pub fn new(scanner: &'a ReferenceScanner<P>, reader: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, scanner, reader)
    }

    pub fn with_capacity(capacity: usize, scanner: &'a ReferenceScanner<P>, reader: R) -> Self {
        // If capacity is not at least as long as longest_candidate we can't do a scan
        let capacity = capacity.max(scanner.pattern().longest_candidate());
        ReferenceReader {
            scanner,
            buffer: Vec::with_capacity(capacity),
            consumed: 0,
            reader,
        }
    }
}

impl<P, R> AsyncRead for ReferenceReader<'_, P, R>
where
    R: AsyncRead,
    P: AsRef<[u8]>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let internal_buf = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amt = buf.remaining().min(internal_buf.len());
        buf.put_slice(&internal_buf[..amt]);
        self.consume(amt);
        Poll::Ready(Ok(()))
    }
}

impl<P, R> AsyncBufRead for ReferenceReader<'_, P, R>
where
    R: AsyncRead,
    P: AsRef<[u8]>,
{
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        #[allow(clippy::manual_saturating_arithmetic)] // for clarity
        let overlap = self
            .scanner
            .pattern
            .longest_candidate()
            .checked_sub(1)
            // If this overflows (longest_candidate = 0), that means there are no needles,
            // so there is no need to have any overlap
            .unwrap_or(0);
        let mut this = self.project();
        // Still data in buffer
        if *this.consumed < this.buffer.len() {
            return Poll::Ready(Ok(&this.buffer[*this.consumed..]));
        }
        // We need to copy last `overlap` bytes to front to deal with references that overlap reads
        if *this.consumed > overlap {
            let start = this.buffer.len() - overlap;
            this.buffer.copy_within(start.., 0);
            this.buffer.truncate(overlap);
            *this.consumed = overlap;
        }
        // Read at least until self.buffer.len() > overlap so we can do one scan
        loop {
            let filled = {
                let mut buf = ReadBuf::uninit(this.buffer.spare_capacity_mut());
                ready!(this.reader.as_mut().poll_read(cx, &mut buf))?;
                buf.filled().len()
            };
            // SAFETY: We just read `filled` amount of data above
            unsafe {
                this.buffer.set_len(filled + this.buffer.len());
            }
            if filled == 0 || this.buffer.len() > overlap {
                break;
            }
        }

        #[allow(clippy::needless_borrows_for_generic_args)] // misfiring lint (breaks code below)
        this.scanner.scan(&this.buffer);

        Poll::Ready(Ok(&this.buffer[*this.consumed..]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        debug_assert!(self.consumed + amt <= self.buffer.len());
        let this = self.project();
        *this.consumed += amt;
    }
}

/// One entry in a [`RewritePattern`]: the needle to look for, the bytes to
/// write in its place, and whether each occurrence's absolute byte offset in
/// the scanned stream should be recorded.
///
/// Recorded positions mirror Nix's `HashModuloSink` (see
/// `nix/src/libstore/references.cc`), which folds self-reference positions
/// into the final hash to prevent collisions between a NAR carrying the
/// self-reference and one where it's already been zeroed.
#[derive(Clone, Debug)]
pub struct RewriteEntry<P> {
    pub needle: P,
    pub replacement: Vec<u8>,
    pub record_positions: bool,
}

pub struct RewritePatternInner<P> {
    entries: Vec<RewriteEntry<P>>,
    longest_candidate: usize,
    // FUTUREWORK: Support overlapping patterns to be compatible with cpp Nix
    searcher: Option<TwoByteWM>,
}

#[derive(Clone)]
pub struct RewritePattern<P> {
    inner: Arc<RewritePatternInner<P>>,
}

impl<P: AsRef<[u8]>> RewritePattern<P> {
    /// Build a pattern from a list of entries. Each entry's replacement length
    /// must equal its needle length so the rewrite can happen in place inside
    /// the streaming buffer without disturbing later offsets. A mismatch
    /// panics (internal-caller invariant).
    ///
    /// Length-equality is not a property of arbitrary hashes — it falls out of
    /// Nix's uniform store-path encoding (compress_hash → 160 bits → 32
    /// base32 chars), which is the encoding `nix-compat`'s `build_ca_path`
    /// produces. As long as callers rewrite Nix store-path hashes to other
    /// Nix store-path hashes (the only use case today), the invariant holds
    /// naturally. Dropping it later — e.g. to use a non-Nix-compatible
    /// canonical form for content addresses — would require turning this into
    /// a copying rewriter with separate input/output cursors and reworking
    /// the streaming overlap logic accordingly.
    pub fn new(entries: Vec<RewriteEntry<P>>) -> Self {
        for e in &entries {
            assert_eq!(
                e.replacement.len(),
                e.needle.as_ref().len(),
                "rewrite replacement length must match needle length"
            );
        }
        let longest_candidate = entries
            .iter()
            .fold(0, |v, e| v.max(e.needle.as_ref().len()));
        let searcher = if entries.is_empty() {
            None
        } else {
            Some(TwoByteWM::new(entries.iter().map(|e| e.needle.as_ref())))
        };
        RewritePattern {
            inner: Arc::new(RewritePatternInner {
                entries,
                longest_candidate,
                searcher,
            }),
        }
    }

    pub fn entries(&self) -> &[RewriteEntry<P>] {
        &self.inner.entries
    }

    pub fn longest_candidate(&self) -> usize {
        self.inner.longest_candidate
    }
}

impl<P> From<Vec<RewriteEntry<P>>> for RewritePattern<P>
where
    P: AsRef<[u8]>,
{
    fn from(entries: Vec<RewriteEntry<P>>) -> Self {
        Self::new(entries)
    }
}

/// Scan `haystack` for non-overlapping matches and overwrite each one in place
/// with its replacement bytes. Returns the absolute byte offsets
/// (`absolute_base_offset + match_offset_in_haystack`) for entries with
/// `record_positions: true`.
///
/// One-shot variant of [`RewritingReferenceReader`] for already-loaded bytes
/// (e.g. symlink targets).
pub fn rewrite_in_place<P: AsRef<[u8]>>(
    pattern: &RewritePattern<P>,
    haystack: &mut [u8],
    absolute_base_offset: u64,
) -> BTreeSet<u64> {
    let mut positions = BTreeSet::new();
    rewrite_buffer_in_place(&pattern.inner, haystack, absolute_base_offset, &mut positions);
    positions
}

fn rewrite_buffer_in_place<P: AsRef<[u8]>>(
    pattern: &RewritePatternInner<P>,
    haystack: &mut [u8],
    absolute_base_offset: u64,
    positions: &mut BTreeSet<u64>,
) {
    if haystack.len() < pattern.longest_candidate {
        return;
    }
    let Some(searcher) = &pattern.searcher else {
        return;
    };
    // wu-manber's find borrows the haystack immutably; collect first, mutate
    // afterwards. Matches are non-overlapping by construction.
    let matches: Vec<(usize, usize)> = searcher
        .find(&*haystack)
        .map(|m| (m.pat_idx, m.start))
        .collect();
    for (pat_idx, start) in matches {
        let entry = &pattern.entries[pat_idx];
        let needle_len = entry.needle.as_ref().len();
        haystack[start..start + needle_len].copy_from_slice(&entry.replacement);
        if entry.record_positions {
            positions.insert(absolute_base_offset + start as u64);
        }
    }
}

/// Streaming variant of [`rewrite_in_place`]: an [`AsyncRead`] wrapper that
/// rewrites matches in flight and records self-reference positions.
///
/// Parallel to [`ReferenceReader`]; the difference is that the bytes produced
/// downstream are the rewritten bytes, and entries flagged with
/// `record_positions` accumulate into the reader.
///
/// To make sure a needle straddling two reads is rewritten before either half
/// is delivered to the consumer, the reader holds back the trailing
/// `longest_candidate - 1` bytes of each fill until the next read or EOF,
/// mirroring Nix's `RewritingSink` in `references.cc`.
#[pin_project]
pub struct RewritingReferenceReader<'a, P, R> {
    pattern: &'a RewritePattern<P>,
    buffer: Vec<u8>,
    consumed: usize,
    /// Absolute byte offset of `buffer[0]` within the stream so far. Bumped
    /// each time the buffer is trimmed during the overlap copy.
    buffer_abs_start: u64,
    /// Set once the underlying reader returns 0 bytes; lets the final fill
    /// emit the held-back tail.
    eof: bool,
    positions: BTreeSet<u64>,
    #[pin]
    reader: R,
}

impl<'a, P, R> RewritingReferenceReader<'a, P, R>
where
    P: AsRef<[u8]>,
{
    pub fn new(pattern: &'a RewritePattern<P>, reader: R) -> Self {
        Self::with_capacity(DEFAULT_BUF_SIZE, pattern, reader)
    }

    pub fn with_capacity(capacity: usize, pattern: &'a RewritePattern<P>, reader: R) -> Self {
        // Need at least longest_candidate bytes to scan a single needle, plus
        // one byte of headroom so we always have something to emit per cycle.
        let capacity = capacity.max(pattern.longest_candidate().saturating_add(1));
        RewritingReferenceReader {
            pattern,
            buffer: Vec::with_capacity(capacity),
            consumed: 0,
            buffer_abs_start: 0,
            eof: false,
            positions: BTreeSet::new(),
            reader,
        }
    }

    /// Recorded absolute byte offsets so far. Stable to call mid-stream;
    /// usually consumed after the underlying reader is drained.
    pub fn positions(&self) -> &BTreeSet<u64> {
        &self.positions
    }

    /// Take the recorded positions out, draining the reader's set.
    pub fn take_positions(&mut self) -> BTreeSet<u64> {
        std::mem::take(&mut self.positions)
    }
}

impl<P, R> AsyncRead for RewritingReferenceReader<'_, P, R>
where
    R: AsyncRead,
    P: AsRef<[u8]>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let internal_buf = ready!(self.as_mut().poll_fill_buf(cx))?;
        let amt = buf.remaining().min(internal_buf.len());
        buf.put_slice(&internal_buf[..amt]);
        self.consume(amt);
        Poll::Ready(Ok(()))
    }
}

impl<P, R> AsyncBufRead for RewritingReferenceReader<'_, P, R>
where
    R: AsyncRead,
    P: AsRef<[u8]>,
{
    fn poll_fill_buf(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        #[allow(clippy::manual_saturating_arithmetic)] // for clarity
        let overlap = self
            .pattern
            .longest_candidate()
            .checked_sub(1)
            .unwrap_or(0);
        let mut this = self.project();

        let emit_limit = |buffer_len: usize, eof: bool, overlap: usize| -> usize {
            if eof || overlap == 0 {
                buffer_len
            } else {
                buffer_len.saturating_sub(overlap)
            }
        };

        // Still emittable data in the buffer.
        let limit = emit_limit(this.buffer.len(), *this.eof, overlap);
        if *this.consumed < limit {
            return Poll::Ready(Ok(&this.buffer[*this.consumed..limit]));
        }
        if *this.eof {
            return Poll::Ready(Ok(&[]));
        }

        // Carry the held-back tail to the front so the next scan sees it.
        if *this.consumed > 0 {
            *this.buffer_abs_start += *this.consumed as u64;
            let kept = this.buffer.len() - *this.consumed;
            this.buffer.copy_within(*this.consumed.., 0);
            this.buffer.truncate(kept);
            *this.consumed = 0;
        }

        // Fill until we have more than overlap bytes (or hit EOF).
        loop {
            let filled = {
                let mut buf = ReadBuf::uninit(this.buffer.spare_capacity_mut());
                ready!(this.reader.as_mut().poll_read(cx, &mut buf))?;
                buf.filled().len()
            };
            // SAFETY: We just read `filled` amount of data above
            unsafe {
                this.buffer.set_len(filled + this.buffer.len());
            }
            if filled == 0 {
                *this.eof = true;
                break;
            }
            if this.buffer.len() > overlap {
                break;
            }
        }

        // Mutate the buffer in place. Re-scanning the overlap region on later
        // polls is a no-op: any match found here was rewritten to bytes that
        // no longer match the original needle, and BTreeSet dedupes positions.
        // FUTUREWORK: if a replacement happens to equal another needle, two
        // sequential scans of the same bytes would chain the rewrites. Our
        // store-path-hash use case never triggers this, so accepted as-is.
        rewrite_buffer_in_place(
            &this.pattern.inner,
            this.buffer,
            *this.buffer_abs_start,
            this.positions,
        );

        let limit = emit_limit(this.buffer.len(), *this.eof, overlap);
        Poll::Ready(Ok(&this.buffer[*this.consumed..limit]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        debug_assert!(self.consumed + amt <= self.buffer.len());
        let this = self.project();
        *this.consumed += amt;
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tokio::io::AsyncReadExt as _;
    use tokio_test::io::Builder;

    use super::*;

    // The actual derivation of `nixpkgs.hello`.
    const HELLO_DRV: &str = r#"Derive([("out","/nix/store/33l4p0pn0mybmqzaxfkpppyh7vx1c74p-hello-2.12.1","","")],[("/nix/store/6z1jfnqqgyqr221zgbpm30v91yfj3r45-bash-5.1-p16.drv",["out"]),("/nix/store/ap9g09fxbicj836zm88d56dn3ff4clxl-stdenv-linux.drv",["out"]),("/nix/store/pf80kikyxr63wrw56k00i1kw6ba76qik-hello-2.12.1.tar.gz.drv",["out"])],["/nix/store/9krlzvny65gdc8s7kpb6lkx8cd02c25b-default-builder.sh"],"x86_64-linux","/nix/store/4xw8n979xpivdc46a9ndcvyhwgif00hz-bash-5.1-p16/bin/bash",["-e","/nix/store/9krlzvny65gdc8s7kpb6lkx8cd02c25b-default-builder.sh"],[("buildInputs",""),("builder","/nix/store/4xw8n979xpivdc46a9ndcvyhwgif00hz-bash-5.1-p16/bin/bash"),("cmakeFlags",""),("configureFlags",""),("depsBuildBuild",""),("depsBuildBuildPropagated",""),("depsBuildTarget",""),("depsBuildTargetPropagated",""),("depsHostHost",""),("depsHostHostPropagated",""),("depsTargetTarget",""),("depsTargetTargetPropagated",""),("doCheck","1"),("doInstallCheck",""),("mesonFlags",""),("name","hello-2.12.1"),("nativeBuildInputs",""),("out","/nix/store/33l4p0pn0mybmqzaxfkpppyh7vx1c74p-hello-2.12.1"),("outputs","out"),("patches",""),("pname","hello"),("propagatedBuildInputs",""),("propagatedNativeBuildInputs",""),("src","/nix/store/pa10z4ngm0g83kx9mssrqzz30s84vq7k-hello-2.12.1.tar.gz"),("stdenv","/nix/store/cp65c8nk29qq5cl1wyy5qyw103cwmax7-stdenv-linux"),("strictDeps",""),("system","x86_64-linux"),("version","2.12.1")])"#;

    #[test]
    fn test_no_patterns() {
        let scanner: ReferenceScanner<String> = ReferenceScanner::new(vec![]);

        scanner.scan(HELLO_DRV);

        let result = scanner.finalise();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_single_match() {
        let scanner = ReferenceScanner::new(vec![
            "/nix/store/4xw8n979xpivdc46a9ndcvyhwgif00hz-bash-5.1-p16".to_string(),
        ]);
        scanner.scan(HELLO_DRV);

        let result = scanner.finalise();

        assert_eq!(result.len(), 1);
        assert!(result.contains("/nix/store/4xw8n979xpivdc46a9ndcvyhwgif00hz-bash-5.1-p16"));
    }

    #[test]
    fn test_multiple_matches() {
        let candidates = vec![
            // these exist in the drv:
            "/nix/store/33l4p0pn0mybmqzaxfkpppyh7vx1c74p-hello-2.12.1".to_string(),
            "/nix/store/pf80kikyxr63wrw56k00i1kw6ba76qik-hello-2.12.1.tar.gz.drv".to_string(),
            "/nix/store/cp65c8nk29qq5cl1wyy5qyw103cwmax7-stdenv-linux".to_string(),
            // this doesn't:
            "/nix/store/fn7zvafq26f0c8b17brs7s95s10ibfzs-emacs-28.2.drv".to_string(),
        ];

        let scanner = ReferenceScanner::new(candidates.clone());
        scanner.scan(HELLO_DRV);

        let result = scanner.finalise();
        assert_eq!(result.len(), 3);

        for c in candidates[..3].iter() {
            assert!(result.contains(c));
        }
    }

    #[rstest]
    #[case::normal(8096, 8096)]
    #[case::small_capacity(8096, 1)]
    #[case::small_read(1, 8096)]
    #[case::all_small(1, 1)]
    #[tokio::test]
    async fn test_reference_reader(#[case] chunk_size: usize, #[case] capacity: usize) {
        let candidates = vec![
            // these exist in the drv:
            "33l4p0pn0mybmqzaxfkpppyh7vx1c74p",
            "pf80kikyxr63wrw56k00i1kw6ba76qik",
            "cp65c8nk29qq5cl1wyy5qyw103cwmax7",
            // this doesn't:
            "fn7zvafq26f0c8b17brs7s95s10ibfzs",
        ];
        let pattern = ReferencePattern::new(candidates.clone());
        let scanner = ReferenceScanner::new(pattern);
        let mut mock = Builder::new();
        for c in HELLO_DRV.as_bytes().chunks(chunk_size) {
            mock.read(c);
        }
        let mock = mock.build();
        let mut reader = ReferenceReader::with_capacity(capacity, &scanner, mock);
        let mut s = String::new();
        reader.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, HELLO_DRV);

        let result = scanner.finalise();
        assert_eq!(result.len(), 3);

        for c in candidates[..3].iter() {
            assert!(result.contains(c));
        }
    }

    #[tokio::test]
    async fn test_reference_reader_no_patterns() {
        let pattern = ReferencePattern::new(Vec::<&str>::new());
        let scanner = ReferenceScanner::new(pattern);
        let mut mock = Builder::new();
        mock.read(HELLO_DRV.as_bytes());
        let mock = mock.build();
        let mut reader = ReferenceReader::new(&scanner, mock);
        let mut s = String::new();
        reader.read_to_string(&mut s).await.unwrap();
        assert_eq!(s, HELLO_DRV);

        let result = scanner.finalise();
        assert_eq!(result.len(), 0);
    }

    // FUTUREWORK: Test with large file

    fn rewrite(needle: &'static str, replacement: &'static [u8]) -> RewriteEntry<&'static str> {
        RewriteEntry {
            needle,
            replacement: replacement.to_vec(),
            record_positions: false,
        }
    }

    fn self_mask(needle: &'static str, replacement: &'static [u8]) -> RewriteEntry<&'static str> {
        RewriteEntry {
            needle,
            replacement: replacement.to_vec(),
            record_positions: true,
        }
    }

    #[test]
    fn rewrite_in_place_substitutes_and_records_positions() {
        // Self-mask: the hello output hash appears twice in HELLO_DRV (in the
        // outputs list and in the env `out` binding) — both should be zeroed
        // and recorded.
        let pattern: RewritePattern<&str> = RewritePattern::new(vec![
            rewrite(
                "cp65c8nk29qq5cl1wyy5qyw103cwmax7",
                b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            ),
            rewrite(
                "pf80kikyxr63wrw56k00i1kw6ba76qik",
                b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            ),
            self_mask(
                "33l4p0pn0mybmqzaxfkpppyh7vx1c74p",
                b"00000000000000000000000000000000",
            ),
        ]);
        let mut bytes = HELLO_DRV.as_bytes().to_vec();
        let positions = rewrite_in_place(&pattern, &mut bytes, 0);
        let rewritten = std::str::from_utf8(&bytes).expect("ascii in, ascii out");

        assert!(rewritten.contains("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-stdenv-linux"));
        assert!(rewritten.contains("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-hello-2.12.1.tar.gz.drv"));
        assert!(!rewritten.contains("cp65c8nk29qq5cl1wyy5qyw103cwmax7"));
        assert!(!rewritten.contains("pf80kikyxr63wrw56k00i1kw6ba76qik"));

        assert_eq!(positions.len(), 2);
        assert!(!rewritten.contains("33l4p0pn0mybmqzaxfkpppyh7vx1c74p"));
        for &p in &positions {
            let p = p as usize;
            assert_eq!(&bytes[p..p + 32], b"00000000000000000000000000000000");
        }
    }

    #[test]
    fn rewrite_in_place_no_patterns() {
        let pattern: RewritePattern<&str> = RewritePattern::new(Vec::new());
        let mut bytes = HELLO_DRV.as_bytes().to_vec();
        let positions = rewrite_in_place(&pattern, &mut bytes, 0);
        assert_eq!(positions.len(), 0);
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), HELLO_DRV);
    }

    #[test]
    fn rewrite_in_place_short_haystack() {
        let pattern: RewritePattern<&str> = RewritePattern::new(vec![rewrite(
            "33l4p0pn0mybmqzaxfkpppyh7vx1c74p",
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )]);
        // Shorter than longest_candidate: must early-return without panicking.
        let mut bytes = b"short".to_vec();
        let positions = rewrite_in_place(&pattern, &mut bytes, 0);
        assert!(positions.is_empty());
        assert_eq!(&bytes, b"short");
    }

    #[test]
    #[should_panic(expected = "rewrite replacement length must match needle length")]
    fn rewrite_pattern_rejects_length_mismatch() {
        let _: RewritePattern<&str> = RewritePattern::new(vec![RewriteEntry {
            needle: "abcdef",
            replacement: b"123".to_vec(),
            record_positions: false,
        }]);
    }

    #[rstest]
    #[case::normal(8096, 8096)]
    #[case::small_capacity(8096, 64)]
    #[case::small_read(64, 8096)]
    #[case::all_small(64, 64)]
    #[tokio::test]
    async fn rewriting_reference_reader_streams_correctly(
        #[case] chunk_size: usize,
        #[case] capacity: usize,
    ) {
        // Drives the same scenario as rewrite_in_place_substitutes... through
        // the async streaming reader at various chunk/capacity combinations.
        let pattern: RewritePattern<&str> = RewritePattern::new(vec![
            rewrite(
                "cp65c8nk29qq5cl1wyy5qyw103cwmax7",
                b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            ),
            rewrite(
                "pf80kikyxr63wrw56k00i1kw6ba76qik",
                b"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            ),
            self_mask(
                "33l4p0pn0mybmqzaxfkpppyh7vx1c74p",
                b"00000000000000000000000000000000",
            ),
        ]);

        let mut mock = Builder::new();
        for c in HELLO_DRV.as_bytes().chunks(chunk_size) {
            mock.read(c);
        }
        let mock = mock.build();

        let mut reader = RewritingReferenceReader::with_capacity(capacity, &pattern, mock);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        let s = std::str::from_utf8(&out).expect("ascii in, ascii out");
        assert!(s.contains("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-stdenv-linux"));
        assert!(s.contains("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC-hello-2.12.1.tar.gz.drv"));
        assert!(!s.contains("cp65c8nk29qq5cl1wyy5qyw103cwmax7"));
        assert!(!s.contains("pf80kikyxr63wrw56k00i1kw6ba76qik"));
        assert!(!s.contains("33l4p0pn0mybmqzaxfkpppyh7vx1c74p"));

        let positions = reader.take_positions();
        assert_eq!(positions.len(), 2, "two self-mask occurrences expected");
        for &p in &positions {
            let p = p as usize;
            assert_eq!(&out[p..p + 32], b"00000000000000000000000000000000");
        }
    }

    #[rstest]
    #[case::normal(8096, 8096)]
    #[case::small_capacity(8096, 64)]
    #[case::small_read(64, 8096)]
    #[case::all_small(64, 64)]
    #[tokio::test]
    async fn rewriting_reference_reader_passes_through_with_no_patterns(
        #[case] chunk_size: usize,
        #[case] capacity: usize,
    ) {
        let pattern: RewritePattern<&str> = RewritePattern::new(Vec::new());
        let mut mock = Builder::new();
        for c in HELLO_DRV.as_bytes().chunks(chunk_size) {
            mock.read(c);
        }
        let mock = mock.build();

        let mut reader = RewritingReferenceReader::with_capacity(capacity, &pattern, mock);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        assert_eq!(std::str::from_utf8(&out).unwrap(), HELLO_DRV);
        assert!(reader.take_positions().is_empty());
    }

    #[tokio::test]
    async fn rewriting_reference_reader_finds_match_across_chunk_boundary() {
        // Place the needle so it straddles two consecutive reads.
        let needle = "33l4p0pn0mybmqzaxfkpppyh7vx1c74p";
        let replacement = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let prefix = "lorem ipsum dolor sit amet";
        let suffix = " - tail";
        let haystack = format!("{}{}{}", prefix, needle, suffix);

        // Split the chunk halfway through the needle.
        let split = prefix.len() + needle.len() / 2;
        let (left, right) = haystack.split_at(split);
        let mut mock = Builder::new();
        mock.read(left.as_bytes());
        mock.read(right.as_bytes());
        let mock = mock.build();

        let pattern: RewritePattern<&str> =
            RewritePattern::new(vec![self_mask(needle, replacement)]);
        let mut reader = RewritingReferenceReader::with_capacity(64, &pattern, mock);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();

        let s = std::str::from_utf8(&out).unwrap();
        assert!(!s.contains(needle));
        assert!(s.contains(prefix));
        assert!(s.contains(suffix));

        let positions = reader.take_positions();
        assert_eq!(positions.len(), 1);
        let p = *positions.iter().next().unwrap() as usize;
        assert_eq!(p, prefix.len());
        assert_eq!(&out[p..p + 32], replacement);
    }
}
