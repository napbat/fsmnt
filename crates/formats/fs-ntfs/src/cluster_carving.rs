//! Signature-based file carving from unallocated clusters.
//!
//! When a file is deleted on NTFS its MFT record may be reused, erasing
//! the metadata needed to locate its content. The clusters that held the
//! content often survive until they are reallocated. This module scans
//! clusters the `$Bitmap` reports as free, looking for the magic bytes
//! ("signatures") of known file types, and reports each recovered
//! fragment — even when no MFT record remains.
//!
//! NTFS aligns file content to cluster boundaries, so a recoverable file
//! header sits at the start of a cluster. [`NtfsClusterCarver`] walks the
//! volume, matches headers against a [`CarvingConfig`] registry, and —
//! for signatures that define a footer — scans forward through the
//! contiguous free clusters that follow to bound the file.
//!
//! Carving is heuristic: a fragmented file, or one whose tail clusters
//! were reallocated, yields a truncated [`CarvedFile`] with
//! [`CarvedFile::footer_found`] reporting `false`.

use alloc::vec;
use alloc::vec::Vec;
use fsmnt_parser_core::error::IoError;

use crate::cluster_bitmap::NtfsClusterBitmap;
use crate::error::Result;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;

/// One mebibyte, for expressing signature size caps.
const MIB: u64 = 1024 * 1024;

/// A known file-type signature used to recognize carved content.
///
/// `header` is matched against the first bytes of a free cluster.
/// `footer`, when present, marks the end of the file and is searched for
/// across the contiguous free clusters that follow the header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSignature {
    name: &'static str,
    header: Vec<u8>,
    footer: Option<Vec<u8>>,
    max_size: u64,
}

impl FileSignature {
    /// Creates a signature.
    ///
    /// `header` should be non-empty (an empty header is ignored by the
    /// carver). `max_size` caps how far carving scans for the footer, or
    /// the contiguous-free extent when no footer is defined.
    pub fn new(name: &'static str, header: &[u8], footer: Option<&[u8]>, max_size: u64) -> Self {
        Self {
            name,
            header: header.to_vec(),
            footer: footer.map(<[u8]>::to_vec),
            max_size,
        }
    }

    /// The human-readable type name (e.g. `"jpeg"`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The magic bytes expected at the start of the file.
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// The trailer bytes that mark the end of the file, if any.
    #[must_use]
    pub fn footer(&self) -> Option<&[u8]> {
        self.footer.as_deref()
    }

    /// The maximum number of bytes attributed to a single carved file.
    #[must_use]
    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    /// The built-in signature set covering common forensic file types.
    ///
    /// Headers and footers are the documented magic constants for each
    /// format; the ZIP signature also recognizes DOCX/XLSX/PPTX/JAR/APK,
    /// which are ZIP containers.
    #[must_use]
    pub fn builtins() -> Vec<FileSignature> {
        vec![
            // JPEG: SOI marker FF D8 FF .. EOI marker FF D9.
            FileSignature::new("jpeg", &[0xFF, 0xD8, 0xFF], Some(&[0xFF, 0xD9]), 64 * MIB),
            // PNG: 8-byte signature .. IEND chunk type + its fixed CRC.
            FileSignature::new(
                "png",
                &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
                Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
                64 * MIB,
            ),
            // GIF: "GIF8" (covers both GIF87a and GIF89a); no firm footer.
            FileSignature::new("gif", b"GIF8", None, 16 * MIB),
            // PDF: "%PDF-" .. last "%%EOF".
            FileSignature::new("pdf", b"%PDF-", Some(b"%%EOF"), 128 * MIB),
            // ZIP local file header; the End-Of-Central-Directory record
            // is not a reliable contiguous trailer, so no footer.
            FileSignature::new("zip", &[0x50, 0x4B, 0x03, 0x04], None, 128 * MIB),
            FileSignature::new("bmp", b"BM", None, 64 * MIB),
            FileSignature::new("gzip", &[0x1F, 0x8B, 0x08], None, 64 * MIB),
            FileSignature::new(
                "rar",
                &[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],
                None,
                128 * MIB,
            ),
            FileSignature::new("7z", &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], None, 128 * MIB),
        ]
    }
}

/// Configuration for [`NtfsClusterCarver`]: the signature registry.
///
/// The registry is pluggable — pass [`CarvingConfig::new`] a list that
/// adds custom [`FileSignature`]s without changing the carver itself.
#[derive(Clone, Debug)]
pub struct CarvingConfig {
    signatures: Vec<FileSignature>,
}

impl CarvingConfig {
    /// Creates a config from an explicit signature list.
    #[must_use]
    pub fn new(signatures: Vec<FileSignature>) -> Self {
        Self { signatures }
    }

    /// The signatures the carver will match against.
    #[must_use]
    pub fn signatures(&self) -> &[FileSignature] {
        &self.signatures
    }
}

impl Default for CarvingConfig {
    fn default() -> Self {
        Self {
            signatures: FileSignature::builtins(),
        }
    }
}

/// A file fragment recovered from unallocated clusters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CarvedFile {
    /// The matched signature's type name.
    pub signature: &'static str,
    /// The cluster the header was found in.
    pub start_cluster: u64,
    /// The absolute byte offset of the header on the volume.
    pub start_offset: u64,
    /// The estimated file length in bytes.
    pub length: u64,
    /// The last cluster of the carved region.
    pub end_cluster: u64,
    /// Whether the signature's footer was located.
    ///
    /// `true` means `length` runs exactly to the end of the footer;
    /// `false` means `length` is the contiguous-free-extent estimate.
    pub footer_found: bool,
}

/// Returns the index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Returns the first signature whose header matches the start of `data`.
fn match_header<'s>(data: &[u8], signatures: &'s [FileSignature]) -> Option<&'s FileSignature> {
    signatures
        .iter()
        .find(|sig| !sig.header.is_empty() && data.starts_with(&sig.header))
}

/// Advances a streaming footer search by one cluster.
///
/// `carry` holds the trailing bytes of already-scanned data so a footer
/// straddling a cluster boundary is still found; `consumed` counts the
/// region bytes that precede `carry`. On a match, returns the region
/// offset just past the footer. Otherwise refreshes `carry` and
/// `consumed` for the next call and returns `None`.
fn footer_search_step(
    carry: &mut Vec<u8>,
    consumed: &mut u64,
    cluster: &[u8],
    footer: &[u8],
) -> Option<u64> {
    let window_start = *consumed;
    let mut window = core::mem::take(carry);
    window.extend_from_slice(cluster);

    if let Some(i) = find_subslice(&window, footer) {
        let match_end =
            u64::try_from(i + footer.len()).expect("an in-memory footer offset fits in u64");
        return Some(window_start + match_end);
    }

    // Retain the last footer.len()-1 bytes so a split footer is caught.
    let keep = footer.len().saturating_sub(1).min(window.len());
    let newly_consumed =
        u64::try_from(window.len() - keep).expect("an in-memory window length fits in u64");
    *consumed += newly_consumed;
    *carry = window[window.len() - keep..].to_vec();
    None
}

/// Scans unallocated clusters for known file signatures.
///
/// Created via [`Ntfs::carve_unallocated`] or [`NtfsClusterCarver::new`].
/// Each call to [`Self::next`] yields one [`CarvedFile`].
pub struct NtfsClusterCarver {
    bitmap: NtfsClusterBitmap,
    config: CarvingConfig,
    cluster_size: u64,
    total_clusters: u64,
    next_cluster: u64,
    buf: Vec<u8>,
}

impl NtfsClusterCarver {
    /// Creates a carver with the default (built-in) signature registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume bitmap cannot be loaded or its cluster
    /// size cannot be represented as an in-memory buffer length.
    pub fn new<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        Self::with_config(ntfs, fs, CarvingConfig::default())
    }

    /// Creates a carver with a custom signature registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the volume bitmap cannot be loaded or its cluster
    /// size cannot be represented as an in-memory buffer length.
    pub fn with_config<T: Read + Seek>(
        ntfs: &Ntfs,
        fs: &mut T,
        config: CarvingConfig,
    ) -> Result<Self> {
        let bitmap = ntfs.cluster_bitmap(fs)?;
        let cluster_size_u32 = ntfs.cluster_size();
        let cluster_size = u64::from(cluster_size_u32);
        let buffer_size =
            usize::try_from(cluster_size_u32).map_err(|_| IoError::invalid_input())?;
        let total_clusters = bitmap.total_clusters();
        Ok(Self {
            bitmap,
            config,
            cluster_size,
            total_clusters,
            next_cluster: 0,
            buf: vec![0u8; buffer_size],
        })
    }

    /// Advances to the next carved file.
    ///
    /// Returns `None` once the whole volume has been scanned.
    pub fn next<T: Read + Seek>(&mut self, fs: &mut T) -> Option<Result<CarvedFile>> {
        while self.next_cluster < self.total_clusters {
            let cluster = self.next_cluster;
            self.next_cluster += 1;

            match self.bitmap.is_allocated(fs, cluster) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Some(Err(e)),
            }

            if let Err(e) = self.read_cluster(fs, cluster) {
                return Some(Err(e));
            }

            // Clone the matched signature out so the `&mut self` carve
            // below is unencumbered by the borrow on `self.config`.
            let Some(sig) = match_header(&self.buf, &self.config.signatures).cloned() else {
                continue;
            };

            let carved = match self.carve(fs, cluster, &sig) {
                Ok(c) => c,
                Err(e) => return Some(Err(e)),
            };
            self.next_cluster = carved.end_cluster + 1;
            return Some(Ok(carved));
        }
        None
    }

    /// Reads cluster `cluster` into `self.buf`.
    fn read_cluster<T: Read + Seek>(&mut self, fs: &mut T, cluster: u64) -> Result<()> {
        let offset = cluster * self.cluster_size;
        fs.seek(SeekFrom::Start(offset))?;
        fs.read_exact(&mut self.buf)?;
        Ok(())
    }

    /// Carves one file starting at `start_cluster`, whose header matched
    /// `sig` and whose first cluster is already in `self.buf`.
    fn carve<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        start_cluster: u64,
        sig: &FileSignature,
    ) -> Result<CarvedFile> {
        let max_clusters = sig.max_size.div_ceil(self.cluster_size).max(1);
        match sig.footer() {
            Some(footer) => self.carve_with_footer(fs, start_cluster, sig, footer, max_clusters),
            None => self.carve_extent(fs, start_cluster, sig, max_clusters),
        }
    }

    /// Carves a footer-bearing file by streaming forward through free
    /// clusters until the footer is found, an allocated cluster is hit,
    /// or `max_clusters` is reached.
    fn carve_with_footer<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        start_cluster: u64,
        sig: &FileSignature,
        footer: &[u8],
        max_clusters: u64,
    ) -> Result<CarvedFile> {
        let start_offset = start_cluster * self.cluster_size;
        let mut carry: Vec<u8> = Vec::new();
        let mut consumed: u64 = 0;
        let mut cluster = start_cluster;
        let mut scanned = 0u64;

        loop {
            if let Some(end) = footer_search_step(&mut carry, &mut consumed, &self.buf, footer) {
                return Ok(CarvedFile {
                    signature: sig.name,
                    start_cluster,
                    start_offset,
                    length: end,
                    end_cluster: cluster,
                    footer_found: true,
                });
            }
            scanned += 1;

            let next = cluster + 1;
            if scanned >= max_clusters || next >= self.total_clusters {
                break;
            }
            match self.bitmap.is_allocated(fs, next) {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => return Err(e),
            }
            self.read_cluster(fs, next)?;
            // A cluster that begins another known signature is the start of
            // the next carved file; this file ends at the previous cluster.
            if match_header(&self.buf, &self.config.signatures).is_some() {
                break;
            }
            cluster = next;
        }

        // No footer within range — fall back to the contiguous extent.
        let length = (scanned * self.cluster_size).min(sig.max_size);
        Ok(CarvedFile {
            signature: sig.name,
            start_cluster,
            start_offset,
            length,
            end_cluster: cluster,
            footer_found: false,
        })
    }

    /// Carves a footer-less file as the run of contiguous free clusters
    /// starting at `start_cluster`, capped at `max_clusters`.
    ///
    /// The run is also cut short at the first cluster that begins another
    /// known signature, so two deleted files sharing one unallocated
    /// extent are reported separately rather than merged into one.
    fn carve_extent<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        start_cluster: u64,
        sig: &FileSignature,
        max_clusters: u64,
    ) -> Result<CarvedFile> {
        let start_offset = start_cluster * self.cluster_size;
        let mut cluster = start_cluster;
        let mut count = 1u64;

        while count < max_clusters {
            let next = cluster + 1;
            if next >= self.total_clusters || self.bitmap.is_allocated(fs, next)? {
                break;
            }
            self.read_cluster(fs, next)?;
            // A cluster that begins another known signature starts the
            // next carved file; the carver resumes the scan there.
            if match_header(&self.buf, &self.config.signatures).is_some() {
                break;
            }
            cluster = next;
            count += 1;
        }

        let length = (count * self.cluster_size).min(sig.max_size);
        Ok(CarvedFile {
            signature: sig.name,
            start_cluster,
            start_offset,
            length,
            end_cluster: cluster,
            footer_found: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_bitmap::NtfsClusterBitmap;
    use crate::data_run_map::DataRunMap;

    /// Cluster size for synthetic carving fixtures.
    const CARVE_CLUSTER_SIZE: u64 = 8;
    /// Total clusters on the synthetic volume.
    const CARVE_TOTAL: u64 = 8;

    /// Footer-less and footer-bearing signatures used by the carver tests.
    fn carve_config() -> CarvingConfig {
        CarvingConfig::new(vec![
            // Footer-less: header 0xAA 0xAA.
            FileSignature::new("aa", &[0xAA, 0xAA], None, 1024),
            // Footer-bearing: header 0xBB 0xBB, footer 0xFF 0xFF.
            FileSignature::new("bb", &[0xBB, 0xBB], Some(&[0xFF, 0xFF]), 1024),
        ])
    }

    /// Builds a carver over an 8-cluster synthetic volume.
    ///
    /// `cluster_contents[i]` is the 8-byte content of cluster `i`.
    /// `allocated` lists the clusters marked allocated in the bitmap.
    /// Layout on disk: cluster contents at byte `cluster * 8`, then the
    /// bitmap bytes (one cached cluster = 8 bytes) at byte `CARVE_TOTAL * 8`.
    fn build_carver(
        cluster_contents: &[[u8; 8]],
        allocated: &[u64],
    ) -> (NtfsClusterCarver, fsmnt_testkit::Cursor<Vec<u8>>) {
        let content_len =
            usize::try_from(CARVE_TOTAL * CARVE_CLUSTER_SIZE).expect("test value fits usize");
        let mut disk = vec![0u8; content_len];
        for (i, content) in cluster_contents.iter().enumerate() {
            let start = i * usize::try_from(CARVE_CLUSTER_SIZE).expect("test value fits usize");
            disk[start..start + 8].copy_from_slice(content);
        }

        // Bitmap: one cached cluster (8 bytes) immediately after the content.
        let bitmap_disk_offset = u64::try_from(content_len).expect("test content length fits u64");
        let mut bitmap = [0u8; 8];
        for &c in allocated {
            let byte_index = usize::try_from(c / 8).expect("test cluster index fits usize");
            let bit_index = u32::try_from(c % 8).expect("bit index is below eight");
            bitmap[byte_index] |= 1 << bit_index;
        }
        disk.extend_from_slice(&bitmap);

        let cursor = fsmnt_testkit::Cursor::new(disk);
        let map =
            DataRunMap::from_segments_for_test(&[(Some(bitmap_disk_offset), CARVE_CLUSTER_SIZE)]);
        let bitmap = NtfsClusterBitmap::from_parts_for_test(
            map,
            CARVE_TOTAL,
            u32::try_from(CARVE_CLUSTER_SIZE).expect("test value fits u32"),
        );

        let carver = NtfsClusterCarver {
            bitmap,
            config: carve_config(),
            cluster_size: CARVE_CLUSTER_SIZE,
            total_clusters: CARVE_TOTAL,
            next_cluster: 0,
            buf: vec![0u8; usize::try_from(CARVE_CLUSTER_SIZE).expect("test value fits usize")],
        };
        (carver, cursor)
    }

    /// Standard fixture matching the module-level carving walkthrough:
    /// cluster 0 & 3 allocated; a footer-less file at cluster 1 (spanning
    /// 1..=2) and a footer-bearing file at cluster 4 (spanning 4..=5).
    fn standard_fixture() -> [[u8; 8]; 8] {
        [
            [0; 8],                               // 0: allocated, ignored
            [0xAA, 0xAA, 1, 2, 3, 4, 5, 6],       // 1: footer-less header
            [7, 8, 9, 10, 11, 12, 13, 14],        // 2: filler, no header
            [0; 8],                               // 3: allocated, ignored
            [0xBB, 0xBB, 20, 21, 22, 23, 24, 25], // 4: footer-bearing header
            [0xFF, 0xFF, 30, 31, 32, 33, 34, 35], // 5: footer
            [40, 41, 42, 43, 44, 45, 46, 47],     // 6: filler, no header
            [50, 51, 52, 53, 54, 55, 56, 57],     // 7: filler, no header
        ]
    }

    #[test]
    fn builtins_cover_expected_types() {
        let names: Vec<&str> = FileSignature::builtins()
            .iter()
            .map(FileSignature::name)
            .collect();
        for expected in ["jpeg", "png", "gif", "pdf", "zip", "bmp"] {
            assert!(names.contains(&expected), "missing signature: {expected}");
        }
    }

    #[test]
    fn signature_accessors_round_trip() {
        let sig = FileSignature::new("custom", &[0xCA, 0xFE], Some(&[0xBE, 0xEF]), 4096);
        assert_eq!(sig.name(), "custom");
        assert_eq!(sig.header(), &[0xCA, 0xFE]);
        assert_eq!(sig.footer(), Some(&[0xBE, 0xEF][..]));
        assert_eq!(sig.max_size(), 4096);
    }

    #[test]
    fn default_config_uses_builtins() {
        assert_eq!(
            CarvingConfig::default().signatures().len(),
            FileSignature::builtins().len(),
        );
    }

    #[test]
    fn find_subslice_locates_and_misses() {
        assert_eq!(find_subslice(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_subslice(b"abcdef", b"xy"), None);
        assert_eq!(find_subslice(b"ab", b"abc"), None);
        assert_eq!(find_subslice(b"abc", b""), None);
    }

    #[test]
    fn find_subslice_equal_length_match() {
        // needle.len() == haystack.len(): the `needle.len() > haystack.len()`
        // guard must be false so the match still succeeds (kills `> with >=`
        // and `> with ==`).
        assert_eq!(find_subslice(b"abc", b"abc"), Some(0));
        assert_eq!(find_subslice(b"abc", b"abd"), None);
    }

    #[test]
    fn builtin_max_size_uses_mib_constant() {
        // jpeg's max_size is 64 * MIB = 64 * 1024 * 1024. A `*`->`+` or
        // `*`->`/` swap in the MIB definition changes this exact value.
        let builtins = FileSignature::builtins();
        let jpeg = builtins.iter().find(|s| s.name() == "jpeg").unwrap();
        assert_eq!(jpeg.max_size(), 64 * 1024 * 1024);
    }

    #[test]
    fn match_header_picks_matching_signature() {
        let sigs = FileSignature::builtins();
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(
            match_header(&jpeg, &sigs).map(FileSignature::name),
            Some("jpeg")
        );

        let pdf = b"%PDF-1.7\n";
        assert_eq!(
            match_header(pdf, &sigs).map(FileSignature::name),
            Some("pdf")
        );

        let noise = [0x00, 0x11, 0x22, 0x33];
        assert!(match_header(&noise, &sigs).is_none());
    }

    #[test]
    fn match_header_ignores_empty_header() {
        let sigs = [FileSignature::new("bad", &[], None, 0)];
        assert!(match_header(b"anything", &sigs).is_none());
    }

    #[test]
    fn footer_found_within_a_single_cluster() {
        let mut carry = Vec::new();
        let mut consumed = 0u64;
        // "....FFD9...." — footer at offset 4, ends at 6.
        let cluster = [0x00, 0x11, 0x22, 0x33, 0xFF, 0xD9, 0x44, 0x55];
        let end = footer_search_step(&mut carry, &mut consumed, &cluster, &[0xFF, 0xD9]);
        assert_eq!(end, Some(6));
    }

    #[test]
    fn footer_split_across_cluster_boundary_is_found() {
        let footer = [0xAA, 0xBB, 0xCC];
        let mut carry = Vec::new();
        let mut consumed = 0u64;

        // First cluster ends with the first two footer bytes.
        let c0 = [0x01, 0x02, 0x03, 0xAA, 0xBB];
        assert_eq!(
            footer_search_step(&mut carry, &mut consumed, &c0, &footer),
            None,
        );
        // Second cluster begins with the final footer byte.
        let c1 = [0xCC, 0x09, 0x09];
        let end = footer_search_step(&mut carry, &mut consumed, &c1, &footer);
        // Footer occupies region bytes 3..6, so it ends at 6.
        assert_eq!(end, Some(6));
    }

    #[test]
    fn footer_search_streams_multiple_clusters() {
        let footer = [0xEE, 0xFF];
        let mut carry = Vec::new();
        let mut consumed = 0u64;

        let empty = [0u8; 8];
        assert_eq!(
            footer_search_step(&mut carry, &mut consumed, &empty, &footer),
            None,
        );
        assert_eq!(
            footer_search_step(&mut carry, &mut consumed, &empty, &footer),
            None,
        );
        // Third cluster (region offset 16) carries the footer at its
        // offset 2, so the footer ends at region offset 20.
        let last = [0x00, 0x00, 0xEE, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let end = footer_search_step(&mut carry, &mut consumed, &last, &footer);
        assert_eq!(end, Some(20));
    }

    #[test]
    fn carver_completes_on_testfs1() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut carver = NtfsClusterCarver::new(&ntfs, &mut testfs1).unwrap();

        let mut count = 0;
        while let Some(result) = carver.next(&mut testfs1) {
            let recovered = result.unwrap();
            // Structural invariants for every reported fragment.
            assert!(recovered.end_cluster >= recovered.start_cluster);
            assert!(recovered.length > 0);
            assert!(!recovered.signature.is_empty());
            count += 1;
            assert!(count <= 10_000, "carver did not terminate");
        }
    }

    #[test]
    fn synth_carve_footerless_extent() {
        // Footer-less file at cluster 1, bounded by allocated cluster 3.
        let (mut carver, mut fs) = build_carver(&standard_fixture(), &[0, 3]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "aa");
        assert_eq!(recovered.start_cluster, 1);
        // start_offset = cluster 1 * cluster_size 8 = 8.
        assert_eq!(recovered.start_offset, 8);
        // Spans clusters 1 and 2 (cluster 3 is allocated), so 2 * 8 = 16 bytes.
        assert_eq!(recovered.end_cluster, 2);
        assert_eq!(recovered.length, 16);
        assert!(!recovered.footer_found);
    }

    #[test]
    fn synth_carve_with_footer() {
        // Advance past the footer-less file to the footer-bearing one.
        let (mut carver, mut fs) = build_carver(&standard_fixture(), &[0, 3]);
        let _first = carver.next(&mut fs).unwrap().unwrap();
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "bb");
        assert_eq!(recovered.start_cluster, 4);
        assert_eq!(recovered.start_offset, 32); // 4 * 8
        assert_eq!(recovered.end_cluster, 5);
        assert!(recovered.footer_found);
        // Footer 0xFF 0xFF sits at region offset 8..10 (start of cluster 5),
        // so the carved length runs to the end of the footer = 10.
        assert_eq!(recovered.length, 10);
    }

    #[test]
    fn synth_carver_terminates_after_last_file() {
        let (mut carver, mut fs) = build_carver(&standard_fixture(), &[0, 3]);
        let mut recovered_files = Vec::new();
        while let Some(result) = carver.next(&mut fs) {
            recovered_files.push(result.unwrap());
            assert!(
                recovered_files.len()
                    <= usize::try_from(CARVE_TOTAL).expect("test value fits usize"),
                "carver runaway"
            );
        }
        // Exactly two files are recovered, in cluster order.
        assert_eq!(recovered_files.len(), 2);
        assert_eq!(recovered_files[0].start_cluster, 1);
        assert_eq!(recovered_files[1].start_cluster, 4);
    }

    #[test]
    fn synth_carver_skips_when_all_allocated() {
        // Every cluster allocated -> nothing to carve, immediate None.
        let all: Vec<u64> = (0..CARVE_TOTAL).collect();
        let (mut carver, mut fs) = build_carver(&standard_fixture(), &all);
        assert!(carver.next(&mut fs).is_none());
    }

    #[test]
    fn synth_carve_extent_capped_by_max_size() {
        // A footer-less signature whose max_size caps the extent at one
        // cluster, even though clusters 1 and 2 are both free and contiguous.
        let contents = standard_fixture();
        let (mut carver, mut fs) = build_carver(&contents, &[0, 3]);
        carver.config = CarvingConfig::new(vec![FileSignature::new(
            "aa",
            &[0xAA, 0xAA],
            None,
            8, // max one cluster
        )]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        // max_clusters = ceil(8/8) = 1, so the extent is a single cluster.
        assert_eq!(recovered.start_cluster, 1);
        assert_eq!(recovered.end_cluster, 1);
        assert_eq!(recovered.length, 8);
        assert!(!recovered.footer_found);
    }

    #[test]
    fn synth_carve_footer_split_across_clusters() {
        // Footer-bearing file whose footer straddles a cluster boundary,
        // exercising carry/consumed accounting across reads.
        let contents = [
            [0; 8],                            // 0: allocated
            [0xBB, 0xBB, 1, 2, 3, 4, 5, 0xFF], // 1: header + first footer byte
            [0xFF, 9, 10, 11, 12, 13, 14, 15], // 2: second footer byte at start
            [0; 8],                            // 3: allocated
            [0; 8],
            [0; 8],
            [0; 8],
            [0; 8],
        ];
        let (mut carver, mut fs) = build_carver(&contents, &[0, 3]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "bb");
        assert_eq!(recovered.start_cluster, 1);
        assert_eq!(recovered.end_cluster, 2);
        assert!(recovered.footer_found);
        // Footer occupies region bytes 7..9, ending at 9.
        assert_eq!(recovered.length, 9);
    }

    #[test]
    fn synth_carve_extent_split_by_second_signature() {
        // Two footer-less files in one contiguous free run: the extent of the
        // first stops at the cluster that begins the second signature.
        let contents = [
            [0; 8],                         // 0: allocated
            [0xAA, 0xAA, 1, 2, 3, 4, 5, 6], // 1: first footer-less file
            [0xAA, 0xAA, 9, 9, 9, 9, 9, 9], // 2: second file's header
            [0; 8],                         // 3: allocated
            [0; 8],
            [0; 8],
            [0; 8],
            [0; 8],
        ];
        let (mut carver, mut fs) = build_carver(&contents, &[0, 3]);
        let first = carver.next(&mut fs).unwrap().unwrap();
        // First file is just cluster 1 (cluster 2 starts a new signature).
        assert_eq!(first.start_cluster, 1);
        assert_eq!(first.end_cluster, 1);
        assert_eq!(first.length, 8);
        // Carver resumes at cluster 2 for the second file.
        let second = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(second.start_cluster, 2);
        assert_eq!(second.end_cluster, 2);
    }

    #[test]
    fn synth_read_cluster_offset() {
        // read_cluster seeks to cluster * cluster_size. Reading cluster 4
        // must load the footer-bearing header bytes, proving the `*` offset
        // (kills `* with +`/`* with /`).
        let (mut carver, mut fs) = build_carver(&standard_fixture(), &[0, 3]);
        carver.read_cluster(&mut fs, 4).unwrap();
        assert_eq!(&carver.buf, &[0xBB, 0xBB, 20, 21, 22, 23, 24, 25]);

        carver.read_cluster(&mut fs, 1).unwrap();
        assert_eq!(&carver.buf, &[0xAA, 0xAA, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn synth_carve_footer_missing_falls_back_to_extent() {
        // Footer-bearing file at cluster 1 whose footer (0xFF 0xFF) never
        // appears; the free run is bounded by allocated cluster 3. The carve
        // must fall back to the contiguous extent (footer_found = false) and
        // report a length of `scanned * cluster_size`.
        let contents = [
            [0; 8],                         // 0: allocated
            [0xBB, 0xBB, 1, 2, 3, 4, 5, 6], // 1: footer-bearing header, no footer
            [7, 7, 7, 7, 7, 7, 7, 7],       // 2: filler, no footer, no header
            [0; 8],                         // 3: allocated -> bounds the run
            [0; 8],
            [0; 8],
            [0; 8],
            [0; 8],
        ];
        let (mut carver, mut fs) = build_carver(&contents, &[0, 3]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "bb");
        assert_eq!(recovered.start_cluster, 1);
        assert!(!recovered.footer_found);
        // Two clusters scanned (1 and 2) before hitting allocated cluster 3.
        // length = scanned(2) * cluster_size(8) = 16 (kills `+= *=` at 330,
        // and `* +`/`* /` at 351).
        assert_eq!(recovered.end_cluster, 2);
        assert_eq!(recovered.length, 16);
    }

    #[test]
    fn synth_carve_footer_missing_bounded_by_volume_end() {
        // Footer-bearing file at cluster 6 with no footer, free clusters
        // running to the volume's last cluster (7). The loop must break on
        // `next >= total_clusters` (the right-hand side of the `||`); turning
        // that into `&&` would let the scan call is_allocated() on cluster 8
        // (out of range) and surface an error instead of carving.
        let contents = [
            [0; 8],                         // 0
            [0; 8],                         // 1
            [0; 8],                         // 2
            [0; 8],                         // 3
            [0; 8],                         // 4
            [0; 8],                         // 5
            [0xBB, 0xBB, 1, 2, 3, 4, 5, 6], // 6: footer-bearing header, no footer
            [9, 9, 9, 9, 9, 9, 9, 9],       // 7: filler, no footer, last cluster
        ];
        // Clusters 0..6 allocated so the scan starts at cluster 6.
        let (mut carver, mut fs) = build_carver(&contents, &[0, 1, 2, 3, 4, 5]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "bb");
        assert_eq!(recovered.start_cluster, 6);
        assert!(!recovered.footer_found);
        assert_eq!(recovered.end_cluster, 7);
        // Scanned clusters 6 and 7 -> length 2 * 8 = 16.
        assert_eq!(recovered.length, 16);
    }

    #[test]
    fn synth_carve_footer_missing_capped_by_max_clusters() {
        // Footer-bearing file with no footer whose max_size caps the scan at
        // one cluster, even though more free clusters follow. The loop must
        // break on `scanned >= max_clusters` (the left-hand side of the
        // `||`), pinning that branch.
        let contents = [
            [0; 8],                         // 0: allocated
            [0xBB, 0xBB, 1, 2, 3, 4, 5, 6], // 1: footer-bearing header, no footer
            [7, 7, 7, 7, 7, 7, 7, 7],       // 2: free filler
            [8, 8, 8, 8, 8, 8, 8, 8],       // 3: free filler
            [0; 8],
            [0; 8],
            [0; 8],
            [0; 8],
        ];
        let (mut carver, mut fs) = build_carver(&contents, &[0]);
        carver.config = CarvingConfig::new(vec![FileSignature::new(
            "bb",
            &[0xBB, 0xBB],
            Some(&[0xFF, 0xFF]),
            8, // max one cluster -> max_clusters = 1
        )]);
        let recovered = carver.next(&mut fs).unwrap().unwrap();
        assert_eq!(recovered.signature, "bb");
        assert!(!recovered.footer_found);
        // Only one cluster scanned before max_clusters stops the loop.
        assert_eq!(recovered.end_cluster, 1);
        assert_eq!(recovered.length, 8);
    }
}
