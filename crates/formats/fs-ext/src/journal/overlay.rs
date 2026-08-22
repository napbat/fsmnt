//! Read/Seek adapter that routes reads through an `OverlaySource`.

use fsmnt_parser_core::error::IoError;

use crate::io;
use crate::io::{Read, Seek, SeekFrom};

/// Internal contract for any artifact that can back an `OverlayReader`.
///
/// Implemented by `JournalReplay` and (later) `OrphanReplay`. The reader
/// consults the source on every block boundary and for every superblock-
/// host read. Kept `pub(crate)` so the trait surface is not part of the
/// crate's external API.
pub(crate) trait OverlaySource {
    fn block_size(&self) -> u32;
    fn sb_host_block(&self) -> u64;
    fn sb_host_block_content(&self) -> &[u8];
    fn overlay_block(&self, fs_block: u64) -> Option<&[u8]>;
}

/// Wraps an underlying `R: Read + Seek` so that reads of fs blocks covered
/// by an overlay source are served from the overlay instead of the disk.
pub struct OverlayReader<'r, 'p, R, S = super::replay::JournalReplay> {
    inner: &'r mut R,
    source: &'p S,
    cursor: u64,
}

#[allow(
    private_bounds,
    reason = "OverlaySource is pub(crate); the default S=JournalReplay hides the bound \
              from external callers, and no external type can name S to satisfy it"
)]
impl<'r, 'p, R: Read + Seek, S: OverlaySource> OverlayReader<'r, 'p, R, S> {
    /// Wraps a filesystem reader with the supplied replay overlay.
    ///
    /// Reads intersecting an overlaid block use recovered content; all other
    /// reads are forwarded to `inner`.
    pub fn new(inner: &'r mut R, source: &'p S) -> Self {
        Self {
            inner,
            source,
            cursor: 0,
        }
    }
}

fn make_invalid_input() -> io::Error {
    #[cfg(feature = "std")]
    {
        IoError::invalid_input().into()
    }
    #[cfg(not(feature = "std"))]
    {
        IoError::invalid_input()
    }
}

#[allow(
    private_bounds,
    reason = "OverlaySource is pub(crate); see OverlayReader::new allow above"
)]
impl<R: Read + Seek, S: OverlaySource> Seek for OverlayReader<'_, '_, R, S> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_cursor = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => i64::try_from(self.cursor)
                .ok()
                .and_then(|c| c.checked_add(n))
                .and_then(|c| u64::try_from(c).ok())
                .ok_or_else(make_invalid_input)?,
            SeekFrom::End(n) => {
                let end = self.inner.seek(SeekFrom::End(0))?;
                i64::try_from(end)
                    .ok()
                    .and_then(|c| c.checked_add(n))
                    .and_then(|c| u64::try_from(c).ok())
                    .ok_or_else(make_invalid_input)?
            }
        };
        self.cursor = new_cursor;
        Ok(self.cursor)
    }
}

#[allow(
    private_bounds,
    reason = "OverlaySource is pub(crate); see OverlayReader::new allow above"
)]
impl<R: Read + Seek, S: OverlaySource> Read for OverlayReader<'_, '_, R, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let block_size = u64::from(self.source.block_size());
        if block_size == 0 {
            return Err(make_invalid_input());
        }
        let cursor = self.cursor;
        let current_block = cursor / block_size;
        let bs_off = usize::try_from(cursor % block_size).map_err(|_| make_invalid_input())?;
        let to_block_end = usize::try_from(block_size)
            .map_err(|_| make_invalid_input())?
            .saturating_sub(bs_off);
        let n = buf.len().min(to_block_end);

        let wrote = if current_block == self.source.sb_host_block() {
            let src = self.source.sb_host_block_content();
            buf[..n].copy_from_slice(&src[bs_off..bs_off + n]);
            n
        } else if let Some(block) = self.source.overlay_block(current_block) {
            buf[..n].copy_from_slice(&block[bs_off..bs_off + n]);
            n
        } else {
            // Single read call — whatever the inner reader returns, return
            // verbatim. Callers requiring a full buffer fill use read_exact,
            // which loops through this method and handles short reads + EOF
            // per the standard `Read` contract. Using read_exact internally
            // would silently drop partial progress on inner failure.
            self.inner.seek(SeekFrom::Start(cursor))?;
            self.inner.read(&mut buf[..n])?
        };

        self.cursor = self
            .cursor
            .saturating_add(u64::try_from(wrote).map_err(|_| make_invalid_input())?);
        Ok(wrote)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;
    use crate::journal::replay::{BlockOverlay, JournalReplay};

    const BLOCK_SIZE: u32 = 4096;

    fn make_replay(
        overlay_blocks: BTreeMap<u64, alloc::boxed::Box<[u8]>>,
        sb_host_block: u64,
        sb_host_block_content: alloc::boxed::Box<[u8]>,
    ) -> JournalReplay {
        JournalReplay::for_test(BlockOverlay {
            block_size: BLOCK_SIZE,
            blocks: overlay_blocks,
            sb_host_block,
            sb_host_block_content,
        })
    }

    fn load_image_bytes() -> alloc::vec::Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        std::fs::read(&path).expect("read ext4.img fixture")
    }

    #[test]
    fn read_block_falls_through_to_inner() {
        let img = load_image_bytes();
        // Block 10 has no overlay entry — reads must fall through to the image.
        let sb_content = alloc::vec![0u8; BLOCK_SIZE as usize].into_boxed_slice();
        let replay = make_replay(BTreeMap::new(), u64::MAX, sb_content);
        let probe_offset = u64::from(BLOCK_SIZE) * 10;

        // Read 16 bytes directly from the image at the probe offset.
        let raw = img[usize::try_from(probe_offset).expect("the test fixture value fits in usize")
            ..usize::try_from(probe_offset).expect("the test fixture value fits in usize") + 16]
            .to_vec();

        let mut fs = fsmnt_testkit::Cursor::new(img);
        let mut overlay = OverlayReader::new(&mut fs, &replay);
        overlay
            .seek(SeekFrom::Start(probe_offset))
            .expect("seek overlay");
        let mut buf = [0u8; 16];
        overlay.read_exact(&mut buf).expect("read overlay");
        assert_eq!(&buf[..], &raw[..]);
    }

    #[test]
    fn overlay_reader_dispatches_via_overlay_source_trait() {
        // This test verifies the compile-time contract: OverlayReader::new
        // accepts any &S where S: OverlaySource.
        fn assert_overlay_source<S: OverlaySource>(_: &S) {}

        let img = load_image_bytes();
        let sb_content = alloc::vec![0u8; BLOCK_SIZE as usize].into_boxed_slice();
        let replay = make_replay(alloc::collections::BTreeMap::new(), u64::MAX, sb_content);
        assert_overlay_source(&replay);

        let mut fs = fsmnt_testkit::Cursor::new(img);
        let _overlay = OverlayReader::new(&mut fs, &replay);
    }

    #[test]
    fn read_sb_host_block_uses_overlay() {
        let img = load_image_bytes();
        // Use block 0 as the sb-host block. Fill it with a distinctive pattern
        // that is guaranteed to differ from the raw image's block 0.
        let mut sb_content = alloc::vec![0xABu8; BLOCK_SIZE as usize].into_boxed_slice();
        sb_content[0] = 0x01;
        sb_content[1] = 0x02;
        sb_content[2] = 0x03;
        sb_content[3] = 0x04;
        let expected = [0x01u8, 0x02, 0x03, 0x04];

        // Block 0 of ext4.img starts with 512 MBR bytes followed by zeros until
        // the superblock at offset 1024. The ext4 magic (0x53EF) is not at byte
        // 0, so the raw image bytes differ from our overlay content.
        assert_ne!(&img[0..4], &expected[..]);

        let replay = make_replay(BTreeMap::new(), 0, sb_content);
        let mut fs = fsmnt_testkit::Cursor::new(img);
        let mut overlay = OverlayReader::new(&mut fs, &replay);
        // Seek to byte 0 (start of sb-host block 0).
        overlay.seek(SeekFrom::Start(0)).expect("seek overlay");
        let mut buf = [0u8; 4];
        overlay.read_exact(&mut buf).expect("read overlay");
        // Overlay content — not the raw image — must be returned.
        assert_eq!(&buf[..], &expected[..]);
    }
}
