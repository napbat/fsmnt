//! E8 x86 CALL target pre/post-processing shared by LZX and LZXD.
//!
//! LZX-family compressors optionally pre-process data by converting
//! relative x86 CALL (0xE8) targets to absolute addresses before
//! compression. After decompression the transform must be reversed.

/// Apply E8 pre-processing to data before compression.
///
/// Scans for x86 CALL (0xE8) instructions and converts relative
/// offsets to absolute addresses. This is the inverse of
/// [`undo_e8_preprocessing`].
///
/// `file_size` is the E8 translation size (12,000,000 for WIM LZX,
/// or the value from the LZXD stream header).
///
/// `chunk_offset` is the total number of uncompressed bytes that
/// precede this chunk. For WIM LZX (single-chunk), pass 0.
#[allow(
    dead_code,
    reason = "used by compress-lzx when that feature is enabled"
)]
pub(crate) fn apply_e8_preprocessing(data: &mut [u8], file_size: i32, chunk_offset: i64) {
    let len = data.len();
    if len <= 10 || chunk_offset >= 0x4000_0000 {
        return;
    }
    let limit = len - 10;
    let mut pos = 0;

    while pos < limit {
        if data[pos] != 0xE8 {
            pos += 1;
            continue;
        }

        let operand_start = pos + 1;
        let n = i32::from_le_bytes([
            data[operand_start],
            data[operand_start + 1],
            data[operand_start + 2],
            data[operand_start + 3],
        ]);

        let Ok(pos_i64) = i64::try_from(pos) else {
            return;
        };
        let Ok(current_pos) = i32::try_from(chunk_offset + pos_i64) else {
            return;
        };

        if n >= -current_pos && n < file_size - current_pos {
            let absolute = if n >= 0 {
                n + current_pos
            } else {
                n + file_size
            };
            let bytes = absolute.to_le_bytes();
            data[operand_start] = bytes[0];
            data[operand_start + 1] = bytes[1];
            data[operand_start + 2] = bytes[2];
            data[operand_start + 3] = bytes[3];
        }

        pos += 5;
    }
}

/// Apply E8 post-processing to decompressed data.
///
/// Scans for x86 CALL (0xE8) instructions and converts absolute
/// call targets back to relative offsets. This reverses the E8
/// pre-processing applied before compression.
///
/// `file_size` is the E8 translation size (12,000,000 for WIM LZX,
/// or the value from the LZXD stream header).
///
/// `chunk_offset` is the total number of uncompressed bytes that
/// precede this chunk. For WIM LZX (single-chunk), pass 0.
pub(crate) fn undo_e8_preprocessing(data: &mut [u8], file_size: i32, chunk_offset: i64) {
    let len = data.len();
    if len <= 10 || chunk_offset >= 0x4000_0000 {
        return;
    }
    let limit = len - 10;
    let mut pos = 0;

    while pos < limit {
        if data[pos] != 0xE8 {
            pos += 1;
            continue;
        }

        let operand_start = pos + 1;
        let n = i32::from_le_bytes([
            data[operand_start],
            data[operand_start + 1],
            data[operand_start + 2],
            data[operand_start + 3],
        ]);

        let Ok(pos_i64) = i64::try_from(pos) else {
            return;
        };
        let Ok(current_pos) = i32::try_from(chunk_offset + pos_i64) else {
            return;
        };

        let result = if n >= 0 && n < file_size {
            let mut relative = n - current_pos;
            if relative >= -current_pos && relative < 0 {
                relative += file_size;
            }
            Some(relative)
        } else if n >= -current_pos && n < 0 {
            let mut restored = n + file_size;
            if restored >= 0 && restored < file_size {
                restored -= file_size;
            }
            Some(restored)
        } else {
            None
        };

        if let Some(value) = result {
            let bytes = value.to_le_bytes();
            data[operand_start] = bytes[0];
            data[operand_start + 1] = bytes[1];
            data[operand_start + 2] = bytes[2];
            data[operand_start + 3] = bytes[3];
        }

        pos += 5;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIM_FILE_SIZE: i32 = 12_000_000;

    #[test]
    fn no_e8_bytes_unchanged() {
        let original = [
            0x00, 0x01, 0x90, 0xFF, 0xCC, 0xC3, 0x55, 0x89, 0x90, 0x90, 0x90,
        ];
        let mut data = original;
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn small_buffer_unchanged() {
        let original = [0xE8, 0x05, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90];
        let mut data = original;
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn e8_absolute_to_relative() {
        let mut data = [
            0x90, 0x90, 0xE8, 0x66, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        let result = i32::from_le_bytes([data[3], data[4], data[5], data[6]]);
        assert_eq!(result, 100);
    }

    #[test]
    fn e8_in_last_10_bytes_unchanged() {
        let mut data = [0x90u8; 20];
        data[10] = 0xE8;
        data[11] = 0x64;
        let original = data;
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn e8_apply_then_undo_roundtrip() {
        let original = [
            0x90, 0x90, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let mut data = original;
        apply_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        let abs_val = i32::from_le_bytes([data[3], data[4], data[5], data[6]]);
        assert_eq!(abs_val, 102);
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0);
        assert_eq!(data, original);
    }

    #[test]
    fn chunk_offset_shifts_position() {
        let mut data = [
            0xE8, 0xF4, 0x01, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        // E8 at pos 0, operand = 500, chunk_offset = 100.
        // current_pos = 100, relative = 500 - 100 = 400.
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 100);
        let result = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        assert_eq!(result, 400);
    }

    #[test]
    fn chunk_offset_above_1gb_skips() {
        let original = [
            0xE8, 0x64, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let mut data = original;
        undo_e8_preprocessing(&mut data, WIM_FILE_SIZE, 0x4000_0000);
        assert_eq!(data, original);
    }
}
