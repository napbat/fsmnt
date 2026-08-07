//! Conventional filesystem-identity formatting.

use std::fmt::Write;

pub(crate) fn uuid(bytes: &[u8; 16]) -> String {
    let mut output = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            output.push('-');
        }
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

pub(crate) fn fat_serial(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff)
}

pub(crate) fn ntfs_serial(serial: u64) -> String {
    format!("{serial:016X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc4122_uuid_without_reordering_parser_bytes() {
        assert_eq!(
            uuid(&[
                0xdf, 0x09, 0xcc, 0x9f, 0xa4, 0x63, 0x49, 0xea, 0x9f, 0xf7, 0xb7, 0xee, 0x9c, 0xb1,
                0x45, 0xf4,
            ]),
            "df09cc9f-a463-49ea-9ff7-b7ee9cb145f4"
        );
    }

    #[test]
    fn formats_dos_and_ntfs_serials_conventionally() {
        assert_eq!(fat_serial(0xdc98_bd27), "DC98-BD27");
        assert_eq!(ntfs_serial(0x0123_4567_89ab_cdef), "0123456789ABCDEF");
    }
}
