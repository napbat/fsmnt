use alloc::vec::Vec;
use core::iter::FusedIterator;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::ReadOnlyCursor;
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of the fixed-size header portion of each EA entry (bytes).
const EA_ENTRY_HEADER_SIZE: usize = 8;

/// Flag indicating the EA is required for correct interpretation
/// of the file.
pub const FILE_NEED_EA: u8 = 0x80;

/// On-disk layout of the fixed header of a `FILE_FULL_EA_INFORMATION`
/// entry.
///
/// Reference: [MS-FSCC] Section 2.4.16
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct EaEntryHeader {
    next_entry_offset: U32<LittleEndian>,
    flags: u8,
    ea_name_length: u8,
    ea_value_length: U16<LittleEndian>,
}

/// A single extended attribute entry parsed from a `$EA` attribute.
///
/// Each entry contains an ASCII name and an arbitrary-length value.
/// Entries form a linked list inside the `$EA` attribute data; use
/// [`NtfsEaEntries`] to iterate over them.
///
/// Reference: [MS-FSCC] Section 2.4.16
#[derive(Clone, Debug)]
pub struct NtfsEaEntry<'s> {
    data: &'s [u8],
    header: EaEntryHeader,
    position: NtfsPosition,
}

impl<'s> NtfsEaEntry<'s> {
    fn new(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < EA_ENTRY_HEADER_SIZE {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::EA,
                expected: u64::try_from(EA_ENTRY_HEADER_SIZE)
                    .expect("the fixed EA header size fits in u64"),
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
            });
        }

        let header = EaEntryHeader::read_from_bytes(&data[..EA_ENTRY_HEADER_SIZE])
            .expect("EA entry header size is always 8 bytes");
        let name_len = usize::from(header.ea_name_length);
        let value_len = usize::from(header.ea_value_length.get());

        // name starts right after the header, followed by a null
        // terminator, then the value
        let min_size = EA_ENTRY_HEADER_SIZE + name_len + 1 + value_len;
        if data.len() < min_size {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::EA,
                expected: u64::try_from(min_size).unwrap_or(u64::MAX),
                actual: u64::try_from(data.len()).unwrap_or(u64::MAX),
            });
        }

        Ok(Self {
            data,
            header,
            position,
        })
    }

    /// Returns the raw flags byte for this entry.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    /// Returns true if the `FILE_NEED_EA` flag is set, meaning this
    /// EA is required for correct file interpretation.
    #[must_use]
    pub fn is_need_ea(&self) -> bool {
        self.flags() & FILE_NEED_EA != 0
    }

    /// Returns the length of the EA name, in bytes (excludes the
    /// null terminator).
    #[must_use]
    pub fn name_length(&self) -> u8 {
        self.header.ea_name_length
    }

    /// Returns the length of the EA value, in bytes.
    #[must_use]
    pub fn value_length(&self) -> u16 {
        self.header.ea_value_length.get()
    }

    /// Returns the ASCII name of this EA (without null terminator).
    #[must_use]
    pub fn name(&self) -> &[u8] {
        let start = EA_ENTRY_HEADER_SIZE;
        let len = usize::from(self.name_length());
        &self.data[start..start + len]
    }

    /// Returns the raw value bytes of this EA.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        let name_len = usize::from(self.name_length());
        // value starts after header + name + null terminator
        let start = EA_ENTRY_HEADER_SIZE + name_len + 1;
        let len = usize::from(self.value_length());
        &self.data[start..start + len]
    }

    /// Returns the position of this entry within the filesystem.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }
}

/// Iterator over extended attribute entries in a `$EA` attribute.
///
/// Yields [`NtfsEaEntry`] values until the linked list is exhausted
/// or a parse error is encountered.
#[derive(Clone, Debug)]
pub struct NtfsEaEntries<'s> {
    data: &'s [u8],
    offset: usize,
    finished: bool,
    position: NtfsPosition,
}

impl<'s> NtfsEaEntries<'s> {
    fn new(data: &'s [u8], position: NtfsPosition) -> Self {
        Self {
            data,
            offset: 0,
            finished: data.is_empty(),
            position,
        }
    }
}

impl<'s> Iterator for NtfsEaEntries<'s> {
    type Item = Result<NtfsEaEntry<'s>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let remaining = &self.data[self.offset..];
        if remaining.len() < EA_ENTRY_HEADER_SIZE {
            self.finished = true;
            return None;
        }

        let Ok(header) = EaEntryHeader::read_from_bytes(&remaining[..EA_ENTRY_HEADER_SIZE]) else {
            self.finished = true;
            return None;
        };

        let next_offset = usize::try_from(header.next_entry_offset.get()).unwrap_or(usize::MAX);
        let entry_position = self.position + u64::try_from(self.offset).unwrap_or(u64::MAX);

        // Determine the slice for this entry: either up to
        // next_entry_offset or to the end of the data.
        let entry_slice = if next_offset == 0 {
            self.finished = true;
            remaining
        } else {
            if next_offset > remaining.len() {
                self.finished = true;
                return Some(Err(NtfsError::InvalidStructuredValueSize {
                    position: entry_position,
                    ty: NtfsAttributeType::EA,
                    expected: u64::try_from(self.offset.saturating_add(next_offset))
                        .unwrap_or(u64::MAX),
                    actual: u64::try_from(self.data.len()).unwrap_or(u64::MAX),
                }));
            }
            let slice = &remaining[..next_offset];
            self.offset += next_offset;
            slice
        };

        Some(NtfsEaEntry::new(entry_slice, entry_position))
    }
}

impl FusedIterator for NtfsEaEntries<'_> {}

/// Structure of a `$EA` attribute (type 0xE0).
///
/// This attribute contains a linked list of
/// `FILE_FULL_EA_INFORMATION` entries, each holding an ASCII name
/// and an arbitrary-length value. The `$EA` attribute can be either
/// resident or non-resident; this type reads all data into memory.
///
/// Reference: [MS-FSCC] Section 2.4.16
#[derive(Clone, Debug)]
pub struct NtfsEa {
    data: Vec<u8>,
    position: NtfsPosition,
}

impl NtfsEa {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        let len =
            usize::try_from(value_length).map_err(|_| NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::EA,
                expected: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                actual: value_length,
            })?;
        let mut data = alloc::vec![0u8; len];
        r.read_exact(&mut data)?;
        Ok(Self { data, position })
    }

    /// Returns an iterator over the EA entries in this attribute.
    #[must_use]
    pub fn entries(&self) -> NtfsEaEntries<'_> {
        NtfsEaEntries::new(&self.data, self.position)
    }
}

impl_structured_value_via_new!(NtfsEa, NtfsAttributeType::EA);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsEa {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsEa {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate a well-formed single EA entry.
        let name_len: u8 = u.int_in_range(1..=32)?;
        let value_len: u8 = u.arbitrary()?;
        let flags: u8 = u.arbitrary()?;

        let mut data = Vec::new();
        // next_entry_offset = 0 (last entry)
        data.extend_from_slice(&0u32.to_le_bytes());
        data.push(flags);
        data.push(name_len);
        data.extend_from_slice(&u16::from(value_len).to_le_bytes());
        let name_bytes = u.bytes(usize::from(name_len))?;
        data.extend_from_slice(name_bytes);
        data.push(0); // null terminator
        let value_bytes = u.bytes(usize::from(value_len))?;
        data.extend_from_slice(value_bytes);

        Ok(Self {
            data,
            position: NtfsPosition::none(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::ReadOnlyCursor;

    /// Build a single EA entry in a byte buffer.
    ///
    /// `next_entry_offset` is set to 0 (last entry) unless
    /// `set_next_offset` is provided.
    fn build_ea_entry(name: &[u8], value: &[u8], flags: u8, next_entry_offset: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // next_entry_offset (u32 LE)
        buf.extend_from_slice(&next_entry_offset.to_le_bytes());
        // flags (u8)
        buf.push(flags);
        // ea_name_length (u8)
        let name_len: u8 = u8::try_from(name.len()).expect("test value fits u8");
        buf.push(name_len);
        // ea_value_length (u16 LE)
        let value_len: u16 = u16::try_from(value.len()).expect("test value fits u16");
        buf.extend_from_slice(&value_len.to_le_bytes());
        // ea_name + null terminator
        buf.extend_from_slice(name);
        buf.push(0);
        // ea_value
        buf.extend_from_slice(value);
        buf
    }

    /// Pad a buffer to a 4-byte boundary.
    fn pad_to_4(buf: &mut Vec<u8>) {
        let rem = buf.len() % 4;
        if rem != 0 {
            let padding = 4 - rem;
            buf.extend(core::iter::repeat_n(0u8, padding));
        }
    }

    #[test]
    fn test_ea_single_entry() {
        let data = build_ea_entry(b"MYEA", b"hello", 0x00, 0);
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse single EA entry");

        let entries: Vec<_> = ea.entries().collect::<Result<Vec<_>, _>>().expect("ok");
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.name(), b"MYEA");
        assert_eq!(entry.value(), b"hello");
        assert_eq!(entry.name_length(), 4);
        assert_eq!(entry.value_length(), 5);
        assert!(!entry.is_need_ea());
        assert_eq!(entry.flags(), 0x00);
    }

    #[test]
    fn test_ea_multiple_entries_with_padding() {
        // First entry: name="A", value="1"
        let mut entry1 = build_ea_entry(b"A", b"1", 0x00, 0);
        // Pad to 4-byte boundary
        pad_to_4(&mut entry1);
        let next_offset = u32::try_from(entry1.len()).expect("test value fits u32");
        // Fix up next_entry_offset in entry1
        entry1[..4].copy_from_slice(&next_offset.to_le_bytes());

        // Second entry: name="BB", value="22"
        let entry2 = build_ea_entry(b"BB", b"22", 0x00, 0);

        let mut data = entry1;
        data.extend_from_slice(&entry2);

        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse multiple EA entries");

        let entries: Vec<_> = ea.entries().collect::<Result<Vec<_>, _>>().expect("ok");
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0].name(), b"A");
        assert_eq!(entries[0].value(), b"1");
        assert_eq!(entries[1].name(), b"BB");
        assert_eq!(entries[1].value(), b"22");
    }

    #[test]
    fn test_ea_file_need_ea_flag() {
        let data = build_ea_entry(b"CRITICAL", b"data", FILE_NEED_EA, 0);
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse EA with FILE_NEED_EA");

        let entries: Vec<_> = ea.entries().collect::<Result<Vec<_>, _>>().expect("ok");
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert!(entry.is_need_ea());
        assert_eq!(entry.flags(), FILE_NEED_EA);
        assert_eq!(entry.name(), b"CRITICAL");
        assert_eq!(entry.value(), b"data");
    }

    #[test]
    fn test_ea_empty_value() {
        let data = build_ea_entry(b"NOVALUE", b"", 0x00, 0);
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse EA with empty value");

        let entries: Vec<_> = ea.entries().collect::<Result<Vec<_>, _>>().expect("ok");
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert_eq!(entry.name(), b"NOVALUE");
        assert!(entry.value().is_empty());
        assert_eq!(entry.value_length(), 0);
    }

    #[test]
    fn test_ea_empty_data() {
        let data: [u8; 0] = [];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea =
            NtfsEa::new(&mut cursor, NtfsPosition::none(), 0).expect("should parse empty EA data");

        let entries: Vec<_> = ea.entries().collect::<Result<Vec<_>, _>>().expect("ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_ea_entry_too_small() {
        // Only 4 bytes, less than the 8-byte header
        let data = [0u8; 4];
        let result = NtfsEaEntry::new(&data, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_ea_next_offset_beyond_remaining_errors() {
        // First entry valid (advances self.offset). Second entry declares a
        // next_entry_offset larger than its own remaining bytes, triggering
        // the line 183 (`next_offset > remaining.len()`) error. The reported
        // `expected` is self.offset + next_offset, exercising line 188.
        let mut entry1 = build_ea_entry(b"A", b"1", 0x00, 0);
        let first_len = u32::try_from(entry1.len()).expect("test value fits u32");
        entry1[..4].copy_from_slice(&first_len.to_le_bytes());

        let mut entry2 = build_ea_entry(b"B", b"2", 0x00, 0);
        // entry2 remaining after offset=first_len; its next_offset is bogus.
        let bogus_next = u32::try_from(entry2.len() + 100).expect("test value fits u32");
        entry2[..4].copy_from_slice(&bogus_next.to_le_bytes());

        let mut data = entry1;
        let offset_at_entry2 = u32::try_from(data.len()).expect("test value fits u32");
        data.extend_from_slice(&entry2);

        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::new(0x100),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse");

        let mut iter = ea.entries();
        let first = iter.next().expect("first").expect("ok");
        assert_eq!(first.name(), b"A");

        let err = iter.next().expect("second item").unwrap_err();
        // expected = self.offset(offset_at_entry2) + next_offset(bogus_next).
        let NtfsError::InvalidStructuredValueSize { expected, .. } = err else {
            panic!("expected InvalidStructuredValueSize, got {err}");
        };
        assert_eq!(
            expected,
            u64::from(offset_at_entry2) + u64::from(bogus_next)
        );
        // Iterator is finished after the error.
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ea_next_offset_exactly_at_boundary_is_ok() {
        // A single entry whose next_entry_offset == the whole buffer length:
        // `next_offset == remaining.len()`. Original `>` is false, so the
        // entry is yielded and offset advances to the end (next call -> None).
        // The `>=` mutant would wrongly treat this as out-of-bounds and error.
        let mut data = build_ea_entry(b"A", b"1", 0x00, 0);
        let exact_len = u32::try_from(data.len()).expect("test value fits u32");
        data[..4].copy_from_slice(&exact_len.to_le_bytes());

        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse");

        let mut iter = ea.entries();
        let entry = iter.next().expect("entry yielded").expect("ok, not error");
        assert_eq!(entry.name(), b"A");
        assert_eq!(entry.value(), b"1");
        // After consuming the full buffer, remaining is empty -> None.
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ea_trailing_partial_header_stops_cleanly() {
        // A complete first entry (next_entry_offset points to a region
        // shorter than the 8-byte header). After consuming entry1, the
        // remaining bytes are fewer than EA_ENTRY_HEADER_SIZE, so `next`
        // returns None at line 161 (`remaining.len() < HEADER_SIZE`).
        let entry1 = build_ea_entry(b"A", b"1", 0x00, 0);
        let next_offset = u32::try_from(entry1.len()).expect("test value fits u32");
        let mut data = entry1;
        data[..4].copy_from_slice(&next_offset.to_le_bytes());
        // Append 5 trailing bytes: fewer than the 8-byte header.
        data.extend_from_slice(&[0xAB; 5]);

        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse");

        let mut iter = ea.entries();
        let first = iter.next().expect("first item").expect("ok entry");
        assert_eq!(first.name(), b"A");
        // The 5-byte tail is too small for a header -> clean stop, no error.
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ea_trailing_eight_bytes_attempts_parse_and_errors() {
        // After consuming entry1, exactly 8 bytes remain (== HEADER_SIZE).
        // Original `< 8` is false, so the iterator tries to parse those
        // 8 bytes as an entry; NtfsEaEntry::new needs header+name+1+value
        // (>= 9 bytes) and therefore returns an ERROR. The `<= 8`/`== 8`
        // mutants would instead return None at line 161 (no error).
        let entry1 = build_ea_entry(b"A", b"1", 0x00, 0);
        let next_offset = u32::try_from(entry1.len()).expect("test value fits u32");
        let mut data = entry1;
        data[..4].copy_from_slice(&next_offset.to_le_bytes());
        // Append exactly an 8-byte trailing region declaring name_len=1 so
        // NtfsEaEntry::new requires 8+1+1+0 = 10 bytes -> InvalidStructuredValueSize.
        let mut tail = Vec::new();
        tail.extend_from_slice(&0u32.to_le_bytes()); // next_entry_offset = 0 (last)
        tail.push(0x00); // flags
        tail.push(1); // name_length = 1 -> needs more than 8 bytes
        tail.extend_from_slice(&0u16.to_le_bytes()); // value_length = 0
        assert_eq!(tail.len(), 8);
        data.extend_from_slice(&tail);

        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse");

        let mut iter = ea.entries();
        let first = iter.next().expect("first").expect("ok");
        assert_eq!(first.name(), b"A");
        // 8-byte tail: original parses (and errors); mutants would yield None.
        let second = iter.next().expect("second item attempted");
        assert!(second.is_err(), "8-byte tail must be parsed and rejected");
    }

    #[test]
    fn test_ea_entries_iterator_is_fused() {
        let data = build_ea_entry(b"X", b"Y", 0x00, 0);
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea = NtfsEa::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA length fits u64"),
        )
        .expect("should parse");

        let mut iter = ea.entries();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
        // Fused: stays None after exhaustion
        assert!(iter.next().is_none());
    }
}
