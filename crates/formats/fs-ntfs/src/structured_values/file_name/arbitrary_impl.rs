use super::{
    ArrayVec, FILE_NAME_HEADER_SIZE, FileNameHeader, FromBytes, NAME_MAX_SIZE, NtfsFileName,
};

impl<'a> arbitrary::Arbitrary<'a> for NtfsFileName {
    // mutants::skip: the `NAME_MAX_SIZE / 2` clamp upper bound equals 255,
    // which is also u8::MAX — the maximum value `header.name_length` (a u8) can
    // hold. Mutating `/` to `*` raises the bound to 1020, but the clamp can
    // never reach it, so the result is identical for every input: a provably
    // equivalent mutant. The other arithmetic in this fn (`%= 4`,
    // `name_chars * size_of::<u16>()`) is exercised by
    // test_file_name_arbitrary_clamps_name_length.
    #[cfg_attr(test, mutants::skip)]
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let header_bytes: [u8; FILE_NAME_HEADER_SIZE] = u.arbitrary()?;
        let mut header = FileNameHeader::read_from_bytes(&header_bytes)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        // Clamp namespace to valid range (0-3).
        header.namespace %= 4;

        // Generate a name of the length specified in the header (clamped to valid range).
        let name_chars = usize::from(header.name_length).clamp(1, NAME_MAX_SIZE / 2);
        header.name_length =
            u8::try_from(name_chars).map_err(|_| arbitrary::Error::IncorrectFormat)?;
        let name_len = name_chars * core::mem::size_of::<u16>();

        let mut name = ArrayVec::new();
        for _ in 0..name_len {
            name.push(u.arbitrary()?);
        }

        Ok(Self { header, name })
    }
}
