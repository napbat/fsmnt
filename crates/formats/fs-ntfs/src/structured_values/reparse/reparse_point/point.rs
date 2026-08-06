use super::{
    ArrayVec, GUID_SIZE, MAX_PATH_BUFFER_SIZE, NtfsAppExecLink, NtfsAttributeType,
    NtfsAttributeValue, NtfsError, NtfsGuid, NtfsLxSymlink, NtfsMountPoint, NtfsNfsReparsePoint,
    NtfsPosition, NtfsReparseTag, NtfsResidentAttributeValue, NtfsStructuredValue,
    NtfsStructuredValueFromResidentAttributeValue, NtfsSymbolicLink, REPARSE_POINT_HEADER_SIZE,
    Read, ReadOnlyCursor, ReparsePointHeader, Result, Seek, read_pod,
};

/// Parsed NTFS reparse point data.
///
/// This is the main structured value for the $`REPARSE_POINT` attribute (0xC0).
/// It contains the reparse tag, optional GUID (for third-party reparse points),
/// and the raw reparse data.
///
/// Use [`as_symbolic_link`](Self::as_symbolic_link) or [`as_mount_point`](Self::as_mount_point)
/// to parse the data as a specific reparse point type.
///
/// Reference: [MS-FSCC] 2.1.2.2, 2.1.2.3
#[derive(Clone, Debug)]
pub struct NtfsReparsePoint {
    /// Raw reparse tag value.
    pub(super) tag: u32,
    /// For third-party reparse points, the owner GUID.
    pub(super) guid: Option<NtfsGuid>,
    /// Raw reparse data (after header, excluding GUID if present).
    pub(super) data: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsReparsePoint {
    /// Creates an [`NtfsReparsePoint`] directly from a byte slice.
    ///
    /// This is useful for testing and fuzzing, bypassing the attribute value
    /// parsing layer.
    ///
    /// # Errors
    ///
    /// Returns an error if the reparse-point header or declared payload length
    /// is invalid.
    pub fn from_bytes(data: &[u8], position: NtfsPosition) -> Result<Self> {
        let value_length = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let mut cursor = ReadOnlyCursor::new(data);
        Self::new(&mut cursor, position, value_length)
    }

    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length
            < u64::try_from(REPARSE_POINT_HEADER_SIZE)
                .expect("the fixed reparse-point header size fits u64")
        {
            return Err(NtfsError::InvalidReparsePointData {
                position,
                reason: "reparse point data too small for header",
            });
        }

        let header = read_pod::<T, ReparsePointHeader, REPARSE_POINT_HEADER_SIZE>(r)?;
        let tag = header.reparse_tag.get();
        let data_length = usize::from(header.reparse_data_length.get());

        // Check if this is a Microsoft reparse point (M bit set)
        let is_microsoft = tag & 0x8000_0000 != 0;

        // For third-party reparse points, read the GUID
        let guid = if !is_microsoft && data_length >= GUID_SIZE {
            Some(read_pod::<T, NtfsGuid, GUID_SIZE>(r)?)
        } else {
            None
        };

        // Calculate remaining data length
        let remaining_data_length = if guid.is_some() {
            data_length.saturating_sub(GUID_SIZE)
        } else {
            data_length
        };

        if remaining_data_length > MAX_PATH_BUFFER_SIZE {
            return Err(NtfsError::ReparseDataTooLarge {
                position,
                size: remaining_data_length,
                max_size: MAX_PATH_BUFFER_SIZE,
            });
        }

        // Read the remaining reparse data
        let mut data = ArrayVec::from([0u8; MAX_PATH_BUFFER_SIZE]);
        r.read_exact(&mut data[..remaining_data_length])?;
        data.truncate(remaining_data_length);

        Ok(Self { tag, guid, data })
    }

    /// Returns the raw reparse tag value.
    #[must_use]
    pub fn tag(&self) -> u32 {
        self.tag
    }

    /// Returns the parsed reparse tag (known or unknown).
    #[must_use]
    pub fn tag_type(&self) -> NtfsReparseTag {
        NtfsReparseTag::from_u32(self.tag)
    }

    /// Returns true if this is a Microsoft-owned reparse point.
    #[must_use]
    pub fn is_microsoft(&self) -> bool {
        self.tag & 0x8000_0000 != 0
    }

    /// Returns true if this is a name surrogate (symlink/junction).
    #[must_use]
    pub fn is_name_surrogate(&self) -> bool {
        self.tag & 0x2000_0000 != 0
    }

    /// Returns the third-party GUID if this is not a Microsoft reparse point.
    #[must_use]
    pub fn guid(&self) -> Option<&NtfsGuid> {
        self.guid.as_ref()
    }

    /// Returns the raw reparse data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Attempts to parse as a symbolic link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_SYMLINK`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different tag or malformed symbolic-link data.
    pub fn as_symbolic_link(&self) -> Result<NtfsSymbolicLink> {
        NtfsSymbolicLink::from_reparse_point(self)
    }

    /// Attempts to parse as a mount point/junction.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_MOUNT_POINT`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different tag or malformed mount-point data.
    pub fn as_mount_point(&self) -> Result<NtfsMountPoint> {
        NtfsMountPoint::from_reparse_point(self)
    }

    /// Attempts to parse as a WSL symbolic link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_LX_SYMLINK`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different tag or malformed WSL link data.
    pub fn as_lx_symlink(&self) -> Result<NtfsLxSymlink> {
        NtfsLxSymlink::from_reparse_point(self)
    }

    /// Attempts to parse as a UWP app execution link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_APPEXECLINK`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different tag or malformed app-link data.
    pub fn as_app_exec_link(&self) -> Result<NtfsAppExecLink> {
        NtfsAppExecLink::from_reparse_point(self)
    }

    /// Attempts to parse as an NFS reparse point.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_NFS`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different tag or malformed NFS reparse data.
    pub fn as_nfs_reparse_point(&self) -> Result<NtfsNfsReparsePoint> {
        NtfsNfsReparsePoint::from_reparse_point(self)
    }
}

impl_structured_value_via_new!(NtfsReparsePoint, NtfsAttributeType::ReparsePoint);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsReparsePoint {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}
