use super::{
    APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE, AppExecLinkReparseDataHeader, ArrayVec, FromBytes,
    LX_SYMLINK_REPARSE_DATA_HEADER_SIZE, LX_SYMLINK_VERSION, LxSymlinkReparseDataHeader,
    MAX_PATH_BUFFER_SIZE, MOUNT_POINT_REPARSE_DATA_HEADER_SIZE, MountPointReparseDataHeader,
    NtfsError, NtfsPosition, NtfsReparsePoint, Result, SYMLINK_REPARSE_DATA_HEADER_SIZE,
    SymbolicLinkReparseDataHeader, decode_utf16le, reparse_tags, split_utf16le_null_terminated,
    symlink_flags,
};

/// Parsed symbolic link reparse point.
///
/// A symbolic link has two names:
/// - **Substitute name**: The target path used for resolution.
/// - **Print name**: A display-friendly path for the user.
///
/// Reference: [MS-FSCC] 2.1.2.4
#[derive(Clone, Debug)]
pub struct NtfsSymbolicLink {
    /// The target path (substitute name) as UTF-16LE bytes.
    substitute_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// The display path (print name) as UTF-16LE bytes.
    print_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// True if this is a relative symlink.
    is_relative: bool,
}

impl NtfsSymbolicLink {
    pub(super) fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::SYMLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::SYMLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < SYMLINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "symbolic link data too small for header",
            });
        }

        // Parse the header
        let header = SymbolicLinkReparseDataHeader::read_from_bytes(
            &data[..SYMLINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse symbolic link header",
        })?;

        let substitute_name_offset = usize::from(header.substitute_name_offset.get());
        let substitute_name_length = usize::from(header.substitute_name_length.get());
        let print_name_offset = usize::from(header.print_name_offset.get());
        let print_name_length = usize::from(header.print_name_length.get());
        let flags = header.flags.get();

        let path_buffer = &data[SYMLINK_REPARSE_DATA_HEADER_SIZE..];

        // Extract substitute name
        let substitute_name_end = substitute_name_offset + substitute_name_length;
        if substitute_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name extends beyond path buffer",
            });
        }
        let mut substitute_name = ArrayVec::new();
        substitute_name
            .try_extend_from_slice(&path_buffer[substitute_name_offset..substitute_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name too large",
            })?;

        // Extract print name
        let print_name_end = print_name_offset + print_name_length;
        if print_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name extends beyond path buffer",
            });
        }
        let mut print_name = ArrayVec::new();
        print_name
            .try_extend_from_slice(&path_buffer[print_name_offset..print_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name too large",
            })?;

        let is_relative = flags & symlink_flags::SYMLINK_FLAG_RELATIVE != 0;

        Ok(Self {
            substitute_name,
            print_name,
            is_relative,
        })
    }

    /// Returns the substitute name as UTF-16LE bytes.
    #[must_use]
    pub fn substitute_name_bytes(&self) -> &[u8] {
        &self.substitute_name
    }

    /// Returns the print name as UTF-16LE bytes.
    #[must_use]
    pub fn print_name_bytes(&self) -> &[u8] {
        &self.print_name
    }

    /// Returns true if this is a relative symbolic link.
    #[must_use]
    pub fn is_relative(&self) -> bool {
        self.is_relative
    }

    /// Decodes the substitute name to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the substitute name contains malformed UTF-16.
    pub fn substitute_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.substitute_name)
    }

    /// Decodes the print name to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the print name contains malformed UTF-16.
    pub fn print_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.print_name)
    }
}

/// Parsed mount point/junction reparse point.
///
/// A mount point (also known as a junction) has two names:
/// - **Substitute name**: The target path used for resolution.
/// - **Print name**: A display-friendly path for the user.
///
/// Unlike symbolic links, mount points do NOT have a flags field and
/// cannot be relative.
///
/// Reference: [MS-FSCC] 2.1.2.5
#[derive(Clone, Debug)]
pub struct NtfsMountPoint {
    /// The target path (substitute name) as UTF-16LE bytes.
    substitute_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// The display path (print name) as UTF-16LE bytes.
    print_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsMountPoint {
    pub(super) fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::MOUNT_POINT {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::MOUNT_POINT,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < MOUNT_POINT_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "mount point data too small for header",
            });
        }

        // Parse the header
        let header = MountPointReparseDataHeader::read_from_bytes(
            &data[..MOUNT_POINT_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse mount point header",
        })?;

        let substitute_name_offset = usize::from(header.substitute_name_offset.get());
        let substitute_name_length = usize::from(header.substitute_name_length.get());
        let print_name_offset = usize::from(header.print_name_offset.get());
        let print_name_length = usize::from(header.print_name_length.get());

        let path_buffer = &data[MOUNT_POINT_REPARSE_DATA_HEADER_SIZE..];

        // Extract substitute name
        let substitute_name_end = substitute_name_offset + substitute_name_length;
        if substitute_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name extends beyond path buffer",
            });
        }
        let mut substitute_name = ArrayVec::new();
        substitute_name
            .try_extend_from_slice(&path_buffer[substitute_name_offset..substitute_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name too large",
            })?;

        // Extract print name
        let print_name_end = print_name_offset + print_name_length;
        if print_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name extends beyond path buffer",
            });
        }
        let mut print_name = ArrayVec::new();
        print_name
            .try_extend_from_slice(&path_buffer[print_name_offset..print_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name too large",
            })?;

        Ok(Self {
            substitute_name,
            print_name,
        })
    }

    /// Returns the substitute name as UTF-16LE bytes.
    #[must_use]
    pub fn substitute_name_bytes(&self) -> &[u8] {
        &self.substitute_name
    }

    /// Returns the print name as UTF-16LE bytes.
    #[must_use]
    pub fn print_name_bytes(&self) -> &[u8] {
        &self.print_name
    }

    /// Decodes the substitute name to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the substitute name contains malformed UTF-16.
    pub fn substitute_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.substitute_name)
    }

    /// Decodes the print name to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the print name contains malformed UTF-16.
    pub fn print_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.print_name)
    }
}

/// Parsed WSL symbolic link reparse point.
///
/// WSL symlinks store a UTF-8 target path (not UTF-16LE like Windows symlinks).
/// The reparse data contains a 4-byte version header followed by the raw
/// UTF-8 target path bytes with no null terminator.
///
/// Reference: [MS-FSCC] 2.1.2.7
#[derive(Clone, Debug)]
pub struct NtfsLxSymlink {
    /// The target path as UTF-8 bytes.
    target_path: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsLxSymlink {
    pub(super) fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::LX_SYMLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::LX_SYMLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < LX_SYMLINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WSL symlink data too small for header",
            });
        }

        let header = LxSymlinkReparseDataHeader::read_from_bytes(
            &data[..LX_SYMLINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse WSL symlink header",
        })?;

        if header.version.get() != LX_SYMLINK_VERSION {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unsupported WSL symlink version (expected 2)",
            });
        }

        let path_bytes = &data[LX_SYMLINK_REPARSE_DATA_HEADER_SIZE..];
        let mut target_path = ArrayVec::new();
        target_path.try_extend_from_slice(path_bytes).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WSL symlink target path too large",
            }
        })?;

        Ok(Self { target_path })
    }

    /// Returns the target path as raw UTF-8 bytes.
    #[must_use]
    pub fn target_path_bytes(&self) -> &[u8] {
        &self.target_path
    }

    /// Validates and returns the target path as a string slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the WSL target path is not valid UTF-8.
    pub fn target_path(&self) -> Result<&str> {
        core::str::from_utf8(&self.target_path).map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "WSL symlink target path is not valid UTF-8",
        })
    }
}

/// Parsed UWP app execution link reparse point.
///
/// `AppExecLink` reparse points are used by Windows to create execution aliases
/// for UWP/MSIX apps (e.g., `python.exe`, `wt.exe` in
/// `%LOCALAPPDATA%\Microsoft\WindowsApps\`).
///
/// The reparse data contains a 4-byte version header followed by
/// null-terminated UTF-16LE strings for package ID, entry point,
/// executable path, and optionally application type.
#[derive(Clone, Debug)]
pub struct NtfsAppExecLink {
    /// Version from the header (typically 3).
    version: u32,
    /// Package family name as UTF-16LE bytes.
    package_id: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Application user model ID as UTF-16LE bytes.
    entry_point: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Target executable path as UTF-16LE bytes.
    executable: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Application type as UTF-16LE bytes (may be empty).
    application_type: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsAppExecLink {
    pub(super) fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::APPEXECLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::APPEXECLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink data too small for header",
            });
        }

        let header = AppExecLinkReparseDataHeader::read_from_bytes(
            &data[..APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse AppExecLink header",
        })?;

        let version = header.version.get();
        let string_data = &data[APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE..];

        // Split on UTF-16LE null terminators (0x00, 0x00).
        // We expect 3 required strings + 1 optional.
        let strings = split_utf16le_null_terminated(string_data)?;

        if strings.len() < 3 {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink data contains fewer than 3 strings",
            });
        }

        let mut package_id = ArrayVec::new();
        package_id.try_extend_from_slice(strings[0]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink package ID too large",
            }
        })?;

        let mut entry_point = ArrayVec::new();
        entry_point.try_extend_from_slice(strings[1]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink entry point too large",
            }
        })?;

        let mut executable = ArrayVec::new();
        executable.try_extend_from_slice(strings[2]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink executable path too large",
            }
        })?;

        let mut application_type = ArrayVec::new();
        if strings.len() > 3 {
            application_type
                .try_extend_from_slice(strings[3])
                .map_err(|_| NtfsError::InvalidReparsePointData {
                    position: NtfsPosition::none(),
                    reason: "AppExecLink application type too large",
                })?;
        }

        Ok(Self {
            version,
            package_id,
            entry_point,
            executable,
            application_type,
        })
    }

    /// Returns the header version (typically 3).
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the package family name as UTF-16LE bytes.
    #[must_use]
    pub fn package_id_bytes(&self) -> &[u8] {
        &self.package_id
    }

    /// Returns the application user model ID as UTF-16LE bytes.
    #[must_use]
    pub fn entry_point_bytes(&self) -> &[u8] {
        &self.entry_point
    }

    /// Returns the executable path as UTF-16LE bytes.
    #[must_use]
    pub fn executable_bytes(&self) -> &[u8] {
        &self.executable
    }

    /// Returns the application type as UTF-16LE bytes (may be empty).
    #[must_use]
    pub fn application_type_bytes(&self) -> &[u8] {
        &self.application_type
    }

    /// Decodes the package family name to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the package family name contains malformed UTF-16.
    pub fn package_id(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.package_id)
    }

    /// Decodes the application user model ID to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the application identifier contains malformed
    /// UTF-16.
    pub fn entry_point(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.entry_point)
    }

    /// Decodes the executable path to a String.
    ///
    /// # Errors
    ///
    /// Returns an error if the executable path contains malformed UTF-16.
    pub fn executable(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.executable)
    }

    /// Decodes the application type to a String, if present.
    ///
    /// Returns `None` if the application type string was not included
    /// in the reparse data.
    #[must_use]
    pub fn application_type(&self) -> Option<Result<alloc::string::String>> {
        if self.application_type.is_empty() {
            None
        } else {
            Some(decode_utf16le(&self.application_type))
        }
    }
}
