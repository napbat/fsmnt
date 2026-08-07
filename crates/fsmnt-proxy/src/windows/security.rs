//! Security descriptor for the elevated named-pipe server.

use std::ffi::c_void;
use std::io;

use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::core::{HSTRING, Owned};

/// Pipe security owned for the duration of `CreateNamedPipeW`.
pub(super) struct PipeSecurity {
    _descriptor: Owned<HLOCAL>,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /// Build a descriptor for elevated-server to local-client communication.
    ///
    /// The DACL denies network logons, grants full access to the system and
    /// administrators, and grants read/write access to locally interactive
    /// users. The medium mandatory label permits a normal process to write to
    /// a pipe created by an elevated process.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if Windows rejects the SDDL descriptor or a
    /// structure size cannot be represented by the Windows API.
    pub(super) fn local_interactive() -> io::Result<Self> {
        const SDDL: &str = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)S:(ML;;NW;;;ME)";

        let sddl = HSTRING::from(SDDL);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();

        // SAFETY: `sddl` is a live, NUL-terminated Windows string and
        // `descriptor` is a valid out pointer. A successful call returns a
        // LocalAlloc allocation that `Owned<HLOCAL>` releases below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl,
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|error| {
            io::Error::other(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW: {error}"
            ))
        })?;

        // SAFETY: The conversion call succeeded and transferred ownership of
        // its LocalAlloc allocation through `descriptor`.
        let descriptor = unsafe { Owned::new(HLOCAL(descriptor.0)) };
        let length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::other("SECURITY_ATTRIBUTES size does not fit u32"))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: length,
            lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
            bInheritHandle: false.into(),
        };

        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }

    /// Return the attributes pointer consumed by `CreateNamedPipeW`.
    pub(super) fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &raw const self.attributes
    }
}
