//! `fsmnt-proxy` — privileged handle-passing proxy for files and block devices.
//!
//! A small server runs with elevated privileges and opens devices on behalf
//! of unprivileged clients, passing the raw OS handle back so subsequent I/O
//! goes directly through the kernel with zero proxy overhead.
//!
//! | Platform | IPC              | Handle passing          |
//! |----------|------------------|-------------------------|
//! | Unix     | Unix socket      | `SCM_RIGHTS` fd-passing |
//! | Windows  | Named pipe       | `DuplicateHandle`       |
//!
//! # Usage
//!
//! Start the server with privileges:
//! ```bash
//! # Unix
//! sudo fsmnt-proxy-server
//! # Windows (run as Administrator)
//! fsmnt-proxy-server.exe
//! ```
//!
//! Then from unprivileged code:
//! ```rust,no_run
//! # #[cfg(any(unix, windows))]
//! # {
//! use fsmnt_proxy::ProxyClient;
//!
//! let mut client = ProxyClient::connect(fsmnt_proxy::DEFAULT_ENDPOINT).unwrap();
//! let opened = client.open("/dev/rdisk10s3").unwrap(); // or "\\\\.\\PhysicalDrive1"
//! // `opened.file` is a standard std::fs::File — Read + Seek, zero proxy overhead.
//! // `opened.size` is the file/device size reported by the server.
//! # }
//! ```

use std::fs::{File, OpenOptions};
use std::io;

#[cfg(any(unix, windows))]
use tracing::{debug, warn};

/// Opcode: open a file/device and receive the raw handle.
///
/// Wire format: `OP_OPEN + u8 mode + i32 flags + u16 path_len + path`
pub(crate) const OP_OPEN: u8 = 0x05;

pub(crate) const STATUS_OK: u8 = 0x00;
pub(crate) const STATUS_ERR: u8 = 0x01;

/// Maximum path length (4 KiB).
pub(crate) const MAX_PATH_LEN: u16 = 4096;

/// Default endpoint for the proxy server.
///
/// On Unix this is a socket path; on Windows a named pipe path.
#[cfg(unix)]
pub const DEFAULT_ENDPOINT: &str = "/tmp/fsmnt-proxy.sock";
/// Default endpoint for the proxy server.
#[cfg(windows)]
pub const DEFAULT_ENDPOINT: &str = r"\\.\pipe\fsmnt-proxy";
/// Default endpoint for the proxy server.
#[cfg(not(any(unix, windows)))]
pub const DEFAULT_ENDPOINT: &str = "";

/// How to open the file on the server side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Read-only.
    ReadOnly,
    /// Read-write.
    ReadWrite,
}

impl OpenMode {
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            OpenMode::ReadOnly => 0x00,
            OpenMode::ReadWrite => 0x01,
        }
    }

    pub(crate) fn from_wire(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(OpenMode::ReadOnly),
            0x01 => Some(OpenMode::ReadWrite),
            _ => None,
        }
    }

    /// Apply this mode to an [`OpenOptions`].
    pub fn apply(self, opts: &mut OpenOptions) {
        match self {
            OpenMode::ReadOnly => {
                opts.read(true);
            }
            OpenMode::ReadWrite => {
                opts.read(true).write(true);
            }
        }
    }
}

/// A file handle returned by [`ProxyClient::open`], along with its size.
///
/// The `size` is the file/device size as reported by the server (via
/// `seek(End(0))`).  This is useful for block devices where the client
/// may not be able to determine the size itself.
#[derive(Debug)]
pub struct OpenedFile {
    /// The opened file handle.  Supports `Read` + `Seek`.
    pub file: File,
    /// Size in bytes as reported by the server.
    pub size: u64,
}

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::open_direct;
#[cfg(unix)]
pub use unix::{ProxyClient, server};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::open_direct;
#[cfg(windows)]
pub use windows::{ProxyClient, server};

/// Open a path directly, falling back to the privileged proxy when access
/// is denied.
///
/// Successful direct opens never contact the proxy. If the direct open is
/// denied, this connects to [`DEFAULT_ENDPOINT`] and asks the server to open
/// the same path with the same mode and platform flags. If the proxy is
/// unavailable or rejects the request, the original direct-open error is
/// returned.
///
/// # Errors
///
/// Returns the direct I/O error when the path cannot be opened directly and
/// the proxy fallback is unavailable or unsuccessful.
#[cfg(any(unix, windows))]
pub fn open_with_proxy_fallback(path: &str, mode: OpenMode, flags: i32) -> io::Result<File> {
    match open_direct(path, mode, flags) {
        Ok(file) => {
            debug!(path, "opened directly");
            Ok(file)
        }
        Err(direct_error) if direct_error.kind() == io::ErrorKind::PermissionDenied => {
            debug!(path, "direct open was denied, asking the privileged proxy");
            let proxy_result = ProxyClient::connect(DEFAULT_ENDPOINT)
                .and_then(|mut client| client.open_with(path, mode, flags))
                .map(|opened| opened.file);
            proxy_result
                .inspect(|_| debug!(path, "opened through the privileged proxy"))
                .map_err(|proxy_error| {
                    warn!(
                        path,
                        error = %proxy_error,
                        "could not open through the privileged proxy, reporting the direct access error"
                    );
                    direct_error
                })
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests;
