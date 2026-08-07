//! Windows implementation — `DuplicateHandle` over named pipes.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

use crate::{MAX_PATH_LEN, OP_OPEN, OpenMode, OpenedFile, STATUS_OK};

pub(crate) mod pipe;
mod security;
pub mod server;

/// A client connection to the privileged proxy server.
///
/// Holds an open named pipe to the server.  Call [`open`](Self::open) to
/// request device handles — each one comes back as a standard [`File`].
pub struct ProxyClient {
    pipe: File,
}

impl ProxyClient {
    /// Connect to the proxy server at the given named-pipe path.
    ///
    /// The default endpoint is [`crate::DEFAULT_ENDPOINT`]
    /// (`\\.\pipe\fsmnt-proxy`).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the named pipe does not exist or cannot be
    /// opened for reading and writing.
    pub fn connect<P: AsRef<Path>>(pipe_path: P) -> io::Result<Self> {
        // Named pipes on Windows can be opened with regular CreateFile
        // (which is what OpenOptions::open does).
        let pipe = OpenOptions::new().read(true).write(true).open(pipe_path)?;
        Ok(Self { pipe })
    }

    /// Open a file/device read-only with no extra flags.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the request cannot be sent, the response is
    /// invalid, or the server cannot open the requested path.
    pub fn open(&mut self, path: &str) -> io::Result<OpenedFile> {
        self.open_with(path, OpenMode::ReadOnly, 0)
    }

    /// Open a file/device with the given mode and flags.
    ///
    /// `flags` are sent to the server but currently ignored on Windows
    /// (reserved for future use — the server logs a warning if non-zero).
    ///
    /// # Errors
    ///
    /// Returns an I/O error if `path` exceeds the protocol limit, the request
    /// or response cannot be transferred, the response is invalid, or the
    /// server cannot open the path.
    pub fn open_with(&mut self, path: &str, mode: OpenMode, flags: i32) -> io::Result<OpenedFile> {
        let path_bytes = path.as_bytes();
        if path_bytes.len() > usize::from(MAX_PATH_LEN) {
            return Err(io::Error::other("path too long"));
        }
        let path_len =
            u16::try_from(path_bytes.len()).map_err(|_| io::Error::other("path too long"))?;

        // Wire: opcode + mode + flags + path_len + path
        let mut msg = Vec::with_capacity(8 + path_bytes.len());
        msg.push(OP_OPEN);
        msg.push(mode.to_wire());
        msg.extend_from_slice(&flags.to_le_bytes());
        msg.extend_from_slice(&path_len.to_le_bytes());
        msg.extend_from_slice(path_bytes);

        self.pipe.write_all(&msg)?;
        self.pipe.flush()?;

        // Response: status(1) + size(8) + handle_value(8) = 17 bytes
        // or:       status(1) + error_len(4) + error_msg
        let mut status = [0u8; 1];
        self.pipe.read_exact(&mut status)?;

        if status[0] != STATUS_OK {
            let mut len_buf = [0u8; 4];
            self.pipe.read_exact(&mut len_buf)?;
            let len = usize::try_from(u32::from_le_bytes(len_buf))
                .map_err(|_| io::Error::other("error response is too large"))?;
            let mut err_buf = vec![0u8; len.min(4096)];
            self.pipe.read_exact(&mut err_buf)?;
            let msg = String::from_utf8_lossy(&err_buf).into_owned();
            return Err(io::Error::other(msg));
        }

        let mut payload = [0u8; 16]; // size(8) + handle(8)
        self.pipe.read_exact(&mut payload)?;

        let size_bytes: [u8; 8] = payload[..8]
            .try_into()
            .map_err(|_| io::Error::other("invalid size response"))?;
        let handle_bytes: [u8; 8] = payload[8..]
            .try_into()
            .map_err(|_| io::Error::other("invalid handle response"))?;
        let size = u64::from_le_bytes(size_bytes);
        let handle_address = usize::try_from(u64::from_le_bytes(handle_bytes))
            .map_err(|_| io::Error::other("server returned an invalid handle"))?;
        let raw_handle = std::ptr::without_provenance_mut::<std::ffi::c_void>(handle_address);

        // SAFETY: The server duplicated a valid handle into our process.
        let file = unsafe { File::from_raw_handle(raw_handle) };
        Ok(OpenedFile { file, size })
    }
}

/// Open a path directly with Windows-compatible sharing.
pub(crate) fn open_direct(path: &str, mode: OpenMode, flags: i32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    mode.apply(&mut options);
    options.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
    if flags != 0 {
        let flags = u32::try_from(flags)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Windows flags"))?;
        options.custom_flags(flags);
    }
    options.open(path)
}
