//! Unix implementation — `SCM_RIGHTS` fd-passing over Unix sockets.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write as _};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::{MAX_PATH_LEN, OP_OPEN, OpenMode, OpenedFile, STATUS_OK};

pub(crate) mod scm;
pub mod server;

/// A client connection to the privileged proxy server.
///
/// Holds an open Unix socket to the server.  Call [`open`](Self::open) to
/// request file descriptors — each one comes back as a standard [`File`]
/// via `SCM_RIGHTS`.
pub struct ProxyClient {
    stream: UnixStream,
}

impl ProxyClient {
    /// Connect to the proxy server at the given socket/endpoint path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the Unix socket does not exist or cannot be
    /// connected.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        Ok(Self { stream })
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

    /// Open a file/device with the given mode and OS flags.
    ///
    /// `flags` are raw OS flags (e.g. `O_NONBLOCK`) passed directly to
    /// `OpenOptions::custom_flags` on the server side.
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
        (&self.stream).write_all(&msg)?;
        (&self.stream).flush()?;

        // The server responds in one of two ways:
        //
        //   Success: STATUS_OK(1) + size(8) sent via sendmsg WITH an
        //            SCM_RIGHTS fd attached.
        //
        //   Error:   STATUS_ERR(1) + err_len(4) + err_msg sent as plain
        //            data (no fd).
        //
        // We first peek at the status byte with a normal read, then
        // branch accordingly.
        let mut status = [0u8; 1];
        (&self.stream).read_exact(&mut status)?;

        if status[0] != STATUS_OK {
            // Error path — read the error message (plain data, no fd).
            let mut len_buf = [0u8; 4];
            (&self.stream).read_exact(&mut len_buf)?;
            let len = usize::try_from(u32::from_le_bytes(len_buf))
                .map_err(|_| io::Error::other("error response is too large"))?;
            let mut err_buf = vec![0u8; len.min(4096)];
            (&self.stream).read_exact(&mut err_buf)?;
            let msg = String::from_utf8_lossy(&err_buf).into_owned();
            return Err(io::Error::other(msg));
        }

        // Success path — receive the fd + size via SCM_RIGHTS.
        let mut size_buf = [0u8; 8];
        let (bytes_read, fd) = scm::recv_fd(&self.stream, &mut size_buf)?;
        // SAFETY: The server passed us a valid fd via SCM_RIGHTS. Construct
        // the owner before validating the payload so an error still closes it.
        let file = unsafe { File::from_raw_fd(fd) };
        if bytes_read != size_buf.len() {
            return Err(io::Error::other("invalid size response"));
        }
        let size = u64::from_le_bytes(size_buf);

        Ok(OpenedFile { file, size })
    }
}

/// Open a path directly with the supplied Unix flags.
pub(crate) fn open_direct(path: &str, mode: OpenMode, flags: i32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    mode.apply(&mut options);
    if flags != 0 {
        options.custom_flags(flags);
    }
    options.open(path)
}
