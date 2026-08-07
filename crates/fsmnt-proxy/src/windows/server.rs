//! Server-side logic for the device proxy (Windows).
//!
//! Opens devices with elevated privileges and passes the raw handle to
//! the client via `DuplicateHandle` over a named pipe.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::thread;

use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::core::{HRESULT, HSTRING};

use crate::{MAX_PATH_LEN, OP_OPEN, OpenMode, STATUS_ERR, STATUS_OK};

use super::security::PipeSecurity;

/// Owning wrapper providing `Read` + `Write` over a Windows named pipe.
///
/// Closes the pipe handle on drop.
pub struct PipeStream {
    handle: HANDLE,
}

impl PipeStream {
    /// Take ownership of an already-connected named pipe handle.
    ///
    /// # Safety
    /// `handle` must be a valid, connected named pipe handle.  The
    /// caller must not close it — `PipeStream` takes ownership.
    #[must_use]
    pub unsafe fn from_raw(handle: HANDLE) -> Self {
        Self { handle }
    }

    /// The underlying pipe handle (borrowed).
    #[must_use]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// SAFETY: The underlying pipe handle is a kernel object that is safe to use
// from any thread.
unsafe impl Send for PipeStream {}

impl Read for &PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        let mut bytes_read: u32 = 0;
        unsafe {
            ReadFile(self.handle, Some(buf), Some(&raw mut bytes_read), None)
                .map_err(|e| io::Error::other(format!("ReadFile: {e}")))?;
        }
        usize::try_from(bytes_read).map_err(|_| io::Error::other("read count does not fit usize"))
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self).read(buf)
    }
}

impl Write for &PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        let mut bytes_written: u32 = 0;
        unsafe {
            WriteFile(self.handle, Some(buf), Some(&raw mut bytes_written), None)
                .map_err(|e| io::Error::other(format!("WriteFile: {e}")))?;
        }
        usize::try_from(bytes_written)
            .map_err(|_| io::Error::other("write count does not fit usize"))
    }

    fn flush(&mut self) -> io::Result<()> {
        use windows::Win32::Storage::FileSystem::FlushFileBuffers;
        unsafe {
            FlushFileBuffers(self.handle)
                .map_err(|e| io::Error::other(format!("FlushFileBuffers: {e}")))?;
        }
        Ok(())
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        (&*self).flush()
    }
}

/// Listen for connections on a named pipe and handle them in threads.
///
/// Creates pipe instances at `endpoint`, then loops accepting clients.
/// Each client is handled in a new thread via [`handle_client`].  This
/// function never returns under normal operation.
///
/// # Errors
///
/// Returns an I/O error if a named-pipe instance cannot be created.
pub fn listen(endpoint: &str) -> io::Result<()> {
    let mut first = true;

    eprintln!("fsmnt-proxy-server: listening on {endpoint}");
    eprintln!("fsmnt-proxy-server: waiting for connections… (Ctrl+C to stop)");

    loop {
        let pipe_handle = create_pipe_instance(endpoint, first)?;
        first = false;

        // Block until a client connects.
        if let Err(e) = connect_pipe(pipe_handle) {
            eprintln!("fsmnt-proxy-server: ConnectNamedPipe failed: {e}");
            unsafe {
                let _ = CloseHandle(pipe_handle);
            }
            continue;
        }

        // PipeStream takes ownership — no manual CloseHandle needed.
        let stream = unsafe { PipeStream::from_raw(pipe_handle) };

        thread::spawn(move || {
            eprintln!("fsmnt-proxy-server: client connected");
            if let Err(e) = handle_client(&stream) {
                eprintln!("fsmnt-proxy-server: client error: {e}");
            }
            eprintln!("fsmnt-proxy-server: client disconnected");
            // `stream` is dropped here → CloseHandle
        });
    }
}

/// Create one named-pipe instance and return its owning raw handle.
pub(crate) fn create_pipe_instance(endpoint: &str, first: bool) -> io::Result<HANDLE> {
    let pipe_name = HSTRING::from(endpoint);
    let security = PipeSecurity::local_interactive()?;
    let open_mode = if first {
        PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        PIPE_ACCESS_DUPLEX
    };

    // SAFETY: `pipe_name` is a live UTF-16 string for the duration of the
    // call. The default security descriptor is requested with `None`.
    let pipe_handle = unsafe {
        CreateNamedPipeW(
            &pipe_name,
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            Some(security.as_ptr()),
        )
    };

    if pipe_handle.is_invalid() {
        Err(io::Error::last_os_error())
    } else {
        Ok(pipe_handle)
    }
}

/// Wait for a client to connect to a named-pipe instance.
pub(crate) fn connect_pipe(pipe_handle: HANDLE) -> io::Result<()> {
    // SAFETY: `pipe_handle` owns a named-pipe server instance created by
    // `CreateNamedPipeW`.
    match unsafe { ConnectNamedPipe(pipe_handle, None) } {
        Ok(()) => Ok(()),
        // A client may connect between pipe creation and this call. Windows
        // reports that successful race as ERROR_PIPE_CONNECTED.
        Err(error) if error.code() == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0) => Ok(()),
        Err(error) => Err(io::Error::other(format!("ConnectNamedPipe: {error}"))),
    }
}

/// Handle a single client connection over a named pipe.
///
/// The pipe must already be connected (i.e. after `ConnectNamedPipe`
/// succeeds).  Each request follows the same wire protocol as the Unix
/// server.
///
/// # Errors
///
/// Returns an I/O error if a request or response cannot be transferred, a
/// request is malformed, or a handle cannot be duplicated into the client.
pub fn handle_client(pipe: &PipeStream) -> io::Result<()> {
    let pipe_handle = pipe.handle();
    let mut stream = pipe;

    loop {
        let mut opcode = [0u8; 1];
        if stream.read_exact(&mut opcode).is_err() {
            return Ok(()); // Client disconnected
        }

        match opcode[0] {
            OP_OPEN => {
                let mut header = [0u8; 7];
                stream.read_exact(&mut header)?;

                let Some(mode) = OpenMode::from_wire(header[0]) else {
                    write_error(&mut stream, "invalid open mode")?;
                    continue;
                };
                let flags_bytes: [u8; 4] = header[1..5]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid flags field"))?;
                let path_len_bytes: [u8; 2] = header[5..7]
                    .try_into()
                    .map_err(|_| io::Error::other("invalid path-length field"))?;
                let flags = i32::from_le_bytes(flags_bytes);
                let path_len = u16::from_le_bytes(path_len_bytes);
                if path_len > MAX_PATH_LEN {
                    write_error(&mut stream, "path too long")?;
                    return Ok(());
                }
                let path_len = usize::from(path_len);

                if flags != 0 {
                    eprintln!(
                        "fsmnt-proxy-server: ignoring unsupported flags 0x{flags:08X} \
                         (flags are not supported on Windows)"
                    );
                }

                let mut path_buf = vec![0u8; path_len];
                stream.read_exact(&mut path_buf)?;
                let path = String::from_utf8_lossy(&path_buf).into_owned();

                let mut opts = OpenOptions::new();
                mode.apply(&mut opts);
                opts.share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
                // FILE_FLAG_BACKUP_SEMANTICS lets us open devices/dirs.
                opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0);

                match opts.open(&path) {
                    Ok(mut file) => {
                        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
                        file.seek(SeekFrom::Start(0)).unwrap_or(0);

                        let source = HANDLE(file.as_raw_handle());

                        match super::pipe::duplicate_to_pipe_client(pipe_handle, source) {
                            Ok(client_handle_val) => {
                                // STATUS_OK + size(8) + handle(8) = 17 bytes
                                let mut payload = [0u8; 17];
                                payload[0] = STATUS_OK;
                                payload[1..9].copy_from_slice(&size.to_le_bytes());
                                payload[9..17].copy_from_slice(&client_handle_val.to_le_bytes());
                                stream.write_all(&payload)?;
                                stream.flush()?;
                            }
                            Err(e) => {
                                write_error(
                                    &mut stream,
                                    &format!("DuplicateHandle \"{path}\": {e}"),
                                )?;
                            }
                        }
                        // `file` is dropped here — the server's handle is
                        // closed but the client now owns its own copy.
                    }
                    Err(e) => {
                        write_error(&mut stream, &format!("open \"{path}\": {e}"))?;
                    }
                }
            }
            _ => return Ok(()),
        }
    }
}

/// Write an error response: `STATUS_ERR + len(4) + message`.
fn write_error(w: &mut impl Write, msg: &str) -> io::Result<()> {
    let msg_bytes = msg.as_bytes();
    let msg_len = u32::try_from(msg_bytes.len())
        .map_err(|_| io::Error::other("error response is too large"))?;
    w.write_all(&[STATUS_ERR])?;
    w.write_all(&msg_len.to_le_bytes())?;
    w.write_all(msg_bytes)?;
    w.flush()
}
