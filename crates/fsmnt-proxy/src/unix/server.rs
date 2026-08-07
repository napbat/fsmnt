//! Server-side logic for the device proxy (Unix).
//!
//! The server's only job is to open files/devices with elevated privileges
//! and pass the raw fd back to the client via `SCM_RIGHTS`.  After that,
//! all I/O goes directly through the kernel — the server is not involved.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use crate::{MAX_PATH_LEN, OP_OPEN, OpenMode, STATUS_ERR, STATUS_OK};

/// Listen for connections and handle them in threads.
///
/// Binds to `endpoint`, sets permissions to `0o666`, then loops
/// accepting clients.  Each client is handled in a new thread via
/// [`handle_client`].  This function never returns under normal
/// operation.
///
/// # Errors
///
/// Returns an I/O error if the socket cannot be removed, bound, or
/// configured.
pub fn listen(endpoint: &str) -> io::Result<()> {
    let path = Path::new(endpoint);
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }

    let listener = UnixListener::bind(endpoint)?;

    // Allow any user to connect.
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o666);
        let _ = std::fs::set_permissions(endpoint, perms);
    }

    eprintln!("fsmnt-proxy-server: listening on {endpoint}");
    eprintln!("fsmnt-proxy-server: waiting for connections… (Ctrl+C to stop)");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    eprintln!("fsmnt-proxy-server: client connected");
                    if let Err(e) = handle_client(stream) {
                        eprintln!("fsmnt-proxy-server: client error: {e}");
                    }
                    eprintln!("fsmnt-proxy-server: client disconnected");
                });
            }
            Err(e) => {
                eprintln!("fsmnt-proxy-server: accept error: {e}");
            }
        }
    }

    Ok(())
}

/// Handle a single client connection.
///
/// The client sends `OP_OPEN` requests; the server opens the path and
/// responds with a status byte followed by either the fd + size (on
/// success) or an error message (on failure).  The connection stays
/// open so the client can request multiple files.
///
/// # Errors
///
/// Returns an I/O error if a request or response cannot be transferred or a
/// request is malformed.
pub fn handle_client(mut stream: UnixStream) -> io::Result<()> {
    loop {
        let mut opcode = [0u8; 1];
        if stream.read_exact(&mut opcode).is_err() {
            return Ok(()); // Client disconnected
        }

        match opcode[0] {
            OP_OPEN => {
                // Read: u8 mode + i32 flags + u16 path_len + path
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

                let mut path_buf = vec![0u8; path_len];
                stream.read_exact(&mut path_buf)?;
                let path = String::from_utf8_lossy(&path_buf).into_owned();

                let mut opts = OpenOptions::new();
                mode.apply(&mut opts);
                if flags != 0 {
                    opts.custom_flags(flags);
                }

                match opts.open(&path) {
                    Ok(mut file) => {
                        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
                        // Seek back — the fd shares the file description
                        // with the client, so the position carries over.
                        file.seek(SeekFrom::Start(0)).unwrap_or(0);
                        let fd = file.as_raw_fd();

                        // Send STATUS_OK as plain data first so the client
                        // can distinguish success from error before calling
                        // recv_fd.
                        stream.write_all(&[STATUS_OK])?;
                        stream.flush()?;

                        // Then send the size + fd via SCM_RIGHTS.
                        super::scm::send_fd(&stream, fd, &size.to_le_bytes())?;
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
