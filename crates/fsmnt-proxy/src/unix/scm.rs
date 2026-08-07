//! `SCM_RIGHTS` helpers — send and receive raw file descriptors over Unix sockets.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Convert a `usize` into an ABI-specific message-header field.
fn usize_to_field<T: TryFrom<usize>>(value: usize, field: &'static str) -> io::Result<T> {
    T::try_from(value).map_err(|_| io::Error::other(format!("{field} does not fit its ABI field")))
}

/// Convert a `u32` into an ABI-specific control-message field.
fn u32_to_field<T: TryFrom<u32>>(value: u32, field: &'static str) -> io::Result<T> {
    T::try_from(value).map_err(|_| io::Error::other(format!("{field} does not fit its ABI field")))
}

/// Send a file descriptor over a Unix socket using `SCM_RIGHTS`.
///
/// Also sends `payload` as the normal data portion of the message.
pub(crate) fn send_fd(stream: &UnixStream, fd: RawFd, payload: &[u8]) -> io::Result<()> {
    let iov = [IoSlice::new(payload)];
    let raw_fd_size = u32::try_from(std::mem::size_of::<RawFd>())
        .map_err(|_| io::Error::other("file descriptor size does not fit c_uint"))?;
    // SAFETY: `CMSG_SPACE` is a pure size calculation for the supplied
    // payload length.
    let ancillary_buf_size = usize::try_from(unsafe { libc::CMSG_SPACE(raw_fd_size) })
        .map_err(|_| io::Error::other("ancillary buffer size does not fit usize"))?;
    let mut ancillary_buf = vec![0u8; ancillary_buf_size];

    // SAFETY: A zeroed `msghdr` is the documented initialization pattern;
    // every field used by `sendmsg` is populated below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_ptr().cast_mut().cast::<libc::iovec>();
    msg.msg_iovlen = usize_to_field(iov.len(), "I/O vector count")?;
    msg.msg_control = ancillary_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = usize_to_field(ancillary_buf_size, "ancillary buffer size")?;

    // SAFETY: `msg` names a control buffer sized by `CMSG_SPACE`.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    if cmsg.is_null() {
        return Err(io::Error::other("failed to construct SCM_RIGHTS header"));
    }
    // SAFETY: `cmsg` points into the live, sufficiently large ancillary
    // buffer owned by `msg`. The copied payload is exactly one `RawFd`.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = u32_to_field(libc::CMSG_LEN(raw_fd_size), "control message length")?;
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(&fd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    // SAFETY: `msg` and all buffers it references remain live for the call;
    // the socket fd is borrowed from `stream`.
    let ret = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const msg, 0) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Receive a file descriptor from a Unix socket via `SCM_RIGHTS`.
///
/// Returns `(bytes_read, fd)`. The caller owns the returned fd.
pub(crate) fn recv_fd(stream: &UnixStream, buf: &mut [u8]) -> io::Result<(usize, RawFd)> {
    let mut iov = [IoSliceMut::new(buf)];
    let raw_fd_size = u32::try_from(std::mem::size_of::<RawFd>())
        .map_err(|_| io::Error::other("file descriptor size does not fit c_uint"))?;
    // SAFETY: `CMSG_SPACE` is a pure size calculation for the supplied
    // payload length.
    let ancillary_buf_size = usize::try_from(unsafe { libc::CMSG_SPACE(raw_fd_size) })
        .map_err(|_| io::Error::other("ancillary buffer size does not fit usize"))?;
    let mut ancillary_buf = vec![0u8; ancillary_buf_size];

    // SAFETY: A zeroed `msghdr` is the documented initialization pattern;
    // every field used by `recvmsg` is populated below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov.as_mut_ptr().cast::<libc::iovec>();
    msg.msg_iovlen = usize_to_field(iov.len(), "I/O vector count")?;
    msg.msg_control = ancillary_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = usize_to_field(ancillary_buf_size, "ancillary buffer size")?;

    // SAFETY: `msg` and all buffers it references remain live for the call;
    // the socket fd is borrowed from `stream`.
    let ret = unsafe { libc::recvmsg(stream.as_raw_fd(), &raw mut msg, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut fd: RawFd = -1;
    // SAFETY: `msg` was initialized by a successful `recvmsg` call and its
    // control buffer remains live.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    if !cmsg.is_null() {
        // SAFETY: `cmsg` points into the control buffer populated by
        // `recvmsg`. Header values are checked before copying one `RawFd`.
        unsafe {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&raw mut fd).cast::<u8>(),
                    std::mem::size_of::<RawFd>(),
                );
            }
        }
    }

    if fd < 0 {
        return Err(io::Error::other("no fd received via SCM_RIGHTS"));
    }

    let bytes_read =
        usize::try_from(ret).map_err(|_| io::Error::other("negative receive length"))?;
    Ok((bytes_read, fd))
}
