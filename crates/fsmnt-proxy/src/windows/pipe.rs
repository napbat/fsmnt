//! Named-pipe helpers for Windows handle-passing.
//!
//! The server opens a device with elevated privileges, then uses
//! `DuplicateHandle` to inject the handle into the client process.
//! The client receives the handle value over the pipe and wraps it
//! as a `std::fs::File`.

use std::io;

use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

/// Duplicate `source_handle` (owned by the current process) into the
/// process that owns the other end of `pipe_handle`.
///
/// Returns the raw handle value *in the client's handle table* as an
/// `u64` suitable for sending over the wire.
pub(crate) fn duplicate_to_pipe_client(
    pipe_handle: HANDLE,
    source_handle: HANDLE,
) -> io::Result<u64> {
    unsafe {
        // Get the PID of the process connected to the named pipe.
        let mut client_pid: u32 = 0;
        GetNamedPipeClientProcessId(pipe_handle, &raw mut client_pid)
            .map_err(|e| io::Error::other(format!("GetNamedPipeClientProcessId: {e}")))?;

        // Open the client process with permission to duplicate handles into it.
        let client_process = OpenProcess(PROCESS_DUP_HANDLE, false, client_pid)
            .map_err(|e| io::Error::other(format!("OpenProcess({client_pid}): {e}")))?;

        // Duplicate the handle into the client process.
        let mut target_handle = HANDLE::default();
        let current_process = GetCurrentProcess();

        let result = DuplicateHandle(
            current_process,
            source_handle,
            client_process,
            &raw mut target_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        );

        let _ = CloseHandle(client_process);

        result.map_err(|e| io::Error::other(format!("DuplicateHandle: {e}")))?;

        u64::try_from(target_handle.0.addr())
            .map_err(|_| io::Error::other("duplicated handle does not fit the wire format"))
    }
}
