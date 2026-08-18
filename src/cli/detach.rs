//! Running a mount in the background (`--detach`).
//!
//! A mount command normally blocks for as long as the volume exists, which
//! makes scripting several mounts awkward.  With `--detach` the command is
//! re-run in a background process and the foreground one only waits until
//! the volume is actually usable, so a script can go on to the next mount
//! and later stop each one by mountpoint with `fsmnt unmount`.
//!
//! Only `--detach` itself is dropped from the arguments handed on, so
//! `--log-file` survives into the background process: its console output is
//! discarded, and the log file is then the only place it can say why a mount
//! failed.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Environment marker set on the background process, so it mounts instead
/// of detaching again even if the flag below is somehow still in its
/// argument list.
const CHILD_MARKER: &str = "FSMNT_DETACHED";

/// The flag that requests detaching; dropped from the arguments handed to
/// the background process.
const DETACH_FLAG: &str = "--detach";

/// How long to wait for the background mount to become usable.
const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How often the mountpoint is checked while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// `CREATE_NEW_PROCESS_GROUP`: the background mount gets its own console
/// process group, so a later Ctrl+C in the parent's shell does not reach
/// it.
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// `DETACHED_PROCESS`: the background mount runs with no console of its
/// own and does not inherit the parent's.
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;

/// Stops the background mount from inheriting this process's standard
/// handles.
///
/// `Command` creates processes with handle inheritance enabled, so
/// anything the shell handed us that is marked inheritable — notably the
/// write end of a pipe, whenever the command's output is piped or captured
/// — would be duplicated into the background mount and held open for as
/// long as the volume exists, leaving the shell waiting on a pipe that
/// never closes.  Clearing the flag on our own handles first keeps the
/// background process out of that pipeline; the handles keep working here,
/// only inheritance is affected.  Unix needs no equivalent, as the child's
/// other descriptors are closed on exec.
#[cfg(windows)]
fn drop_handle_inheritance() {
    use windows_sys::Win32::Foundation::{
        HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: both calls only read or alter the inheritance flag of
        // this process's own standard handles, and unusable handles are
        // skipped.
        unsafe {
            let handle = GetStdHandle(id);
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
            }
        }
    }
}

/// Whether this process is the background mount spawned by [`spawn`].
pub fn is_background_mount() -> bool {
    std::env::var_os(CHILD_MARKER).is_some()
}

/// Re-runs this process's command line in the background and waits until
/// `mountpoint` is mounted, returning the background process id.
///
/// The background process gets the same arguments minus `--detach`, no
/// console (Windows) and its own process group (Unix), and null standard
/// streams — its output would otherwise land in a shell that has already
/// moved on.
///
/// # Errors
///
/// Returns an error if this executable's path cannot be determined, the
/// background process cannot be started, it exits before the volume is
/// ready (its console output is gone with its console, so the message
/// suggests re-running in the foreground — or `--log-file`, which it keeps),
/// or the volume does not appear within [`READY_TIMEOUT`].
pub fn spawn(mountpoint: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let program = std::env::current_exe()?;
    let flag = std::ffi::OsStr::new(DETACH_FLAG);
    let args = std::env::args_os().skip(1).filter(|arg| arg != flag);

    let mut command = Command::new(program);
    command
        .args(args)
        .env(CHILD_MARKER, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        drop_handle_inheritance();
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn()?;
    let pid = child.id();
    let deadline = Instant::now() + READY_TIMEOUT;

    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "the background mount exited before {mountpoint} was ready ({status}); \
                 re-run with --log-file, or without {DETACH_FLAG}, to see why"
            )
            .into());
        }
        if fsmnt::is_mounted(mountpoint) {
            return Ok(pid);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{mountpoint} was not mounted within {}s; the background mount (pid {pid}) may \
                 still be starting — run 'fsmnt unmount {mountpoint}' to stop it",
                READY_TIMEOUT.as_secs()
            )
            .into());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}
