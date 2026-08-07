//! Unit tests for proxy handle passing and direct-open fallback.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use tempfile::TempDir;

use crate::{OpenMode, ProxyClient, open_with_proxy_fallback};

#[cfg(unix)]
mod platform {
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::thread;

    use super::JoinHandle;
    use crate::server::handle_client;

    pub(super) fn endpoint(directory: &Path) -> String {
        directory.join("proxy.sock").to_string_lossy().into_owned()
    }

    pub(super) fn start_test_server(endpoint: &str) -> JoinHandle<()> {
        let listener = UnixListener::bind(endpoint).expect("bind test proxy socket");

        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept test proxy client");
            handle_client(stream).expect("serve test proxy client");
        })
    }
}

#[cfg(windows)]
mod platform {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use super::JoinHandle;
    use crate::windows::server::{PipeStream, connect_pipe, create_pipe_instance, handle_client};

    static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn endpoint(_directory: &Path) -> String {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let process = std::process::id();
        format!(r"\\.\pipe\fsmnt-test-{process}-{id}")
    }

    pub(super) fn start_test_server(endpoint: &str) -> JoinHandle<()> {
        let endpoint = endpoint.to_string();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(0);

        let server = thread::spawn(move || {
            let handle = create_pipe_instance(&endpoint, true).expect("create test proxy pipe");
            ready_sender.send(()).expect("signal test proxy readiness");
            connect_pipe(handle).expect("connect test proxy pipe");
            // SAFETY: `handle` is a connected pipe instance owned by this
            // thread, and `PipeStream` assumes responsibility for closing it.
            let stream = unsafe { PipeStream::from_raw(handle) };
            handle_client(&stream).expect("serve test proxy client");
        });

        ready_receiver
            .recv()
            .expect("wait for test proxy readiness");
        server
    }
}

fn test_file(directory: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let path = directory.path().join(name);
    std::fs::write(&path, content).expect("write test device");
    path
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn proxy_client_opens_reads_and_seeks() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let endpoint = platform::endpoint(directory.path());
    let server = platform::start_test_server(&endpoint);
    let data = b"0123456789ABCDEF";
    let path = test_file(&directory, "device.bin", data);

    let mut client = ProxyClient::connect(&endpoint).expect("connect proxy client");
    let opened = client
        .open(&path_text(&path))
        .expect("open file through proxy");

    assert_eq!(
        opened.size,
        u64::try_from(data.len()).expect("test data length fits u64")
    );

    let mut file = opened.file;
    assert_eq!(file.seek(SeekFrom::Start(10)).expect("seek proxy file"), 10);

    let mut buffer = [0_u8; 4];
    file.read_exact(&mut buffer).expect("read proxy file");
    assert_eq!(&buffer, b"ABCD");

    drop(client);
    server.join().expect("join test proxy server");
}

#[test]
fn proxy_client_reports_missing_file() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let endpoint = platform::endpoint(directory.path());
    let server = platform::start_test_server(&endpoint);
    let missing = directory.path().join("missing-device.bin");

    let mut client = ProxyClient::connect(&endpoint).expect("connect proxy client");
    let result = client.open(&path_text(&missing));
    assert!(result.is_err(), "missing file should fail: {result:?}");

    drop(client);
    server.join().expect("join test proxy server");
}

#[test]
fn proxy_client_reports_missing_endpoint() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let endpoint = platform::endpoint(directory.path());

    let result = ProxyClient::connect(endpoint);
    assert!(result.is_err());
}

#[test]
fn fallback_opens_accessible_file_directly() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let data = b"direct access";
    let path = test_file(&directory, "direct.bin", data);
    let mut file = open_with_proxy_fallback(&path_text(&path), OpenMode::ReadOnly, 0)
        .expect("open accessible file directly");

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("read direct file");
    assert_eq!(buffer, data);
}
