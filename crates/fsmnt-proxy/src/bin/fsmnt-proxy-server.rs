//! Privileged filesystem proxy server.
//!
//! Unix:    `sudo fsmnt-proxy-server [socket_path]`
//! Windows: run as Administrator — `fsmnt-proxy-server.exe [pipe_path]`

use std::io::IsTerminal;

use tracing::error;
use tracing_subscriber::EnvFilter;

fn main() {
    // Diagnostics go to stderr, filtered by `FSMNT_LOG` (default `info`).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("FSMNT_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .without_time()
        .with_target(false)
        .init();

    let mut args = std::env::args();
    let program = args
        .next()
        .unwrap_or_else(|| "fsmnt-proxy-server".to_string());
    let endpoint = args.next();
    if args.next().is_some() {
        eprintln!("Usage: {program} [endpoint]");
        std::process::exit(1);
    }

    let endpoint = endpoint.as_deref().unwrap_or(fsmnt_proxy::DEFAULT_ENDPOINT);

    if let Err(e) = fsmnt_proxy::server::listen(endpoint) {
        error!(endpoint, error = %e, "the proxy server stopped");
        std::process::exit(1);
    }
}
