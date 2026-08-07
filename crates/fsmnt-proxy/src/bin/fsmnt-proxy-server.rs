//! Privileged filesystem proxy server.
//!
//! Unix:    `sudo fsmnt-proxy-server [socket_path]`
//! Windows: run as Administrator — `fsmnt-proxy-server.exe [pipe_path]`

fn main() {
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
        eprintln!("fsmnt-proxy-server: fatal: {e}");
        std::process::exit(1);
    }
}
