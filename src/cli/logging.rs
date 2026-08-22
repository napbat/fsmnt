//! Everything the command line says that is not the command's product.
//!
//! The tables, and the mount lifecycle lines a script keys on, go to stdout
//! by `println!`. Everything else — what was detected where, why a partition
//! table is synthetic, which sectors could not be read, the final error —
//! is a `tracing` event, so the same message reaches the console, a log
//! file, or neither, according to `-v`/`-q`/`--log-file`/`FSMNT_LOG`. That
//! also picks up the libraries: every first-party crate emits events, and
//! `tracing-log` forwards what `fuser` and `ewf` write through the `log`
//! crate into the same stream.
//!
//! The format is deliberately unlike a server log — no timestamps, no span
//! list, one line per event reading `level: message key=value` — because
//! these messages are read next to the command's own output, in a terminal,
//! while the operator is working.

use std::error::Error;
use std::fmt;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Args};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::{Format, Json, JsonFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt as _;
use tracing_subscriber::{EnvFilter, Layer};

use super::output::SCHEMA;

/// Environment variable holding [`EnvFilter`] directives.
///
/// A filter written here is the whole answer: it overrides `-v`/`-q`,
/// because "`fsmnt_device=trace,info`" is a statement `-vv` cannot make.
const FILTER_ENV: &str = "FSMNT_LOG";

/// How much the command says, where it says it, and in what form.
///
/// Global on purpose: `fsmnt -v partitions disk.bin` and
/// `fsmnt partitions disk.bin -v` are the same command, and a flag whose
/// position matters is a flag people get wrong. `--json` sits here for the
/// same reason and because it answers the same question — who is reading —
/// rather than anything about the media.
#[derive(Args, Clone, Debug, Default)]
pub(crate) struct LogOptions {
    /// Say more on stderr: once for the decisions inside the library
    /// (`-v`, debug), twice for every operation a mounted volume serves
    /// (`-vv`, trace). Without it, progress and outcomes only.
    #[arg(short, long, action = ArgAction::Count, global = true, display_order = 900)]
    pub(crate) verbose: u8,

    /// Say less on stderr: warnings and errors only, so a scripted mount's
    /// log keeps what went wrong and nothing else.
    #[arg(
        short,
        long,
        global = true,
        conflicts_with = "verbose",
        display_order = 901
    )]
    pub(crate) quiet: bool,

    /// Append every message to this file as well, without colour. Kept
    /// across `--detach`, so a mount that failed in the background can
    /// still say why.
    #[arg(long, value_name = "PATH", global = true, display_order = 902)]
    pub(crate) log_file: Option<PathBuf>,

    /// Speak to a program instead of a person: stdout carries JSON only —
    /// one document for `drives`, `partitions`, `scan` and `unmount`, one
    /// event per line for `mount` — and every message on stderr becomes one
    /// JSON object keyed by `level`. `-v`/`-q` still choose how much is
    /// said, and `--log-file` stays plain text. See "Machine-readable
    /// output" in the README for the documents and the stability promise.
    #[arg(long, global = true, display_order = 903)]
    pub(crate) json: bool,
}

/// Report an error that occurs before the tracing subscriber is available.
///
/// Parsing and subscriber setup can both fail before an `error!` event can
/// be emitted. This keeps those failures inside the same stderr contract as
/// later events when `--json` was requested, while retaining clap-style text
/// for a person.
pub(crate) fn report_startup_error(json: bool, error: &dyn fmt::Display) {
    if json {
        eprintln!(
            "{}",
            serde_json::json!({
                "schema": SCHEMA,
                "level": "ERROR",
                "message": error.to_string(),
            })
        );
    } else {
        eprintln!("error: {error}");
    }
}

/// Install the subscriber these options describe.
///
/// Two layers over one registry: stderr, coloured only for a terminal, and
/// the optional log file. Both are filtered the same way, so the file is a
/// transcript of the console rather than a different account of the run.
///
/// The log file keeps its plain-text format even under `--json`, because a
/// log file is read by a person after the fact while the stream a program
/// parses is stderr.
///
/// # Errors
///
/// Returns an error if `FSMNT_LOG` holds directives that do not parse, the
/// log file cannot be opened for appending, or a subscriber is already
/// installed in this process.
pub(crate) fn init(options: &LogOptions) -> Result<(), Box<dyn Error>> {
    let show_target = options.verbose > 0;
    let console = console_layer(options)?;

    let file = match options.log_file.as_deref() {
        Some(path) => Some(
            tracing_subscriber::fmt::layer()
                .with_writer(open_log_file(path)?)
                .with_ansi(false)
                .event_format(CompactFormat { show_target })
                .with_filter(filter(options)?),
        ),
        None => None,
    };

    // `tracing-log` is enabled, so this also installs `LogTracer`: the
    // records `fuser` and `ewf` write through the `log` crate arrive here
    // under the same filter as everything else.
    tracing_subscriber::registry()
        .with(console)
        .with(file)
        .try_init()?;
    Ok(())
}

/// The stderr layer, in whichever of the two formats was asked for.
///
/// Boxed because the two are different types and the choice is made at
/// runtime; the filter is built inside, since [`EnvFilter`] keeps
/// per-callsite state and cannot be cloned into both branches.
///
/// # Errors
///
/// Returns an error if `FSMNT_LOG` holds directives that do not parse.
fn console_layer<S>(options: &LogOptions) -> Result<Box<dyn Layer<S> + Send + Sync>, Box<dyn Error>>
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    if options.json {
        return Ok(tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .fmt_fields(JsonFields::new())
            .event_format(SchemaJson::new())
            .with_filter(filter(options)?)
            .boxed());
    }
    Ok(tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        // Escape codes are for a person watching; a redirected stream gets
        // plain text so a captured log stays greppable.
        .with_ansi(std::io::stderr().is_terminal())
        .event_format(CompactFormat {
            show_target: options.verbose > 0,
        })
        .with_filter(filter(options)?)
        .boxed())
}

/// Open the `--log-file` for appending, creating it if it does not exist.
///
/// Appending, never truncating: several mounts run against one log file is
/// the normal case, and a `--detach`ed mount is a second process writing to
/// the file the foreground one named.
fn open_log_file(path: &Path) -> Result<std::fs::File, Box<dyn Error>> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            format!(
                "failed to open log file '{}' for appending: {error}",
                path.display()
            )
            .into()
        })
}

/// The filter both layers use: `FSMNT_LOG` when it is set, else the level
/// `-v`/`-q` selects.
///
/// Built twice rather than cloned because [`EnvFilter`] keeps per-callsite
/// state and is not `Clone`.
fn filter(options: &LogOptions) -> Result<EnvFilter, Box<dyn Error>> {
    if std::env::var_os(FILTER_ENV).is_some() {
        return EnvFilter::try_from_env(FILTER_ENV).map_err(|error| {
            format!("{FILTER_ENV} is not a valid set of tracing directives: {error}").into()
        });
    }
    Ok(EnvFilter::new(
        console_level(options.verbose, options.quiet).as_str(),
    ))
}

/// The level `-q` and `-v...` ask for.
///
/// `info` by default: what was detected where, and where it was mounted.
const fn console_level(verbose: u8, quiet: bool) -> Level {
    if quiet {
        return Level::WARN;
    }
    match verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    }
}

/// One line per event: `level: message key=value`, and `level: target:
/// message …` once `-v` is on.
///
/// No timestamp — a command that runs for as long as a mount lives is read
/// as a narrative, not correlated across machines — and no span list, since
/// the fields carry the offsets and paths that would otherwise be in one.
struct CompactFormat {
    /// Whether to name the module each event came from, which is what makes
    /// `-v` output navigable once several crates are talking at once.
    show_target: bool,
}

impl<S, N> FormatEvent<S, N> for CompactFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let level = *metadata.level();
        if writer.has_ansi_escapes() {
            write!(
                writer,
                "\u{1b}[{}m{}\u{1b}[0m: ",
                level_colour(level),
                level_name(level)
            )?;
        } else {
            write!(writer, "{}: ", level_name(level))?;
        }
        if self.show_target {
            write!(writer, "{}: ", metadata.target())?;
        }
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// One JSON object per event, for `--json`.
///
/// The subscriber's own JSON format does the work — a flattened event, so
/// `message` and the event's fields sit beside `level`, `timestamp` and
/// `target`, with no span machinery a command-line tool has no use for. It
/// offers no way to add a constant field, so the object it produces is
/// reopened here to put [`SCHEMA`] in front: a program then reads the same
/// version marker off a stderr event as off a stdout document, without
/// having to know which stream it came from.
struct SchemaJson(Format<Json>);

impl SchemaJson {
    /// The format as `--json` configures it.
    fn new() -> Self {
        Self(
            tracing_subscriber::fmt::format()
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .with_span_list(false)
                .with_target(true),
        )
    }
}

impl<S, N> FormatEvent<S, N> for SchemaJson
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut line = String::new();
        self.0.format_event(ctx, Writer::new(&mut line), event)?;
        // Anything that is not the object it always is goes out untouched:
        // a malformed line is easier to diagnose than a mangled one.
        let Some(body) = line.trim_end().strip_prefix('{') else {
            return writer.write_str(&line);
        };
        let separator = if body.starts_with('}') { "" } else { "," };
        writeln!(writer, "{{\"schema\":{SCHEMA}{separator}{body}")
    }
}

/// Level name as the messages spell it: lowercase, so `warn: …` reads as
/// part of the sentence rather than as a banner.
fn level_name(level: Level) -> &'static str {
    match level {
        Level::ERROR => "error",
        Level::WARN => "warn",
        Level::INFO => "info",
        Level::DEBUG => "debug",
        _ => "trace",
    }
}

/// SGR parameters for a level, used only when stderr is a terminal.
fn level_colour(level: Level) -> &'static str {
    match level {
        Level::ERROR => "1;31",
        Level::WARN => "1;33",
        Level::INFO => "1;32",
        Level::DEBUG => "1;34",
        _ => "1;35",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::Level;
    use tracing_subscriber::fmt::MakeWriter;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{CompactFormat, console_level};

    /// A writer that keeps what was written, so a test can read the exact
    /// bytes an event produced.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Captured {
        /// Everything written so far.
        fn text(&self) -> String {
            let bytes = self.0.lock().expect("log buffer").clone();
            String::from_utf8(bytes).expect("the formatter writes UTF-8")
        }
    }

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for Captured {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    /// Run `emit` against a subscriber using this crate's event format, and
    /// return what it wrote.
    fn capture(show_target: bool, emit: impl FnOnce()) -> String {
        let captured = Captured::default();
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(captured.clone())
            .with_ansi(false)
            .event_format(CompactFormat { show_target });
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, emit);
        captured.text()
    }

    #[test]
    fn an_event_is_one_line_of_level_message_and_fields() {
        let text = capture(false, || {
            tracing::warn!(offset = 4096, "the partition table is synthetic");
        });
        assert_eq!(text, "warn: the partition table is synthetic offset=4096\n");
    }

    #[test]
    fn verbosity_names_the_module_each_event_came_from() {
        let text = capture(true, || tracing::debug!("classified the disk layout"));
        assert_eq!(
            text,
            "debug: fsmnt::cli::logging::tests: classified the disk layout\n"
        );
    }

    #[test]
    fn quiet_keeps_warnings_and_verbosity_adds_detail() {
        assert_eq!(console_level(0, false), Level::INFO);
        assert_eq!(console_level(1, false), Level::DEBUG);
        assert_eq!(console_level(2, false), Level::TRACE);
        assert_eq!(console_level(7, false), Level::TRACE);
        assert_eq!(
            console_level(0, true),
            Level::WARN,
            "-q still has to report what went wrong"
        );
    }
}
