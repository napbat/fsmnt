# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. These
rules are enforced by tooling — do not work around them.

## Project

This repository is a Cargo workspace implementing a cross-platform read-only
virtual-mount system (ported from tracium's `fs-mount` stack). The root
package `fsmnt` is the umbrella: a library (`src/lib.rs`) re-exporting the
member crates plus the platform dispatch, and a CLI binary (`src/main.rs`)
kept as a thin wrapper over it. Member crates under `crates/`:

- `fsmnt-core` — `TargetFilesystem` trait, entry/metadata types,
  `DirFilesystem` host-directory backend, listing filters. Platform-neutral.
- `fsmnt-device` — block-device abstraction: `HostDriveEnumerator` trait,
  GPT/MBR parsing (`Disk`), `PartitionReader`, boot-sector detection, and
  the `FilesystemDriver`/`DriverRegistry` plug-in point for filesystem
  parsers. fsmnt ships **no** parsers; consumers register drivers.
- `fsmnt-device-windows` / `-linux` / `-macos` — per-OS drive enumeration
  and raw opening.
- `fsmnt-fuse` / `fsmnt-dokan` — the mount backends (Unix FUSE / Windows
  Dokan).
- `crates/formats/` — parent directory (not a crate) for filesystem-format
  parser crates (NTFS, FAT, ext, …); members via the `crates/formats/*`
  glob. Each parser implements `TargetFilesystem` and plugs into device
  mounting through a `FilesystemDriver` adapter.

Platform-specific crates must self-gate: their dependencies live under
`[target.'cfg(...)'.dependencies]` and their modules behind `#[cfg(...)]`,
so they compile to empty libraries on other targets and workspace-wide
builds succeed on every OS.

The Rust toolchain (latest stable) and `prek` are managed by
[mise](https://mise.jdx.dev/) via `mise.toml`. Git hooks are
managed by [prek](https://github.com/j178/prek) via `.pre-commit-config.yaml`.

## Setup

```sh
mise install   # installs the pinned Rust toolchain and prek
prek install   # installs the git pre-commit hooks
```

## Rules (non-negotiable)

### 1. Clippy pedantic is enforced

- The root `Cargo.toml` sets `[workspace.lints.clippy] pedantic = { level = "deny", priority = -1 }`,
  inherited by every crate via `[lints] workspace = true`. Never remove,
  weaken, or bypass this.
- All code must pass `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Blanket suppression is forbidden: no `#![allow(clippy::pedantic)]`, no
  crate- or module-level `allow` attributes for pedantic lints.
- A narrowly scoped `#[allow(clippy::<specific_lint>, reason = "...")]` on a
  single item is acceptable only when the lint is genuinely wrong for that
  code, and the `reason` must explain why.

### 2. Public items must be documented

- The root `Cargo.toml` sets `[workspace.lints.rust] missing_docs = "deny"`.
- Every public item (functions, types, traits, modules, fields, …) requires a
  doc comment (`///`), and every crate root (`src/lib.rs`, `src/main.rs`)
  requires crate-level docs (`//!`).
- Doc comments must say something useful — restating the item name is not
  documentation. Pedantic's `missing_errors_doc` / `missing_panics_doc` also
  require `# Errors` / `# Panics` sections where applicable.

### 3. Everything comes from the workspace

- The root `Cargo.toml` is the workspace root. All shared configuration lives
  there: `[workspace.package]`, `[workspace.dependencies]`, and
  `[workspace.lints]`.
- Every dependency must be declared once in `[workspace.dependencies]`; a
  crate that needs it imports it with `<name> = { workspace = true }`
  (adding `features = [...]` per crate as needed). Never write a version
  number in a member crate's `[dependencies]`.
- Every crate must inherit workspace settings: `version.workspace = true`,
  `edition.workspace = true`, and `[lints] workspace = true`. Do not define
  per-crate lint tables.

### 4. Standard Cargo project layout

Follow the [Cargo project layout](https://doc.rust-lang.org/cargo/guide/project-layout.html):

```
.
├── Cargo.toml         # workspace root + fsmnt umbrella package
├── Cargo.lock
├── src/               # umbrella library (lib.rs) + CLI (main.rs)
└── crates/
    └── <name>/        # member crate, each following the standard layout:
        ├── Cargo.toml
        ├── src/       #   lib.rs (+ modules)
        ├── benches/   #   benchmarks
        ├── examples/  #   examples
        └── tests/     #   integration tests
```

- All source code lives under `src/`. Integration tests go in `tests/`,
  examples in `examples/`, benchmarks in `benches/`.
- Do not invent other top-level source directories or place `.rs` files
  outside these locations.
- Additional crates join the workspace as members under `crates/<name>/`,
  each following this same layout and the workspace-inheritance rules above.

### 5. Rust files must not exceed 1000 lines

- No `.rs` file may exceed 1000 lines. This is enforced by the
  `max-file-lines` prek hook (`scripts/check_max_lines.py`).
- Approaching the limit is a signal to split the file into submodules, not to
  compress or densify the code.

## Checks

Run these before considering any change complete:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
prek run --all-files
```

The same checks run as git pre-commit hooks via prek. Never commit with
`--no-verify`.
