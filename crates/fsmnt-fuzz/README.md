# fsmnt fuzzing

This first-party crate keeps fuzz sources in Cargo's standard `src/bin`
layout. Its control record is a typed little-endian structure; discriminants
are converted to semantic enums before calling `fs-btrfs`. Canonical mutation
modes are serialized by `fs-btrfs` itself, so the harness does not duplicate
Btrfs field offsets.

List and run the targets from the workspace root:

```powershell
cargo +nightly fuzz list --fuzz-dir crates/fsmnt-fuzz
cargo +nightly fuzz run btrfs_parser --fuzz-dir crates/fsmnt-fuzz -- -max_len=131072
```

Use `-runs=N` for a bounded regression campaign. Corpus and artifact
directories are generated locally and ignored by Git.

On Windows, cargo-fuzz links the MSVC AddressSanitizer runtime dynamically.
The workspace helper locates the matching Visual Studio runtime, scopes its
directory to the child process, and runs a bounded campaign:

```powershell
.\scripts\run_btrfs_fuzz.ps1 -Runs 100000 -MaxLength 131072
```
