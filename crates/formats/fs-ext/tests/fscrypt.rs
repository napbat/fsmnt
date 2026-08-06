//! End-to-end fscrypt acceptance tests for issue #121.
//!
//! Reads the deterministic `ext4-fscrypt.img` fixture; reconstructs the
//! master keys via SHA-512 derivation; exercises every #121 acceptance
//! criterion plus #123's combined `ENCRYPT_FL+CASEFOLD_FL` path.
//!
//! The fixture is committed to git; if it goes missing the tests fail
//! fast pointing to `sudo bash crates/fs-ext/testdata/gen-fixtures.sh`.

#![cfg(feature = "fscrypt")]

#[path = "fscrypt/basic.rs"]
mod basic;
#[path = "fscrypt/modes.rs"]
mod modes;
#[path = "fscrypt/nokey.rs"]
mod nokey;
#[path = "fscrypt/support.rs"]
mod support;
#[path = "fscrypt/wrapped.rs"]
mod wrapped;
