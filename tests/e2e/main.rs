//! End-to-end tests: the real `dog` binary, run against loopback servers
//! that replay responses captured from real nameservers.
//!
//! Nothing here touches the internet. Output that must not change is kept
//! in golden files under `tests/golden/`; see `test_support::golden`.

mod common;
mod exit_codes;
mod meta;
mod pipes;
mod records;
mod request_shape;
mod transports;
