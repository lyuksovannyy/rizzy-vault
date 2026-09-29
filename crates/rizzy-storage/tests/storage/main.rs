//! Integration tests of `rizzy-storage` against real databases.
//!
//! - [`sqlite`]: real SQLite files in a temporary directory, always run.
//! - [`postgres`]: a real PostgreSQL database, `#[ignore]`d unless run with
//!   `RIZZY_TEST_POSTGRES_URL=postgres://… cargo test -p rizzy-storage -- --ignored`, where the
//!   URL names an empty database the tests may fill (and a local server, or
//!   `sslmode=verify-full`).

mod common;
mod postgres;
mod sqlite;
