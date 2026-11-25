//! Anyinstaller Protocol (AIP) v1 stub.
//!
//! The stub is the trusted entry point of a single-file Anyinstaller package.
//! It verifies the package signature, validates the embedded configuration,
//! extracts the package into a private session directory, launches the client
//! and backend, relays AIP frames, and cleans the session up.

#![cfg(windows)]

pub mod acl;
#[cfg(any(test, feature = "dev"))]
pub mod build;
pub mod config;
pub mod frame;
pub mod package;
pub mod path;
pub mod pipe;
pub mod process;
pub mod session;
pub mod signature;
pub mod stub;
pub mod winutil;

pub use stub::run;
