//! Development-only package builder.
//!
//! This module exists so the stub's unit and integration tests can construct
//! packages without a separate packager. It is compiled for tests and for
//! builds with the `dev` feature, never for a release build.

use sha2::{Digest, Sha256};

pub const ARCHIVE_MAGIC: &[u8; 4] = b"AIPK";
pub const DIRECTORY_MAGIC: &[u8; 4] = b"AIPD";
pub const FOOTER_MAGIC: &[u8; 4] = b"AIPF";
pub const FOOTER_END_MAGIC: &[u8; 8] = b"AIP1END\0";
pub const FORMAT_VERSION: u32 = 1;

/// Build an image with `prefix` (normally a PE stub), the archive, the
/// directory, the footer, and optional trailing bytes that simulate an
/// Authenticode certificate table.
pub fn build_package(entries: &[(String, Vec<u8>)], prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let archive_offset = prefix.len() as u64;
    let mut data = prefix.to_vec();
    let mut body = Vec::new();
    body.extend_from_slice(ARCHIVE_MAGIC);
    body.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    let mut directory = Vec::new();
    directory.extend_from_slice(DIRECTORY_MAGIC);
    directory.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    directory.extend_from_slice(&(entries.len() as u32).to_le_bytes());

    let mut offsets = Vec::new();
    for (_, content) in entries {
        offsets.push(archive_offset + body.len() as u64);
        body.extend_from_slice(content);
    }
    for ((name, content), offset) in entries.iter().zip(offsets) {
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(name.as_bytes());
        directory.extend_from_slice(&offset.to_le_bytes());
        directory.extend_from_slice(&(content.len() as u64).to_le_bytes());
        directory.extend_from_slice(&Sha256::digest(content));
    }

    let directory_offset = archive_offset + body.len() as u64;
    let directory_size = directory.len() as u64;
    body.extend_from_slice(&directory);
    let archive_size = body.len() as u64;
    data.extend_from_slice(&body);

    let mut footer = Vec::new();
    footer.extend_from_slice(FOOTER_MAGIC);
    footer.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    footer.extend_from_slice(&archive_offset.to_le_bytes());
    footer.extend_from_slice(&archive_size.to_le_bytes());
    footer.extend_from_slice(&directory_offset.to_le_bytes());
    footer.extend_from_slice(&directory_size.to_le_bytes());
    footer.extend_from_slice(FOOTER_END_MAGIC);
    data.extend_from_slice(&footer);
    data.extend_from_slice(suffix);
    data
}

/// A minimal local PE image for tests that only need `MZ`/`PE\0\0`.
pub fn fake_pe() -> Vec<u8> {
    let mut data = vec![0u8; 256];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    data
}
