//! Development-only AIP child used by the stub integration test.
//!
//! The same executable is stored in the test package as both `client.exe` and
//! `backend.exe`; it picks its role from its own file name. Behaviour is
//! controlled by environment variables inherited from the test:
//!
//! - `AIP_TEST_MARKER`: append phase lines to this file.
//! - `AIP_TEST_MODE=cancel`: the client connects and exits without sending
//!   `readyToExit`.
//!
//! This binary is never built for release because it requires the `dev`
//! feature.

use anyhow::{bail, Context, Result};
use std::io::Write;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};

fn main() -> Result<()> {
    let pipe_name = argument("--aip-pipe-name")?;
    let handle = connect(&format!(r"\\.\pipe\{pipe_name}"))?;
    let role = std::env::current_exe()?
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let result = if role == "backend.exe" {
        backend(handle)
    } else {
        client(handle)
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn argument(name: &str) -> Result<String> {
    let mut arguments = std::env::args_os();
    while let Some(argument) = arguments.next() {
        if argument == name {
            return arguments
                .next()
                .map(|value| value.to_string_lossy().into_owned())
                .with_context(|| format!("{name} requires a value"));
        }
    }
    bail!("missing required argument {name}")
}

fn connect(pipe_path: &str) -> Result<HANDLE> {
    let wide: Vec<u16> = pipe_path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            None,
        )
    }
    .with_context(|| format!("failed to open {pipe_path}"))
}

fn mark(event: &str) {
    let Some(path) = std::env::var_os("AIP_TEST_MARKER") else {
        return;
    };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{event}");
    }
}

fn client(handle: HANDLE) -> Result<()> {
    mark("client:connected");
    if std::env::var("AIP_TEST_MODE").as_deref() == Ok("cancel") {
        mark("client:cancel");
        return Ok(());
    }
    write_frame(
        handle,
        b"type = \"setInstallLocation\"\nvalue = 'C:\\Apps\\Example'",
    )?;
    write_frame(handle, b"type = \"startInstall\"")?;
    mark("client:startInstall");
    let frame = read_frame(handle)?;
    if !contains(&frame, b"installFinished") {
        bail!("client received an unexpected frame: {frame:?}");
    }
    mark("client:installFinished");
    write_frame(handle, b"type = \"readyToExit\"")?;
    mark("client:readyToExit");
    Ok(())
}

fn backend(handle: HANDLE) -> Result<()> {
    mark("backend:connected");
    if std::env::var("AIP_TEST_MODE").as_deref() == Ok("backend-crash") {
        mark("backend:crash");
        return Ok(());
    }
    let frame = read_frame(handle)?;
    if !contains(&frame, b"setInstallLocation") {
        bail!("backend received an unexpected frame: {frame:?}");
    }
    mark("backend:setInstallLocation");
    let frame = read_frame(handle)?;
    if !contains(&frame, b"startInstall") {
        bail!("backend received an unexpected frame: {frame:?}");
    }
    mark("backend:startInstall");
    write_frame(handle, b"type = \"installFinished\"\nsuccess = true")?;
    mark("backend:installFinished");
    Ok(())
}

fn read_frame(handle: HANDLE) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    read_exact(handle, &mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > 1024 * 1024 {
        bail!("invalid frame length {length}");
    }
    let mut body = vec![0u8; length];
    read_exact(handle, &mut body)?;
    Ok(body)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn read_exact(handle: HANDLE, buffer: &mut [u8]) -> Result<()> {
    let mut total = 0usize;
    while total < buffer.len() {
        let mut read = 0u32;
        unsafe { ReadFile(handle, Some(&mut buffer[total..]), Some(&mut read), None) }
            .context("ReadFile failed")?;
        if read == 0 {
            bail!("pipe closed in the middle of a frame");
        }
        total += read as usize;
    }
    Ok(())
}

fn write_frame(handle: HANDLE, body: &[u8]) -> Result<()> {
    let mut encoded = Vec::with_capacity(4 + body.len());
    encoded.extend_from_slice(&(body.len() as u32).to_le_bytes());
    encoded.extend_from_slice(body);
    let mut total = 0usize;
    while total < encoded.len() {
        let mut written = 0u32;
        unsafe { WriteFile(handle, Some(&encoded[total..]), Some(&mut written), None) }
            .context("WriteFile failed")?;
        if written == 0 {
            bail!("pipe write made no progress");
        }
        total += written as usize;
    }
    Ok(())
}
