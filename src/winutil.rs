use anyhow::{bail, Context, Result};
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::core::PWSTR;
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

pub const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;

pub fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn wide_str(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Compare a `windows` error against a Win32 error code. The crate reports
/// Win32 failures as `HRESULT_FROM_WIN32(code)`, not as the bare code.
pub fn is_win32(
    error: &windows::core::Error,
    code: windows::Win32::Foundation::WIN32_ERROR,
) -> bool {
    error.code() == windows::core::HRESULT::from_win32(code.0)
}

/// Add the Win32 verbatim prefix so file APIs do not apply MAX_PATH limits or
/// legacy path normalization. Input must already be absolute and normalized.
pub fn verbatim(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text.starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix(r"\\") {
        return PathBuf::from(format!(r"\\?\UNC\{rest}"));
    }
    if text.len() >= 3 && text.as_bytes()[1] == b':' {
        return PathBuf::from(format!(r"\\?\{text}"));
    }
    path.to_path_buf()
}

pub fn known_folder(folder: &windows::core::GUID) -> Result<PathBuf> {
    let raw: PWSTR = unsafe {
        SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None)
            .context("SHGetKnownFolderPath failed")?
    };
    let result = unsafe { raw.to_string() }.context("known folder path is not valid UTF-16");
    unsafe { CoTaskMemFree(Some(raw.0 as *const c_void)) };
    let path = result?;
    if path.is_empty() {
        bail!("known folder path is empty");
    }
    Ok(PathBuf::from(path))
}

pub fn local_app_data() -> Result<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

pub fn file_attributes(path: &Path) -> Result<FILE_FLAGS_AND_ATTRIBUTES> {
    let wide_path = wide(verbatim(path));
    let attrs = unsafe { GetFileAttributesW(windows::core::PCWSTR(wide_path.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(windows::core::Error::from_thread())
            .with_context(|| format!("GetFileAttributesW failed for {}", path.display()));
    }
    Ok(FILE_FLAGS_AND_ATTRIBUTES(attrs))
}

pub fn set_readonly(path: &Path, readonly: bool) -> Result<()> {
    let attrs = file_attributes(path)?;
    let mut value = attrs.0;
    if readonly {
        value |= FILE_ATTRIBUTE_READONLY.0;
    } else {
        value &= !FILE_ATTRIBUTE_READONLY.0;
    }
    let wide_path = wide(verbatim(path));
    unsafe {
        SetFileAttributesW(
            windows::core::PCWSTR(wide_path.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(value),
        )
    }
    .with_context(|| format!("SetFileAttributesW failed for {}", path.display()))
}

pub fn is_reparse_point(attrs: FILE_FLAGS_AND_ATTRIBUTES) -> bool {
    attrs.0 & windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("random generator failed: {error}"))?;
    Ok(bytes)
}

pub fn random_hex<const N: usize>() -> Result<String> {
    let bytes = random_bytes::<N>()?;
    let mut out = String::with_capacity(N * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    Ok(out)
}
