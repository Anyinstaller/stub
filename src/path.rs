use anyhow::{bail, Context, Result};
use std::path::Path;
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::GetFullPathNameW;
use windows::Win32::UI::Shell::{
    FOLDERID_Desktop, FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_ProgramFiles,
    FOLDERID_ProgramFilesX86, FOLDERID_Programs, FOLDERID_Windows,
};

use crate::winutil;

const MAX_INSTALL_PATH_UTF16: usize = 32_767;
const MAX_PACKAGE_PATH_UTF16: usize = 32_767;

/// Expand `%VAR%` references exactly once, using the current process
/// environment. Unresolvable or malformed references are fatal.
pub fn expand_environment(input: &str) -> Result<String> {
    let chars: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(input.len());
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '%' {
            let start = index;
            index += 1;
            while index < chars.len() && chars[index] != '%' {
                index += 1;
            }
            if index == chars.len() {
                bail!("unterminated environment variable reference in {input:?}");
            }
            let name: String = chars[start + 1..index].iter().collect();
            if name.is_empty() {
                bail!("empty environment variable reference in {input:?}");
            }
            let value = std::env::var_os(&name)
                .with_context(|| format!("environment variable %{name}% is not defined"))?;
            output.push_str(&value.to_string_lossy());
            index += 1;
        } else {
            output.push(ch);
            index += 1;
        }
    }
    Ok(output)
}

/// Validate an install location template and return the expanded, normalized
/// local drive path. UNC, device, relative, drive-relative, ADS and traversal
/// paths are rejected.
pub fn validate_install_location(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("install location is empty");
    }
    if input.encode_utf16().count() > MAX_INSTALL_PATH_UTF16 {
        bail!("install location is too long");
    }
    let expanded = expand_environment(input)?;
    validate_absolute_shape(&expanded)?;
    let normalized = full_path(&expanded)?;
    validate_absolute_shape(&normalized)?;
    reject_protected_locations(&normalized)?;
    Ok(normalized)
}

/// Reject install locations that must never be used regardless of what the
/// package requests: drive roots, the Windows directory, and the root of
/// Program Files, ProgramData, the user profile, Desktop, and Start Menu.
fn reject_protected_locations(path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if bytes.len() == 3 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        bail!("install location must not be a drive root: {path:?}");
    }

    let roots = [
        (FOLDERID_Windows, true, "the Windows directory"),
        (FOLDERID_ProgramFiles, false, "the Program Files root"),
        (
            FOLDERID_ProgramFilesX86,
            false,
            "the Program Files (x86) root",
        ),
        (FOLDERID_ProgramData, false, "the ProgramData root"),
        (FOLDERID_Profile, false, "the user profile root"),
        (FOLDERID_Desktop, false, "the Desktop root"),
        (FOLDERID_Programs, false, "the Start Menu root"),
    ];
    for (folder, include_children, description) in roots {
        // Missing optional folders (for example Program Files (x86) on a
        // 32-bit system) are skipped; the remaining checks still apply.
        let Ok(root) = winutil::known_folder(&folder) else {
            continue;
        };
        let Ok(root) = full_path(&root.to_string_lossy()) else {
            continue;
        };
        if same_or_under(path, &root, include_children) {
            bail!("install location must not be {description}: {path:?}");
        }
    }
    Ok(())
}

fn same_or_under(path: &str, root: &str, include_children: bool) -> bool {
    let path = normalize_for_compare(path);
    let root = normalize_for_compare(root);
    if path == root {
        return true;
    }
    include_children
        && path
            .strip_prefix(&root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

fn normalize_for_compare(path: &str) -> String {
    path.trim_end_matches(['\\', '/']).to_lowercase()
}

/// Validate an install location against an additional forbidden root, such as
/// the session directory tree. The forbidden root and its children are
/// rejected.
pub fn validate_install_location_against(input: &str, forbidden_root: &Path) -> Result<String> {
    let normalized = validate_install_location(input)?;
    let forbidden = full_path(&forbidden_root.to_string_lossy())?;
    if same_or_under(&normalized, &forbidden, true) {
        bail!("install location must not be inside the session directory: {normalized:?}");
    }
    Ok(normalized)
}

fn validate_absolute_shape(path: &str) -> Result<()> {
    if path.encode_utf16().count() > MAX_INSTALL_PATH_UTF16 {
        bail!("path is too long");
    }
    for ch in path.chars() {
        if ch == '\0' || (ch as u32) < 0x20 {
            bail!("path contains a control character");
        }
    }
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || (bytes[2] != b'\\' && bytes[2] != b'/')
    {
        bail!("path must be an absolute local drive path: {path:?}");
    }
    let rest = &path[2..];
    if rest.contains(':') {
        bail!("path must not contain an alternate data stream: {path:?}");
    }
    for component in rest.split(['\\', '/']) {
        if component.is_empty() {
            continue;
        }
        if component == "." || component == ".." {
            bail!("path must not contain relative components: {path:?}");
        }
        if component.ends_with('.') || component.ends_with(' ') {
            bail!("path component ends with a dot or space: {component:?}");
        }
        if is_device_name(component) {
            bail!("path contains a reserved device name: {component:?}");
        }
    }
    Ok(())
}

fn full_path(path: &str) -> Result<String> {
    let input = crate::winutil::wide_str(path);
    let mut buffer = vec![0u16; 512];
    loop {
        let length = unsafe { GetFullPathNameW(PCWSTR(input.as_ptr()), Some(&mut buffer), None) };
        if length == 0 {
            return Err(windows::core::Error::from_thread())
                .with_context(|| format!("GetFullPathNameW failed for {path:?}"));
        }
        let length = length as usize;
        if length < buffer.len() {
            let text = String::from_utf16(&buffer[..length])
                .context("normalized path is not valid UTF-16")?;
            return Ok(text);
        }
        buffer.resize(length + 1, 0);
    }
}

/// Validate a package-internal relative path and normalize separators to `/`.
pub fn validate_package_relative(input: &str) -> Result<String> {
    if input.is_empty() {
        bail!("package path is empty");
    }
    if input.encode_utf16().count() > MAX_PACKAGE_PATH_UTF16 {
        bail!("package path is too long");
    }
    if input.starts_with('/') || input.starts_with('\\') {
        bail!("package path must be relative: {input:?}");
    }
    let mut normalized = String::with_capacity(input.len());
    for (index, raw_component) in input.split(['/', '\\']).enumerate() {
        if index > 0 {
            normalized.push('/');
        }
        if raw_component.is_empty() {
            bail!("package path contains an empty component: {input:?}");
        }
        if raw_component == "." || raw_component == ".." {
            bail!("package path contains a relative component: {input:?}");
        }
        if raw_component.ends_with('.') || raw_component.ends_with(' ') {
            bail!("package path component ends with a dot or space: {raw_component:?}");
        }
        if raw_component.contains(':') {
            bail!("package path must not contain a drive or alternate data stream: {input:?}");
        }
        if raw_component.chars().any(|ch| {
            ch == '\0' || (ch as u32) < 0x20 || matches!(ch, '<' | '>' | '"' | '|' | '?' | '*')
        }) {
            bail!("package path contains an invalid character: {input:?}");
        }
        if is_device_name(raw_component) {
            bail!("package path contains a reserved device name: {raw_component:?}");
        }
        normalized.push_str(raw_component);
    }
    Ok(normalized)
}

pub fn is_special_background(value: &str) -> bool {
    [
        "acrylic",
        "acrylicblur",
        "mica",
        "windowsmanaged",
        "transparent",
    ]
    .iter()
    .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

pub fn is_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|byte| byte.is_ascii_hexdigit())
}

pub fn is_device_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0')
}

pub fn is_local_absolute(path: &Path) -> bool {
    let text = path.to_string_lossy();
    validate_absolute_shape(&text).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_local_paths() {
        assert!(validate_install_location(r"D:\Apps\Example").is_ok());
        assert!(validate_install_location(r"C:\Program Files\Example").is_ok());
        assert!(validate_install_location(r"%LOCALAPPDATA%\Programs\Example").is_ok());
    }

    #[test]
    fn rejects_unsafe_install_paths() {
        for path in [
            r"\\server\share\app",
            r"\\.\C:\app",
            r"\\?\C:\app",
            r"C:app",
            r"app\sub",
            r"C:\Apps\..\Windows",
            r"C:\Apps\file:stream",
            r"C:\Apps\CON",
            r"C:\Apps\trailing.",
            r"C:\Apps\%NOPE%",
            "",
        ] {
            assert!(
                validate_install_location(path).is_err(),
                "expected rejection: {path:?}"
            );
        }
    }

    #[test]
    fn normalizes_package_paths() {
        assert_eq!(
            validate_package_relative(r"assets\background.avif").unwrap(),
            "assets/background.avif"
        );
        assert_eq!(
            validate_package_relative("assets/icon.ico").unwrap(),
            "assets/icon.ico"
        );
    }

    #[test]
    fn rejects_unsafe_package_paths() {
        for path in [
            "",
            "/absolute",
            r"C:\absolute",
            r"..\escape",
            "a/../b",
            "a//b",
            "a/b.",
            "a/NUL",
            "a/file:stream",
            "a/<bad>",
            "./file",
        ] {
            assert!(
                validate_package_relative(path).is_err(),
                "expected rejection: {path:?}"
            );
        }
    }

    #[test]
    fn background_values() {
        assert!(is_special_background("AcrylicBlur"));
        assert!(is_hex_color("#1e90ff"));
        assert!(!is_hex_color("#fff"));
        assert!(!is_hex_color("#GGGGGG"));
    }

    #[test]
    fn rejects_protected_roots() {
        assert!(validate_install_location(r"C:\").is_err());
        assert!(validate_install_location(r"C:/").is_err());

        let windows = winutil::known_folder(&FOLDERID_Windows).unwrap();
        assert!(validate_install_location(&windows.to_string_lossy()).is_err());
        assert!(validate_install_location(&windows.join("Temp").to_string_lossy()).is_err());

        let profile = winutil::known_folder(&FOLDERID_Profile).unwrap();
        assert!(validate_install_location(&profile.to_string_lossy()).is_err());
        assert!(validate_install_location(
            &profile.join("Programs").join("Example").to_string_lossy()
        )
        .is_ok());

        let program_files = winutil::known_folder(&FOLDERID_ProgramFiles).unwrap();
        assert!(validate_install_location(&program_files.to_string_lossy()).is_err());
        assert!(
            validate_install_location(&program_files.join("Example").to_string_lossy()).is_ok()
        );
    }

    #[test]
    fn rejects_session_tree() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("Sessions");
        let session = sessions.join("abc");
        std::fs::create_dir_all(&session).unwrap();
        assert!(validate_install_location_against(
            &session.join("App").to_string_lossy(),
            &sessions
        )
        .is_err());
        assert!(validate_install_location_against(
            &root.path().join("Apps").to_string_lossy(),
            &sessions
        )
        .is_ok());
    }
}
