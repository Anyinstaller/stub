use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::winutil;

pub const SESSION_SDDL_SYSTEM_SID: &str = "SY";

pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let wide = winutil::wide_str(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
            .context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")?;
        }
        Ok(Self(descriptor))
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

pub fn security_attributes(descriptor: &SecurityDescriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr().0,
        bInheritHandle: BOOL(0),
    }
}

pub fn session_sddl(sid: &str) -> String {
    format!("D:P(A;OICI;FA;;;{SESSION_SDDL_SYSTEM_SID})(A;OICI;FA;;;{sid})")
}

/// After extraction the session tree is read-only for the current user:
/// read and execute only, while SYSTEM keeps full control for servicing.
pub fn session_readonly_sddl(sid: &str) -> String {
    format!("D:P(A;OICI;GRGX;;;{sid})(A;OICI;FA;;;{SESSION_SDDL_SYSTEM_SID})")
}

pub fn pipe_sddl(sid: &str) -> String {
    format!("D:P(A;;GA;;;{sid})")
}

pub fn current_user_sid_string() -> Result<String> {
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("OpenProcessToken failed")?;
    }
    let result = token_user_sid(token);
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

pub fn process_user_sid(pid: u32) -> Result<String> {
    let process = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
            .with_context(|| format!("OpenProcess failed for child PID {pid}"))?
    };
    let mut token = HANDLE::default();
    let token_result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    unsafe {
        let _ = CloseHandle(process);
    }
    token_result.with_context(|| format!("OpenProcessToken failed for child PID {pid}"))?;
    let result = token_user_sid(token);
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

fn token_user_sid(token: HANDLE) -> Result<String> {
    let mut needed = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
    }
    if needed == 0 {
        return Err(windows::core::Error::from_thread())
            .context("GetTokenInformation(TokenUser) failed");
    }
    let mut buffer = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        )
        .context("GetTokenInformation(TokenUser) failed")?;
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        if user.User.Sid.0.is_null() {
            bail!("current token has no user SID");
        }
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut text)
            .context("ConvertSidToStringSidW failed")?;
        let value = text.to_string().context("SID is not valid UTF-16")?;
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
        Ok(value)
    }
}

/// Create a directory with a security descriptor. Returns `false` when the
/// directory already exists; existing directories must be validated separately.
pub fn create_directory_exclusive(path: &Path, descriptor: &SecurityDescriptor) -> Result<bool> {
    let wide = winutil::wide(winutil::verbatim(path));
    let attributes = security_attributes(descriptor);
    let result = unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) };
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            if winutil::is_win32(&error, ERROR_ALREADY_EXISTS) {
                Ok(false)
            } else {
                Err(error)
                    .with_context(|| format!("CreateDirectoryW failed for {}", path.display()))
            }
        }
    }
}

pub fn set_private_dacl(path: &Path, sddl: &str) -> Result<()> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let mut present = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(descriptor.as_ptr(), &mut present, &mut dacl, &mut defaulted)
            .context("GetSecurityDescriptorDacl failed")?;
    }
    if !present.as_bool() || dacl.is_null() {
        bail!("security descriptor has no DACL");
    }
    let mut wide = winutil::wide(winutil::verbatim(path));
    let result = unsafe {
        SetNamedSecurityInfoW(
            PWSTR(wide.as_mut_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | windows::Win32::Security::PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if result != ERROR_SUCCESS {
        bail!(
            "SetNamedSecurityInfoW failed for {}: error {}",
            path.display(),
            result.0
        );
    }
    Ok(())
}

pub fn verify_directory(path: &Path) -> Result<()> {
    let attrs = winutil::file_attributes(path)?;
    if attrs.0 & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        bail!("{} is not a directory", path.display());
    }
    if winutil::is_reparse_point(FILE_FLAGS_AND_ATTRIBUTES(attrs.0)) {
        bail!("{} is a reparse point", path.display());
    }
    Ok(())
}

/// Create `%LOCALAPPDATA%\Anyinstaller\Sessions` with a DACL that allows only
/// the current user and SYSTEM. Existing components are checked for reparse
/// points and re-secured.
pub fn create_session_base(descriptor: &SecurityDescriptor) -> Result<std::path::PathBuf> {
    let local = winutil::local_app_data()?;
    verify_directory(&local)?;
    let mut current = local;
    for component in ["Anyinstaller", "Sessions"] {
        current.push(component);
        if !create_directory_exclusive(&current, descriptor)? {
            verify_directory(&current)?;
            set_private_dacl(&current, &session_sddl(&current_user_sid_string()?))?;
        }
        verify_directory(&current)?;
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_sid_is_available() {
        let sid = current_user_sid_string().unwrap();
        assert!(sid.starts_with("S-1-"));
    }

    #[test]
    fn private_directory_can_be_created() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("session");
        let sid = current_user_sid_string().unwrap();
        let descriptor = SecurityDescriptor::from_sddl(&session_sddl(&sid)).unwrap();
        assert!(create_directory_exclusive(&path, &descriptor).unwrap());
        verify_directory(&path).unwrap();
        set_private_dacl(&path, &session_sddl(&sid)).unwrap();
        std::fs::remove_dir(&path).unwrap();
    }
}
