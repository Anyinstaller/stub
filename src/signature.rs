#[cfg(not(feature = "dev"))]
use anyhow::bail;
use anyhow::Result;
#[cfg(not(feature = "dev"))]
use std::ffi::c_void;
#[cfg(not(feature = "dev"))]
use std::mem::size_of;
#[cfg(not(feature = "dev"))]
use std::os::windows::io::AsRawHandle;
#[cfg(not(feature = "dev"))]
use std::path::Path;
#[cfg(not(feature = "dev"))]
use windows::Win32::Foundation::{HANDLE, HWND};
#[cfg(not(feature = "dev"))]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UI_NONE,
};

#[cfg(not(feature = "dev"))]
use crate::winutil;

/// Verify the Authenticode signature of an already opened package file.
///
/// `WinVerifyTrust` requires a path, but the open handle is what ties the
/// signature to the bytes the stub will actually read. If the file is swapped
/// between verification and extraction, the handle and the path no longer
/// agree and verification fails closed.
pub fn verify_authenticode(path: &std::path::Path, file: &std::fs::File) -> Result<()> {
    #[cfg(feature = "dev")]
    {
        let _ = (path, file);
        Ok(())
    }

    #[cfg(not(feature = "dev"))]
    {
        verify_with_handle(path, HANDLE(file.as_raw_handle()))
    }
}

#[cfg(not(feature = "dev"))]
fn verify_with_handle(path: &Path, handle: HANDLE) -> Result<()> {
    let wide_path = winutil::wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(wide_path.as_ptr()),
        hFile: handle,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    if status != 0 {
        let code = status as u32;
        let reason = match code {
            0x800B_0100 => "the file is not signed",
            0x800B_0109 => "the certificate chain is not trusted",
            0x800B_0101 => "the certificate has expired",
            0x800B_010C => "the certificate has been revoked",
            0x8009_6010 => "the file digest does not match the signature",
            0x800B_0003 => "the signature subject is not a file",
            _ => "signature validation failed",
        };
        bail!("Authenticode verification failed: {reason} (0x{code:08X})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "dev"))]
    #[test]
    fn rejects_unsigned_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.exe");
        std::fs::write(&path, b"MZ").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(super::verify_authenticode(&path, &file).is_err());
    }
}
