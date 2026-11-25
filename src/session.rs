use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, MoveFileExW, CREATE_NEW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
    FILE_SHARE_WRITE, MOVEFILE_DELAY_UNTIL_REBOOT, OPEN_EXISTING,
};

use crate::acl::{self, SecurityDescriptor};
use crate::winutil;

pub struct Session {
    path: PathBuf,
    /// Sibling lock file held open for the lifetime of the session. A stale
    /// session can be recognised because its lock file is no longer held.
    lock: HANDLE,
    lock_path: PathBuf,
}

impl Session {
    pub fn create() -> Result<Self> {
        let sid = acl::current_user_sid_string()?;
        let descriptor = SecurityDescriptor::from_sddl(&acl::session_sddl(&sid))?;
        let base = acl::create_session_base(&descriptor)?;
        sweep_stale_sessions(&base);
        for _ in 0..8 {
            let id = winutil::random_hex::<16>()?;
            let path = base.join(&id);
            let lock_path = base.join(format!("{id}.lock"));
            // Take the lock before the directory exists. A concurrent sweep
            // can then never see a directory that belongs to a live session
            // but has no held lock yet.
            let lock = create_lock(&lock_path)?;
            match acl::create_directory_exclusive(&path, &descriptor) {
                Ok(true) => {
                    if let Err(error) = acl::verify_directory(&path) {
                        release_lock(lock, &lock_path);
                        return Err(error);
                    }
                    return Ok(Self {
                        path,
                        lock,
                        lock_path,
                    });
                }
                Ok(false) => {
                    // A directory with this random name already exists; use a
                    // different name and let the sweep handle the stale one.
                    release_lock(lock, &lock_path);
                }
                Err(error) => {
                    release_lock(lock, &lock_path);
                    return Err(error);
                }
            }
        }
        bail!("failed to allocate a unique session directory")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Make the extracted tree read-only for the current user. The owner keeps
    /// implicit WRITE_DAC access, so the stub can restore the DACL when it
    /// deletes the session.
    pub fn mark_read_only(&self) -> Result<()> {
        let sid = acl::current_user_sid_string()?;
        apply_tree(&self.path, &acl::session_readonly_sddl(&sid), true)
    }

    fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.lock_path);
        delete_session_tree(&self.path);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Release the lock first so a concurrent sweep can delete the tree if
        // this cleanup fails.
        unsafe {
            let _ = CloseHandle(self.lock);
        }
        self.cleanup();
    }
}

/// Create and hold the session lock file. The handle grants delete access but
/// shares only read/write, so any other process opening the lock with delete
/// access gets a sharing violation while this session is alive.
fn create_lock(path: &Path) -> Result<HANDLE> {
    let wide = winutil::wide(winutil::verbatim(path));
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0 | DELETE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("failed to create session lock {}", path.display()))
}

fn release_lock(lock: HANDLE, path: &Path) {
    unsafe {
        let _ = CloseHandle(lock);
    }
    let _ = std::fs::remove_file(path);
}

/// Best effort removal of sessions left behind by a crashed or terminated stub.
fn sweep_stale_sessions(base: &Path) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_dir() {
            let lock_path = base.join(format!("{name}.lock"));
            match open_lock_for_delete(&lock_path) {
                Ok(handle) => {
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    let _ = std::fs::remove_file(&lock_path);
                }
                Err(_) if lock_path.exists() => continue,
                Err(_) => {}
            }
            delete_session_tree(&path);
        } else if name.ends_with(".lock") {
            if let Ok(handle) = open_lock_for_delete(&path) {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn open_lock_for_delete(path: &Path) -> Result<HANDLE> {
    let wide = winutil::wide(winutil::verbatim(path));
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            DELETE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .context("CreateFileW failed")
}

fn delete_session_tree(path: &Path) {
    if let Ok(sid) = acl::current_user_sid_string() {
        let _ = apply_tree(path, &acl::session_sddl(&sid), false);
    }
    // Attribute-only fallback for trees whose DACL could not be restored.
    let _ = mark_tree(path, false);
    if std::fs::remove_dir_all(path).is_err() {
        schedule_reboot_delete(path);
    }
}

/// Apply a DACL and the read-only attribute to a tree. Children are processed
/// before their parent so tightening never blocks the walk. Loosening applies
/// the DACL before clearing attributes; the owner keeps implicit WRITE_DAC, so
/// the read-only DACL can be replaced during cleanup.
fn apply_tree(path: &Path, sddl: &str, readonly: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("refusing to change a reparse point in the session tree");
    }
    if metadata.file_type().is_dir() {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry.context("failed to read session directory entry")?;
            apply_tree(&entry.path(), sddl, readonly)?;
        }
    }
    if readonly {
        winutil::set_readonly(path, true)?;
        acl::set_private_dacl(path, sddl)?;
    } else {
        acl::set_private_dacl(path, sddl)?;
        winutil::set_readonly(path, false)?;
    }
    Ok(())
}

fn mark_tree(path: &Path, readonly: bool) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_dir() {
        for entry in
            std::fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))?
        {
            let entry = entry.context("failed to read session directory entry")?;
            mark_tree(&entry.path(), readonly)?;
        }
    }
    winutil::set_readonly(path, readonly)?;
    Ok(())
}

fn schedule_reboot_delete(path: &Path) {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };
    if metadata.file_type().is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                schedule_reboot_delete(&entry.path());
            }
        }
    }
    let wide = winutil::wide(winutil::verbatim(path));
    unsafe {
        let _ = MoveFileExW(PCWSTR(wide.as_ptr()), None, MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_private_session_and_cleans_up() {
        let session = Session::create().unwrap();
        let path = session.path().to_path_buf();
        let lock_path = session.lock_path.clone();
        assert!(path.is_dir());
        assert!(lock_path.is_file());
        std::fs::write(path.join("file.txt"), b"hello").unwrap();
        drop(session);
        assert!(!path.exists());
        assert!(!lock_path.exists());
    }

    #[test]
    fn marks_read_only_and_denies_writes() {
        let session = Session::create().unwrap();
        let path = session.path().to_path_buf();
        let file = path.join("file.txt");
        std::fs::write(&file, b"hello").unwrap();
        session.mark_read_only().unwrap();

        assert!(
            winutil::file_attributes(&file).unwrap().0
                & windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY.0
                != 0
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"hello");
        assert!(std::fs::OpenOptions::new().write(true).open(&file).is_err());
        assert!(std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path.join("new.txt"))
            .is_err());

        drop(session);
        assert!(!path.exists());
    }

    #[test]
    fn sweep_keeps_live_sessions_and_removes_stale_ones() {
        let base = tempfile::tempdir().unwrap();

        let live = base.path().join("live");
        std::fs::create_dir(&live).unwrap();
        let live_lock = create_lock(&base.path().join("live.lock")).unwrap();

        let stale = base.path().join("stale");
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("leftover.txt"), b"x").unwrap();
        let stale_lock = create_lock(&base.path().join("stale.lock")).unwrap();
        unsafe {
            let _ = CloseHandle(stale_lock);
        }

        let unlocked = base.path().join("unlocked");
        std::fs::create_dir(&unlocked).unwrap();

        sweep_stale_sessions(base.path());

        assert!(live.exists());
        assert!(!stale.exists());
        assert!(!unlocked.exists());
        assert!(base.path().join("live.lock").exists());
        assert!(!base.path().join("stale.lock").exists());

        unsafe {
            let _ = CloseHandle(live_lock);
        }
    }
}
