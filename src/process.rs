use anyhow::{Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::Path;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, TerminateProcess, WaitForSingleObject,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

use crate::winutil;

pub struct Job {
    handle: HANDLE,
}

impl Job {
    pub fn create() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(None, None) }.context("CreateJobObjectW failed")?;
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &information as *const _ as *const c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .context("SetInformationJobObject failed")?;
        }
        Ok(Self { handle })
    }

    fn assign(&self, process: HANDLE) -> Result<()> {
        unsafe { AssignProcessToJobObject(self.handle, process) }
            .context("AssignProcessToJobObject failed")
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

pub struct Child {
    process: HANDLE,
    pub pid: u32,
    pub label: &'static str,
}

impl Child {
    pub fn launch(path: &Path, pipe_name: &str, cwd: &Path, job: &Job) -> Result<Self> {
        let application = winutil::wide(path.as_os_str());
        let mut command_line = format!("\"{}\" --aip-pipe-name {pipe_name}", path.display())
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>();
        let working_directory = winutil::wide(cwd.as_os_str());
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut process_information = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command_line.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                None,
                PCWSTR(working_directory.as_ptr()),
                &startup,
                &mut process_information,
            )
            .with_context(|| format!("failed to launch {}", path.display()))?;
        }

        let process = process_information.hProcess;
        let thread = process_information.hThread;
        if let Err(error) = job.assign(process) {
            unsafe {
                let _ = TerminateProcess(process, 1);
                let _ = CloseHandle(thread);
                let _ = CloseHandle(process);
            }
            return Err(error);
        }
        let resumed = unsafe { ResumeThread(thread) };
        unsafe {
            let _ = CloseHandle(thread);
        }
        if resumed == u32::MAX {
            unsafe {
                let _ = TerminateProcess(process, 1);
                let _ = CloseHandle(process);
            }
            return Err(windows::core::Error::from_thread()).context("ResumeThread failed");
        }

        Ok(Self {
            process,
            pid: process_information.dwProcessId,
            label: if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("client.exe"))
            {
                "client"
            } else {
                "backend"
            },
        })
    }

    pub fn wait_exit(&self, timeout_ms: u32) -> Option<u32> {
        let result = unsafe { WaitForSingleObject(self.process, timeout_ms) };
        if result != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        unsafe {
            let _ = GetExitCodeProcess(self.process, &mut code);
        }
        Some(code)
    }

    pub fn terminate(&self) {
        unsafe {
            let _ = TerminateProcess(self.process, 1);
        }
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            // The explicit shutdown path already waited; this is a backstop
            // for early returns and errors, so the session directory is never
            // deleted while a child still has files open.
            let _ = TerminateProcess(self.process, 1);
            let _ = WaitForSingleObject(self.process, 5_000);
            let _ = CloseHandle(self.process);
        }
    }
}
