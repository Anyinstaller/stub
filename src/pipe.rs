use anyhow::{bail, Context, Result};
use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_CONNECTED, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, GetNamedPipeServerSessionId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use crate::acl;
use crate::frame::{self, Frame};
use crate::winutil;

pub struct Event(HANDLE);

unsafe impl Send for Event {}
unsafe impl Sync for Event {}

impl Event {
    pub fn new() -> Result<Self> {
        let handle =
            unsafe { CreateEventW(None, true, false, None) }.context("CreateEventW failed")?;
        Ok(Self(handle))
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }

    pub fn set(&self) {
        unsafe {
            let _ = SetEvent(self.0);
        }
    }

    pub fn reset(&self) {
        unsafe {
            let _ = ResetEvent(self.0);
        }
    }

    pub fn is_set(&self) -> bool {
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

pub struct PipeServer {
    name: String,
    handle: Option<HANDLE>,
}

impl PipeServer {
    pub fn create(name: &str, sddl: &str) -> Result<Self> {
        let descriptor = acl::SecurityDescriptor::from_sddl(sddl)?;
        let attributes = acl::security_attributes(&descriptor);
        let full_name = format!(r"\\.\pipe\{name}");
        let wide = winutil::wide_str(&full_name);
        let open_mode = windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
            PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0 | FILE_FLAG_OVERLAPPED.0,
        );
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                open_mode,
                pipe_mode,
                1,
                1024 * 1024,
                1024 * 1024,
                0,
                Some(&attributes),
            )
        };
        if handle.is_invalid() {
            return Err(windows::core::Error::from_thread())
                .with_context(|| format!("CreateNamedPipeW failed for {full_name}"));
        }
        Ok(Self {
            name: full_name,
            handle: Some(handle),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn connect(&self, expected_pid: u32, timeout_ms: u32) -> Result<()> {
        let handle = self.handle.context("pipe has already been consumed")?;
        let event = Event::new()?;
        event.reset();
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..Default::default()
        };
        let result = unsafe { ConnectNamedPipe(handle, Some(&mut overlapped as *mut _)) };
        match result {
            Ok(()) => {}
            Err(error) => {
                if winutil::is_win32(&error, ERROR_PIPE_CONNECTED) {
                    // The client connected before ConnectNamedPipe was called.
                } else if winutil::is_win32(&error, ERROR_IO_PENDING) {
                    match unsafe { WaitForSingleObject(event.raw(), timeout_ms) } {
                        WAIT_OBJECT_0 => {
                            let mut transferred = 0u32;
                            unsafe {
                                GetOverlappedResult(handle, &overlapped, &mut transferred, false)
                                    .context("ConnectNamedPipe failed")?;
                            }
                        }
                        WAIT_TIMEOUT => {
                            cancel_and_reap(handle, &overlapped);
                            bail!("timed out waiting for a client to connect to {}", self.name);
                        }
                        _ => {
                            cancel_and_reap(handle, &overlapped);
                            return Err(windows::core::Error::from_thread()).context("wait failed");
                        }
                    }
                } else {
                    return Err(error)
                        .with_context(|| format!("ConnectNamedPipe failed for {}", self.name));
                }
            }
        }
        verify_client(handle, expected_pid)
    }

    pub fn into_handle(mut self) -> Result<Arc<PipeHandle>> {
        let handle = self
            .handle
            .take()
            .context("pipe has already been consumed")?;
        Ok(Arc::new(PipeHandle::new(handle)?))
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }
}

fn verify_client(handle: HANDLE, expected_pid: u32) -> Result<()> {
    let mut pid = 0u32;
    unsafe {
        GetNamedPipeClientProcessId(handle, &mut pid)
            .context("GetNamedPipeClientProcessId failed")?;
    }
    if pid != expected_pid {
        bail!("pipe client PID {pid} does not match the launched child PID {expected_pid}");
    }

    let mut client_session = 0u32;
    let mut server_session = 0u32;
    unsafe {
        GetNamedPipeClientSessionId(handle, &mut client_session)
            .context("GetNamedPipeClientSessionId failed")?;
        GetNamedPipeServerSessionId(handle, &mut server_session)
            .context("GetNamedPipeServerSessionId failed")?;
    }
    if client_session != server_session {
        bail!("pipe client is in a different logon session");
    }

    let expected_sid = acl::current_user_sid_string()?;
    let actual_sid = acl::process_user_sid(pid)?;
    if !actual_sid.eq_ignore_ascii_case(&expected_sid) {
        bail!("pipe client token user SID does not match the current user");
    }
    Ok(())
}

/// Cancel a pending overlapped operation and wait for the kernel to release
/// the OVERLAPPED structure. Safe to call even when the operation completed.
fn cancel_and_reap(handle: HANDLE, overlapped: &OVERLAPPED) {
    unsafe {
        let _ = CancelIoEx(handle, Some(overlapped as *const _));
    }
    let mut ignored = 0u32;
    let _ = unsafe { GetOverlappedResult(handle, overlapped, &mut ignored, true) };
}

pub struct PipeHandle {
    handle: HANDLE,
    read_event: Event,
    write_event: Event,
}

unsafe impl Send for PipeHandle {}
unsafe impl Sync for PipeHandle {}

impl PipeHandle {
    fn new(handle: HANDLE) -> Result<Self> {
        Ok(Self {
            handle,
            read_event: Event::new()?,
            write_event: Event::new()?,
        })
    }

    pub fn read_frame(&self, stop: &Event) -> Result<Option<Frame>> {
        let mut header = [0u8; 4];
        let read = self.read_exact(&mut header, stop, true)?;
        if read == 0 {
            return Ok(None);
        }
        let length = frame::decode_length(header)?;
        let mut body = vec![0u8; length];
        self.read_exact(&mut body, stop, false)?;
        Ok(Some(frame::parse_message(&body)?))
    }

    pub fn write_frame(&self, body: &[u8], stop: &Event) -> Result<()> {
        let encoded = frame::encode_frame(body)?;
        self.write_all(&encoded, stop)
    }

    fn read_exact(
        &self,
        buffer: &mut [u8],
        stop: &Event,
        allow_initial_eof: bool,
    ) -> Result<usize> {
        let mut total = 0;
        while total < buffer.len() {
            let read = self.read_once(&mut buffer[total..], stop)?;
            if read == 0 {
                if total == 0 && allow_initial_eof {
                    return Ok(0);
                }
                bail!("pipe closed in the middle of a frame");
            }
            total += read;
        }
        Ok(total)
    }

    fn read_once(&self, buffer: &mut [u8], stop: &Event) -> Result<usize> {
        self.read_event.reset();
        let mut overlapped = OVERLAPPED {
            hEvent: self.read_event.raw(),
            ..Default::default()
        };
        let mut transferred = 0u32;
        let result = unsafe {
            ReadFile(
                self.handle,
                Some(&mut buffer[..]),
                Some(&mut transferred),
                Some(&mut overlapped),
            )
        };
        if let Err(error) = result {
            if winutil::is_win32(&error, ERROR_IO_PENDING) {
                self.wait_io(self.read_event.raw(), &overlapped, stop)?;
                let mut completed = 0u32;
                match unsafe {
                    GetOverlappedResult(self.handle, &overlapped, &mut completed, false)
                } {
                    Ok(()) => return Ok(completed as usize),
                    Err(error) => {
                        if winutil::is_win32(&error, ERROR_BROKEN_PIPE)
                            || winutil::is_win32(&error, ERROR_HANDLE_EOF)
                        {
                            return Ok(0);
                        }
                        if winutil::is_win32(&error, ERROR_OPERATION_ABORTED) && stop.is_set() {
                            bail!("pipe operation cancelled");
                        }
                        return Err(error).context("ReadFile failed");
                    }
                }
            }
            if winutil::is_win32(&error, ERROR_BROKEN_PIPE)
                || winutil::is_win32(&error, ERROR_HANDLE_EOF)
            {
                return Ok(0);
            }
            return Err(error).context("ReadFile failed");
        }
        Ok(transferred as usize)
    }

    fn write_all(&self, buffer: &[u8], stop: &Event) -> Result<()> {
        let mut total = 0usize;
        while total < buffer.len() {
            self.write_event.reset();
            let mut overlapped = OVERLAPPED {
                hEvent: self.write_event.raw(),
                ..Default::default()
            };
            let mut transferred = 0u32;
            let result = unsafe {
                WriteFile(
                    self.handle,
                    Some(&buffer[total..]),
                    Some(&mut transferred),
                    Some(&mut overlapped),
                )
            };
            if let Err(error) = result {
                if winutil::is_win32(&error, ERROR_IO_PENDING) {
                    self.wait_io(self.write_event.raw(), &overlapped, stop)?;
                    let mut completed = 0u32;
                    match unsafe {
                        GetOverlappedResult(self.handle, &overlapped, &mut completed, false)
                    } {
                        Ok(()) => transferred = completed,
                        Err(error) => {
                            if winutil::is_win32(&error, ERROR_OPERATION_ABORTED) && stop.is_set() {
                                bail!("pipe operation cancelled");
                            }
                            return Err(error).context("WriteFile failed");
                        }
                    }
                } else {
                    return Err(error).context("WriteFile failed");
                }
            }
            if transferred == 0 {
                bail!("pipe write made no progress");
            }
            total += transferred as usize;
        }
        Ok(())
    }

    /// Wait for either the overlapped operation or the stop event. On stop we
    /// must cancel the operation and wait until the kernel is done with
    /// `overlapped` before returning, because the caller owns it on the stack.
    fn wait_io(&self, event: HANDLE, overlapped: &OVERLAPPED, stop: &Event) -> Result<()> {
        let handles = [event, stop.raw()];
        let result = unsafe { WaitForMultipleObjects(&handles, false, u32::MAX) };
        if result == WAIT_OBJECT_0 {
            return Ok(());
        }
        let wait_error = if result == WAIT_FAILED {
            Some(windows::core::Error::from_thread())
        } else {
            None
        };
        cancel_and_reap(self.handle, overlapped);
        if result.0 == WAIT_OBJECT_0.0 + 1 {
            bail!("pipe operation cancelled");
        }
        Err(wait_error.unwrap_or_else(windows::core::Error::from_thread))
            .context("WaitForMultipleObjects failed")
    }

    pub fn disconnect(&self) {
        unsafe {
            let _ = DisconnectNamedPipe(self.handle);
        }
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
