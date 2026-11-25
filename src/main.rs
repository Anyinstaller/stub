#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(feature = "dev"))]
use windows::core::PCWSTR;
#[cfg(not(feature = "dev"))]
use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

fn main() {
    if let Err(error) = anyinstaller_stub::run() {
        let message = format!("{error:#}");
        #[cfg(feature = "dev")]
        {
            eprintln!("{message}");
        }
        #[cfg(not(feature = "dev"))]
        show_error(&message);
        std::process::exit(1);
    }
}

#[cfg(not(feature = "dev"))]
fn show_error(message: &str) {
    let title: Vec<u16> = "Anyinstaller\0".encode_utf16().collect();
    let mut body: Vec<u16> = message.encode_utf16().collect();
    if body.len() > 30_000 {
        body.truncate(30_000);
    }
    body.push(0);
    unsafe {
        MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}
