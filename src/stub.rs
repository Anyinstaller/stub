use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::acl;
use crate::config::{Config, MAX_CONFIG_BYTES};
use crate::package::Package;
use crate::path;
use crate::pipe::{Event, PipeHandle, PipeServer};
use crate::process::{Child, Job};
use crate::session::Session;
use crate::signature;
use crate::winutil;

const CONNECT_TIMEOUT_MS: u32 = 30_000;
const CHILD_EXIT_GRACE: Duration = Duration::from_secs(1);
const SHUTDOWN_GRACE_MS: u32 = 5_000;

#[derive(Clone, Copy, Debug)]
enum Side {
    Client,
    Backend,
}

impl Side {
    fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Backend => "backend",
        }
    }
}

enum RelayEvent {
    ReadyToExit,
    InstallFinished,
    Closed(Side),
    Error(Side, String),
}

pub fn run() -> Result<()> {
    // Never resolve DLLs from the working directory or other user-writable
    // locations. This applies to the stub itself; children set their own
    // policy when they start.
    unsafe {
        windows::Win32::System::LibraryLoader::SetDefaultDllDirectories(
            windows::Win32::System::LibraryLoader::LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .context("SetDefaultDllDirectories failed")?;

    let executable = std::env::current_exe().context("failed to determine the stub path")?;

    let package_path = package_path(&executable)?;
    let package_file = crate::package::open_package(&package_path)?;
    signature::verify_authenticode(&package_path, &package_file)?;
    let package = Package::from_file(package_file)
        .with_context(|| format!("failed to parse package {}", package_path.display()))?;
    let config_bytes = package.read_entry("config.toml", MAX_CONFIG_BYTES)?;
    let config = Config::parse(&config_bytes)?;
    if let Some(icon) = &config.icon {
        if package.entry(icon).is_none() {
            bail!("config.toml references an icon missing from the package: {icon:?}");
        }
    }
    if let Some(background) = &config.background {
        let is_effect = path::is_special_background(background) || path::is_hex_color(background);
        if !is_effect && package.entry(background).is_none() {
            bail!("config.toml references a background missing from the package: {background:?}");
        }
    }

    let session = Session::create()?;
    let sessions_root = session
        .path()
        .parent()
        .context("session directory has no parent")?;
    path::validate_install_location_against(&config.defaults.install_location, sessions_root)
        .context("defaults.installLocation is invalid")?;
    package.extract_all(session.path())?;
    session.mark_read_only()?;

    let sid = acl::current_user_sid_string()?;
    let pipe_sddl = acl::pipe_sddl(&sid);
    let session_id = winutil::random_hex::<16>()?;
    let client_pipe_name = format!("aip-{session_id}-client");
    let backend_pipe_name = format!("aip-{session_id}-backend");

    let client_pipe = PipeServer::create(&client_pipe_name, &pipe_sddl)?;
    let backend_pipe = PipeServer::create(&backend_pipe_name, &pipe_sddl)?;

    let job = Job::create()?;
    let backend_path = session.path().join("backend.exe");
    let client_path = session.path().join("client.exe");
    let backend = Child::launch(&backend_path, &backend_pipe_name, session.path(), &job)?;
    let client = Child::launch(&client_path, &client_pipe_name, session.path(), &job)?;

    client_pipe
        .connect(client.pid, CONNECT_TIMEOUT_MS)
        .context("client pipe connection failed")?;
    backend_pipe
        .connect(backend.pid, CONNECT_TIMEOUT_MS)
        .context("backend pipe connection failed")?;

    let stop = Arc::new(Event::new()?);
    let (sender, receiver) = mpsc::channel();
    let client_handle = client_pipe.into_handle()?;
    let backend_handle = backend_pipe.into_handle()?;

    let client_to_backend = spawn_relay(
        Arc::clone(&client_handle),
        Arc::clone(&backend_handle),
        Side::Client,
        Arc::clone(&stop),
        sender.clone(),
    );
    let backend_to_client = spawn_relay(
        Arc::clone(&backend_handle),
        Arc::clone(&client_handle),
        Side::Backend,
        Arc::clone(&stop),
        sender,
    );

    let outcome = supervise(&receiver, &client, &backend);

    stop.set();
    let _ = client_to_backend.join();
    let _ = backend_to_client.join();
    client_handle.disconnect();
    backend_handle.disconnect();
    shutdown_children(&client, &backend);

    outcome
}

fn package_path(executable: &Path) -> Result<PathBuf> {
    #[cfg(feature = "dev")]
    {
        let mut arguments = std::env::args_os().skip(1);
        while let Some(argument) = arguments.next() {
            if argument == "--aip-dev-package" {
                return arguments
                    .next()
                    .map(PathBuf::from)
                    .context("--aip-dev-package requires a path");
            }
            if let Some(text) = argument.to_str() {
                if let Some(path) = text.strip_prefix("--aip-dev-package=") {
                    return Ok(PathBuf::from(path));
                }
            }
        }
    }
    Ok(executable.to_path_buf())
}

fn spawn_relay(
    source: Arc<PipeHandle>,
    destination: Arc<PipeHandle>,
    side: Side,
    stop: Arc<Event>,
    sender: Sender<RelayEvent>,
) -> std::thread::JoinHandle<()> {
    let destination_side = match side {
        Side::Client => Side::Backend,
        Side::Backend => Side::Client,
    };
    std::thread::spawn(move || loop {
        match source.read_frame(&stop) {
            Ok(Some(frame)) => {
                if matches!(side, Side::Client) && frame.message_type == "readyToExit" {
                    let _ = sender.send(RelayEvent::ReadyToExit);
                    return;
                }
                if matches!(side, Side::Backend) && frame.message_type == "readyToExit" {
                    continue;
                }
                if matches!(side, Side::Backend) && frame.message_type == "installFinished" {
                    let _ = sender.send(RelayEvent::InstallFinished);
                }
                if destination.write_frame(&frame.body, &stop).is_err() {
                    // A failed write means the peer is gone. Report it as a
                    // close of that side so a client disconnect is treated as
                    // cancellation instead of a protocol error.
                    if !stop.is_set() {
                        let _ = sender.send(RelayEvent::Closed(destination_side));
                    }
                    return;
                }
            }
            Ok(None) => {
                let _ = sender.send(RelayEvent::Closed(side));
                return;
            }
            Err(error) => {
                if !stop.is_set() {
                    let _ = sender.send(RelayEvent::Error(side, format!("{error:#}")));
                }
                return;
            }
        }
    })
}

fn supervise(receiver: &Receiver<RelayEvent>, client: &Child, backend: &Child) -> Result<()> {
    let mut install_finished = false;
    let mut client_exit: Option<Instant> = None;
    let mut backend_exit: Option<Instant> = None;

    loop {
        match receiver.recv_timeout(Duration::from_millis(100)) {
            Ok(RelayEvent::ReadyToExit) => return Ok(()),
            Ok(RelayEvent::InstallFinished) => install_finished = true,
            Ok(RelayEvent::Closed(Side::Client)) => {
                // The client closed without readyToExit: treat as a user
                // cancellation and clean up without an error dialog.
                return Ok(());
            }
            Ok(RelayEvent::Closed(Side::Backend)) => {
                if !install_finished && backend_exit.is_none() {
                    bail!("backend disconnected before sending installFinished");
                }
                backend_exit.get_or_insert_with(Instant::now);
            }
            Ok(RelayEvent::Error(side, message)) => {
                bail!("{} relay failed: {message}", side.label());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                if !install_finished {
                    bail!("both pipe relays stopped before installFinished");
                }
                bail!("client did not send readyToExit");
            }
        }

        if client_exit.is_none() && client.wait_exit(0).is_some() {
            client_exit = Some(Instant::now());
        }
        if backend_exit.is_none() && !install_finished && backend.wait_exit(0).is_some() {
            backend_exit = Some(Instant::now());
        }
        if let Some(started) = client_exit {
            if started.elapsed() > CHILD_EXIT_GRACE {
                // The pipe relay normally reports the close first; this is a
                // backstop for a client that exited but left its pipe open.
                return Ok(());
            }
        }
        if let Some(started) = backend_exit {
            if !install_finished && started.elapsed() > CHILD_EXIT_GRACE {
                bail!("backend exited before sending installFinished");
            }
        }
    }
}

fn shutdown_children(client: &Child, backend: &Child) {
    wait_or_terminate(client);
    wait_or_terminate(backend);
}

fn wait_or_terminate(child: &Child) {
    if child.wait_exit(SHUTDOWN_GRACE_MS).is_none() {
        child.terminate();
        let _ = child.wait_exit(SHUTDOWN_GRACE_MS);
    }
}
