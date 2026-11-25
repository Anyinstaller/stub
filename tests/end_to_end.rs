#![cfg(all(feature = "dev", windows))]

//! End-to-end tests for the development build of the stub.
//!
//! Run with: `cargo test --features dev`
//!
//! The package stores the same helper executable as `client.exe` and
//! `backend.exe`; the helper picks its role from its file name, speaks AIP
//! over the two pipes, and records its progress in a marker file.

use anyhow::{Context, Result};
use std::process::{Command, ExitStatus};

const CONFIG: &str = r#"
protocol = 1
name = "AIP Test"

[defaults]
installLocation = 'C:\Apps\AIP Test'
createStartMenuFolder = false
createDesktopShortcut = false
"#;

fn build_package() -> Result<Vec<u8>> {
    let helper = std::fs::read(env!("CARGO_BIN_EXE_aip-dev-child"))
        .context("failed to read the dev child executable")?;
    let entries = vec![
        ("client.exe".to_string(), helper.clone()),
        ("backend.exe".to_string(), helper),
        ("config.toml".to_string(), CONFIG.as_bytes().to_vec()),
        ("payload.zip".to_string(), b"PK\x03\x04test".to_vec()),
    ];
    Ok(anyinstaller_stub::build::build_package(
        &entries,
        &anyinstaller_stub::build::fake_pe(),
        b"",
    ))
}

struct Run {
    status: ExitStatus,
    phases: String,
    _dir: tempfile::TempDir,
}

fn run_stub(mode: Option<&str>) -> Result<Run> {
    let dir = tempfile::tempdir().context("failed to create test directory")?;
    let package = dir.path().join("foo.exe");
    std::fs::write(&package, build_package()?)
        .with_context(|| format!("failed to write {}", package.display()))?;
    let marker = dir.path().join("phases.txt");

    let mut command = Command::new(env!("CARGO_BIN_EXE_stub"));
    command
        .arg("--aip-dev-package")
        .arg(&package)
        .env("AIP_TEST_MARKER", &marker);
    if let Some(mode) = mode {
        command.env("AIP_TEST_MODE", mode);
    }
    let status = command.status().context("failed to run the stub")?;
    let phases = std::fs::read_to_string(&marker).unwrap_or_default();
    Ok(Run {
        status,
        phases,
        _dir: dir,
    })
}

fn assert_phase(run: &Run, phase: &str) {
    assert!(
        run.phases.lines().any(|line| line == phase),
        "missing phase {phase:?}; recorded phases:\n{}",
        run.phases
    );
}

#[test]
fn relays_install_and_exits_cleanly() -> Result<()> {
    let run = run_stub(None)?;
    assert!(
        run.status.success(),
        "stub failed with {}; phases:\n{}",
        run.status,
        run.phases
    );
    for phase in [
        "client:connected",
        "backend:connected",
        "client:startInstall",
        "backend:setInstallLocation",
        "backend:startInstall",
        "backend:installFinished",
        "client:installFinished",
        "client:readyToExit",
    ] {
        assert_phase(&run, phase);
    }
    Ok(())
}

#[test]
fn client_close_cancels_the_session() -> Result<()> {
    let run = run_stub(Some("cancel"))?;
    assert!(
        run.status.success(),
        "cancellation should not fail; phases:\n{}",
        run.phases
    );
    assert_phase(&run, "client:cancel");
    assert!(!run.phases.contains("client:readyToExit"));
    Ok(())
}

#[test]
fn backend_crash_fails_closed() -> Result<()> {
    let run = run_stub(Some("backend-crash"))?;
    assert!(
        !run.status.success(),
        "the stub must fail when the backend disappears; phases:\n{}",
        run.phases
    );
    assert!(!run.phases.contains("client:installFinished"));
    Ok(())
}
