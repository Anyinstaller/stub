# stub

**AIP v1 的受信任入口 / The trusted entry point of an Anyinstaller package**

`stub` is the executable at the front of every AIP v1 single-file package
(`foo.exe`). At startup it verifies the Authenticode signature, opens the
appended archive, validates `config.toml`, extracts the package into a private
session directory, launches `client.exe` and `backend.exe`, and relays AIP
frames between them over two named pipes.

## Requirements / 环境

- Windows 10/11 (x64)
- Rust 1.85+ with the MSVC toolchain

## Build / 构建

```powershell
cargo build --release
```

Release builds always verify Authenticode. The package must be signed with
`signtool` after the archive is appended; the stub scans backwards for the
`AIPF` footer, so the certificate table written after the footer is allowed.

`.cargo/config.toml` enables Control Flow Guard for all Rust targets. ASLR,
DEP, and high-entropy VA come from the x86_64 MSVC target itself.

For local development only:

```powershell
cargo build --features dev
target\debug\stub.exe --aip-dev-package path\to\foo.exe
```

The `dev` feature skips signature verification and enables
`--aip-dev-package`. It must never be used for a release build.

## Package layout / 包结构

```text
foo.exe
├─ PE image (the stub, the entry point)
├─ AIPK archive (stored, uncompressed entries)
├─ AIPD directory (name, absolute offset, size, SHA-256 per entry)
├─ AIPF footer
└─ optional Authenticode certificate table
```

Required entries are `client.exe`, `backend.exe`, `config.toml`, and
`payload.zip`. Entry names are package-relative and `/`-separated; traversal
components, drive/UNC/device paths, ADS, reserved device names, trailing dots
or spaces, and reparse points are rejected before extraction.

`config.toml` must be UTF-8 without a BOM and at most 64 KiB. The `icon` and
`background` values in a packaged config must be package-relative paths; the
stub rejects a config that references a missing resource. `background` may
instead be one of the documented visual effects or an `#RRGGBB` color.

## Runtime / 运行流程

1. Set `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` so the stub
   never resolves DLLs from user-writable locations.
2. Open the package file with `FILE_SHARE_READ` only, then verify its
   Authenticode signature with `WinVerifyTrust` (whole chain, revocation, no
   UI). Verification and extraction use the same handle, and the share mode
   denies writers and deleters, so the bytes cannot be swapped after
   verification.
3. Parse the footer and archive, verify every hash, and validate the config
   and resource references.
4. Create `%LOCALAPPDATA%\Anyinstaller\Sessions\<128-bit-id>` with a protected
   DACL for the current user and SYSTEM, extract every entry while checking
   SHA-256, re-hash the extracted tree, and make it read-only.
5. Create two named pipes with 128-bit random names, a current-user-only
   DACL, one instance each, and `PIPE_REJECT_REMOTE_CLIENTS`.
6. Launch `backend.exe` and `client.exe` suspended, assign both to a
   kill-on-close Job Object, resume them, and verify each connecting client's
   PID, logon session, and user SID.
7. Relay frames. `readyToExit` is consumed only from the client pipe; the same
   message on the backend pipe is ignored. A client that disconnects without
   `readyToExit` is treated as a cancellation. A backend that disconnects
   before `installFinished` fails the session.
8. On exit, stop the relays, disconnect the pipes, terminate remaining
   children, and delete the session directory. Sessions left behind by a
   crashed stub are swept on the next start.

## Limits / 限制

- Frame: 4-byte little-endian length + UTF-8 TOML, 1 MiB maximum.
- `config.toml`: 64 KiB maximum, UTF-8 without BOM.
- Pipe connect timeout: 30 s; shutdown grace: 5 s.
- `installLocation` must be an absolute local drive path and must not be a
  drive root, the Windows directory or its children, or the root of Program
  Files, ProgramData, the user profile, Desktop, Start Menu, or the session
  tree.

## Tests / 测试

```powershell
cargo test
cargo test --features dev   # end-to-end pipe and relay tests
cargo clippy --all-targets --features dev -- -D warnings
```

## Layout / 目录

| Path | Purpose |
| --- | --- |
| `src/stub.rs` | Startup, relay supervision, cleanup |
| `src/package.rs` | Footer scan, archive parsing, extraction, hash checks |
| `src/signature.rs` | `WinVerifyTrust` on an open file handle |
| `src/session.rs` | Session directory, lock, stale-session sweep |
| `src/pipe.rs` | Named pipe creation, client verification, overlapped I/O |
| `src/process.rs` | Job Object and suspended child launch |
| `src/path.rs` | Install-location and package-path validation |
| `src/acl.rs` | SIDs, SDDL, private DACLs |
| `src/config.rs` | `config.toml` parsing |
| `src/frame.rs` | AIP frame encoding and TOML message parsing |
| `src/build.rs` | Dev-only package builder used by tests |
| `tests/end_to_end.rs` | Dev-only end-to-end tests |
| `.cargo/config.toml` | Control Flow Guard for all targets |

## License

[Mozilla Public License 2.0](LICENSE)
