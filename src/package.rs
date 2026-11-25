use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::path;
use crate::winutil;

const ARCHIVE_MAGIC: &[u8; 4] = b"AIPK";
const DIRECTORY_MAGIC: &[u8; 4] = b"AIPD";
const FOOTER_MAGIC: &[u8; 4] = b"AIPF";
const FOOTER_END_MAGIC: &[u8; 8] = b"AIP1END\0";
const FORMAT_VERSION: u32 = 1;
const ARCHIVE_HEADER_LEN: u64 = 16;
const DIRECTORY_HEADER_LEN: usize = 12;
const FOOTER_LEN: usize = 48;
const FOOTER_END_OFFSET: usize = 40;
const MAX_FOOTER_SCAN: u64 = 32 * 1024 * 1024;
const MAX_DIRECTORY_SIZE: u64 = 16 * 1024 * 1024;
const MAX_ENTRIES: u32 = 100_000;
const MAX_ENTRY_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TOTAL_SIZE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_EXECUTABLE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_PAYLOAD_SIZE: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug)]
pub struct Package {
    file: File,
    entries: Vec<Entry>,
    archive_offset: u64,
    archive_size: u64,
}

/// Open a package for reading while denying writers and deleters. Holding this
/// handle keeps the bytes used for signature verification and extraction the
/// same even if another process can write to the package's directory.
pub fn open_package(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .with_context(|| format!("failed to open package {}", path.display()))
}

impl Package {
    /// Locate and validate the AIP archive appended to the running executable.
    pub fn open(path: &Path) -> Result<Self> {
        Self::from_file(open_package(path)?)
    }

    /// Parse a package from an already opened file. The caller is responsible
    /// for verifying the file's signature before trusting any of its contents.
    pub fn from_file(file: File) -> Result<Self> {
        let mut file = file;
        let file_len = file
            .metadata()
            .context("failed to read package metadata")?
            .len();
        if file_len < ARCHIVE_HEADER_LEN + FOOTER_LEN as u64 {
            bail!("file is too small to contain an AIP package");
        }

        let scan_len = file_len.min(MAX_FOOTER_SCAN);
        let scan_start = file_len - scan_len;
        file.seek(SeekFrom::Start(scan_start))?;
        let mut window = vec![0u8; scan_len as usize];
        file.read_exact(&mut window)
            .context("failed to read package footer window")?;

        let mut last_error: Option<anyhow::Error> = None;
        for position in (0..=window.len().saturating_sub(FOOTER_END_MAGIC.len())).rev() {
            if &window[position..position + FOOTER_END_MAGIC.len()] != FOOTER_END_MAGIC {
                continue;
            }
            let Some(footer_start) = position.checked_sub(FOOTER_END_OFFSET) else {
                continue;
            };
            let absolute_footer = scan_start + footer_start as u64;
            match parse_footer(
                &window[footer_start..footer_start + FOOTER_LEN],
                absolute_footer,
                file_len,
            ) {
                Ok(footer) => match parse_archive(&file, &footer) {
                    Ok((entries, archive_offset, archive_size)) => {
                        return Ok(Self {
                            file,
                            entries,
                            archive_offset,
                            archive_size,
                        });
                    }
                    Err(error) => last_error = Some(error),
                },
                Err(error) => last_error = Some(error),
            }
        }

        match last_error {
            Some(error) => Err(error).context("AIP package footer is invalid"),
            None => bail!("no AIP package footer found"),
        }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    pub fn archive_offset(&self) -> u64 {
        self.archive_offset
    }

    pub fn archive_size(&self) -> u64 {
        self.archive_size
    }

    pub fn read_entry(&self, name: &str, max_size: usize) -> Result<Vec<u8>> {
        let entry = self
            .entry(name)
            .with_context(|| format!("package is missing {name}"))?;
        if entry.size > max_size as u64 {
            bail!("{name} is larger than the allowed {max_size} bytes");
        }
        let mut file = self
            .file
            .try_clone()
            .context("failed to clone package handle")?;
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut data = vec![0u8; entry.size as usize];
        file.read_exact(&mut data)
            .with_context(|| format!("failed to read {name} from package"))?;
        let actual: [u8; 32] = Sha256::digest(&data).into();
        if actual != entry.sha256 {
            bail!("SHA-256 mismatch for {name}");
        }
        Ok(data)
    }

    pub fn extract_all(&self, root: &Path) -> Result<()> {
        for entry in &self.entries {
            let destination = root.join(entry.name.replace('/', std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = destination.parent() {
                create_private_subdirectories(root, parent)?;
            }
            self.extract_entry(entry, &destination)?;
        }
        self.validate_extracted(root)
    }

    fn extract_entry(&self, entry: &Entry, destination: &Path) -> Result<()> {
        let mut source = self
            .file
            .try_clone()
            .context("failed to clone package handle")?;
        source.seek(SeekFrom::Start(entry.offset))?;
        let destination_path = winutil::verbatim(destination);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination_path)
            .with_context(|| format!("failed to create {}", destination.display()))?;

        let mut hasher = Sha256::new();
        let mut remaining = entry.size;
        let mut buffer = vec![0u8; 1024 * 1024];
        let result = (|| -> Result<()> {
            while remaining > 0 {
                let chunk = remaining.min(buffer.len() as u64) as usize;
                source
                    .read_exact(&mut buffer[..chunk])
                    .with_context(|| format!("failed to read {}", entry.name))?;
                hasher.update(&buffer[..chunk]);
                output
                    .write_all(&buffer[..chunk])
                    .with_context(|| format!("failed to write {}", destination.display()))?;
                remaining -= chunk as u64;
            }
            output.flush().context("failed to flush extracted file")?;
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != entry.sha256 {
                bail!("SHA-256 mismatch for {}", entry.name);
            }
            Ok(())
        })();

        drop(output);
        if result.is_err() {
            let _ = std::fs::remove_file(&destination_path);
        }
        result
    }

    fn validate_extracted(&self, root: &Path) -> Result<()> {
        // Re-read every extracted file from disk. This catches replacement
        // during extraction, not just a bad archive.
        for entry in &self.entries {
            verify_extracted_entry(entry, root)?;
        }
        for name in ["client.exe", "backend.exe"] {
            let path = root.join(name);
            if !looks_like_pe(&path)? {
                bail!("{name} is not a valid PE executable");
            }
        }
        let payload = root.join("payload.zip");
        let mut file = File::open(&payload).context("failed to open extracted payload.zip")?;
        let mut signature = [0u8; 4];
        file.read_exact(&mut signature)
            .context("payload.zip is truncated")?;
        if &signature[..2] != b"PK" {
            bail!("payload.zip is not a ZIP archive");
        }
        Ok(())
    }
}

fn verify_extracted_entry(entry: &Entry, root: &Path) -> Result<()> {
    let path = root.join(entry.name.replace('/', std::path::MAIN_SEPARATOR_STR));
    let mut file =
        File::open(&path).with_context(|| format!("failed to reopen extracted {}", entry.name))?;
    let mut hasher = Sha256::new();
    let mut remaining = entry.size;
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..chunk])
            .with_context(|| format!("failed to re-read extracted {}", entry.name))?;
        hasher.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != entry.sha256 {
        bail!("SHA-256 mismatch for extracted {}", entry.name);
    }
    Ok(())
}

struct Footer {
    archive_offset: u64,
    archive_size: u64,
    directory_offset: u64,
    directory_size: u64,
}

fn parse_footer(bytes: &[u8], footer_start: u64, file_len: u64) -> Result<Footer> {
    if bytes.len() != FOOTER_LEN {
        bail!("truncated package footer");
    }
    if &bytes[0..4] != FOOTER_MAGIC {
        bail!("bad package footer magic");
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("unsupported package format version {version}");
    }
    let archive_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let archive_size = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    let directory_offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let directory_size = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
    if &bytes[40..48] != FOOTER_END_MAGIC {
        bail!("bad package footer terminator");
    }
    if archive_size < ARCHIVE_HEADER_LEN {
        bail!("package archive is too small");
    }
    let archive_end = archive_offset
        .checked_add(archive_size)
        .context("package archive range overflows")?;
    if archive_end != footer_start {
        bail!("package footer is not adjacent to the archive");
    }
    if archive_end > file_len {
        bail!("package archive extends past the end of the file");
    }
    let directory_end = directory_offset
        .checked_add(directory_size)
        .context("package directory range overflows")?;
    if directory_offset < archive_offset + ARCHIVE_HEADER_LEN || directory_end != archive_end {
        bail!("package directory range is invalid");
    }
    if directory_size < DIRECTORY_HEADER_LEN as u64 || directory_size > MAX_DIRECTORY_SIZE {
        bail!("package directory size is invalid");
    }
    Ok(Footer {
        archive_offset,
        archive_size,
        directory_offset,
        directory_size,
    })
}

fn parse_archive(file: &File, footer: &Footer) -> Result<(Vec<Entry>, u64, u64)> {
    let mut reader = file.try_clone().context("failed to clone package handle")?;
    let mut header = [0u8; ARCHIVE_HEADER_LEN as usize];
    reader.seek(SeekFrom::Start(footer.archive_offset))?;
    reader
        .read_exact(&mut header)
        .context("truncated archive header")?;
    if &header[0..4] != ARCHIVE_MAGIC {
        bail!("bad archive magic");
    }
    let version = u32::from_le_bytes(header[4..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        bail!("unsupported archive version {version}");
    }
    let flags = u32::from_le_bytes(header[8..12].try_into().unwrap());
    if flags != 0 {
        bail!("unsupported archive flags: {flags:#x}");
    }
    let count = u32::from_le_bytes(header[12..16].try_into().unwrap());
    if count == 0 || count > MAX_ENTRIES {
        bail!("invalid archive entry count: {count}");
    }

    let mut directory = vec![0u8; footer.directory_size as usize];
    reader.seek(SeekFrom::Start(footer.directory_offset))?;
    reader
        .read_exact(&mut directory)
        .context("truncated archive directory")?;

    let mut cursor = Cursor::new(&directory);
    if cursor.take(4)? != DIRECTORY_MAGIC {
        bail!("bad archive directory magic");
    }
    let directory_version = cursor.u32()?;
    if directory_version != FORMAT_VERSION {
        bail!("unsupported archive directory version {directory_version}");
    }
    let directory_count = cursor.u32()?;
    if directory_count != count {
        bail!("archive and directory entry counts differ");
    }

    let mut entries = Vec::with_capacity(count as usize);
    let mut names = std::collections::HashSet::new();
    let mut total_size = 0u64;
    for _ in 0..count {
        let name_len = cursor.u16()? as usize;
        if name_len == 0 || name_len > 1024 {
            bail!("invalid archive entry name length");
        }
        let raw_name = cursor.take(name_len)?;
        let raw_name = std::str::from_utf8(raw_name).context("entry name is not UTF-8")?;
        let name = path::validate_package_relative(raw_name)?;
        if name != raw_name {
            bail!("archive entry names must use '/' separators: {raw_name:?}");
        }
        if !names.insert(name.to_ascii_lowercase()) {
            bail!("duplicate archive entry: {name}");
        }
        let offset = cursor.u64()?;
        let size = cursor.u64()?;
        let sha256: [u8; 32] = cursor.take(32)?.try_into().unwrap();
        if size > MAX_ENTRY_SIZE {
            bail!("archive entry {name} is too large");
        }
        let end = offset
            .checked_add(size)
            .context("archive entry range overflows")?;
        if offset < footer.archive_offset + ARCHIVE_HEADER_LEN || end > footer.directory_offset {
            bail!("archive entry {name} has an invalid range");
        }
        total_size = total_size
            .checked_add(size)
            .context("archive total size overflows")?;
        if total_size > MAX_TOTAL_SIZE {
            bail!("archive contents are too large");
        }
        entries.push(Entry {
            name,
            offset,
            size,
            sha256,
        });
    }
    if cursor.remaining() != 0 {
        bail!("archive directory has trailing data");
    }

    for required in ["client.exe", "backend.exe", "config.toml", "payload.zip"] {
        let entry = entries
            .iter()
            .find(|entry| entry.name == required)
            .with_context(|| format!("package is missing required entry {required}"))?;
        match required {
            "config.toml" if entry.size > crate::config::MAX_CONFIG_BYTES as u64 => {
                bail!("config.toml is larger than 64 KiB");
            }
            "client.exe" | "backend.exe" if entry.size > MAX_EXECUTABLE_SIZE => {
                bail!("{required} is too large");
            }
            "payload.zip" if entry.size > MAX_PAYLOAD_SIZE => {
                bail!("payload.zip is too large");
            }
            _ => {}
        }
    }

    Ok((entries, footer.archive_offset, footer.archive_size))
}

fn create_private_subdirectories(root: &Path, parent: &Path) -> Result<()> {
    let relative = parent.strip_prefix(root).with_context(|| {
        format!(
            "destination {} escapes the session directory",
            parent.display()
        )
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match std::fs::create_dir(&current) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to create {}", current.display()))
            }
        }
        let attrs = winutil::file_attributes(&current)?;
        if winutil::is_reparse_point(attrs) {
            bail!(
                "refusing to extract through reparse point {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn looks_like_pe(path: &Path) -> Result<bool> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut dos = [0u8; 64];
    match file.read_exact(&mut dos) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to read {}", path.display()))
        }
    }
    if &dos[0..2] != b"MZ" {
        return Ok(false);
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    if pe_offset > 16 * 1024 * 1024 {
        return Ok(false);
    }
    file.seek(SeekFrom::Start(pe_offset))?;
    let mut signature = [0u8; 4];
    file.read_exact(&mut signature)?;
    Ok(&signature == b"PE\0\0")
}

struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .context("directory cursor overflow")?;
        if end > self.data.len() {
            bail!("truncated archive directory");
        }
        let slice = &self.data[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &[u8] = br#"
protocol = 1
name = "Example"
[defaults]
installLocation = 'C:\Apps\Example'
createStartMenuFolder = true
createDesktopShortcut = true
"#;

    fn pe_stub() -> Vec<u8> {
        crate::build::fake_pe()
    }

    fn base_entries() -> Vec<(String, Vec<u8>)> {
        vec![
            ("client.exe".into(), pe_stub()),
            ("backend.exe".into(), pe_stub()),
            ("config.toml".into(), CONFIG.to_vec()),
            ("payload.zip".into(), b"PK\x03\x04payload".to_vec()),
            ("assets/background.avif".into(), b"background".to_vec()),
        ]
    }

    fn build_package(entries: &[(String, Vec<u8>)], suffix: &[u8]) -> Vec<u8> {
        crate::build::build_package(entries, &[0x90u8; 4096], suffix)
    }

    fn open_temp(entries: &[(String, Vec<u8>)], suffix: &[u8]) -> (tempfile::TempDir, Package) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.exe");
        std::fs::write(&path, build_package(entries, suffix)).unwrap();
        let package = Package::open(&path).unwrap();
        (dir, package)
    }

    #[test]
    fn opens_and_reads_package() {
        let (_dir, package) = open_temp(&base_entries(), b"");
        assert_eq!(package.entries().len(), 5);
        let config = package.read_entry("config.toml", 64 * 1024).unwrap();
        assert_eq!(config, CONFIG);
    }

    #[test]
    fn tolerates_trailing_authenticode_data() {
        let (_dir, package) = open_temp(&base_entries(), b"certificate-table-bytes");
        assert_eq!(package.entries().len(), 5);
    }

    #[test]
    fn extracts_and_verifies_hashes() {
        let (dir, package) = open_temp(&base_entries(), b"");
        let session = dir.path().join("session");
        std::fs::create_dir(&session).unwrap();
        package.extract_all(&session).unwrap();
        assert!(session.join("client.exe").exists());
        assert!(session.join("assets/background.avif").exists());
    }

    #[test]
    fn rejects_tampered_content() {
        let entries = base_entries();
        let mut data = build_package(&entries, b"");
        let position = data
            .windows(CONFIG.len())
            .position(|window| window == CONFIG)
            .expect("config bytes are present in the package");
        data[position] ^= 0x01;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.exe");
        std::fs::write(&path, &data).unwrap();
        let package = Package::open(&path).unwrap();
        let session = dir.path().join("session");
        std::fs::create_dir(&session).unwrap();
        assert!(package.extract_all(&session).is_err());
    }

    #[test]
    fn rejects_traversal_names() {
        let mut entries = base_entries();
        entries.push(("../escape".into(), b"x".to_vec()));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.exe");
        std::fs::write(&path, build_package(&entries, b"")).unwrap();
        assert!(Package::open(&path).is_err());
    }

    #[test]
    fn rejects_missing_required_entry() {
        let mut entries = base_entries();
        entries.retain(|(name, _)| name != "payload.zip");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.exe");
        std::fs::write(&path, build_package(&entries, b"")).unwrap();
        assert!(Package::open(&path).is_err());
    }

    #[test]
    fn rejects_corrupt_directory() {
        let mut data = build_package(&base_entries(), b"");
        let position = data
            .windows(DIRECTORY_MAGIC.len())
            .position(|window| window == DIRECTORY_MAGIC)
            .expect("directory magic is present");
        data[position] = b'X';

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foo.exe");
        std::fs::write(&path, &data).unwrap();
        assert!(Package::open(&path).is_err());
    }
}
