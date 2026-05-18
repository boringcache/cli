use anyhow::{Context, Result, anyhow};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use zstd::stream::write::Encoder as ZstdEncoder;

const PACKAGE_ZSTD_LEVEL: i32 = 3;

#[derive(Debug, Clone)]
pub(crate) struct PackageTar {
    pub digest: String,
    pub size_bytes: u64,
    pub entry_count: usize,
}

pub(crate) fn write_package_tar(
    root: &Path,
    install_paths: &[PathBuf],
    destination: &Path,
) -> Result<PackageTar> {
    let entries = package_entries(root, install_paths)?;
    let writer = File::create(destination)
        .with_context(|| format!("Failed to create package blob {}", destination.display()))?;
    let writer = BufWriter::new(writer);
    let hashing_writer = HashingWriter::new(writer);
    let mut encoder = ZstdEncoder::new(hashing_writer, PACKAGE_ZSTD_LEVEL)
        .context("Failed to initialize package zstd encoder")?;
    encoder
        .include_checksum(true)
        .context("Failed to enable package zstd checksum")?;

    let mut builder = tar::Builder::new(encoder);
    builder.mode(tar::HeaderMode::Deterministic);

    for (relative, absolute) in &entries {
        append_path(&mut builder, root, relative, absolute)?;
    }

    let encoder = builder
        .into_inner()
        .context("Failed to finalize package tar")?;
    let mut hashing_writer = encoder
        .finish()
        .context("Failed to finish package zstd stream")?;
    hashing_writer
        .flush()
        .context("Failed to flush package blob")?;
    let digest = hashing_writer.finish_hash();

    let size_bytes = fs::metadata(destination)
        .with_context(|| format!("Failed to stat package blob {}", destination.display()))?
        .len();

    Ok(PackageTar {
        digest,
        size_bytes,
        entry_count: entries.len(),
    })
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish_hash(self) -> String {
        let digest = self.hasher.finalize();
        let mut output = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            let _ = write!(output, "{byte:02x}");
        }
        format!("sha256:{output}")
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn hash_file(path: &Path) -> Result<String> {
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .with_context(|| format!("Failed to hash {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{:02x}", byte);
    }
    Ok(format!("sha256:{output}"))
}

fn package_entries(root: &Path, install_paths: &[PathBuf]) -> Result<BTreeMap<String, PathBuf>> {
    let mut entries = BTreeMap::new();

    for install_path in install_paths {
        let absolute = crate::cas_file::safe_join_path(root, install_path)?;
        let metadata = fs::symlink_metadata(&absolute)
            .with_context(|| format!("Failed to inspect {}", absolute.display()))?;

        if metadata.is_dir() {
            collect_tree(root, &absolute, &mut entries)?;
        } else {
            insert_entry(root, &absolute, &mut entries)?;
        }
    }

    Ok(entries)
}

pub(crate) fn collect_tree(
    root: &Path,
    absolute: &Path,
    entries: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    insert_entry(root, absolute, entries)?;

    let metadata = fs::symlink_metadata(absolute)
        .with_context(|| format!("Failed to inspect {}", absolute.display()))?;
    if !metadata.is_dir() {
        return Ok(());
    }

    let mut children = fs::read_dir(absolute)
        .with_context(|| format!("Failed to read directory {}", absolute.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("Failed to read directory {}", absolute.display()))?;
    children.sort_by(|left, right| {
        crate::cache::cas_pkg::normalize_path_for_pointer(left)
            .cmp(&crate::cache::cas_pkg::normalize_path_for_pointer(right))
    });

    for child in children {
        let child_metadata = fs::symlink_metadata(&child)
            .with_context(|| format!("Failed to inspect {}", child.display()))?;
        if child_metadata.is_dir() {
            collect_tree(root, &child, entries)?;
        } else {
            insert_entry(root, &child, entries)?;
        }
    }

    Ok(())
}

pub(crate) fn insert_entry(
    root: &Path,
    absolute: &Path,
    entries: &mut BTreeMap<String, PathBuf>,
) -> Result<()> {
    let relative = absolute.strip_prefix(root).with_context(|| {
        format!(
            "Package path {} is not under {}",
            absolute.display(),
            root.display()
        )
    })?;
    let relative = crate::cache::cas_pkg::normalize_path_for_pointer(relative);
    if relative.is_empty() {
        return Err(anyhow!(
            "Package CAS cannot store install root as a package entry"
        ));
    }
    entries.insert(relative, absolute.to_path_buf());
    Ok(())
}

fn append_path<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    root: &Path,
    relative: &str,
    absolute: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(absolute)
        .with_context(|| format!("Failed to inspect {}", absolute.display()))?;

    if metadata.is_dir() {
        let mut header = normalized_header(tar::EntryType::Directory, 0, 0o755)?;
        builder
            .append_data(&mut header, relative, io::empty())
            .with_context(|| format!("Failed to append directory {}", relative))?;
        return Ok(());
    }

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(absolute)
            .with_context(|| format!("Failed to read symlink {}", absolute.display()))?;
        let destination = crate::cas_file::safe_join(root, relative)?;
        crate::cas_file::validate_symlink_target(root, &destination, &target, true)?;
        let mut header = normalized_header(tar::EntryType::Symlink, 0, 0o755)?;
        builder
            .append_link(&mut header, relative, &target)
            .with_context(|| format!("Failed to append symlink {}", relative))?;
        return Ok(());
    }

    if metadata.is_file() {
        let mut file = File::open(absolute)
            .with_context(|| format!("Failed to open {}", absolute.display()))?;
        let mut header = normalized_header(
            tar::EntryType::Regular,
            metadata.len(),
            normalized_file_mode(&metadata),
        )?;
        builder
            .append_data(&mut header, relative, &mut file)
            .with_context(|| format!("Failed to append file {}", relative))?;
        return Ok(());
    }

    Err(anyhow!(
        "Unsupported package CAS entry type for {}",
        absolute.display()
    ))
}

fn normalized_header(entry_type: tar::EntryType, size: u64, mode: u32) -> Result<tar::Header> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_username("")?;
    header.set_groupname("")?;
    header.set_cksum();
    Ok(header)
}

fn normalized_file_mode(metadata: &fs::Metadata) -> u32 {
    if is_executable(metadata) {
        0o755
    } else {
        0o644
    }
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}
