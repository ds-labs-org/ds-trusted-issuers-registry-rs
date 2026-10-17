//! Where the registry and its audit log are kept. Every admin write goes
//! through [`Store::commit`], which must make the new registry and that
//! write's [`AuditEntry`] durable together, or neither.
//!
//! - [`MemoryStore`]: nothing survives a restart (development, tests).
//! - [`JsonFileStore`]: the registry as one JSON file, rewritten atomically
//!   after each write.

use std::io::Write;
use std::path::{Path as FsPath, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use trusted_issuers_core::{AuditEntry, Registry};

/// Durable home of the registry and its audit log.
///
/// [`Store::commit`] is only called under the registry's write lock, so
/// calls never overlap and [`Store::audit_head`] is always the entry the
/// next one chains from.
pub trait Store: Send + Sync + 'static {
    /// Makes `registry` the stored state and appends `entry` to the audit
    /// log, both or neither: on an error the store is as it was.
    fn commit(&self, registry: &Registry, entry: &AuditEntry) -> std::io::Result<()>;

    /// The latest audit entry, `None` while the log is empty.
    fn audit_head(&self) -> Option<AuditEntry>;

    /// Audit entries with `seq` above `after`, oldest first, at most
    /// `limit`, and only those about `id` (canonical) when given.
    fn audit_page(
        &self,
        after: u64,
        limit: usize,
        id: Option<&str>,
    ) -> std::io::Result<Vec<AuditEntry>>;
}

/// Keeps nothing beyond the process.
#[derive(Default)]
pub struct MemoryStore {}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn commit(&self, _registry: &Registry, _entry: &AuditEntry) -> std::io::Result<()> {
        Ok(())
    }

    fn audit_head(&self) -> Option<AuditEntry> {
        None
    }

    fn audit_page(
        &self,
        _after: u64,
        _limit: usize,
        _id: Option<&str>,
    ) -> std::io::Result<Vec<AuditEntry>> {
        Ok(Vec::new())
    }
}

/// Where a [`JsonFileStore`] keeps the audit log of `data_file`: next to it,
/// `<data file>.audit.jsonl`.
pub fn audit_file(data_file: &FsPath) -> PathBuf {
    let mut name = data_file.as_os_str().to_owned();
    name.push(".audit.jsonl");
    PathBuf::from(name)
}

/// The registry as one JSON file (see [`persist`]).
pub struct JsonFileStore {
    path: PathBuf,
}

impl JsonFileStore {
    /// Opens the store at `path` and returns it with the registry it holds
    /// (see [`load`] for `create_if_missing`).
    pub fn open(path: &FsPath, create_if_missing: bool) -> Result<(Self, Registry), String> {
        let registry = load(path, create_if_missing)?;
        Ok((
            Self {
                path: path.to_path_buf(),
            },
            registry,
        ))
    }
}

impl Store for JsonFileStore {
    fn commit(&self, registry: &Registry, _entry: &AuditEntry) -> std::io::Result<()> {
        persist(&self.path, registry)
    }

    fn audit_head(&self) -> Option<AuditEntry> {
        None
    }

    fn audit_page(
        &self,
        _after: u64,
        _limit: usize,
        _id: Option<&str>,
    ) -> std::io::Result<Vec<AuditEntry>> {
        Ok(Vec::new())
    }
}

/// Loads a registry persisted by [`persist`] and re-checks it against the
/// write rules, so a hand-edited file can't smuggle in what the API would
/// refuse. A missing file is an error unless `create_if_missing`, so an
/// unmounted volume or a mistyped path doesn't silently serve an empty
/// registry.
pub fn load(path: &FsPath, create_if_missing: bool) -> Result<Registry, String> {
    let registry: Registry = match std::fs::read(path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create_if_missing => {
            return Ok(Registry::default());
        }
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    registry
        .revalidated()
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Writes the registry to `path` atomically and durably: a uniquely named
/// temp file in the same directory (created exclusively, so a planted file
/// or symlink is never written through), fsynced, renamed over `path`,
/// then the directory fsynced so the rename survives a power loss.
pub fn persist(path: &FsPath, registry: &Registry) -> std::io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => FsPath::new("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("data file path has no file name"))?
        .to_string_lossy();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = dir.join(format!(".{name}.{}.{nanos}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(registry)?)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
