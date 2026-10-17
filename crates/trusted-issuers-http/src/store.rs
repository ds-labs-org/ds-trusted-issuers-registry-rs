//! Where the registry and its audit log are kept. Every admin write goes
//! through [`Store::commit`], which must make the new registry and that
//! write's [`AuditEntry`] durable together, or neither.
//!
//! - [`MemoryStore`]: nothing survives a restart (development, tests).
//! - [`JsonFileStore`]: the registry as one JSON file, rewritten atomically
//!   after each write, and the audit log as JSON lines next to it.

use std::io::Write;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use trusted_issuers_core::{AuditEntry, Registry, verify_audit_chain};

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

/// Keeps the audit log in memory; nothing survives a restart.
#[derive(Default)]
pub struct MemoryStore {
    audit: Mutex<Vec<AuditEntry>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn commit(&self, _registry: &Registry, entry: &AuditEntry) -> std::io::Result<()> {
        lock(&self.audit).push(entry.clone());
        Ok(())
    }

    fn audit_head(&self) -> Option<AuditEntry> {
        lock(&self.audit).last().cloned()
    }

    fn audit_page(
        &self,
        after: u64,
        limit: usize,
        id: Option<&str>,
    ) -> std::io::Result<Vec<AuditEntry>> {
        Ok(page(&lock(&self.audit), after, limit, id))
    }
}

/// Locks `m`, ignoring poisoning: every writer leaves the data consistent
/// before anything that can panic.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// [`Store::audit_page`] over entries held in order.
fn page(entries: &[AuditEntry], after: u64, limit: usize, id: Option<&str>) -> Vec<AuditEntry> {
    entries
        .iter()
        .filter(|e| e.seq > after && id.is_none_or(|id| e.id == id))
        .take(limit)
        .cloned()
        .collect()
}

/// Where a [`JsonFileStore`] keeps the audit log of `data_file`: next to it,
/// `<data file>.audit.jsonl`.
pub fn audit_file(data_file: &FsPath) -> PathBuf {
    let mut name = data_file.as_os_str().to_owned();
    name.push(".audit.jsonl");
    PathBuf::from(name)
}

/// The registry as one JSON file (see [`persist`]), and its audit log as
/// JSON lines in [`audit_file`], one entry per line.
///
/// A commit appends the entry to the log and fsyncs it, then replaces the
/// registry file. If replacing fails the log is truncated back, so neither
/// changes. A crash between the two leaves the log one entry ahead of the
/// registry; [`JsonFileStore::open`] drops entries newer than the
/// registry's `version`, since their writes never happened.
pub struct JsonFileStore {
    path: PathBuf,
    audit_path: PathBuf,
    audit: Mutex<Vec<AuditEntry>>,
}

impl JsonFileStore {
    /// Opens the store at `path` and returns it with the registry it holds
    /// (see [`load`] for `create_if_missing`). The audit log is read and
    /// its hash chain verified; a broken chain is an error, so a tampered
    /// log stops the registry from starting instead of being extended.
    pub fn open(path: &FsPath, create_if_missing: bool) -> Result<(Self, Registry), String> {
        let registry = load(path, create_if_missing)?;
        let audit_path = audit_file(path);
        let err = |e: &dyn std::fmt::Display| format!("{}: {e}", audit_path.display());
        let mut entries = match std::fs::read_to_string(&audit_path) {
            Ok(text) => text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str::<AuditEntry>(line).map_err(|e| err(&e)))
                .collect::<Result<Vec<_>, _>>()?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(err(&e)),
        };
        if entries.first().is_some_and(|e| e.seq != 1) {
            return Err(err(&"the audit log does not start at entry 1"));
        }
        verify_audit_chain(&entries).map_err(|e| err(&e))?;
        let kept = entries
            .iter()
            .position(|e| e.version > registry.version)
            .unwrap_or(entries.len());
        if kept < entries.len() {
            tracing::warn!(
                "{}: dropping {} audit entries newer than the registry (version {}): their writes did not complete",
                audit_path.display(),
                entries.len() - kept,
                registry.version
            );
            entries.truncate(kept);
            rewrite_lines(&audit_path, &entries).map_err(|e| err(&e))?;
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                audit_path,
                audit: Mutex::new(entries),
            },
            registry,
        ))
    }
}

impl Store for JsonFileStore {
    fn commit(&self, registry: &Registry, entry: &AuditEntry) -> std::io::Result<()> {
        let mut audit = lock(&self.audit);
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_path)?;
        let len = file.metadata()?.len();
        let appended = file.write_all(&line).and_then(|()| file.sync_all());
        let committed = appended.and_then(|()| {
            if len == 0 {
                // A new log file: make its directory entry durable too.
                sync_dir(&self.path)?;
            }
            persist(&self.path, registry)
        });
        if let Err(e) = committed {
            if let Err(undo) = file.set_len(len).and_then(|()| file.sync_all()) {
                tracing::error!(
                    "{}: could not remove the audit entry of a failed write: {undo}",
                    self.audit_path.display()
                );
            }
            return Err(e);
        }
        audit.push(entry.clone());
        Ok(())
    }

    fn audit_head(&self) -> Option<AuditEntry> {
        lock(&self.audit).last().cloned()
    }

    fn audit_page(
        &self,
        after: u64,
        limit: usize,
        id: Option<&str>,
    ) -> std::io::Result<Vec<AuditEntry>> {
        Ok(page(&lock(&self.audit), after, limit, id))
    }
}

/// Atomically replaces `path` with `entries`, one JSON line each.
fn rewrite_lines(path: &FsPath, entries: &[AuditEntry]) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    for entry in entries {
        serde_json::to_writer(&mut bytes, entry)?;
        bytes.push(b'\n');
    }
    write_atomically(path, &bytes)
}

/// Fsyncs the directory holding `path`.
fn sync_dir(path: &FsPath) -> std::io::Result<()> {
    std::fs::File::open(parent_dir(path))?.sync_all()
}

fn parent_dir(path: &FsPath) -> &FsPath {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => FsPath::new("."),
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
    write_atomically(path, &serde_json::to_vec_pretty(registry)?)
}

/// See [`persist`].
fn write_atomically(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    let dir = parent_dir(path);
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
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}
