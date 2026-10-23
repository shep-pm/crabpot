//! What the path rules ask of the disk, behind one trait so a test can answer
//! for a Windows volume on any host.

use std::fs;
use std::io;

/// What a name on disk is. A junction is a [`Kind::Link`] like a symlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A file, or anything that is neither a directory nor a link.
    File,
    /// A directory.
    Dir,
    /// A symlink or a junction.
    Link,
}

/// One name in a directory, as the disk spells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The name, without its directory.
    pub name: String,
    /// What it is, a link not followed.
    pub kind: Kind,
}

/// Why the disk could not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiskError {
    /// Nothing is there, or a parent is not a directory.
    Absent,
    /// Looking failed for another reason, such as access denied; holds the
    /// reason as the OS gave it.
    Other(String),
}

/// The disk, as a path is resolved and walked on it.
pub trait Disk {
    /// `path` with links, junctions, 8.3 names and case resolved: the final
    /// path `srt-win` resolves too.
    ///
    /// # Errors
    ///
    /// [`DiskError::Absent`] when nothing is there, [`DiskError::Other`] when
    /// it could not be looked at.
    fn real_path(&self, path: &str) -> Result<String, DiskError>;

    /// Whether something is at `path`, a link followed. What cannot be looked
    /// at counts as there: a deny must not be dropped for it.
    fn exists(&self, path: &str) -> bool;

    /// What `path` is, a link not followed.
    ///
    /// # Errors
    ///
    /// As [`Disk::real_path`].
    fn lstat(&self, path: &str) -> Result<Kind, DiskError>;

    /// The names in the directory `path`.
    ///
    /// # Errors
    ///
    /// As [`Disk::real_path`].
    fn read_dir(&self, path: &str) -> Result<Vec<Entry>, DiskError>;
}

/// The disk of this host.
#[derive(Clone, Copy, Debug, Default)]
pub struct StdDisk;

fn disk_error(err: &io::Error) -> DiskError {
    if matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
    ) {
        DiskError::Absent
    } else {
        DiskError::Other(err.kind().to_string())
    }
}

fn kind_of(file_type: fs::FileType) -> Kind {
    if file_type.is_symlink() {
        Kind::Link
    } else if file_type.is_dir() {
        Kind::Dir
    } else {
        Kind::File
    }
}

impl Disk for StdDisk {
    fn real_path(&self, path: &str) -> Result<String, DiskError> {
        let real = fs::canonicalize(path).map_err(|err| disk_error(&err))?;
        real.into_os_string()
            .into_string()
            .map_err(|_| DiskError::Other("the real path is not valid UTF-8".to_owned()))
    }

    fn exists(&self, path: &str) -> bool {
        match fs::metadata(path) {
            Ok(_) => true,
            Err(err) => disk_error(&err) != DiskError::Absent,
        }
    }

    fn lstat(&self, path: &str) -> Result<Kind, DiskError> {
        fs::symlink_metadata(path)
            .map(|meta| kind_of(meta.file_type()))
            .map_err(|err| disk_error(&err))
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>, DiskError> {
        let listing = fs::read_dir(path).map_err(|err| disk_error(&err))?;
        let mut entries = Vec::new();
        for entry in listing.flatten() {
            // A name that is not text cannot be matched by a pattern, or
            // handed to `srt-win` as JSON.
            let (Ok(name), Ok(file_type)) = (entry.file_name().into_string(), entry.file_type())
            else {
                continue;
            };
            entries.push(Entry {
                name,
                kind: kind_of(file_type),
            });
        }
        Ok(entries)
    }
}
