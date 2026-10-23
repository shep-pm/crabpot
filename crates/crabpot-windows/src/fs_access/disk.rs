//! What the path rules ask of the disk, behind one trait so a test can answer
//! for a Windows volume on any host.

use std::ffi::OsString;
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
        entries_of(listing.map(|item| -> io::Result<_> {
            let entry = item?;
            Ok((entry.file_name(), entry.file_type()))
        }))
    }
}

/// An error part way through a listing. It is never [`DiskError::Absent`], even
/// for an entry that vanished between the read and the stat: the directory is
/// there, and a listing that lost an entry is not a complete one.
fn listing_error(err: &io::Error) -> DiskError {
    DiskError::Other(err.kind().to_string())
}

/// The entries of a listing, or the first error in it: a listing that stopped
/// part way is not one that was read, and the caller must not take it for all
/// of the directory.
fn entries_of(
    listing: impl Iterator<Item = io::Result<(OsString, io::Result<fs::FileType>)>>,
) -> Result<Vec<Entry>, DiskError> {
    let mut entries = Vec::new();
    for item in listing {
        let (name, file_type) = item.map_err(|err| listing_error(&err))?;
        let file_type = file_type.map_err(|err| listing_error(&err))?;
        // A name that is not text cannot be matched by a pattern, or handed to
        // `srt-win` as JSON.
        let Ok(name) = name.into_string() else {
            continue;
        };
        entries.push(Entry {
            name,
            kind: kind_of(file_type),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listing_that_fails_part_way_is_an_error() {
        let listing = vec![Err(io::Error::from(io::ErrorKind::PermissionDenied))];
        assert_eq!(
            entries_of(listing.into_iter()),
            Err(DiskError::Other("permission denied".to_owned()))
        );
    }

    #[test]
    fn an_entry_that_vanished_mid_listing_is_not_an_absent_directory() {
        let listing = vec![Ok((
            OsString::from("Key.pem"),
            Err(io::Error::from(io::ErrorKind::NotFound)),
        ))];
        assert_eq!(
            entries_of(listing.into_iter()),
            Err(DiskError::Other("entity not found".to_owned()))
        );
    }

    #[test]
    fn an_entry_whose_type_cannot_be_read_is_an_error() {
        let listing = vec![Ok((
            OsString::from("Key.pem"),
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        ))];
        assert_eq!(
            entries_of(listing.into_iter()),
            Err(DiskError::Other("permission denied".to_owned()))
        );
    }
}
