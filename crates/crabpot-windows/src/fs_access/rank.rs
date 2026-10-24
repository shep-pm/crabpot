//! `rankWindowsFsAccess` and `windowsGrantsBeneathDenies`: the lists of the
//! settings against each other.

use crabpot_core::config::PathEntry;

use super::expand::{ExpandError, Mode, expand_paths};
use super::spelling::is_at_or_under;
use super::{Access, Disk, Host, Ordered};

/// The expanded lists, as concrete paths ([`expand_paths`]).
#[derive(Clone, Copy, Debug)]
pub struct Lists<'a> {
    /// `allowRead`.
    pub allow_read: &'a [String],
    /// `allowWrite`.
    pub allow_write: &'a [String],
    /// `denyRead`.
    pub deny_read: &'a [String],
    /// `denyWrite`.
    pub deny_write: &'a [String],
    /// The credential files, which are read-denied and outrank every grant.
    pub credential_deny: &'a [String],
    /// Grants that are on disk already, when one command brings denies of its
    /// own.
    pub held: Option<Held<'a>>,
}

/// Grants on disk already. They cannot be taken back for one command, so a
/// deny that covers one is set at its own path, where `srt-win` puts a deny
/// first.
#[derive(Clone, Copy, Debug)]
pub struct Held<'a> {
    /// The read grants.
    pub read: &'a [String],
    /// The write grants.
    pub write: &'a [String],
}

/// The one of `dirs` that a path is, or lies beneath.
struct Covering<'a> {
    dirs: &'a [String],
    keys: Vec<String>,
}

impl<'a> Covering<'a> {
    fn new<D: Disk>(host: &Host<D>, dirs: &'a [String]) -> Self {
        Self {
            dirs,
            keys: dirs.iter().map(|dir| host.key(dir)).collect(),
        }
    }

    fn over<D: Disk>(&self, host: &Host<D>, path: &str) -> Option<&'a str> {
        if self.keys.is_empty() {
            return None;
        }
        let key = host.key(path);
        let at = self.keys.iter().position(|dir| is_at_or_under(&key, dir))?;
        Some(self.dirs[at].as_str())
    }
}

/// Ranks the lists against each other, as on the other platforms, and returns
/// the grants and denies that say so.
///
/// The ACEs set on an object come before the ones it inherits, so beneath a
/// deny on a directory an allow set further down is the one that counts. That
/// is the rank of `allowRead` over `denyRead`, and see
/// [`grants_beneath_denies`]. The other two ranks are the opposite one, so
/// `srt-win` is handed no such allow for them:
///
/// - `denyWrite` over `allowWrite`: a write grant at or beneath a write deny
///   is a read grant.
/// - the credential files over `allowRead` and `allowWrite`: a grant at or
///   beneath one is left out. The caller adds the grants for the library's own
///   files, so they are the only exceptions.
pub fn rank<D: Disk>(host: &Host<D>, lists: &Lists<'_>) -> Access {
    let credential = Covering::new(host, lists.credential_deny);
    let write_deny = Covering::new(host, lists.deny_write);
    let mut read = Ordered::default();
    let mut write = Ordered::default();
    for (path, is_write) in lists
        .allow_read
        .iter()
        .map(|path| (path, false))
        .chain(lists.allow_write.iter().map(|path| (path, true)))
    {
        let over_credential = credential.over(host, path);
        let over_write = if is_write {
            write_deny.over(host, path)
        } else {
            None
        };
        match (over_credential, over_write) {
            (None, None) if is_write => write.insert(path),
            (None, None) => read.insert(path),
            // A write grant under a write deny stays a read grant.
            (None, Some(_)) => read.insert(path),
            (Some(_), _) => {}
        }
    }
    let held = lists.held.unwrap_or(Held {
        read: &[],
        write: &[],
    });
    let mut deny_read = Ordered::default();
    deny_read.extend(lists.deny_read.iter().map(String::as_str));
    deny_read.extend(lists.credential_deny.iter().map(String::as_str));
    deny_read.extend(
        held.read
            .iter()
            .chain(held.write)
            .filter(|path| credential.over(host, path).is_some())
            .map(String::as_str),
    );
    let mut deny_write = Ordered::default();
    deny_write.extend(lists.deny_write.iter().map(String::as_str));
    deny_write.extend(
        held.write
            .iter()
            .filter(|path| write_deny.over(host, path).is_some())
            .map(String::as_str),
    );
    Access {
        read: read.into_vec(),
        write: write.into_vec(),
        deny_read: deny_read.into_vec(),
        deny_write: deny_write.into_vec(),
    }
}

/// The ones of `grants` that lie strictly beneath one of `denies`, the topmost
/// per deny: the grants that rank above those denies, an allow set further down
/// being the one that counts. `denyReadExcept` re-grants these beneath a deny.
pub fn grants_beneath_denies<D: Disk>(
    host: &Host<D>,
    grants: &[String],
    denies: &[String],
) -> Vec<String> {
    if grants.is_empty() || denies.is_empty() {
        return Vec::new();
    }
    let keyed: Vec<(&String, String)> = grants.iter().map(|g| (g, host.key(g))).collect();
    let mut out: Vec<(String, &String)> = Vec::new();
    for deny in denies.iter().map(|deny| host.key(deny)) {
        let beneath: Vec<_> = keyed
            .iter()
            .filter(|(_, key)| *key != deny && is_at_or_under(key, &deny))
            .collect();
        for (path, key) in &beneath {
            let covered = beneath
                .iter()
                .any(|(_, other)| other != key && is_at_or_under(key, other));
            if !covered && !out.iter().any(|(seen, _)| seen == key) {
                out.push((key.clone(), path));
            }
        }
    }
    out.into_iter().map(|(_, path)| path.clone()).collect()
}

/// The lists of the settings and the files the library masked, before they are
/// expanded.
#[derive(Clone, Copy, Debug)]
pub struct Settings<'a> {
    /// `filesystem.allowRead`.
    pub allow_read: &'a [PathEntry],
    /// `filesystem.allowWrite`.
    pub allow_write: &'a [PathEntry],
    /// `filesystem.denyRead`.
    pub deny_read: &'a [PathEntry],
    /// `filesystem.denyWrite`.
    pub deny_write: &'a [PathEntry],
    /// The credential files' paths.
    pub credential_deny: &'a [PathEntry],
    /// Files the library opened to mask. An ACL cannot redirect a read, so each
    /// is unreadable, and none is expanded.
    pub masked_files: &'a [String],
}

/// `computeWindowsFsAccessSet`: the settings' lists expanded and ranked. A deny
/// keeps a path that is not there, and a grant drops it.
///
/// # Errors
///
/// [`ExpandError`] as [`expand_paths`] has it.
pub fn access<D: Disk>(host: &Host<D>, settings: &Settings<'_>) -> Result<Access, ExpandError> {
    let allow_read = expand_paths(host, settings.allow_read, Mode::Grant)?;
    let allow_write = expand_paths(host, settings.allow_write, Mode::Grant)?;
    let deny_read = expand_paths(host, settings.deny_read, Mode::Deny)?;
    let deny_write = expand_paths(host, settings.deny_write, Mode::Deny)?;
    let mut credential_deny = expand_paths(host, settings.credential_deny, Mode::Deny)?;
    credential_deny.extend_from_slice(settings.masked_files);
    Ok(rank(
        host,
        &Lists {
            allow_read: &allow_read,
            allow_write: &allow_write,
            deny_read: &deny_read,
            deny_write: &deny_write,
            credential_deny: &credential_deny,
            held: None,
        },
    ))
}
