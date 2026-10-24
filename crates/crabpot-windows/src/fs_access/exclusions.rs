//! `windowsProfileExclusionConflicts`: the paths a session must not grant while
//! the profile read grant exists.

use super::spelling::{normalize_case, profile_key};
use super::{Disk, DiskError, Host, Kind, Look, key_from_look};

/// The profile read grant, as `srt-win` records it. Paths are absolute, `*`
/// stands for one name, and a trailing `*` for a prefix.
#[derive(Clone, Copy, Debug)]
pub struct ProfileGrant<'a> {
    /// Every protected path the grant keeps unreadable. A session may not grant
    /// a path that is one, lies inside one, or lies above one.
    pub exclusions: &'a [String],
    /// Directories that are not readable through the grant and are not denied
    /// (the user's temporary directory). A session may not grant one, or a
    /// path above one.
    pub ungranted_only: &'a [String],
}

/// What else the check is told.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConflictOptions<'a> {
    /// Paths a read may be granted despite a protected exclusion at or above
    /// them. A path above an exclusion is still checked against it.
    pub override_: &'a [String],
    /// The grant is a write grant, and no path is admitted.
    pub write: bool,
}

/// Which list an exclusion is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExclusionKind {
    /// `exclusions`.
    Protected,
    /// `ungranted_only`.
    UngrantedOnly,
}

/// How a path stands to an exclusion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relation {
    /// The path is the excluded one.
    Equal,
    /// It lies beneath an excluded directory (protected only).
    Inside,
    /// An excluded path lies beneath it.
    Above,
}

/// A path a session wants to grant, and the exclusion it collides with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The path as the session's settings resolved it.
    pub path: String,
    /// The exclusion, as the grant recorded it.
    pub exclusion: String,
    /// Which list the exclusion is on.
    pub kind: ExclusionKind,
    /// What the session would have granted on the path.
    pub write: bool,
    /// How the path stands to the exclusion.
    pub relation: Relation,
    /// Set on an `Above` conflict with a wildcard exclusion when the path
    /// could not be examined for what the exclusion covers beneath it (access
    /// denied, an I/O error, a path on a share), with the reason.
    pub unexamined: Option<String>,
}

struct Rule<'a> {
    exclusion: &'a str,
    kind: ExclusionKind,
    parts: Vec<String>,
    only_equal: bool,
}

/// One component of a recorded exclusion against one of a path; both lower case.
fn component_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

enum Beneath {
    None,
    Match,
    Unexamined(String),
}

/// Whether something that exists beneath the directory `dir` matches `rest`,
/// the components of an exclusion that `dir` lies above.
fn matched_beneath<D: Disk>(host: &Host<D>, dir: &str, rest: &[String], top: bool) -> Beneath {
    if rest.is_empty() {
        return Beneath::Match;
    }
    match host.disk().lstat(dir) {
        // Beneath `dir` a link is not followed. `dir` itself was resolved a
        // moment ago and should not be one.
        Ok(Kind::Link) if top => return Beneath::Unexamined(format!("'{dir}' is a link")),
        Ok(Kind::Dir) => {}
        Ok(_) | Err(DiskError::Absent) => return Beneath::None,
        Err(DiskError::Other(code)) => {
            return Beneath::Unexamined(format!("'{dir}' could not be listed ({code})"));
        }
    }
    let entries = match host.disk().read_dir(dir) {
        Ok(entries) => entries,
        Err(DiskError::Absent) => return Beneath::None,
        Err(DiskError::Other(code)) => {
            return Beneath::Unexamined(format!("'{dir}' could not be listed ({code})"));
        }
    };
    let mut unexamined = None;
    for entry in entries {
        if !component_matches(&rest[0], &normalize_case(&entry.name)) {
            continue;
        }
        let child = format!("{}\\{}", dir.trim_end_matches('\\'), entry.name);
        match matched_beneath(host, &child, &rest[1..], false) {
            Beneath::Match => return Beneath::Match,
            Beneath::Unexamined(why) => {
                unexamined.get_or_insert(why);
            }
            Beneath::None => {}
        }
    }
    unexamined.map_or(Beneath::None, Beneath::Unexamined)
}

fn rules_of(list: &[String], kind: ExclusionKind, only_equal: bool) -> Vec<Rule<'_>> {
    list.iter()
        .map(|exclusion| Rule {
            exclusion,
            kind,
            parts: profile_key(exclusion)
                .split('/')
                .map(str::to_owned)
                .collect(),
            only_equal,
        })
        .collect()
}

/// The paths among `paths` a session must not grant while the profile read
/// grant exists, with the exclusion each collides with. Paths are resolved
/// first, and a path that exists and cannot be listed fails closed.
pub fn profile_exclusion_conflicts<D: Disk>(
    host: &Host<D>,
    paths: &[String],
    grant: &ProfileGrant<'_>,
    opts: &ConflictOptions<'_>,
) -> Vec<Conflict> {
    if paths.is_empty() {
        return Vec::new();
    }
    // The ungranted-only directory itself is looked for first, so it is
    // reported as what it is and not as "above" something inside it.
    let mut rules = rules_of(grant.ungranted_only, ExclusionKind::UngrantedOnly, true);
    rules.extend(rules_of(grant.exclusions, ExclusionKind::Protected, false));
    rules.extend(rules_of(
        grant.ungranted_only,
        ExclusionKind::UngrantedOnly,
        false,
    ));
    if rules.is_empty() {
        return Vec::new();
    }
    let admitted: Vec<String> = if opts.write {
        Vec::new()
    } else {
        opts.override_.iter().map(|path| host.key(path)).collect()
    };
    let mut out = Vec::new();
    for path in paths {
        // One look at the path: the key and the lookups beneath it use the
        // same result.
        let on_disk = host.look(path);
        let key = key_from_look(path, &on_disk);
        let parts: Vec<&str> = key.split('/').collect();
        for rule in &rules {
            let shared = parts.len().min(rule.parts.len());
            if !(0..shared).all(|i| component_matches(&rule.parts[i], parts[i])) {
                continue;
            }
            let relation = match parts.len().cmp(&rule.parts.len()) {
                core::cmp::Ordering::Equal => Relation::Equal,
                core::cmp::Ordering::Greater => Relation::Inside,
                core::cmp::Ordering::Less => Relation::Above,
            };
            if rule.only_equal && relation != Relation::Equal {
                continue;
            }
            let mut unexamined = None;
            if relation == Relation::Above && rule.exclusion.contains('*') {
                match &on_disk {
                    Look::Absent => continue,
                    Look::Resolved(real) => {
                        match matched_beneath(host, real, &rule.parts[parts.len()..], true) {
                            Beneath::None => continue,
                            Beneath::Match => {}
                            Beneath::Unexamined(why) => unexamined = Some(why),
                        }
                    }
                    // Never opened (a share, the device namespace) or not
                    // openable: nothing was looked at, so nothing is admitted.
                    Look::Unprobed => {
                        unexamined = Some(format!(
                            "'{path}' is not on a local drive and is not examined"
                        ));
                    }
                    Look::Error(code) => {
                        unexamined = Some(format!("'{path}' could not be resolved ({code})"));
                    }
                }
            }
            if rule.kind == ExclusionKind::UngrantedOnly {
                if relation == Relation::Inside {
                    continue;
                }
            } else if relation != Relation::Above && admitted.contains(&key) {
                // An admitted path is still checked against the other
                // exclusions: it may lie above one of them.
                continue;
            }
            out.push(Conflict {
                path: path.clone(),
                exclusion: rule.exclusion.to_owned(),
                kind: rule.kind,
                write: opts.write,
                relation,
                unexamined,
            });
            break;
        }
    }
    out
}
