//! The grants one process holds for a sandbox user, and how it releases them.
//! One `acl grant` call makes them, and the holder pid names this process in
//! every call after it. Dropping the [`Held`] revokes them, and restores the
//! denies only when every grant came back released, since a grant that is
//! still on disk needs its deny kept under it.

use core::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use super::srt::{Call, Output, Srt};

/// The grants one process holds for a sandbox user, released when it drops.
pub(crate) struct Held {
    pub(crate) srt: Arc<dyn Srt>,
    pub(crate) sid: String,
    pub(crate) holder: u32,
}

impl fmt::Debug for Held {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Held")
            .field("sid", &self.sid)
            .field("holder", &self.holder)
            .finish_non_exhaustive()
    }
}

impl Held {
    fn call(&self, verb: &str) -> Call {
        Call::new([
            "acl",
            verb,
            "--holder-pid",
            &self.holder.to_string(),
            "--sandbox-user-sid",
            &self.sid,
            "--json",
        ])
    }
}

impl Drop for Held {
    /// Revokes the grants, then restores the denies. A revoke that did not
    /// finish leaves the denies in place, since a grant may still be on disk.
    fn drop(&mut self) {
        if revoked(&self.srt.run(&self.call("revoke"))) {
            let _ = self.srt.run(&self.call("restore"));
        } else {
            eprintln!(
                "crabpot: the sandbox's grants could not all be revoked, so its denies stay in place; `crabpot --srt-win acl recover` clears them once this process has exited"
            );
        }
    }
}

/// One path `acl revoke` reports on.
#[derive(Deserialize)]
struct Outcome {
    path: String,
    status: String,
}

impl Outcome {
    /// Whether the grant is released. A status this build does not know is not.
    fn released(&self) -> bool {
        match self.status.as_str() {
            "revoked" | "stillHeld" | "downgraded" | "relocated" | "mismatch" | "noRow"
            | "gone" => true,
            // An older srt-win says it of a path it could not open too, so it
            // counts only when the path is gone.
            "missing" => matches!(
                Path::new(&self.path).symlink_metadata(),
                Err(e) if e.kind() == io::ErrorKind::NotFound
            ),
            _ => false,
        }
    }
}

/// Whether an `acl revoke` ran to the end and released every grant.
fn revoked(output: &io::Result<Output>) -> bool {
    let Ok(output) = output else {
        return false;
    };
    output.succeeded()
        && serde_json::from_str::<Vec<Outcome>>(&output.stdout)
            .is_ok_and(|outcomes| outcomes.iter().all(Outcome::released))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::srt::fake::{Fake, exit};

    /// Grants held for this suite's sandbox user and holder pid.
    fn held(srt: Fake) -> Held {
        Held {
            srt: Arc::new(srt),
            sid: "S-1-5-21-7".to_owned(),
            holder: 4242,
        }
    }

    /// The words a release call of this holder is made of.
    fn release(verb: &str) -> Vec<String> {
        ["acl", verb, "--holder-pid", "4242"]
            .into_iter()
            .chain(["--sandbox-user-sid", "S-1-5-21-7", "--json"])
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn held_grants_are_revoked_then_restored() {
        let (srt, calls) = Fake::passing();

        drop(held(srt));

        let all = calls.all();
        let [revoke, restore] = all.as_slice() else {
            panic!("calls: {all:?}");
        };
        assert_eq!(revoke.args, release("revoke"));
        assert_eq!(restore.args, release("restore"));
    }

    #[test]
    fn a_revoke_that_did_not_finish_leaves_the_denies_in_place() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(1, r#"[{"path":"C:\\work","status":"pending"}]"#),
            _ => exit(0, "[]"),
        });

        drop(held(srt));

        assert!(calls.starting(&["acl", "restore"]).is_empty());
    }

    #[test]
    fn a_revoke_that_found_a_substituted_path_is_finished() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(0, r#"[{"path":"C:\\work","status":"mismatch"}]"#),
            _ => exit(0, "[]"),
        });

        drop(held(srt));

        assert_eq!(calls.starting(&["acl", "restore"]).len(), 1);
    }

    #[test]
    fn a_revoke_that_printed_an_unknown_status_is_not_finished() {
        let (srt, calls) = Fake::answering(|call| match call.args[1].as_str() {
            "revoke" => exit(0, r#"[{"path":"C:\\work","status":"somethingNew"}]"#),
            _ => exit(0, "[]"),
        });

        drop(held(srt));

        assert!(calls.starting(&["acl", "restore"]).is_empty());
    }
}
