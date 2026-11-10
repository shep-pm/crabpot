//! How a command's masks are made again from the sockets the host holds. The
//! sockets are handed to [`Masks::refresh_from`], so these cases do not read
//! the live host listing, which other tests' sockets fill, and they run on
//! every Unix host.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{at, build, policy};
use crate::support::Tree;

/// How many words bwrap takes after each flag the plan writes.
fn arity(flag: &str) -> Option<usize> {
    match flag {
        "--ro-bind" | "--bind" | "--symlink" => Some(2),
        "--tmpfs" | "--dev" | "--proc" => Some(1),
        _ if flag.starts_with("--") => Some(0),
        _ => None,
    }
}

/// Every word of `words` sits where bwrap reads it: a flag, then as many
/// arguments as it takes. A cut through a triple leaves a flag where an
/// argument belongs, or an argument where a flag does.
fn well_formed(words: &[String]) -> Result<(), String> {
    let mut at = 0;
    while at < words.len() {
        let flag = &words[at];
        let takes = arity(flag).ok_or_else(|| format!("{flag} at {at} is no flag: {words:#?}"))?;
        for word in words.get(at + 1..at + 1 + takes).unwrap_or_default() {
            if word.starts_with("--") {
                return Err(format!("{flag} at {at} takes {word}: {words:#?}"));
            }
        }
        if at + takes >= words.len() {
            return Err(format!("{flag} at {at} runs past the end: {words:#?}"));
        }
        at += 1 + takes;
    }
    Ok(())
}

fn text(words: &[OsString]) -> Vec<String> {
    words
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The masks are made again for each command, from what the host holds then.
#[test]
fn a_socket_bound_after_the_plan_is_masked_in_the_words_a_later_command_gets() {
    let tree = Tree::empty("fs-unix-refresh");
    let listed = at(&tree, "listed.sock");
    let later = at(&tree, "later.sock");
    // A denied file in a folder beneath a write root makes the plan pin that
    // folder, ahead of the masks, which moves where the section's words sit.
    let work = at(&tree, "work");
    let secret = at(&tree, "work/sub/secret");
    tree.file("work/sub/secret", "x");
    let held = build(&tree, &policy(&[&listed], &[&secret], &[&work]));
    let masks = held.unix_masks().expect("a list makes masks");
    let planned = text(held.words());
    well_formed(&planned).expect("the plan's own words");
    let pin = at(&tree, "work/sub");
    assert!(
        planned
            .windows(3)
            .any(|run| run == ["--ro-bind", &pin, &pin]),
        "the folder is pinned: {planned:#?}"
    );

    let (fresh, open) = masks.refresh_from(
        held.words(),
        Some(vec![PathBuf::from(&listed), PathBuf::from(&later)]),
    );
    let fresh = text(&fresh);

    assert!(open);
    well_formed(&fresh).expect("the refreshed words");
    let mask = |socket: &str| {
        fresh
            .windows(3)
            .any(|run| run == ["--ro-bind", "/dev/null", socket])
    };
    assert!(mask(&later), "a socket bound after the plan: {fresh:#?}");
    assert!(!mask(&listed), "a listed socket: {fresh:#?}");
    // Beside its one new mask, the section is cut out and nothing else moved:
    // the words are what the same refresh gives with no socket held.
    let (bare, _) = masks.refresh_from(held.words(), Some(Vec::new()));
    let mut shut = fresh.clone();
    let at = shut
        .windows(3)
        .position(|run| run == ["--ro-bind", "/dev/null", later.as_str()])
        .expect("the mask is there");
    shut.drain(at..at + 3);
    assert_eq!(shut, text(&bare));
}

/// A listing that cannot be read masks none of the sockets and leaves
/// `AF_UNIX` refused.
#[test]
fn no_listing_leaves_the_words_without_masks_and_the_call_refused() {
    let tree = Tree::empty("fs-unix-refresh-none");
    let listed = at(&tree, "listed.sock");
    let held = build(&tree, &policy(&[&listed], &[], &[]));
    let masks = held.unix_masks().expect("a list makes masks");

    let (fresh, open) = masks.refresh_from(held.words(), None);

    assert!(!open);
    well_formed(&text(&fresh)).expect("the refreshed words");
    assert!(!text(&fresh).iter().any(|word| word == "/dev/null"));
}
