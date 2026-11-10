//! What `allowUnixSockets` masks on Linux, and where those masks land in the
//! plan.
//!
//! Every case here needs a socket the kernel is holding, so they run on Linux,
//! where the plan reads `/proc/net/unix` at all.

use std::os::unix::net::UnixListener;

use super::{at, bind_at, build, mount_at, plan};
use crate::support::Tree;
use crabpot_core::config::Config;

/// A config with `network.allowUnixSockets` of `sockets`, `denyRead` of `deny`
/// and `allowWrite` of `write`.
fn policy(sockets: &[&str], deny: &[&str], write: &[&str]) -> Config {
    let list = |entries: &[&str]| {
        entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    Config::from_json(&format!(
        r#"{{
                "network": {{
                    "allowedDomains": [], "deniedDomains": [],
                    "allowUnixSockets": [{}]
                }},
                "filesystem": {{
                    "denyRead": [{}], "allowRead": [],
                    "allowWrite": [{}], "denyWrite": []
                }}
            }}"#,
        list(sockets),
        list(deny),
        list(write)
    ))
    .expect("a config")
}

/// A socket in `tree` at `name`, listening, held so the kernel keeps it in its
/// listing while a plan is built. Its path, as a config would spell it.
fn listening(tree: &Tree, name: &str) -> (String, UnixListener) {
    let path = at(tree, name);
    let listener = UnixListener::bind(&path).expect("a socket");
    (path, listener)
}

/// Whether the plan mounts `/dev/null` over `socket`.
fn masked(words: &[String], socket: &str) -> bool {
    mask_at(words, socket).is_some()
}

/// Where the plan mounts `/dev/null` over `socket`.
fn mask_at(words: &[String], socket: &str) -> Option<usize> {
    words
        .windows(3)
        .position(|run| run == ["--ro-bind", "/dev/null", socket])
}

#[test]
fn a_socket_the_list_leaves_out_is_masked_and_a_listed_one_is_not() {
    let tree = Tree::empty("fs-unix-sockets-list");
    let (listed, _listed) = listening(&tree, "listed.sock");
    let (other, _other) = listening(&tree, "other.sock");

    let words = plan(&tree, &policy(&[&listed], &[], &[]));

    assert!(masked(&words, &other), "the list leaves it out: {words:#?}");
    assert!(!masked(&words, &listed), "the list opens it: {words:#?}");
}

#[test]
fn a_listed_directory_leaves_every_socket_beneath_it_unmasked() {
    let tree = Tree::empty("fs-unix-sockets-dir");
    tree.dir("socks");
    let (inside, _inside) = listening(&tree, "socks/inside.sock");
    let (outside, _outside) = listening(&tree, "outside.sock");
    let socks = at(&tree, "socks");

    let words = plan(&tree, &policy(&[&socks], &[], &[]));

    assert!(
        !masked(&words, &inside),
        "beneath the listed one: {words:#?}"
    );
    assert!(masked(&words, &outside), "beside it: {words:#?}");
}

#[test]
fn a_listed_directory_is_no_listed_socket_of_a_name_that_starts_with_it() {
    let tree = Tree::empty("fs-unix-sockets-prefix");
    let (socket, _socket) = listening(&tree, "socksdir.sock");
    let listed = at(&tree, "socks");

    let words = plan(&tree, &policy(&[&listed], &[], &[]));

    assert!(
        masked(&words, &socket),
        "the match is by component: {words:#?}"
    );
}

#[test]
fn with_no_list_no_socket_is_masked() {
    let tree = Tree::empty("fs-unix-sockets-none");
    let (live, _live) = listening(&tree, "live.sock");

    let words = plan(&tree, &policy(&[], &[], &[]));

    assert!(
        !masked(&words, &live),
        "no list, and the filter refuses `AF_UNIX` instead: {words:#?}"
    );
}

/// An empty entry is the plan's working directory, as the macOS profile reads
/// it, and not the whole filesystem.
#[test]
fn an_empty_entry_opens_the_plans_working_directory_and_nothing_above_it() {
    let tree = Tree::empty("fs-unix-sockets-empty-entry");
    tree.dir("cwd");
    let (under, _under) = listening(&tree, "cwd/under.sock");
    let (above, _above) = listening(&tree, "above.sock");

    let words = plan(&tree, &policy(&[""], &[], &[]));

    assert!(
        !masked(&words, &under),
        "beneath the working directory: {words:#?}"
    );
    assert!(masked(&words, &above), "beside it: {words:#?}");
}

#[test]
fn a_socket_the_read_sections_already_hid_is_not_masked_again() {
    let tree = Tree::empty("fs-unix-sockets-denied");
    tree.dir("hidden");
    let (listed, _listed) = listening(&tree, "listed.sock");
    let (hidden, _hidden) = listening(&tree, "hidden/a.sock");
    let dir = at(&tree, "hidden");

    let words = plan(&tree, &policy(&[&listed], &[&dir], &[]));

    assert!(
        words
            .windows(2)
            .any(|pair| pair == ["--tmpfs", dir.as_str()]),
        "the deny over the directory is still there: {words:#?}"
    );
    assert!(
        mask_at(&words, &hidden).is_none(),
        "bwrap cannot make a mount point under the tmpfs, so the socket stays \
         behind the mask it is already under: {words:#?}"
    );
}

#[test]
fn the_masks_follow_every_write_bind_and_come_before_the_sandboxs_own_mounts() {
    let tree = Tree::empty("fs-unix-sockets-order");
    tree.dir("work");
    let (listed, _listed) = listening(&tree, "listed.sock");
    let (live, _live) = listening(&tree, "work/live.sock");
    let (work, live) = (at(&tree, "work"), live);

    let words = plan(&tree, &policy(&[&listed], &[], &[&work]));

    let mask = mask_at(&words, &live).expect("the socket is masked");
    assert!(
        bind_at(&words, &work) < mask,
        "a write bind of the directory would otherwise cover the mask: {words:#?}"
    );
    assert!(
        mask < mount_at(&words, "--dev", "/dev"),
        "the sandbox's own mounts stay last: {words:#?}"
    );
}

/// A listed socket in a writable directory is left bindable: the plan pins the
/// ancestors of a deny so it cannot be renamed away, and a socket mask is no
/// deny of the command's own path.
#[test]
fn a_masked_socket_pins_nothing_above_it() {
    let tree = Tree::empty("fs-unix-sockets-pins");
    tree.dir("work");
    let (listed, _listed) = listening(&tree, "listed.sock");
    let (other, _other) = listening(&tree, "work/other.sock");
    let work = at(&tree, "work");

    let words = plan(&tree, &policy(&[&listed], &[], &[&work]));

    assert!(masked(&words, &other), "{words:#?}");
    assert!(
        mask_at(&words, &work).is_none(),
        "`{work}` is a directory, not a socket: {words:#?}"
    );
    assert!(
        !words
            .windows(3)
            .any(|run| run == ["--ro-bind", work.as_str(), work.as_str()]),
        "the directory holding a masked socket is not pinned read-only: {words:#?}"
    );
}

/// The plan is built from the kernel's listing, so a socket that is not a
/// socket, or is under a mount bwrap makes afresh, is no mask.
#[test]
fn only_the_kernels_named_sockets_are_found() {
    let tree = Tree::empty("fs-unix-sockets-found");
    tree.file("plain.sock", "");
    tree.dir("dir");
    let (live, _live) = listening(&tree, "live.sock");
    let (plain, dir) = (at(&tree, "plain.sock"), at(&tree, "dir"));

    let found = crate::fs::unix_sockets::bound().expect("the kernel's listing");

    assert!(
        found
            .iter()
            .any(|socket| socket == std::path::Path::new(&live)),
        "{found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|socket| socket == std::path::Path::new(&plain)),
        "a file named `.sock` is no socket: {found:?}"
    );
    assert!(
        !found
            .iter()
            .any(|socket| socket == std::path::Path::new(&dir)),
        "the directory holding one is no socket: {found:?}"
    );
    assert!(
        !found.iter().any(|socket| socket.starts_with("/proc")),
        "bwrap makes `/proc` afresh: {found:?}"
    );
}

/// The masks are the plan's own words, so a whole plan carries them.
#[test]
fn a_list_of_sockets_says_the_filter_may_open_af_unix() {
    let tree = Tree::empty("fs-unix-sockets-open");
    let (listed, _listed) = listening(&tree, "listed.sock");

    let with = build(&tree, &policy(&[&listed], &[], &[]));
    let without = build(&tree, &policy(&[], &[], &[]));

    assert!(with.unix_sockets_open());
    assert!(
        !without.unix_sockets_open(),
        "no list, and the filter keeps refusing `AF_UNIX`"
    );
}
