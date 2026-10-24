//! The mount points bwrap makes on the host for a deny of a path that is not
//! there, and which sandbox removes them.

use super::{at, build, denying_writes};
use crate::support::Tree;

/// A path that is not there is bound at its first missing component, and that
/// component is made on the host by bwrap, so the plan is to remove it.
#[test]
fn an_absent_path_gets_a_host_mount_point() {
    let tree = Tree::empty("fs-deny-write-absent");
    tree.dir("work/.git");
    let (work, hooks) = (at(&tree, "work"), at(&tree, "work/.git/hooks"));
    let mount_point = tree.root().join("work/.git/hooks");

    let plan = build(&tree, &denying_writes(&[&work], &[&hooks]));

    let words: Vec<_> = plan.words().iter().map(|w| w.to_string_lossy()).collect();
    let at = words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/dev/null", &*mount_point.to_string_lossy()]);
    assert!(at.is_some(), "{words:#?}");
    assert_eq!(plan.mount_points(), [mount_point]);
}

/// A component with a deny beneath it is an empty directory, which stays
/// traversable, and a deny of the component itself shares the mount point.
#[test]
fn a_component_with_a_deny_beneath_it_is_an_empty_directory() {
    let tree = Tree::empty("fs-deny-write-component");
    tree.dir("work");
    let (work, claude, commands) = (
        at(&tree, "work"),
        at(&tree, "work/.claude"),
        at(&tree, "work/.claude/commands"),
    );

    let plan = build(&tree, &denying_writes(&[&work], &[&claude, &commands]));

    let words: Vec<_> = plan.words().iter().map(|w| w.to_string_lossy()).collect();
    let at = words
        .windows(3)
        .position(|triple| triple[0] == "--ro-bind" && triple[2] == claude)
        .expect("a bind at the first missing component");
    assert_ne!(words[at + 1], "/dev/null", "{words:#?}");
    assert_eq!(
        words.iter().filter(|word| **word == claude).count(),
        // The bind's dest and the empty directory's own read-only bind are not
        // this path; the pin of the source is under the temp directory.
        1,
        "{words:#?}"
    );
    assert_eq!(plan.mount_points(), [std::path::PathBuf::from(&claude)]);
}

/// bwrap leaves its mount points behind, so a plan removes the ones it is
/// still holding when it drops. Anything that has been written to is not the
/// empty file bwrap made, and stays.
#[test]
fn mount_points_are_removed_when_the_sandbox_drops() {
    let tree = Tree::empty("fs-deny-write-drop");
    tree.dir("work");
    let (work, made, written) = (
        at(&tree, "work"),
        tree.root().join("work/made"),
        tree.root().join("work/written"),
    );
    let plan = build(
        &tree,
        &denying_writes(
            &[&work],
            &[&made.to_string_lossy(), &written.to_string_lossy()],
        ),
    );
    // What bwrap does when it runs.
    std::fs::write(&made, "").expect("a mount point");
    std::fs::write(&written, "kept").expect("a file");

    drop(plan);

    assert!(!made.exists());
    assert!(written.exists());
}

/// A mount point goes when the last plan holding it drops: removing it under a
/// bwrap that is still running detaches that one's bind.
#[test]
fn a_mount_point_outlives_the_first_of_two_sandboxes_to_drop() {
    let tree = Tree::empty("fs-deny-write-shared");
    tree.dir("work");
    let (work, made) = (at(&tree, "work"), tree.root().join("work/made"));
    let config = denying_writes(&[&work], &[&made.to_string_lossy()]);
    let first = build(&tree, &config);
    let second = build(&tree, &config);
    std::fs::write(&made, "").expect("a mount point");

    drop(first);
    assert!(made.exists());
    drop(second);
    assert!(!made.exists());
}

/// A plan built after bwrap made the first one's mount point finds the path
/// there, and holds it all the same.
#[test]
fn a_mount_point_that_exists_is_held_by_the_next_sandbox() {
    let tree = Tree::empty("fs-deny-write-existing");
    tree.dir("work");
    let (work, made) = (at(&tree, "work"), tree.root().join("work/made"));
    let config = denying_writes(&[&work], &[&made.to_string_lossy()]);
    let first = build(&tree, &config);
    std::fs::write(&made, "").expect("a mount point");
    let second = build(&tree, &config);

    drop(first);
    assert!(made.exists());
    assert_eq!(second.mount_points(), std::slice::from_ref(&made));
    drop(second);
    assert!(!made.exists());
}
/// A mount point another sandbox holds as a directory above this one's is held
/// as well, or it is left behind with the second's inside it.
#[test]
fn a_mount_point_above_the_next_sandboxs_is_held_by_it() {
    let tree = Tree::empty("fs-deny-write-above");
    tree.dir("work");
    let (work, commands) = (at(&tree, "work"), at(&tree, "work/.claude/commands"));
    let claude = tree.root().join("work/.claude");
    let config = denying_writes(&[&work], &[&commands]);
    let first = build(&tree, &config);
    std::fs::create_dir(&claude).expect("a mount point");
    let second = build(&tree, &config);
    std::fs::create_dir(claude.join("commands")).expect("a mount point");

    drop(first);
    assert!(claude.exists());
    drop(second);
    assert!(!claude.exists());
}
