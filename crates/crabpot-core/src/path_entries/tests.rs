use super::ListKind::{Allow, Deny};
use super::*;
use crate::test_tree::Tree;

mod table;
use table::{READINGS, Reading};

fn spelled(spelling: &str) -> PathEntry {
    PathEntry::Spelled(spelling.to_owned())
}

fn literal(path: &str) -> PathEntry {
    PathEntry::Literal(path.to_owned())
}

fn readings_of(tree: &Tree, spelling: &str, kind: ListKind) -> Vec<PathReading> {
    literal_readings(&tree.base(), &tree.spell(spelling), kind)
        .expect("the tree has a home and a working directory")
        .into_iter()
        .map(|reading| match reading {
            PathReading::Name { path } => PathReading::Name {
                path: tree.unspell(&path),
            },
            PathReading::Pattern { path, anchor } => PathReading::Pattern {
                path: tree.unspell(&path),
                anchor: tree.unspell(&anchor),
            },
        })
        .collect()
}

#[test]
fn every_table_entry_reads_as_upstream_does() {
    let tree = Tree::new("readings");
    assert!(READINGS.len() >= 40);
    for (spelling, kind, expected) in READINGS {
        let expected: Vec<PathReading> = expected
            .iter()
            .map(|reading| match *reading {
                Reading::Name { path } => PathReading::Name {
                    path: path.to_owned(),
                },
                Reading::Pattern { path, anchor } => PathReading::Pattern {
                    path: path.to_owned(),
                    anchor: anchor.to_owned(),
                },
            })
            .collect();
        assert_eq!(
            readings_of(&tree, spelling, *kind),
            expected,
            "literal_readings({spelling:?}, {kind:?})"
        );
    }
}

#[test]
fn a_path_without_a_glob_means_the_folder_and_all_under_it() {
    let tree = Tree::new("no-glob");
    for spelling in [
        "{root}/real",
        "{root}/real/",
        "{root}/real/**",
        "{root}/link",
        "~/.aws",
        "rel",
    ] {
        for kind in [Allow, Deny] {
            assert_eq!(
                readings_of(&tree, spelling, kind),
                [],
                "{spelling:?} {kind:?}"
            );
        }
    }
}

#[test]
fn a_pattern_over_a_folder_that_exists_is_also_the_name() {
    let tree = Tree::new("also-name");
    let name = PathReading::Name {
        path: "{root}/a[b".to_owned(),
    };
    assert_eq!(
        readings_of(&tree, "{root}/a[b", Deny),
        std::slice::from_ref(&name)
    );
    assert_eq!(readings_of(&tree, "{root}/a[b/**", Allow), [name]);
    assert_eq!(readings_of(&tree, "{root}/missing/[x]", Deny), []);
}

#[test]
fn a_link_is_a_name_to_a_deny_and_no_name_to_an_allow() {
    let tree = Tree::new("link-kinds");
    let name = PathReading::Name {
        path: "{root}/real/sub/lnk[1]".to_owned(),
    };
    assert_eq!(readings_of(&tree, "{root}/real/sub/lnk[1]", Deny), [name]);
    assert_eq!(readings_of(&tree, "{root}/real/sub/lnk[1]", Allow), []);
    assert_eq!(readings_of(&tree, "{root}/dang[1]", Deny).len(), 1);
    assert_eq!(readings_of(&tree, "{root}/dang[1]", Allow), []);
}

#[test]
fn a_symlink_outside_the_boundary_keeps_its_own_spelling() {
    let tree = Tree::new("outside-boundary");
    assert_eq!(
        readings_of(&tree, "{root}/across/a[b", Deny),
        [PathReading::Name {
            path: "{root}/across/a[b".to_owned()
        }]
    );
}

#[test]
fn a_literal_entry_is_never_a_pattern() {
    let tree = Tree::new("literal");
    let marked = [literal(&tree.spell("{root}/a[b"))];
    let rules = read_rules_of(&tree.base(), &marked, Some(&marked), &[])
        .expect("the tree has a home and a working directory");
    assert_eq!(rules.deny_read, marked);
    assert_eq!(rules.allow_read, Some(marked.to_vec()));

    // The same characters as a spelling are also the name they spell.
    let spelling = spelled(&tree.spell("{root}/a[b"));
    let rules = read_rules_of(&tree.base(), std::slice::from_ref(&spelling), None, &[])
        .expect("the tree has a home and a working directory");
    assert_eq!(rules.deny_read, [spelling, marked[0].clone()]);
    assert_eq!(rules.allow_read, None);
}

#[test]
fn credential_denies_are_spellings_too() {
    let tree = Tree::new("credentials");
    let credential = [tree.spell("{root}/a[b/file")];
    let rules = read_rules_of(&tree.base(), &[], Some(&[]), &credential)
        .expect("the tree has a home and a working directory");
    assert_eq!(
        rules.deny_read,
        [spelled(&credential[0]), literal(&credential[0])]
    );
    assert_eq!(rules.allow_read, Some(vec![]));
}

#[test]
fn a_spelling_that_needs_a_missing_home_is_an_error() {
    let base = PathBase::new(None, Some("/work".to_owned()));
    assert_eq!(
        literal_readings(&base, "~/a[b", Deny),
        Err(PathError::NoHomeDirectory)
    );
    assert_eq!(literal_readings(&base, "/work/x", Deny), Ok(vec![]));
}

#[test]
fn entries_split_into_spellings_and_literal_paths() {
    let entries = [
        spelled("/a"),
        literal("/b[1]"),
        spelled("/c*"),
        literal("/d"),
    ];
    assert_eq!(
        split_path_entries(&entries),
        SplitEntries {
            spelled: vec!["/a", "/c*"],
            marked: vec!["/b[1]", "/d"],
        }
    );
    assert_eq!(spelled_of(&entries), ["/a", "/c*"]);
    assert_eq!(split_path_entries(&[]), SplitEntries::default());
}

#[test]
fn a_literal_list_is_present_only_when_it_is_not_empty() {
    let marked = [literal("/a[1]"), spelled("/b")];
    let unmarked = [spelled("/b")];
    assert_eq!(
        literal_read_lists(&marked, &unmarked),
        LiteralReadLists {
            literal_deny_only: Some(vec!["/a[1]".to_owned()]),
            literal_allow_within_deny: None,
        }
    );
    assert_eq!(
        literal_write_lists(&unmarked, &marked),
        LiteralWriteLists {
            literal_allow_only: None,
            literal_deny_within_allow: Some(vec!["/a[1]".to_owned()]),
        }
    );
}

#[test]
fn a_write_root_is_in_either_allow_list() {
    let roots = write_roots_of(&["/a".to_owned()], &["/b[1]".to_owned()]);
    assert_eq!(roots, ["/a", "/b[1]"]);
    assert_eq!(write_roots_of(&[], &[]), Vec::<String>::new());
}

#[test]
fn a_deny_is_re_exposed_by_every_allow() {
    let re_exposed = re_exposed_by(
        &["/expanded".to_owned()],
        &[spelled("/spelled*"), literal("/marked[1]")],
        &["/write".to_owned()],
        &["/write[1]".to_owned()],
    );
    assert_eq!(
        re_exposed,
        ["/expanded", "/marked[1]", "/write", "/write[1]"]
    );
}
