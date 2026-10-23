use super::*;
use crate::test_tree::Tree;

// Each row of these tables is what upstream gives, from the
// `dist/sandbox/sandbox-utils.js` of npm's @anthropic-ai/sandbox-runtime
// 0.0.81 run on macOS over the tree of `test_tree` (HOME in `home`, working
// directory `cwd`) and printed as Rust, the root written `{root}`.

// A spelling, whether it is literal, and its normalised form.
const NORMALISED: &[(&str, bool, &str)] = &[
    ("{root}/real", false, "{root}/real"),
    ("{root}/real/", false, "{root}/real"),
    ("{root}//real//file.txt", false, "{root}/real/file.txt"),
    ("{root}/./real/./file.txt", false, "{root}/real/file.txt"),
    (
        "{root}/real/../real/file.txt",
        false,
        "{root}/real/file.txt",
    ),
    ("{root}/missing/../real", false, "{root}/real"),
    ("{root}/real/missing/..", false, "{root}/real"),
    ("{root}/real/.", false, "{root}/real"),
    ("{root}/real/file.txt", false, "{root}/real/file.txt"),
    ("{root}/link", false, "{root}/link"),
    ("{root}/link/", false, "{root}/link"),
    ("{root}/link/file.txt", false, "{root}/link/file.txt"),
    ("{root}/link/sub", false, "{root}/link/sub"),
    ("{root}/link/missing", false, "{root}/link/missing"),
    ("{root}/link/../real", false, "{root}/real"),
    ("{root}/up", false, "{root}/up"),
    ("{root}/up/real", false, "{root}/up/real"),
    ("{root}/up/real/file.txt", false, "{root}/up/real/file.txt"),
    ("{root}/across", false, "{root}/across"),
    ("{root}/across/a[b", false, "{root}/across/a[b"),
    ("{root}/rootlink", false, "{root}/rootlink"),
    ("{root}/rootlink/usr", false, "{root}/rootlink/usr"),
    ("{root}/dangling", false, "{root}/dangling"),
    ("{root}/dangling/x", false, "{root}/dangling/x"),
    ("{root}/loop", false, "{root}/loop"),
    ("{root}/loop/x", false, "{root}/loop/x"),
    ("/", false, "/"),
    ("//", false, "/"),
    ("/.", false, "/"),
    ("/..", false, "/"),
    ("~", false, "{root}/home"),
    ("~/", false, "{root}/home"),
    ("~/.cfg", false, "{root}/home/.cfg"),
    ("~/.aws", false, "{root}/home/.aws"),
    ("~/missing", false, "{root}/home/missing"),
    ("~//.cfg", false, "{root}/home/.cfg"),
    ("~user", false, "{root}/cwd/~user"),
    ("~/.aws/*.pem", false, "{root}/home/.aws/*.pem"),
    ("~/.aws//*.pem", false, "{root}/home/.aws/*.pem"),
    ("", false, "{root}/cwd"),
    (".", false, "{root}/cwd"),
    ("./", false, "{root}/cwd"),
    ("..", false, "{root}"),
    ("rel", false, "{root}/cwd/rel"),
    ("./rel", false, "{root}/cwd/rel"),
    ("rel/file.txt", false, "{root}/cwd/rel/file.txt"),
    ("inside", false, "{root}/cwd/inside"),
    ("../real", false, "{root}/real"),
    ("../link/file.txt", false, "{root}/link/file.txt"),
    ("missing", false, "{root}/cwd/missing"),
    ("{root}/link/*.txt", false, "{root}/link/*.txt"),
    ("{root}/real/**", false, "{root}/real/**"),
    ("{root}/real/*/", false, "{root}/real/*/"),
    ("{root}/missing/*", false, "{root}/missing/*"),
    ("{root}/a[b", false, "{root}/a[b"),
    ("{root}/a[b/file", false, "{root}/a[b/file"),
    ("{root}/link/sub/[a-z]*", false, "{root}/link/sub/[a-z]*"),
    ("{root}/up/*", false, "{root}/up/*"),
    ("{root}/across/*.txt", false, "{root}/across/*.txt"),
    ("{root}/*", false, "{root}/*"),
    ("{root}/real/x*", false, "{root}/real/x*"),
    ("{root}/link/x?", false, "{root}/link/x?"),
    ("{root}/dangling/*", false, "{root}/dangling/*"),
    ("{root}/rootlink/*", false, "{root}/rootlink/*"),
    ("{root}/real/../real/*.txt", false, "{root}/real/*.txt"),
    ("{root}//link//*.txt", false, "{root}/link/*.txt"),
    ("{root}/./link/*", false, "{root}/link/*"),
    ("*.txt", false, "{root}/cwd/*.txt"),
    ("*", false, "{root}/cwd/*"),
    ("**/secret", false, "{root}/cwd/**/secret"),
    ("/*", false, "/*"),
    ("/**", false, "/**"),
    ("a[b", false, "{root}/cwd/a[b"),
    ("inside/*", false, "{root}/cwd/inside/*"),
    ("rel/*", false, "{root}/cwd/rel/*"),
    ("~/*", false, "{root}/home/*"),
    ("~/.aws/[ab]*", false, "{root}/home/.aws/[ab]*"),
    ("{root}/link/**/x", false, "{root}/link/**/x"),
    ("{root}/lin?", false, "{root}/lin?"),
    ("{root}/link]", false, "{root}/link]"),
    ("{root}/a[b", true, "{root}/a[b"),
    ("{root}/a[b/", true, "{root}/a[b"),
    ("{root}/link/x?", true, "{root}/link/x?"),
    ("{root}/real/*", true, "{root}/real/*"),
    ("{root}/real/*/", true, "{root}/real/*"),
    ("{root}/across/a[b", true, "{root}/across/a[b"),
    ("{root}/link", true, "{root}/link"),
    ("{root}/link/", true, "{root}/link"),
    ("~/*", true, "{root}/home/*"),
    ("~/", true, "{root}/home"),
    ("a[b", true, "{root}/cwd/a[b"),
    ("*", true, "{root}/cwd/*"),
    ("{root}/real/**", true, "{root}/real/**"),
    ("{root}/real/../real/*", true, "{root}/real/../real/*"),
    ("{root}//real//*", true, "{root}/real/*"),
    ("/", true, "/"),
    ("", true, "{root}/cwd"),
    ("..", true, "{root}"),
];
const BOUNDARY: &[(&str, &str, bool)] = &[
    ("/a/b", "/a/b", false),
    ("/tmp/x", "/private/tmp/x", false),
    ("/var/x", "/private/var/x", false),
    ("/var/folders/ab/T/x", "/private/var/folders/ab/T/x", false),
    ("/tmp/x", "/private/tmp/y", true),
    ("/tmp/x", "/", true),
    ("/a/b", "/", true),
    ("/a/b", "/usr", true),
    ("/a/b/c", "/a/b", true),
    ("/a/b/c", "/a", true),
    ("/tmp/x/y", "/private/tmp", true),
    ("/tmp/x", "/private/tmp/x/y", false),
    ("/a/b", "/a/b/c", false),
    ("/a/b", "/a/c", true),
    ("/a/b", "/c/d", true),
    ("/a/b/", "/a/b", true),
    ("/a//b", "/a/b", false),
    ("/a/./b", "/a/b", false),
    ("/tmp/x", "/Users/me/x", true),
    ("/var/x", "/private/var/x/y", false),
    ("/var/x", "/private/var", true),
    ("/private/tmp/x", "/tmp/x", true),
    ("/a/b", "/a/b/", false),
    ("/x/y", "/x/y/z/w", false),
];
const SPELLINGS: &[(&str, &[&str])] = &[
    ("{root}/real", &["{root}/real"]),
    ("{root}/link", &["{root}/link", "{root}/real"]),
    (
        "{root}/link/file.txt",
        &["{root}/link/file.txt", "{root}/real/file.txt"],
    ),
    ("{root}/dangling", &["{root}/dangling"]),
    ("{root}/missing", &["{root}/missing"]),
    ("{root}/up", &["{root}/up", "{root}"]),
    ("{root}/loop", &["{root}/loop"]),
    (
        "{root}/real/../link",
        &["{root}/real/../link", "{root}/real"],
    ),
    ("{root}/across", &["{root}/across", "{root}/real/sub"]),
    ("{root}/rootlink", &["{root}/rootlink", "/"]),
];

#[test]
fn every_table_path_normalises_as_upstream_does() {
    let tree = Tree::new("normalise");
    assert!(NORMALISED.len() >= 40);
    for &(spelling, literal, expected) in NORMALISED {
        let normalised = normalize_path_for_sandbox(&tree.base(), &tree.spell(spelling), literal)
            .expect("the tree has a home and a working directory");
        assert_eq!(
            tree.unspell(&normalised),
            expected,
            "normalize_path_for_sandbox({spelling:?}, literal: {literal})"
        );
    }
}

#[test]
fn every_table_resolution_is_judged_as_upstream_does() {
    for &(original, resolved, outside) in BOUNDARY {
        assert_eq!(
            is_symlink_outside_boundary(original, resolved),
            outside,
            "is_symlink_outside_boundary({original:?}, {resolved:?})"
        );
    }
}

#[test]
fn a_path_is_named_by_its_spelling_and_by_its_real_path() {
    let tree = Tree::new("spellings");
    for &(spelling, named) in SPELLINGS {
        let spellings = path_spellings(&tree.base(), &tree.spell(spelling));
        let spellings: Vec<String> = spellings.iter().map(|p| tree.unspell(p)).collect();
        assert_eq!(spellings, named, "path_spellings({spelling:?})");
    }
}

#[test]
fn an_empty_home_is_not_the_root() {
    let base = PathBase::new(Some(String::new()), Some("/work".to_owned()));
    assert_eq!(
        normalize_path_for_sandbox(&base, "~", false).as_deref(),
        Ok("")
    );
    assert_eq!(expand_tilde(&base, "~/x").as_deref(), Ok("/x"));
}

#[test]
fn a_tilde_with_no_home_is_an_error() {
    let base = PathBase::new(None, Some("/work".to_owned()));
    assert_eq!(
        normalize_path_for_sandbox(&base, "~/x", false),
        Err(PathError::NoHomeDirectory)
    );
    assert_eq!(expand_tilde(&base, "~user").as_deref(), Ok("~user"));
}

#[test]
fn a_relative_path_with_no_working_directory_is_an_error() {
    let base = PathBase::new(Some("/home/u".to_owned()), None);
    assert_eq!(
        normalize_path_for_sandbox(&base, "x", false),
        Err(PathError::NoWorkingDirectory)
    );
    assert_eq!(
        normalize_path_for_sandbox(&base, "/no/such/x", false).as_deref(),
        Ok("/no/such/x")
    );
}

#[test]
fn only_the_four_glob_characters_make_a_pattern() {
    for spelling in ["*", "a?", "[a]", "a]", "src/**/x"] {
        assert!(contains_glob_chars(spelling), "{spelling:?}");
    }
    for spelling in ["", "/", "a{b,c}", "~/.ssh", "a\\b"] {
        assert!(!contains_glob_chars(spelling), "{spelling:?}");
    }
}

#[test]
fn a_trailing_double_star_only_says_all_beneath() {
    let stripped: Vec<String> = [
        "", "/", "/**", "a/**", "a/**/", "a/***", "/a/**/**", "**", "/a/*",
    ]
    .map(remove_trailing_glob_suffix)
    .into();
    assert_eq!(
        stripped,
        ["/", "/", "/", "a", "a/**/", "a/***", "/a/**", "**", "/a/*"]
    );
}

#[test]
fn interior_spellings_collapse_and_the_ends_stay() {
    let collapsed: Vec<String> = [
        "a//b", "a///./b", "/./a", "/././a", "/./.", "a/./", "a//./b", "/a/.", "/a/.//b", "/a/./.",
        "/..//./x", "é//./ü",
    ]
    .map(collapse_interior_spellings)
    .into();
    assert_eq!(
        collapsed,
        [
            "a/b", "a/b", "/a", "/a", "/.", "a/", "a/b", "/a/.", "/a/b", "/a/.", "/../x", "é/ü"
        ]
    );
}

#[test]
fn a_path_is_under_a_directory_by_component() {
    let under: Vec<bool> = [
        ("/x", "/x"),
        ("/xy", "/x"),
        ("/x/y", "/x"),
        ("/", "/"),
        ("/a", "/"),
        ("a", "/"),
        ("//", "/"),
        ("/x/", "/x"),
    ]
    .map(|(path, dir)| lexical::is_at_or_under(path, dir))
    .into();
    assert_eq!(under, [true, false, true, true, true, false, true, true]);
}

#[test]
fn the_base_of_the_process_is_its_working_directory() {
    let cwd = std::env::current_dir().expect("the test has a working directory");
    assert_eq!(
        PathBase::from_env().cwd().map(std::path::Path::new),
        Ok(cwd.as_path())
    );
}
