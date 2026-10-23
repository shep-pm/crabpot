use crate::path_entries::ListKind::{self, Allow, Deny};

use Reading::{Name, Pattern};

/// One reading, as the table writes it.
pub(super) enum Reading {
    Name {
        path: &'static str,
    },
    Pattern {
        path: &'static str,
        anchor: &'static str,
    },
}

// Each row is an entry, the kind of list, and the readings upstream's
// `literalReadings` gives for it, from the `dist/sandbox/path-entries.js` of
// npm's @anthropic-ai/sandbox-runtime 0.0.81 run on macOS over the tree of
// `test_tree`, the root written `{root}`.
pub(super) const READINGS: &[(&str, ListKind, &[Reading])] = &[
    ("{root}/real", Deny, &[]),
    ("{root}/real", Allow, &[]),
    ("{root}/real/**", Deny, &[]),
    ("{root}/real/**", Allow, &[]),
    ("{root}/real/file.txt", Deny, &[]),
    ("{root}/real/file.txt", Allow, &[]),
    ("{root}/a[b", Deny, &[Name { path: "{root}/a[b" }]),
    ("{root}/a[b", Allow, &[Name { path: "{root}/a[b" }]),
    (
        "{root}/a[b/*",
        Deny,
        &[Pattern {
            path: "{root}/a[b/*",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/*",
        Allow,
        &[Pattern {
            path: "{root}/a[b/*",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/file",
        Deny,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}/a[b/file",
        Allow,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}/a[b/*/",
        Deny,
        &[Pattern {
            path: "{root}/a[b/*/",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/*/",
        Allow,
        &[Pattern {
            path: "{root}/a[b/*/",
            anchor: "{root}/a[b",
        }],
    ),
    ("{root}/a[b/**", Deny, &[Name { path: "{root}/a[b" }]),
    ("{root}/a[b/**", Allow, &[Name { path: "{root}/a[b" }]),
    (
        "{root}/a[b/*/**",
        Deny,
        &[Pattern {
            path: "{root}/a[b/*/**",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/*/**",
        Allow,
        &[Pattern {
            path: "{root}/a[b/*/**",
            anchor: "{root}/a[b",
        }],
    ),
    ("{root}/missing/[x]", Deny, &[]),
    ("{root}/missing/[x]", Allow, &[]),
    (
        "{root}/across/a[b",
        Deny,
        &[Name {
            path: "{root}/across/a[b",
        }],
    ),
    (
        "{root}/across/a[b",
        Allow,
        &[Name {
            path: "{root}/across/a[b",
        }],
    ),
    (
        "{root}/across/a[b/*",
        Deny,
        &[Pattern {
            path: "{root}/across/a[b/*",
            anchor: "{root}/across/a[b",
        }],
    ),
    (
        "{root}/across/a[b/*",
        Allow,
        &[Pattern {
            path: "{root}/across/a[b/*",
            anchor: "{root}/across/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/*.txt",
        Deny,
        &[Pattern {
            path: "{root}/real/sub/a[b/*.txt",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/*.txt",
        Allow,
        &[Pattern {
            path: "{root}/real/sub/a[b/*.txt",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/*.txt/**",
        Deny,
        &[Pattern {
            path: "{root}/real/sub/a[b/*.txt/**",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/*.txt/**",
        Allow,
        &[Pattern {
            path: "{root}/real/sub/a[b/*.txt/**",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/inner.txt",
        Deny,
        &[Name {
            path: "{root}/real/sub/a[b/inner.txt",
        }],
    ),
    (
        "{root}/real/sub/a[b/inner.txt",
        Allow,
        &[Name {
            path: "{root}/real/sub/a[b/inner.txt",
        }],
    ),
    (
        "{root}/real/sub/lnk[1]",
        Deny,
        &[Name {
            path: "{root}/real/sub/lnk[1]",
        }],
    ),
    ("{root}/real/sub/lnk[1]", Allow, &[]),
    (
        "{root}/real/sub/lnk[1]/*.txt",
        Deny,
        &[Pattern {
            path: "{root}/real/sub/lnk[1]/*.txt",
            anchor: "{root}/real/sub/lnk[1]",
        }],
    ),
    ("{root}/real/sub/lnk[1]/*.txt", Allow, &[]),
    (
        "{root}/real/sub/lnk[1]/inner.txt",
        Deny,
        &[Name {
            path: "{root}/real/sub/lnk[1]/inner.txt",
        }],
    ),
    ("{root}/real/sub/lnk[1]/inner.txt", Allow, &[]),
    (
        "{root}/dang[1]",
        Deny,
        &[Name {
            path: "{root}/dang[1]",
        }],
    ),
    ("{root}/dang[1]", Allow, &[]),
    ("{root}/dang[1]/*", Deny, &[]),
    ("{root}/dang[1]/*", Allow, &[]),
    ("~/[x]*", Deny, &[]),
    ("~/[x]*", Allow, &[]),
    ("~/.aws/*", Deny, &[]),
    ("~/.aws/*", Allow, &[]),
    ("{root}/*/[a]*", Deny, &[]),
    ("{root}/*/[a]*", Allow, &[]),
    (
        "a[b",
        Deny,
        &[Name {
            path: "{root}/cwd/a[b",
        }],
    ),
    (
        "a[b",
        Allow,
        &[Name {
            path: "{root}/cwd/a[b",
        }],
    ),
    (
        "a[b/*",
        Deny,
        &[Pattern {
            path: "{root}/cwd/a[b/*",
            anchor: "{root}/cwd/a[b",
        }],
    ),
    (
        "a[b/*",
        Allow,
        &[Pattern {
            path: "{root}/cwd/a[b/*",
            anchor: "{root}/cwd/a[b",
        }],
    ),
    (
        "a[b/",
        Deny,
        &[Name {
            path: "{root}/cwd/a[b",
        }],
    ),
    (
        "a[b/",
        Allow,
        &[Name {
            path: "{root}/cwd/a[b",
        }],
    ),
    ("{root}/a[b/", Deny, &[Name { path: "{root}/a[b" }]),
    ("{root}/a[b/", Allow, &[Name { path: "{root}/a[b" }]),
    ("{root}/link/*", Deny, &[]),
    ("{root}/link/*", Allow, &[]),
    ("{root}/real/*", Deny, &[]),
    ("{root}/real/*", Allow, &[]),
    (
        "{root}/a[b//file",
        Deny,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}/a[b//file",
        Allow,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}//a[b/./file",
        Deny,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}//a[b/./file",
        Allow,
        &[Name {
            path: "{root}/a[b/file",
        }],
    ),
    (
        "{root}/a[b/../a[b/*",
        Deny,
        &[
            Pattern {
                path: "{root}/a[b/*",
                anchor: "{root}/a[b",
            },
            Pattern {
                path: "{root}/a[b/*",
                anchor: "{root}",
            },
        ],
    ),
    (
        "{root}/a[b/../a[b/*",
        Allow,
        &[
            Pattern {
                path: "{root}/a[b/*",
                anchor: "{root}/a[b",
            },
            Pattern {
                path: "{root}/a[b/*",
                anchor: "{root}",
            },
        ],
    ),
    (
        "{root}/a[b/missing/*",
        Deny,
        &[Pattern {
            path: "{root}/a[b/missing/*",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/missing/*",
        Allow,
        &[Pattern {
            path: "{root}/a[b/missing/*",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/missing/x[1]/*",
        Deny,
        &[Pattern {
            path: "{root}/a[b/missing/x[1]/*",
            anchor: "{root}/a[b",
        }],
    ),
    (
        "{root}/a[b/missing/x[1]/*",
        Allow,
        &[Pattern {
            path: "{root}/a[b/missing/x[1]/*",
            anchor: "{root}/a[b",
        }],
    ),
    ("{root}/*", Deny, &[]),
    ("{root}/*", Allow, &[]),
    ("*", Deny, &[]),
    ("*", Allow, &[]),
    ("/*", Deny, &[]),
    ("/*", Allow, &[]),
    ("/**", Deny, &[]),
    ("/**", Allow, &[]),
    ("{root}/real/sub/*/a[b", Deny, &[]),
    ("{root}/real/sub/*/a[b", Allow, &[]),
    (
        "{root}/real/sub/a[b/*/*",
        Deny,
        &[Pattern {
            path: "{root}/real/sub/a[b/*/*",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
    (
        "{root}/real/sub/a[b/*/*",
        Allow,
        &[Pattern {
            path: "{root}/real/sub/a[b/*/*",
            anchor: "{root}/real/sub/a[b",
        }],
    ),
];
