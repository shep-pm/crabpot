//! How the plan reads the kernel's `/proc/net/unix`. The parser is plain bytes,
//! so these cases run on every Unix host.

use std::path::PathBuf;

use crate::fs::unix_sockets::names;

const HEAD: &str = "Num       RefCount Protocol Flags    Type St Inode Path\n";

/// A listing of `lines`, each a socket's seven fixed fields and `name`.
fn listing(names: &[&[u8]]) -> Vec<u8> {
    let mut text = HEAD.as_bytes().to_vec();
    for name in names {
        text.extend_from_slice(b"0000000000000000: 00000002 00000000 00010000 0001 01 12345 ");
        text.extend_from_slice(name);
        text.push(b'\n');
    }
    text
}

#[test]
fn a_path_is_read_byte_for_byte_with_its_runs_of_spaces() {
    let read = names(&listing(&[b"/run/a  b", b"/run/ c ", b"/run/d\te"])).unwrap();

    assert_eq!(
        read,
        [
            PathBuf::from("/run/a  b"),
            PathBuf::from("/run/ c "),
            PathBuf::from("/run/d\te"),
        ]
    );
}

#[test]
fn an_unnamed_and_an_abstract_socket_are_no_path() {
    let mut text = HEAD.as_bytes().to_vec();
    text.extend_from_slice(b"0000000000000000: 00000002 00000000 00010000 0001 01 1\n");
    text.extend_from_slice(
        b"0000000000000000: 00000002 00000000 00010000 0001 01     2 @abstract\n",
    );
    text.extend_from_slice(b"0000000000000000: 00000002 00000000 00010000 0001 01     3 /run/x\n");

    assert_eq!(names(&text).unwrap(), [PathBuf::from("/run/x")]);
}

#[test]
fn a_name_the_parser_does_not_understand_is_no_listing_at_all() {
    // Fewer than the seven fixed fields.
    let mut short = HEAD.as_bytes().to_vec();
    short.extend_from_slice(b"0000000000000000: 00000002 00000000\n");
    assert_eq!(names(&short), None);
    // A path holding a newline spills a line with no fixed fields onto the
    // next one, and masking the part of it that parsed would hide the rest.
    assert_eq!(names(&listing(&[b"/run/a\nb"])), None);
}

/// Any process of the host can bind a relative name, and the kernel lists it as
/// the process spelled it. It has no path to mount over, and it must not cost
/// the sockets beside it.
#[test]
fn a_relative_name_is_skipped_and_the_sockets_beside_it_are_kept() {
    let read = names(&listing(&[
        b"/run/a",
        b"foo.sock",
        b"./b.sock",
        b"../c",
        b"/run/d",
    ]));

    assert_eq!(
        read,
        Some(vec![PathBuf::from("/run/a"), PathBuf::from("/run/d")])
    );
}
