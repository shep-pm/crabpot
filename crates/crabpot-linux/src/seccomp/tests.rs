use super::interpreter::{SeccompData, Verdict, stacked};
use super::*;

const EPERM: Verdict = Verdict::Errno(1);
const ENOSYS: Verdict = Verdict::Errno(38);

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const AUDIT_ARCH_I386: u32 = 0x4000_0003;

const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const AF_VSOCK: u64 = 40;

const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_NEWNS: u64 = 0x0002_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_NEWUSER: u64 = 0x1000_0000;
const SIGCHLD: u64 = 17;

/// A syscall's number on each architecture, from the kernel's tables.
struct Call {
    x86_64: u32,
    aarch64: u32,
}

impl Call {
    const fn same(nr: u32) -> Self {
        Self {
            x86_64: nr,
            aarch64: nr,
        }
    }

    fn nr(&self, arch: Arch) -> u32 {
        match arch {
            Arch::X86_64 => self.x86_64,
            Arch::Aarch64 => self.aarch64,
        }
    }
}

const SOCKET: Call = Call {
    x86_64: 41,
    aarch64: 198,
};
const SOCKETPAIR: Call = Call {
    x86_64: 53,
    aarch64: 199,
};
const SENDMSG: Call = Call {
    x86_64: 46,
    aarch64: 211,
};
const READ: Call = Call {
    x86_64: 0,
    aarch64: 63,
};
const CLONE: Call = Call {
    x86_64: 56,
    aarch64: 220,
};
const UNSHARE: Call = Call {
    x86_64: 272,
    aarch64: 97,
};
const CLONE3: Call = Call::same(435);
const IO_URING_SETUP: Call = Call::same(425);
const IO_URING_ENTER: Call = Call::same(426);
const IO_URING_REGISTER: Call = Call::same(427);

/// The calls that answer EPERM whatever they are passed.
const MOUNT_FAMILY: [(&str, Call); 12] = [
    (
        "setns",
        Call {
            x86_64: 308,
            aarch64: 268,
        },
    ),
    (
        "mount",
        Call {
            x86_64: 165,
            aarch64: 40,
        },
    ),
    (
        "umount2",
        Call {
            x86_64: 166,
            aarch64: 39,
        },
    ),
    (
        "pivot_root",
        Call {
            x86_64: 155,
            aarch64: 41,
        },
    ),
    ("open_tree", Call::same(428)),
    ("move_mount", Call::same(429)),
    ("fsopen", Call::same(430)),
    ("fsconfig", Call::same(431)),
    ("fsmount", Call::same(432)),
    ("fspick", Call::same(433)),
    ("mount_setattr", Call::same(442)),
    ("open_tree_attr", Call::same(467)),
];

fn token(arch: Arch) -> u32 {
    match arch {
        Arch::X86_64 => AUDIT_ARCH_X86_64,
        Arch::Aarch64 => AUDIT_ARCH_AARCH64,
    }
}

/// The answer of the three filters, installed one over another, to a call
/// made on `arch` with `arg0` as its first argument.
fn answer(arch: Arch, call: &Call, arg0: u64) -> Verdict {
    answer_to(arch, call.nr(arch), token(arch), arg0)
}

fn answer_to(built_for: Arch, nr: u32, arch: u32, arg0: u64) -> Verdict {
    let unix = unix(built_for).expect("the unix filter builds");
    let namespaces = namespaces(built_for).expect("the namespaces filters build");
    let data = SeccompData {
        nr,
        arch,
        args: [arg0, 0, 0, 0, 0, 0],
    };
    stacked(&[&unix, &namespaces.eperm, &namespaces.enosys], &data)
}

#[test]
fn socket_af_unix_is_refused_on_both_architectures() {
    for arch in ARCHES {
        assert_eq!(answer(arch, &SOCKET, AF_UNIX), EPERM, "{arch:?}");
        // The domain is an int: the kernel ignores the register's upper half.
        assert_eq!(
            answer(arch, &SOCKET, AF_UNIX | 1 << 32),
            EPERM,
            "{arch:?} with the upper half set"
        );
    }
}

#[test]
fn socket_af_vsock_is_refused() {
    for arch in ARCHES {
        assert_eq!(answer(arch, &SOCKET, AF_VSOCK), EPERM, "{arch:?}");
        assert_eq!(
            answer(arch, &SOCKET, AF_VSOCK | 0xdead_beef << 32),
            EPERM,
            "{arch:?} with the upper half set"
        );
    }
}

#[test]
fn io_uring_calls_are_refused() {
    for arch in ARCHES {
        for call in [IO_URING_SETUP, IO_URING_ENTER, IO_URING_REGISTER] {
            assert_eq!(answer(arch, &call, 0), EPERM, "{arch:?} {}", call.nr(arch));
        }
    }
}

#[test]
fn socket_af_inet_and_socketpair_are_allowed() {
    for arch in ARCHES {
        for family in [AF_INET, AF_INET6, AF_NETLINK] {
            assert_eq!(
                answer(arch, &SOCKET, family),
                Verdict::Allow,
                "{arch:?} {family}"
            );
        }
        // Only the whole 32-bit domain matches, not its low byte.
        for family in [AF_UNIX | 0x100, AF_VSOCK | 0x100] {
            assert_eq!(
                answer(arch, &SOCKET, family),
                Verdict::Allow,
                "{arch:?} {family}"
            );
        }
        // Inherited descriptors and SCM_RIGHTS keep working.
        assert_eq!(
            answer(arch, &SOCKETPAIR, AF_UNIX),
            Verdict::Allow,
            "{arch:?}"
        );
        assert_eq!(answer(arch, &SENDMSG, 3), Verdict::Allow, "{arch:?}");
        assert_eq!(answer(arch, &READ, 3), Verdict::Allow, "{arch:?}");
    }
}

#[test]
fn unshare_and_clone_with_a_namespace_flag_are_refused() {
    for arch in ARCHES {
        for call in [UNSHARE, CLONE] {
            for flag in [CLONE_NEWUSER, CLONE_NEWNS] {
                assert_eq!(answer(arch, &call, flag), EPERM, "{arch:?} {flag:#x}");
                assert_eq!(
                    answer(arch, &call, flag | CLONE_FILES | CLONE_FS | SIGCHLD),
                    EPERM,
                    "{arch:?} {flag:#x} beside other flags"
                );
            }
            assert_eq!(
                answer(arch, &call, CLONE_NEWUSER | CLONE_NEWNS),
                EPERM,
                "{arch:?} both flags"
            );
        }
        // Linux 7.1: unshare(2) takes this bit for a mount namespace with no
        // submounts. To clone(2) it is CLONE_PARENT_SETTID.
        assert_eq!(
            answer(arch, &UNSHARE, CLONE_PARENT_SETTID),
            EPERM,
            "{arch:?}"
        );
    }
}

#[test]
fn clone3_answers_enosys() {
    for arch in ARCHES {
        assert_eq!(answer(arch, &CLONE3, 0), ENOSYS, "{arch:?}");
    }
}

#[test]
fn the_mount_family_answers_eperm() {
    for arch in ARCHES {
        for (name, call) in &MOUNT_FAMILY {
            assert_eq!(answer(arch, call, 0), EPERM, "{arch:?} {name}");
        }
    }
}

#[test]
fn a_plain_clone_and_fork_are_allowed() {
    let thread = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID;
    for arch in ARCHES {
        assert_eq!(
            answer(arch, &CLONE, thread),
            Verdict::Allow,
            "{arch:?} a thread"
        );
        assert_eq!(
            answer(arch, &CLONE, SIGCHLD),
            Verdict::Allow,
            "{arch:?} a fork"
        );
        assert_eq!(
            answer(arch, &UNSHARE, CLONE_FILES),
            Verdict::Allow,
            "{arch:?}"
        );
    }
    // aarch64 has no fork(2) or vfork(2); libc calls clone(2).
    for (name, nr) in [("fork", 57), ("vfork", 58)] {
        assert_eq!(
            answer_to(Arch::X86_64, nr, AUDIT_ARCH_X86_64, 0),
            Verdict::Allow,
            "{name}"
        );
    }
}

#[test]
fn a_foreign_architecture_is_killed() {
    // A filter holds one architecture, as `seccomp_init` in the C source does.
    let x32 = 0x4000_0000;
    let calls = [
        (Arch::X86_64, SOCKET.x86_64, AUDIT_ARCH_AARCH64),
        (Arch::X86_64, READ.x86_64, AUDIT_ARCH_I386),
        (Arch::Aarch64, SOCKET.aarch64, AUDIT_ARCH_X86_64),
        (Arch::Aarch64, READ.aarch64, AUDIT_ARCH_I386),
        // x32 calls report the x86_64 token with this bit set in the number.
        (Arch::X86_64, READ.x86_64 | x32, AUDIT_ARCH_X86_64),
        (Arch::X86_64, SOCKET.x86_64 | x32, AUDIT_ARCH_X86_64),
    ];
    for (built_for, nr, arch) in calls {
        assert_eq!(
            answer_to(built_for, nr, arch, AF_INET),
            Verdict::Kill,
            "{built_for:?} filter, call {nr:#x}, arch {arch:#x}"
        );
    }
}
