//! The seccomp filters the helper installs before it execs the command, built
//! per architecture and installed by nobody here (ADR-0014).
//!
//! Upstream's `seccomp-unix-block.c` makes two filters with libseccomp, and the
//! rules here are its rules:
//!
//! - [`unix`] refuses `socket(AF_UNIX)`, `socket(AF_VSOCK)` and the three
//!   `io_uring` calls with EPERM. `socketpair`, and so inherited descriptors
//!   and `SCM_RIGHTS`, stay allowed.
//! - [`namespaces`] keeps the command in the namespaces the sandbox made for
//!   it. seccompiler has one match action a filter, so its rules are two
//!   programs: EPERM for `unshare` and `clone` with a namespace flag and for
//!   the mount family, ENOSYS for `clone3`.
//!
//! Both default to allow. A call from any other architecture is killed, as
//! libseccomp's default bad-architecture action does. That includes x86_64's
//! x32 ABI, which reports the x86_64 token with a bit set in the number. So
//! 32-bit x86 is killed whole, and its `socketcall` hole, the TODO in the C
//! source's header, cannot be reached.

use core::fmt;
use std::collections::BTreeMap;

use seccompiler::{
    BackendError, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};

#[cfg(test)]
mod interpreter;
#[cfg(test)]
mod tests;

/// A built filter, ready for `seccompiler::apply_filter`.
pub type Program = seccompiler::BpfProgram;

/// An architecture the filters are built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    /// `x86_64`.
    X86_64,
    /// `aarch64`.
    Aarch64,
}

impl Arch {
    fn target(self) -> TargetArch {
        match self {
            Self::X86_64 => TargetArch::x86_64,
            Self::Aarch64 => TargetArch::aarch64,
        }
    }
}

/// The programs of the `namespaces` filter, split by what they answer.
#[derive(Clone, Debug)]
pub struct NamespaceFilters {
    /// Answers EPERM.
    pub eperm: Program,
    /// Answers ENOSYS.
    pub enosys: Program,
}

/// Why a filter could not be built.
#[derive(Debug)]
pub enum Error {
    /// seccompiler refused the rules of the filter, or its program is longer
    /// than the kernel takes.
    Compile {
        /// The filter that failed.
        filter: &'static str,
        /// What seccompiler said.
        source: Box<dyn core::error::Error + Send + Sync>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile { filter, source } => {
                write!(f, "cannot build the {filter} seccomp filter: {source}")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Compile { source, .. } => Some(source.as_ref()),
        }
    }
}

/// Linux's errno values, the same on both architectures.
const EPERM: u32 = 1;
const ENOSYS: u32 = 38;

const AF_UNIX: u32 = 1;
const AF_VSOCK: u32 = 40;
/// Not pulled from a header: the values are ABI.
const CLONE_NEWNS: u32 = 0x0002_0000;
const CLONE_NEWUSER: u32 = 0x1000_0000;
/// To `unshare(2)` alone, from Linux 7.1: a mount namespace with the root
/// mount and none beneath it. To `clone(2)` the bit is `CLONE_PARENT_SETTID`.
const UNSHARE_EMPTY_MNTNS: u32 = 0x0010_0000;

/// A syscall's number on each architecture.
#[derive(Clone, Copy)]
struct Syscall {
    x86_64: i64,
    aarch64: i64,
}

impl Syscall {
    /// A call numbered alike everywhere: all added since Linux 5.1 are.
    const fn same(nr: i64) -> Self {
        Self {
            x86_64: nr,
            aarch64: nr,
        }
    }

    fn on(self, arch: Arch) -> i64 {
        match arch {
            Arch::X86_64 => self.x86_64,
            Arch::Aarch64 => self.aarch64,
        }
    }
}

/// `argument0 & mask == value`, on the low 32 bits. Both the domain of
/// `socket` and the flags of `unshare` and `clone` are 32-bit values, and the
/// kernel ignores the register's upper half.
#[derive(Clone, Copy)]
struct Arg0 {
    mask: u32,
    value: u32,
}

impl Arg0 {
    const fn is(value: u32) -> Self {
        Self {
            mask: u32::MAX,
            value,
        }
    }

    /// One rule a flag, so other flags beside it do not save the call.
    const fn has(flag: u32) -> Self {
        Self {
            mask: flag,
            value: flag,
        }
    }
}

/// A call a filter refuses: whenever `when` is empty, and otherwise when the
/// first argument matches any of `when`.
struct Refusal {
    call: Syscall,
    when: &'static [Arg0],
}

impl Refusal {
    const fn always(call: Syscall) -> Self {
        Self { call, when: &[] }
    }
}

const SOCKET: Syscall = Syscall {
    x86_64: 41,
    aarch64: 198,
};

const UNIX_REFUSALS: &[Refusal] = &[
    Refusal {
        call: SOCKET,
        when: &[Arg0::is(AF_UNIX), Arg0::is(AF_VSOCK)],
    },
    // IORING_OP_SOCKET makes sockets in the kernel, past the rule above, and
    // the ring's submissions cannot be read: the calls are refused whole.
    Refusal::always(Syscall::same(425)),
    Refusal::always(Syscall::same(426)),
    Refusal::always(Syscall::same(427)),
];

const EPERM_REFUSALS: &[Refusal] = &[
    // A command started by uid 0 can make a mount namespace with no new user
    // namespace.
    Refusal {
        call: Syscall {
            x86_64: 272,
            aarch64: 97,
        },
        when: &[
            Arg0::has(CLONE_NEWUSER),
            Arg0::has(CLONE_NEWNS),
            Arg0::has(UNSHARE_EMPTY_MNTNS),
        ],
    },
    Refusal {
        call: Syscall {
            x86_64: 56,
            aarch64: 220,
        },
        when: &[Arg0::has(CLONE_NEWUSER), Arg0::has(CLONE_NEWNS)],
    },
    // Joining another namespace and changing a mount tree: what holds a
    // command started by uid 0, which has those capabilities already.
    Refusal::always(Syscall {
        x86_64: 308,
        aarch64: 268,
    }),
    Refusal::always(Syscall {
        x86_64: 165,
        aarch64: 40,
    }),
    Refusal::always(Syscall {
        x86_64: 166,
        aarch64: 39,
    }),
    Refusal::always(Syscall {
        x86_64: 155,
        aarch64: 41,
    }),
    Refusal::always(Syscall::same(428)),
    Refusal::always(Syscall::same(429)),
    Refusal::always(Syscall::same(430)),
    Refusal::always(Syscall::same(431)),
    Refusal::always(Syscall::same(432)),
    Refusal::always(Syscall::same(433)),
    // `mount_setattr` and `open_tree_attr` are newer than some libseccomps,
    // which upstream takes by number. So does this.
    Refusal::always(Syscall::same(442)),
    Refusal::always(Syscall::same(467)),
];

/// `clone3(2)` passes its flags in a struct, which a filter cannot read.
/// ENOSYS, not EPERM: libc and language runtimes take it as "this kernel has
/// no clone3" and fall back to `clone(2)`, which `EPERM_REFUSALS` covers. EPERM
/// breaks thread creation.
const ENOSYS_REFUSALS: &[Refusal] = &[Refusal::always(Syscall::same(435))];

/// The `unix` filter for `arch`.
///
/// # Errors
///
/// [`Error::Compile`] if seccompiler cannot compile the rules.
pub fn unix(arch: Arch) -> Result<Program, Error> {
    compile("unix", arch, EPERM, UNIX_REFUSALS)
}

/// The `namespaces` filter for `arch`, as two programs.
///
/// # Errors
///
/// [`Error::Compile`] if seccompiler cannot compile the rules.
pub fn namespaces(arch: Arch) -> Result<NamespaceFilters, Error> {
    Ok(NamespaceFilters {
        eperm: compile("namespaces (EPERM)", arch, EPERM, EPERM_REFUSALS)?,
        enosys: compile("namespaces (ENOSYS)", arch, ENOSYS, ENOSYS_REFUSALS)?,
    })
}

fn compile(
    filter: &'static str,
    arch: Arch,
    errno: u32,
    refusals: &[Refusal],
) -> Result<Program, Error> {
    let failed = |source: BackendError| Error::Compile {
        filter,
        source: Box::new(source),
    };
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for refusal in refusals {
        let chain = rules.entry(refusal.call.on(arch)).or_default();
        for arg0 in refusal.when {
            let condition = SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::MaskedEq(arg0.mask.into()),
                arg0.value.into(),
            )
            .map_err(failed)?;
            chain.push(SeccompRule::new(vec![condition]).map_err(failed)?);
        }
    }
    let program = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(errno),
        arch.target(),
    )
    .and_then(Program::try_from)
    .map_err(failed)?;
    Ok(match arch {
        Arch::X86_64 => kill_x32(program),
        Arch::Aarch64 => program,
    })
}

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_JGE_K: u16 = 0x35;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// An x32 call carries the x86_64 token with this bit set in its number.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// The number `syscall(-1)` and a tracer skipping a call carry. It has the x32
/// bit but is no call in either ABI, and the kernel answers it ENOSYS.
const NO_SYSCALL: u32 = u32::MAX;

/// `program` behind a check that kills an x32 call, as libseccomp's x86_64
/// filters do, except for [`NO_SYSCALL`]. seccompiler checks the token only,
/// and x32 numbers are not x86_64's.
fn kill_x32(program: Program) -> Program {
    let step = |code, jt, jf, k| sock_filter { code, jt, jf, k };
    let mut guarded = vec![
        step(BPF_LD_W_ABS, 0, 0, 0),
        step(BPF_JEQ_K, 2, 0, NO_SYSCALL),
        step(BPF_JGE_K, 0, 1, X32_SYSCALL_BIT),
        step(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    ];
    guarded.extend(program);
    guarded
}
