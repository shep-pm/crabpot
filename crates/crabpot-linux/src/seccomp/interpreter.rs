//! A classic-BPF interpreter for the instructions seccompiler emits, so a
//! test can run a built program against a crafted `seccomp_data` without
//! installing it. It panics on anything outside that subset.

use seccompiler::sock_filter;

const LD_W_ABS: u16 = 0x20;
const AND_K: u16 = 0x54;
const JA: u16 = 0x05;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;

const RET_ACTION: u32 = 0xffff_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_KILL_THREAD: u32 = 0;
const RET_KILL_PROCESS: u32 = 0x8000_0000;

/// What the kernel hands a filter, minus the instruction pointer.
#[derive(Clone, Copy, Debug)]
pub(super) struct SeccompData {
    pub(super) nr: u32,
    pub(super) arch: u32,
    pub(super) args: [u64; 6],
}

impl SeccompData {
    /// The 32-bit word at `offset` in `struct seccomp_data`.
    fn word(&self, offset: u32) -> u32 {
        match offset {
            0 => self.nr,
            4 => self.arch,
            16..=63 => {
                let arg = self.args[((offset - 16) / 8) as usize];
                match offset & 7 {
                    0 => arg as u32,
                    4 => (arg >> 32) as u32,
                    _ => panic!("a program read offset {offset}, which splits an argument"),
                }
            }
            _ => panic!("a program read offset {offset}, which is no word it may read"),
        }
    }
}

/// What a filter answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Allow,
    Errno(u16),
    Kill,
}

/// The raw `SECCOMP_RET_*` value `program` returns for `data`.
fn run(program: &[sock_filter], data: &SeccompData) -> u32 {
    let mut accumulator = 0_u32;
    let mut pc = 0_usize;
    loop {
        let step = program.get(pc).expect("a program ran off its end");
        pc += 1;
        match step.code {
            LD_W_ABS => accumulator = data.word(step.k),
            AND_K => accumulator &= step.k,
            JA => pc += step.k as usize,
            JEQ_K | JGT_K | JGE_K => {
                let hit = match step.code {
                    JEQ_K => accumulator == step.k,
                    JGT_K => accumulator > step.k,
                    _ => accumulator >= step.k,
                };
                pc += usize::from(if hit { step.jt } else { step.jf });
            }
            RET_K => return step.k,
            code => panic!("a program used opcode {code:#x}, which the interpreter lacks"),
        }
    }
}

/// The verdict of `programs` installed in order, as the kernel combines them:
/// the most severe answer wins, kills first, and the newest filter wins a tie.
pub(super) fn stacked(programs: &[&[sock_filter]], data: &SeccompData) -> Verdict {
    let returned = programs
        .iter()
        .rev()
        .map(|program| run(program, data))
        .min_by_key(|ret| (ret & RET_ACTION) as i32)
        .expect("at least one program is stacked");
    match returned & RET_ACTION {
        RET_ALLOW => Verdict::Allow,
        RET_ERRNO => Verdict::Errno((returned & 0xffff) as u16),
        RET_KILL_THREAD | RET_KILL_PROCESS => Verdict::Kill,
        other => panic!("a program returned action {other:#x}, which the interpreter lacks"),
    }
}
