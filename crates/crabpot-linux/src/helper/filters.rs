//! Installing the seccomp filters (ADR-0014).
//!
//! A filter that cannot be built or installed stops the helper before the
//! command, as `die` does in upstream's `apply-seccomp.c`. The command is never
//! run with a filter missing.
//!
//! `seccompiler::apply_filter` sets `PR_SET_NO_NEW_PRIVS` itself, on every call,
//! so nothing here sets it: the first install does.

use std::ffi::OsString;

use super::exec::{ExecError, exec};
use super::init::InitError;
use crate::seccomp::{self, Arch, Program};

/// A built filter and the name its errors give it.
struct Filter {
    name: &'static str,
    program: Program,
}

fn host() -> Result<Arch, InitError> {
    Arch::host().ok_or_else(|| {
        InitError::Filter("no seccomp filter is built for this architecture".to_owned())
    })
}

fn built(error: seccomp::Error) -> InitError {
    InitError::Filter(error.to_string())
}

fn namespaces(arch: Arch) -> Result<[Filter; 2], InitError> {
    let programs = seccomp::namespaces(arch).map_err(built)?;
    Ok([
        Filter {
            name: "namespaces (EPERM)",
            program: programs.eperm,
        },
        Filter {
            name: "namespaces (ENOSYS)",
            program: programs.enosys,
        },
    ])
}

fn install(
    filters: impl IntoIterator<Item = Filter>,
    mut apply: impl FnMut(&Program) -> Result<(), seccompiler::Error>,
) -> Result<(), InitError> {
    for Filter { name, program } in filters {
        apply(&program).map_err(|source| {
            InitError::Filter(format!(
                "cannot install the {name} seccomp filter: {source}"
            ))
        })?;
    }
    Ok(())
}

/// Installs the `namespaces` filter on this process, the outer helper's, which
/// stays outside the namespaces it made.
pub(super) fn install_namespaces() -> Result<(), InitError> {
    install(namespaces(host()?)?, apply)
}

/// Installs the `namespaces` filter, then the `unix` filter, and replaces this
/// process with the command `argv` names. It returns only when a filter was not
/// installed or the command could not be started.
pub(super) fn exec_confined(argv: &[OsString]) -> InitError {
    run_confined(argv, apply, exec)
}

fn apply(program: &Program) -> Result<(), seccompiler::Error> {
    seccompiler::apply_filter(program)
}

fn run_confined(
    argv: &[OsString],
    apply: impl FnMut(&Program) -> Result<(), seccompiler::Error>,
    run: impl FnOnce(&[OsString]) -> ExecError,
) -> InitError {
    let installed = host().and_then(|arch| {
        let [eperm, enosys] = namespaces(arch)?;
        let unix = Filter {
            name: "unix",
            program: seccomp::unix(arch).map_err(built)?,
        };
        install([eperm, enosys, unix], apply)
    });
    match installed {
        Ok(()) => InitError::Exec(run(argv)),
        Err(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io;

    use super::*;

    fn command() -> Vec<OsString> {
        vec!["echo".into(), "ran".into()]
    }

    fn host() -> Arch {
        Arch::host().expect("the tests run on an architecture the filters are built for")
    }

    #[test]
    fn the_namespaces_filter_goes_in_before_the_unix_filter_and_the_command_after_both() {
        let mut installed = Vec::new();
        let order = RefCell::new(Vec::new());

        let error = run_confined(
            &command(),
            |program| {
                installed.push(program.clone());
                order.borrow_mut().push("filter");
                Ok(())
            },
            |argv| {
                order.borrow_mut().push("command");
                assert_eq!(argv, command());
                ExecError::NoCommand
            },
        );

        let namespaces = seccomp::namespaces(host()).unwrap();
        assert_eq!(
            installed,
            [
                namespaces.eperm,
                namespaces.enosys,
                seccomp::unix(host()).unwrap()
            ]
        );
        assert_eq!(*order.borrow(), ["filter", "filter", "filter", "command"]);
        assert_eq!(error, InitError::Exec(ExecError::NoCommand));
    }

    #[test]
    fn a_filter_that_cannot_be_installed_exits_1_before_the_command() {
        let mut attempts = 0;
        let mut ran = false;

        let error = run_confined(
            &command(),
            |_| {
                attempts += 1;
                Err(seccompiler::Error::Seccomp(io::Error::from_raw_os_error(1)))
            },
            |_| {
                ran = true;
                ExecError::NoCommand
            },
        );

        assert!(!ran, "the command ran with a filter missing");
        assert_eq!(attempts, 1, "the helper went on after a failed install");
        let InitError::Filter(reason) = error else {
            panic!("expected a filter error, got {error:?}");
        };
        assert!(
            reason.starts_with("cannot install the namespaces (EPERM) seccomp filter: "),
            "{reason}"
        );
    }
}
