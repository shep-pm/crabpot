//! The `tasklist` output the Windows `ps` probe reads.
//!
//! The reading is its own module rather than a part of the Windows probes
//! because it is plain text work with no Windows call in it: every host builds
//! and tests it, so the ordinary test job catches what only a Windows runner
//! used to.

/// The program that names a process and how it runs, which a host asks when it
/// decides whether a session it attached to still holds.
pub const TASKLIST: &str = "tasklist";

/// Whether `tasklist`'s output names `pid`.
///
/// `/FO CSV /NH` gives one row per process with every field quoted, and the pid
/// is the second field of it: `"probe.exe","1234","Console","1","3,072 K"`. The
/// pid is read as that field and not searched for, because every field is quoted
/// and a search for it between two commas answers for the session number too,
/// which is a quoted number of its own. A field that holds a comma of its own
/// stays inside its quotes, so `","` is what separates the fields.
///
/// Where nothing matches its filter, `tasklist` prints `INFO: No tasks are
/// running which match the specified criteria.`, which is no row at all.
pub fn names_the_pid(stdout: &[u8], pid: u32) -> bool {
    let pid = pid.to_string();
    stdout
        .split(|byte| *byte == b'\n')
        .any(|row| the_pid_field(row, &pid))
}

/// Whether the `tasklist` row `row` names `pid` as its pid field.
fn the_pid_field(row: &[u8], pid: &str) -> bool {
    let Ok(row) = std::str::from_utf8(row) else {
        return false;
    };
    let Some(fields) = row
        .trim_end_matches('\r')
        .strip_prefix('"')
        .and_then(|row| row.strip_suffix('"'))
    else {
        return false;
    };
    fields.split("\",\"").nth(1) == Some(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line `tasklist` gives for a match, with a memory column that holds a
    /// comma of its own, and the line it gives for none.
    #[test]
    fn tasklist_output_names_the_pid_and_no_other_number_in_it() {
        let line = b"\"probe.exe\",\"1234\",\"Console\",\"1\",\"3,072 K\"\r\n";
        assert!(names_the_pid(line, 1234));
        assert!(!names_the_pid(line, 3072));
        assert!(!names_the_pid(line, 1));
        assert!(!names_the_pid(
            b"INFO: No tasks are running which match the specified criteria.\r\n",
            1234
        ));
    }

    /// A row for another process, whose session number happens to be the pid the
    /// probe asked for. `tasklist` quotes every column, the session number
    /// among them, so the pid has to be read as the column it is in and not
    /// searched for.
    #[test]
    fn a_row_of_another_process_names_the_pid_only_in_the_pid_column() {
        let row = b"\"svchost.exe\",\"4096\",\"Services\",\"1234\",\"1,024 K\"\r\n";
        assert!(!names_the_pid(row, 1234));
        assert!(names_the_pid(row, 4096));
    }

    /// A process name that holds a comma of its own stays inside its quotes, so
    /// the columns after it are still where they are.
    #[test]
    fn a_process_name_holding_a_comma_leaves_the_pid_where_it_is() {
        let row = b"\"Microsoft Edge, WebView2.exe\",\"1234\",\"Console\",\"1\",\"3,072 K\"\r\n";
        assert!(names_the_pid(row, 1234));
        assert!(!names_the_pid(row, 1));
    }
}
