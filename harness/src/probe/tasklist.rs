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
/// which is a quoted number of its own.
///
/// The row is read as bytes. `tasklist` writes the console's own code page, and
/// a localized process name, session name or memory label is no UTF-8 in the
/// legacy ones, which is no bar to the pid: that field is ASCII digits.
///
/// Where nothing matches its filter, `tasklist` prints `INFO: No tasks are
/// running which match the specified criteria.`, which is no row at all.
pub fn names_the_pid(stdout: &[u8], pid: u32) -> bool {
    let pid = pid.to_string();
    stdout
        .split(|byte| *byte == b'\n')
        .any(|row| the_pid_field(row, pid.as_bytes()))
}

/// Whether the `tasklist` row `row` names `pid` as its pid field.
///
/// A row is its fields each in its own quotes, so the quotes are what split it,
/// and a field lands on the index its place gives it: the pid is the second
/// field, at index 3 of the split of the whole row. A process name, a session
/// name and a memory label hold no quote of their own, so no field is ever out
/// of its place, and a line that is no row at all has no field there.
fn the_pid_field(row: &[u8], pid: &[u8]) -> bool {
    let row = row.strip_suffix(b"\r").unwrap_or(row);
    if !row.starts_with(b"\"") || !row.ends_with(b"\"") {
        return false;
    }
    row.split(|byte| *byte == b'"').nth(3) == Some(pid)
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

    /// A row whose session name is a localized word written in the console's own
    /// code page, which is what `tasklist` writes: `控制台` in code page 936 is
    /// `bf d8 d6 c6 cc a8`, and no UTF-8 decoding takes it. The pid field is
    /// ASCII digits, so the row is read as bytes and the pid is still named.
    #[test]
    fn a_row_written_in_a_console_code_page_names_the_pid() {
        let mut row = b"\"probe.exe\",\"1234\",".to_vec();
        row.extend_from_slice(&[0xbf, 0xd8, 0xd6, 0xc6, 0xcc, 0xa8]);
        row.extend_from_slice(b",\"1\",\"3,072 K\"\r\n");
        assert!(names_the_pid(&row, 1234));
        assert!(!names_the_pid(&row, 1));
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
