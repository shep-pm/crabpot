//! The file a Windows command runs, found the way `std::process::Command`
//! finds it, so a program that is an executable can skip `cmd.exe`.

use std::path::Path;

/// The `.exe` or `.com` file `program` runs, or `None` when it runs through
/// `cmd.exe`: a file of another kind, `cmd.exe` itself, or no file.
///
/// A program with a directory part is taken as it is. A bare name is looked up
/// in each entry of `path`, the `PATH` the command sees, and the current
/// directory is not searched. `.exe` is added to a name with no extension.
/// `is_file` is the lookup of a file on disk.
pub(super) fn executable(
    program: &str,
    path: Option<&str>,
    is_file: &dyn Fn(&Path) -> bool,
) -> Option<String> {
    let candidates: Vec<String> = if program.contains(['\\', '/', ':']) {
        vec![program.to_owned()]
    } else {
        path?
            .split(';')
            .map(|dir| dir.trim_matches('"').trim_end_matches(['\\', '/']))
            .filter(|dir| !dir.is_empty())
            .map(|dir| format!("{dir}\\{program}"))
            .collect()
    };
    candidates
        .into_iter()
        .map(|path| match extension(&path) {
            Some(_) => path,
            None => format!("{path}.exe"),
        })
        .find(|path| {
            extension(path).is_some_and(|ext| {
                ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("com")
            }) && !is_cmd(path)
                && is_file(Path::new(path))
        })
}

/// Whether `path` names `cmd.exe`, which reads the words after `/c` itself.
fn is_cmd(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    name.trim_end_matches(['.', ' '])
        .eq_ignore_ascii_case("cmd.exe")
}

/// The extension of the last component of `path`, a leading dot not starting one.
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit(['\\', '/']).next()?;
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty()).then_some(ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on_disk<'a>(files: &'a [&'a str]) -> impl Fn(&Path) -> bool + 'a {
        move |path| {
            files
                .iter()
                .any(|file| file.eq_ignore_ascii_case(&path.to_string_lossy()))
        }
    }

    fn found(program: &str, path: Option<&str>, files: &[&str]) -> Option<String> {
        executable(program, path, &on_disk(files))
    }

    #[test]
    fn a_path_entry_is_tried_in_order_and_may_end_in_a_backslash() {
        let files = [r"C:\mine\env.exe", r"C:\late\env.exe"];

        assert_eq!(
            found("env.exe", Some(r"C:\empty;;C:\mine\;C:\late"), &files),
            Some(r"C:\mine\env.exe".to_owned())
        );
    }

    #[test]
    fn a_bare_name_with_no_path_is_not_found() {
        assert_eq!(found("env", None, &[r"C:\mine\env.exe", "env.exe"]), None);
    }

    #[test]
    fn the_current_directory_is_not_searched() {
        assert_eq!(found("env", Some(r"C:\mine"), &["env.exe"]), None);
    }

    #[test]
    fn a_name_with_no_extension_gets_exe() {
        assert_eq!(
            found(r"C:\tools\env", None, &[r"C:\tools\env.exe"]),
            Some(r"C:\tools\env.exe".to_owned())
        );
        assert_eq!(
            found("env", Some(r"C:\mine"), &[r"C:\mine\env.exe"]),
            Some(r"C:\mine\env.exe".to_owned())
        );
    }

    #[test]
    fn a_dot_in_a_directory_is_not_an_extension() {
        assert_eq!(
            found(r"C:\my.dir\env", None, &[r"C:\my.dir\env.exe"]),
            Some(r"C:\my.dir\env.exe".to_owned())
        );
    }

    #[test]
    fn a_com_file_is_an_executable_whatever_its_case() {
        let path = r"C:\tools\OLD.COM";

        assert_eq!(found(path, None, &[path]), Some(path.to_owned()));
    }

    #[test]
    fn a_batch_file_is_not_an_executable() {
        let path = r"C:\tools\run.bat";

        assert_eq!(found(path, None, &[path]), None);
    }

    #[test]
    fn a_missing_file_is_not_an_executable() {
        assert_eq!(found(r"C:\tools\env.exe", None, &[]), None);
    }

    #[test]
    fn cmd_is_left_to_the_cmd_line() {
        for program in ["cmd", "CMD.EXE", r"C:\Windows\System32\cmd.exe"] {
            let files = [r"C:\Windows\System32\cmd.exe"];
            let path = Some(r"C:\Windows\System32");

            assert_eq!(found(program, path, &files), None, "{program}");
        }
    }
}
