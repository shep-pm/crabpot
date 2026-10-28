//! The file a Windows command runs, found the way `std::process::Command`
//! finds it, so a program that is an executable can skip `cmd.exe`.

use std::path::Path;

/// The `.exe` or `.com` file `program` runs, or `None` when it is another kind
/// of file or no file.
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
            }) && is_file(Path::new(path))
        })
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
        move |path| files.iter().any(|file| Path::new(file) == path)
    }

    #[test]
    fn a_path_entry_is_tried_in_order_and_may_end_in_a_backslash() {
        let files = [r"C:\mine\env.exe", r"C:\late\env.exe"];

        assert_eq!(
            executable(
                "env.exe",
                Some(r"C:\empty;;C:\mine\;C:\late"),
                &on_disk(&files)
            ),
            Some(r"C:\mine\env.exe".to_owned())
        );
    }

    #[test]
    fn a_bare_name_with_no_path_is_not_found() {
        let files = [r"C:\mine\env.exe", "env.exe"];

        assert_eq!(executable("env", None, &on_disk(&files)), None);
    }

    #[test]
    fn the_current_directory_is_not_searched() {
        assert_eq!(
            executable("env", Some(r"C:\mine"), &on_disk(&["env.exe"])),
            None
        );
    }

    #[test]
    fn a_name_with_no_extension_gets_exe() {
        assert_eq!(
            executable(r"C:\tools\env", None, &on_disk(&[r"C:\tools\env.exe"])),
            Some(r"C:\tools\env.exe".to_owned())
        );
        assert_eq!(
            executable("env", Some(r"C:\mine"), &on_disk(&[r"C:\mine\env.exe"])),
            Some(r"C:\mine\env.exe".to_owned())
        );
    }

    #[test]
    fn a_dot_in_a_directory_is_not_an_extension() {
        assert_eq!(
            executable(r"C:\my.dir\env", None, &on_disk(&[r"C:\my.dir\env.exe"])),
            Some(r"C:\my.dir\env.exe".to_owned())
        );
    }

    #[test]
    fn a_com_file_is_an_executable_whatever_its_case() {
        let path = r"C:\tools\OLD.COM";

        assert_eq!(
            executable(path, None, &on_disk(&[path])),
            Some(path.to_owned())
        );
    }

    #[test]
    fn a_batch_file_is_not_an_executable() {
        let path = r"C:\tools\run.bat";

        assert_eq!(executable(path, None, &on_disk(&[path])), None);
    }

    #[test]
    fn a_missing_file_is_not_an_executable() {
        assert_eq!(executable(r"C:\tools\env.exe", None, &on_disk(&[])), None);
    }
}
