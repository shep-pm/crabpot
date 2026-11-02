use std::env;
use std::io::Write as _;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::{Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crabpot_core::config::{AddressRange, DomainEntry};

use super::*;

/// The three lists a sandbox follows, kept the way `Sandbox` keeps them: only
/// `config.network`'s lists are taken, and every other key is left alone.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
struct Held {
    allowed: Vec<DomainEntry>,
    denied: Vec<DomainEntry>,
    resolved: Vec<AddressRange>,
    replacements: usize,
}

#[derive(Debug, Default)]
struct Fake {
    held: Mutex<Held>,
    changed: Condvar,
}

impl Fake {
    fn held(&self) -> Held {
        self.held.lock().unwrap().clone()
    }

    /// Waits until `count` replacements have landed, or panics after [`WAIT`].
    fn wait_for(&self, count: usize) {
        let held = self.held.lock().unwrap();
        let (_held, timeout) = self
            .changed
            .wait_timeout_while(held, WAIT, |held| held.replacements < count)
            .unwrap();
        assert!(!timeout.timed_out(), "{count} replacements in time");
    }
}

/// Real time bounds a wait on the reader's thread.
const WAIT: Duration = Duration::from_secs(10);

impl Lists for Fake {
    fn replace_network_lists(&self, config: &Config) {
        let mut held = self.held.lock().unwrap();
        held.allowed = config.network.allowed_domains.clone();
        held.denied = config.network.denied_domains.clone();
        held.resolved = config
            .network
            .denied_resolved_addresses
            .clone()
            .unwrap_or_default();
        held.replacements += 1;
        self.changed.notify_all();
    }
}

/// One line of a control stream: a full config with these network lists and
/// this `denyRead`.
fn line(allowed: &[&str], denied: &[&str], deny_read: &[&str]) -> String {
    format!(
        "{}\n",
        serde_json::json!({
            "network": {"allowedDomains": allowed, "deniedDomains": denied},
            "filesystem": {"denyRead": deny_read, "allowWrite": [], "denyWrite": []},
        })
    )
}

fn domains(names: &[&str]) -> Vec<DomainEntry> {
    names
        .iter()
        .map(|name| DomainEntry::parse_allowed(name).expect("a domain"))
        .collect()
}

/// Feeds `input` to a fresh fake and returns what it holds and what was said.
fn feed(input: &str) -> (Held, String) {
    let lists = Fake::default();
    let mut said = Vec::new();
    follow(&mut input.as_bytes(), &lists, &mut said).expect("the input is read");
    (lists.held(), String::from_utf8(said).unwrap())
}

#[test]
fn a_line_replaces_the_network_lists() {
    let input = line(&["a.example"], &["b.example"], &[]) + &line(&["c.example"], &[], &[]);

    let (held, said) = feed(&input);

    assert_eq!(held.allowed, domains(&["c.example"]));
    assert_eq!(held.denied, domains(&[]), "the second line replaces both");
    assert_eq!(held.replacements, 2);
    assert_eq!(said, "");
}

#[test]
fn a_line_that_does_not_parse_is_ignored_and_the_last_lists_stay() {
    let input = line(&["a.example"], &[], &[])
        + "{not json\n"
        + "{\"network\": {\"allowedDomains\": [\"*.com\"]}}\n"
        + "\n";

    let (held, said) = feed(&input);

    assert_eq!(held.allowed, domains(&["a.example"]));
    assert_eq!(held.replacements, 1);
    assert_eq!(said.lines().count(), 3, "one message for each line: {said}");
    assert!(
        said.lines()
            .all(|message| message.starts_with("crabpot: control line ignored: ")),
        "{said}"
    );
}

#[test]
fn a_line_that_is_not_text_is_ignored_with_a_message() {
    let lists = Fake::default();
    let mut said = Vec::new();
    let mut input: Vec<u8> = vec![0xff, 0xfe, b'\n'];
    input.extend_from_slice(line(&["a.example"], &[], &[]).as_bytes());

    follow(&mut input.as_slice(), &lists, &mut said).unwrap();

    assert_eq!(lists.held().allowed, domains(&["a.example"]));
    assert_eq!(String::from_utf8(said).unwrap().lines().count(), 1);
}

#[test]
fn end_of_input_keeps_the_last_lists() {
    // The last line has no newline, as a host that closes its end may leave it.
    let input = line(&["a.example"], &[], &[]) + line(&["b.example"], &[], &[]).trim_end();

    let (held, said) = feed(&input);

    assert_eq!(held.allowed, domains(&["b.example"]));
    assert_eq!(said, "");
    assert_eq!(feed("").0, Held::default(), "no input changes nothing");
}

#[test]
fn a_line_changing_only_filesystem_keys_changes_nothing() {
    let input = line(&["a.example"], &["b.example"], &[])
        + &line(&["a.example"], &["b.example"], &["/secret"]);

    let (held, said) = feed(&input);
    let (first, _) = feed(&line(&["a.example"], &["b.example"], &[]));

    assert_eq!(
        Held {
            replacements: first.replacements,
            ..held
        },
        first,
        "the lists are the first line's"
    );
    assert_eq!(said, "", "the second line is accepted");
}

#[test]
fn a_read_error_ends_the_stream_with_that_error() {
    struct Broken;
    impl io::Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("broken"))
        }
    }
    let lists = Fake::default();

    let error = follow(&mut io::BufReader::new(Broken), &lists, &mut Vec::new()).unwrap_err();

    assert_eq!(error.to_string(), "broken");
}

#[test]
fn a_close_on_exec_descriptor_is_followed() {
    // `io::pipe` makes both ends close-on-exec, as a host's own pipe is.
    let (read, mut write) = io::pipe().unwrap();
    let fd = read.into_raw_fd();
    write
        .write_all(line(&["a.example"], &[], &[]).as_bytes())
        .unwrap();
    drop(write);
    let lists = Arc::new(Fake::default());

    let control = start(fd, Arc::clone(&lists)).expect("the descriptor is accepted");
    lists.wait_for(1);
    drop(control);
    let held = lists.held();

    assert_eq!(held.allowed, domains(&["a.example"]));
}

#[test]
fn a_descriptor_that_is_not_open_refuses_the_start() {
    let lists = Arc::new(Fake::default());

    let error = start(-1, lists).unwrap_err();

    assert!(matches!(error, ControlError::Descriptor(_)), "{error}");
}

#[test]
fn a_descriptor_that_fails_to_read_refuses_the_start() {
    // Reading a directory fails at once, so the failure comes before any line.
    let dir = std::fs::File::open(env::temp_dir()).unwrap();
    let lists = Arc::new(Fake::default());

    let error = start(dir.into_raw_fd(), lists).unwrap_err();

    assert!(matches!(error, ControlError::Read(_)), "{error}");
}

#[test]
fn the_descriptor_number_is_left_as_dev_null() {
    // The write end stays open, so a read of the pipe itself would block.
    let (read, _write) = io::pipe().unwrap();
    let fd = read.into_raw_fd();

    let control = start(fd, Arc::new(Fake::default())).unwrap();

    let held = std::fs::metadata(format!("/dev/fd/{fd}")).unwrap();
    let null = std::fs::metadata("/dev/null").unwrap();
    assert!(held.file_type().is_char_device(), "{held:?}");
    assert_eq!(held.rdev(), null.rdev(), "the device of /dev/null");
    drop(control);
}

#[test]
fn a_host_that_keeps_writing_does_not_keep_the_reader_from_stopping() {
    let (read, mut write) = io::pipe().unwrap();
    let lists = Arc::new(Fake::default());
    let control = start(read.into_raw_fd(), Arc::clone(&lists)).unwrap();
    // It ends when the reader's end closes and the write fails.
    let writer = thread::spawn(move || {
        let line = line(&["a.example"], &[], &[]);
        while write.write_all(line.as_bytes()).is_ok() {}
    });
    lists.wait_for(1);

    let (stopped, ended) = mpsc::channel();
    thread::spawn(move || {
        drop(control);
        let _ = stopped.send(());
    });

    ended.recv_timeout(WAIT).expect("the reader stopped");
    writer.join().unwrap();
}

#[test]
fn a_descriptor_is_checked_before_anything_takes_it() {
    let (read, _write) = io::pipe().unwrap();
    let open = read.into_raw_fd();

    assert!(check(open).is_ok());
    assert!(matches!(check(-1), Err(ControlError::Descriptor(_))));
    // `check` leaves the descriptor as it was.
    assert!(check(open).is_ok());
    assert!(
        !std::fs::metadata(format!("/dev/fd/{open}"))
            .unwrap()
            .file_type()
            .is_char_device()
    );
}

#[test]
fn a_message_that_cannot_be_written_does_not_stop_the_lines_after_it() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let lists = Fake::default();
    let input = "{not json\n".to_owned() + &line(&["a.example"], &[], &[]);

    follow(&mut input.as_bytes(), &lists, &mut Closed).expect("the input is read");

    assert_eq!(lists.held().allowed, domains(&["a.example"]));
}
