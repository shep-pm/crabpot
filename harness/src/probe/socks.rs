//! The probe's SOCKS5 client: one `CONNECT` through a proxy (RFC 1928), with
//! the username and password of RFC 1929 when the proxy's URL carries them.

use std::io::{Read, Write};

use super::Error;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;
const CONNECT: u8 = 1;
const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;
const SUCCEEDED: u8 = 0;

/// Asks the proxy on `stream` for a tunnel to `host:port`. `Ok(false)` when the
/// proxy refuses: it offers no method the client has, rejects the login, or
/// answers the request with anything but success.
pub(super) fn connect<S: Read + Write>(
    stream: &mut S,
    login: Option<(&str, &str)>,
    host: &str,
    port: u16,
) -> Result<bool, Error> {
    let io = Error::Io;
    let method = if login.is_some() {
        USERNAME_PASSWORD
    } else {
        NO_AUTH
    };
    stream.write_all(&[VERSION, 1, method]).map_err(io)?;
    let mut chosen = [0u8; 2];
    stream.read_exact(&mut chosen).map_err(io)?;
    if chosen[0] != VERSION {
        return Err(Error::BadSocksAnswer(chosen.to_vec()));
    }
    if chosen[1] != method {
        return Ok(false);
    }
    if let Some((user, password)) = login
        && !log_in(stream, user, password)?
    {
        return Ok(false);
    }
    let mut request = vec![VERSION, CONNECT, 0];
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            request.push(IPV4);
            request.extend_from_slice(&address.octets());
        }
        Ok(std::net::IpAddr::V6(address)) => {
            request.push(IPV6);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let length = u8::try_from(host.len()).map_err(|_| Error::Usage)?;
            request.extend_from_slice(&[DOMAIN, length]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(io)?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).map_err(io)?;
    if reply[0] != VERSION {
        return Err(Error::BadSocksAnswer(reply.to_vec()));
    }
    Ok(reply[1] == SUCCEEDED)
}

/// The subnegotiation of RFC 1929: whether the proxy accepted the login.
fn log_in<S: Read + Write>(stream: &mut S, user: &str, password: &str) -> Result<bool, Error> {
    let io = Error::Io;
    let (Ok(user_length), Ok(password_length)) =
        (u8::try_from(user.len()), u8::try_from(password.len()))
    else {
        return Err(Error::BadSocksProxy);
    };
    let mut message = vec![1, user_length];
    message.extend_from_slice(user.as_bytes());
    message.push(password_length);
    message.extend_from_slice(password.as_bytes());
    stream.write_all(&message).map_err(io)?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).map_err(io)?;
    Ok(status[1] == 0)
}

/// `text` with each `%XX` read as a byte, which is how a URL's userinfo
/// carries a username that has a `=` or a `/` in it.
pub(super) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let decoded = (bytes[at] == b'%')
            .then(|| bytes.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| core::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// A stream that answers with `answers` and keeps what is written to it.
    struct Script {
        answers: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Script {
        fn new(answers: &[u8]) -> Self {
            Self {
                answers: Cursor::new(answers.to_vec()),
                written: Vec::new(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.answers.read(buf)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const GRANTED: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    #[test]
    fn a_login_and_a_domain_are_sent_in_order() {
        let mut proxy = Script::new(&[&[5, 2, 1, 0][..], &GRANTED[..]].concat());

        let granted = connect(&mut proxy, Some(("srt", "tok")), "example.com", 443).unwrap();

        assert!(granted);
        let mut sent = vec![5, 1, 2, 1, 3];
        sent.extend_from_slice(b"srt");
        sent.extend_from_slice(&[3]);
        sent.extend_from_slice(b"tok");
        sent.extend_from_slice(&[5, 1, 0, 3, 11]);
        sent.extend_from_slice(b"example.com");
        sent.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(proxy.written, sent);
    }

    #[test]
    fn an_address_is_sent_as_one() {
        let mut proxy = Script::new(&[&[5, 0][..], &GRANTED[..]].concat());

        assert!(connect(&mut proxy, None, "127.0.0.1", 80).unwrap());

        assert_eq!(
            proxy.written,
            [5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80],
            "greeting with no login, then the request"
        );
    }

    #[test]
    fn a_proxy_that_refuses_the_method_the_login_or_the_host_is_a_refusal() {
        let refused_method = Script::new(&[5, 0xFF]);
        let refused_login = Script::new(&[5, 2, 1, 1]);
        let refused_host =
            Script::new(&[&[5, 2, 1, 0][..], &[5, 2, 0, 1, 0, 0, 0, 0, 0, 0][..]].concat());
        for mut proxy in [refused_method, refused_login, refused_host] {
            let granted = connect(&mut proxy, Some(("srt", "tok")), "example.com", 443).unwrap();

            assert!(!granted);
        }
    }

    #[test]
    fn an_answer_that_is_not_socks5_is_an_error() {
        let mut proxy = Script::new(b"HT");

        assert!(matches!(
            connect(&mut proxy, None, "example.com", 443),
            Err(Error::BadSocksAnswer(_))
        ));
    }

    #[test]
    fn a_percent_escape_is_read_as_its_byte() {
        assert_eq!(percent_decode("srt.dHJ1ZQ%3D%3D"), "srt.dHJ1ZQ==");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
