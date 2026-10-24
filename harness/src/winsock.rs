//! The AF_UNIX sockets Windows 10 and later carry, through Winsock: the
//! listener a served case answers on and the connect that ends its accept.
//! `std` has no AF_UNIX on Windows, so a stream is held as the
//! [`TcpStream`] of its socket, which only reads and writes a Winsock stream
//! socket whatever its family.

#![allow(unsafe_code)]

use core::mem::offset_of;
use core::ptr;
use std::io;
use std::net::TcpStream;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, SOCKET_ERROR,
    WSA_FLAG_NO_HANDLE_INHERIT, WSA_FLAG_OVERLAPPED, WSADATA, WSAGetLastError, WSASocketW,
    WSAStartup, accept, bind, connect, listen,
};

/// The longest path a `sockaddr_un` carries, with the terminator after it.
const MAX_PATH: usize = size_of::<SOCKADDR_UN>() - offset_of!(SOCKADDR_UN, sun_path) - 1;

/// The backlog std listens with.
const BACKLOG: i32 = 128;

/// Winsock version 2.2, as `MAKEWORD(2, 2)`.
const WINSOCK_VERSION: u16 = 0x0202;

/// The status of the one `WSAStartup`, since std starts Winsock only for the
/// sockets std makes.
static WINSOCK: OnceLock<i32> = OnceLock::new();

fn start_winsock() -> io::Result<()> {
    let status = *WINSOCK.get_or_init(|| {
        let mut data = WSADATA::default();
        // SAFETY: `data` is a live `WSADATA` the call writes into.
        unsafe { WSAStartup(WINSOCK_VERSION, &raw mut data) }
    });
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status))
    }
}

fn last_error() -> io::Error {
    // SAFETY: `WSAGetLastError` reads only the calling thread's error.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// A `sockaddr_un` for a path.
struct Address(SOCKADDR_UN);

impl Address {
    /// # Errors
    ///
    /// An [`io::Error`] of kind `InvalidInput` for a path that is not UTF-8,
    /// holds a NUL byte, or is longer than `sun_path` carries beside its
    /// terminator.
    fn new(path: &Path) -> io::Result<Self> {
        let invalid = |why: &str| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the socket path {} {why}", path.display()),
            )
        };
        let name = path
            .to_str()
            .ok_or_else(|| invalid("is not UTF-8"))?
            .as_bytes();
        if name.len() > MAX_PATH {
            return Err(invalid("is longer than a sockaddr_un takes"));
        }
        if name.contains(&0) {
            return Err(invalid("holds a NUL byte"));
        }
        let mut address = SOCKADDR_UN {
            sun_family: AF_UNIX,
            ..SOCKADDR_UN::default()
        };
        for (slot, byte) in address.sun_path.iter_mut().zip(name) {
            *slot = i8::from_ne_bytes([*byte]);
        }
        Ok(Self(address))
    }

    fn as_ptr(&self) -> *const SOCKADDR {
        (&raw const self.0).cast()
    }

    fn len() -> i32 {
        size_of::<SOCKADDR_UN>() as i32
    }
}

/// A blocking stream socket that a child does not inherit.
fn socket() -> io::Result<OwnedSocket> {
    start_winsock()?;
    // SAFETY: `WSASocketW` reads no memory of this process's, as the protocol
    // info is null.
    let raw = unsafe {
        WSASocketW(
            i32::from(AF_UNIX),
            SOCK_STREAM,
            0,
            ptr::null(),
            0,
            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if raw == INVALID_SOCKET {
        return Err(last_error());
    }
    // SAFETY: `raw` is a socket `WSASocketW` just returned, and nothing else
    // owns it.
    Ok(unsafe { OwnedSocket::from_raw_socket(raw as RawSocket) })
}

/// Dials the AF_UNIX socket at `path`.
///
/// # Errors
///
/// An [`io::Error`] of kind `InvalidInput` for a path `sun_path` cannot carry,
/// and otherwise the error of whichever Winsock call failed.
pub fn connect_unix(path: &Path) -> io::Result<TcpStream> {
    let address = Address::new(path)?;
    let socket = socket()?;
    // SAFETY: `address` holds the `len` bytes of an initialised `sockaddr_un`,
    // and the socket is open.
    if unsafe {
        connect(
            socket.as_raw_socket() as usize,
            address.as_ptr(),
            Address::len(),
        )
    } == SOCKET_ERROR
    {
        return Err(last_error());
    }
    Ok(TcpStream::from(socket))
}

/// A listening AF_UNIX socket. It is blocking.
#[derive(Debug)]
pub struct Listener(OwnedSocket);

impl Listener {
    /// Binds and listens on an AF_UNIX socket at `path`.
    ///
    /// # Errors
    ///
    /// As [`connect_unix`].
    pub fn bind(path: &Path) -> io::Result<Self> {
        let address = Address::new(path)?;
        let socket = socket()?;
        let raw = socket.as_raw_socket() as usize;
        // SAFETY: as in `connect_unix`.
        if unsafe { bind(raw, address.as_ptr(), Address::len()) } == SOCKET_ERROR {
            return Err(last_error());
        }
        // SAFETY: `raw` is an open, bound socket.
        if unsafe { listen(raw, BACKLOG) } == SOCKET_ERROR {
            return Err(last_error());
        }
        Ok(Self(socket))
    }

    /// Waits for one connection.
    ///
    /// # Errors
    ///
    /// The error of the Winsock call, which a closed listener ends with.
    pub fn accept(&self) -> io::Result<TcpStream> {
        // SAFETY: the address is not asked for, so both pointers are null, and
        // the socket is an open, listening one.
        let raw = unsafe {
            accept(
                self.0.as_raw_socket() as usize,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if raw == INVALID_SOCKET {
            return Err(last_error());
        }
        // SAFETY: `raw` is a socket `accept` just returned, and nothing else
        // owns it.
        Ok(TcpStream::from(unsafe {
            OwnedSocket::from_raw_socket(raw as RawSocket)
        }))
    }
}
