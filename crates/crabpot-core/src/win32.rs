//! The crate's Windows FFI: this host's interface addresses, through
//! `GetAdaptersAddresses`, and the AF_UNIX sockets Windows 10 and later
//! carry, through Winsock.

use core::mem::offset_of;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::ptr;
use std::io;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket, RawSocket};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNIX, AF_UNSPEC, FIONBIO, INVALID_SOCKET, SOCK_STREAM, SOCKADDR,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_UN, SOCKET_ERROR, WSA_FLAG_NO_HANDLE_INHERIT,
    WSA_FLAG_OVERLAPPED, WSADATA, WSAGetLastError, WSASocketW, WSAStartup, connect, ioctlsocket,
};
#[cfg(test)]
use windows_sys::Win32::Networking::WinSock::{accept, bind, listen};

/// The size Microsoft's documentation starts the buffer at.
const FIRST_SIZE: u32 = 15_000;

/// How many times the buffer is sized, since the adapters can change between
/// the call that reports the size and the next.
const TRIES: usize = 3;

/// The unicast addresses assigned to this host's adapters. Where they cannot be
/// listed the built-in classes still apply.
pub(crate) fn interface_addresses() -> Vec<IpAddr> {
    let mut size = FIRST_SIZE;
    for _ in 0..TRIES {
        // Words of eight bytes keep the buffer aligned for the adapter structs.
        let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `adapters` points to the `buffer`, which is at least `size`
        // bytes, writable and aligned for the struct, and `size` is a live
        // `u32`. The call writes only into the buffer, and on
        // `ERROR_BUFFER_OVERFLOW` sets `size` to the bytes it needs.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                ptr::null(),
                adapters,
                &raw mut size,
            )
        };
        match status {
            // SAFETY: the call succeeded, so the buffer holds a list it wrote,
            // and `buffer` is alive until the end of this iteration.
            ERROR_SUCCESS => return unsafe { unicast_addresses(adapters) },
            ERROR_BUFFER_OVERFLOW => {}
            _ => return Vec::new(),
        }
    }
    Vec::new()
}

/// Every unicast address of the adapters in the list at `first`.
///
/// # Safety
///
/// `first` is null, or the head of a list `GetAdaptersAddresses` wrote into a
/// buffer that is still alive, whose links and sockaddrs are in that buffer.
unsafe fn unicast_addresses(first: *const IP_ADAPTER_ADDRESSES_LH) -> Vec<IpAddr> {
    let mut found = Vec::new();
    let mut adapter = first;
    while !adapter.is_null() {
        // SAFETY: non-null, and a link of the list the caller vouches for.
        let current = unsafe { &*adapter };
        let mut unicast = current.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: non-null, and a link of the same list.
            let address = unsafe { &*unicast };
            // SAFETY: the sockaddr is null or in the same buffer, of the family
            // it names.
            if let Some(ip) = unsafe { ip_of(address.Address.lpSockaddr) } {
                found.push(ip);
            }
            unicast = address.Next;
        }
        adapter = current.Next;
    }
    found
}

/// The IP address a sockaddr holds, or `None` for a null one or another family.
///
/// # Safety
///
/// `sockaddr` is null, or points to a sockaddr of the family its `sa_family`
/// names, which is at least as large as that family's struct.
unsafe fn ip_of(sockaddr: *const SOCKADDR) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    // SAFETY: non-null, and a sockaddr, which starts with its family.
    match unsafe { (*sockaddr).sa_family } {
        AF_INET => {
            // SAFETY: the family is `AF_INET`, so this is a `SOCKADDR_IN`.
            let v4 = unsafe { &*sockaddr.cast::<SOCKADDR_IN>() };
            // SAFETY: every field of the union is plain integers.
            let network_order = unsafe { v4.sin_addr.S_un.S_addr };
            Some(IpAddr::V4(Ipv4Addr::from(network_order.to_ne_bytes())))
        }
        AF_INET6 => {
            // SAFETY: the family is `AF_INET6`, so this is a `SOCKADDR_IN6`.
            let v6 = unsafe { &*sockaddr.cast::<SOCKADDR_IN6>() };
            // SAFETY: every field of the union is plain integers.
            let bytes = unsafe { v6.sin6_addr.u.Byte };
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// The longest path a `sockaddr_un` carries, with the terminator after it.
const MAX_PATH: usize = size_of::<SOCKADDR_UN>() - offset_of!(SOCKADDR_UN, sun_path) - 1;

/// The backlog std listens with.
#[cfg(test)]
const BACKLOG: i32 = 128;

/// Winsock version 2.2, as `MAKEWORD(2, 2)`.
const WINSOCK_VERSION: u16 = 0x0202;

/// The status of the one `WSAStartup`, since every socket call needs Winsock up
/// and std starts it only for the sockets std makes.
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
    /// An [`io::Error`] of kind `InvalidInput` for a path that is not UTF-8, which
    /// is what Windows reads `sun_path` as, holds a NUL byte, or is longer than
    /// the 107 bytes `sun_path` carries beside its terminator.
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
            return Err(invalid(&format!(
                "is {} bytes, and this platform takes {MAX_PATH} at most",
                name.len()
            )));
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

/// Dials the AF_UNIX socket at `address` and leaves the socket non-blocking.
fn dial(address: &Address) -> io::Result<OwnedSocket> {
    let socket = socket()?;
    let raw = socket.as_raw_socket() as usize;
    // SAFETY: `address` holds the `len` bytes of an initialised `sockaddr_un`,
    // and `raw` is an open socket.
    if unsafe { connect(raw, address.as_ptr(), Address::len()) } == SOCKET_ERROR {
        return Err(last_error());
    }
    let mut on = 1u32;
    // SAFETY: `on` is a live `u32`, which is what `FIONBIO` reads, and `raw` is
    // an open socket.
    if unsafe { ioctlsocket(raw, FIONBIO, &raw mut on) } == SOCKET_ERROR {
        return Err(last_error());
    }
    Ok(socket)
}

/// Dials the AF_UNIX socket at `path`. The stream is a
/// [`tokio::net::TcpStream`], which only holds a Winsock stream socket and
/// reads and writes it as one, whatever its family.
///
/// The connect runs on a blocking thread: it ends at once on a local path, and
/// the thread leaves the runtime free of any doubt about how a non-blocking
/// AF_UNIX connect reports it is done.
///
/// # Errors
///
/// An [`io::Error`] of kind `InvalidInput` for a path `sun_path` cannot carry,
/// and otherwise the error of whichever Winsock call failed.
pub(crate) async fn connect_unix(path: &Path) -> io::Result<tokio::net::TcpStream> {
    let address = Address::new(path)?;
    let socket = tokio::task::spawn_blocking(move || dial(&address))
        .await
        .map_err(io::Error::other)??;
    tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))
}

/// A listening AF_UNIX socket, which the tests need a peer on.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Listener(OwnedSocket);

/// Binds and listens on an AF_UNIX socket at `path`. The listener is blocking.
///
/// # Errors
///
/// As [`connect_unix`].
#[cfg(test)]
pub(crate) fn bind_unix(path: &Path) -> io::Result<Listener> {
    let address = Address::new(path)?;
    let socket = socket()?;
    let raw = socket.as_raw_socket() as usize;
    // SAFETY: as in `dial`.
    if unsafe { bind(raw, address.as_ptr(), Address::len()) } == SOCKET_ERROR {
        return Err(last_error());
    }
    // SAFETY: `raw` is an open, bound socket.
    if unsafe { listen(raw, BACKLOG) } == SOCKET_ERROR {
        return Err(last_error());
    }
    Ok(Listener(socket))
}

#[cfg(test)]
impl Listener {
    /// Waits for one connection.
    pub(crate) fn accept(&self) -> io::Result<std::net::TcpStream> {
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
        Ok(std::net::TcpStream::from(unsafe {
            OwnedSocket::from_raw_socket(raw as RawSocket)
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::path::PathBuf;
    use std::thread;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::runtime::Builder;

    use super::*;

    #[test]
    fn interface_addresses_include_loopback() {
        let addresses = interface_addresses();

        assert!(
            addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{addresses:?}"
        );
    }

    /// A folder of its own, and the paths in it of exact lengths.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("win-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        /// A socket path in this folder that is `len` bytes long.
        fn socket_of(&self, len: usize) -> PathBuf {
            let dir = self.0.as_os_str().len() + 1;
            let path = self.0.join("s".repeat(len - dir));
            assert_eq!(path.as_os_str().len(), len);
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn block<F: Future>(task: F) -> F::Output {
        Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap()
            .block_on(task)
    }

    #[test]
    fn connects_to_a_listening_socket() {
        let fixture = Fixture::new("listening");
        let path = fixture.socket_of(40);
        let listener = bind_unix(&path).unwrap();
        let server = thread::spawn(move || {
            let mut client = listener.accept().unwrap();
            let mut byte = [0u8];
            client.read_exact(&mut byte).unwrap();
            client.write_all(&[byte[0] + 1]).unwrap();
        });

        block(async {
            let mut stream = connect_unix(&path).await.unwrap();
            stream.write_all(&[41]).await.unwrap();
            let mut answer = [0u8];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, [42]);
        });

        server.join().unwrap();
    }

    #[test]
    fn a_missing_path_is_an_error() {
        let fixture = Fixture::new("missing");

        let outcome = block(connect_unix(&fixture.socket_of(40)));

        assert!(outcome.is_err());
    }

    #[test]
    fn a_path_over_the_sun_path_limit_is_an_error() {
        let fixture = Fixture::new("long");

        let outcome = block(connect_unix(&fixture.socket_of(MAX_PATH + 1)));

        assert_eq!(outcome.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }
}
