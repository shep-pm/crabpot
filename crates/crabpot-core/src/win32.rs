//! The crate's Windows FFI: this host's interface addresses, through
//! `GetAdaptersAddresses`.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::ptr;

use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_addresses_include_loopback() {
        let addresses = interface_addresses();

        assert!(
            addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
            "{addresses:?}"
        );
    }
}
