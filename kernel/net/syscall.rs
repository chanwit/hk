//! Socket System Call Handlers
//!
//! This module implements the socket-related system calls for the network stack.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::sync::Weak;

use crate::fs::dentry::Dentry;
use crate::fs::file::{File, FileOps, flags as file_flags};
use crate::fs::inode::{Inode, InodeMode, NULL_INODE_OPS, Timespec};
use crate::net::ipv4::Ipv4Addr;
use crate::net::socket::{AddressFamily, SockAddrIn, Socket, SocketType, sock_flags};
use crate::net::socket_file::SocketFileOps;
use crate::net::tcp::{self, TcpState};
use crate::task::fdtable::get_task_fd;
use crate::task::percpu::current_tid;

/// Get RLIMIT_NOFILE limit for fd allocation
#[inline]
fn get_nofile_limit() -> u64 {
    let limit = crate::rlimit::rlimit(crate::rlimit::RLIMIT_NOFILE);
    if limit == crate::rlimit::RLIM_INFINITY {
        u64::MAX
    } else {
        limit
    }
}

/// Error numbers (negative)
mod errno {
    pub const EINVAL: i64 = -22;
    pub const EBADF: i64 = -9;
    pub const ENOTSOCK: i64 = -88;
    pub const EAFNOSUPPORT: i64 = -97;
    pub const ESOCKTNOSUPPORT: i64 = -94;
    pub const EPROTONOSUPPORT: i64 = -93;
    pub const ENOMEM: i64 = -12;
    pub const EOPNOTSUPP: i64 = -95;
    pub const ENOTCONN: i64 = -107;
    pub const EISCONN: i64 = -106;
    pub const EFAULT: i64 = -14;
    #[allow(dead_code)]
    pub const EAGAIN: i64 = -11;
    pub const EINPROGRESS: i64 = -115;
    pub const EALREADY: i64 = -114;
}

/// Create a dummy dentry for sockets
///
/// Sockets don't have a real filesystem entry, but our File struct
/// requires a dentry. This creates a minimal anonymous dentry.
fn create_socket_dentry() -> Result<Arc<Dentry>, i64> {
    // Create anonymous inode for socket
    let mode = InodeMode::socket(0o600);
    let inode = Arc::new(Inode::new(
        0, // ino=0 for anonymous
        mode,
        0,                      // uid (root)
        0,                      // gid (root)
        0,                      // size
        Timespec::from_secs(0), // mtime
        Weak::new(),            // no superblock for anonymous inode
        &NULL_INODE_OPS,
    ));

    // Create anonymous dentry
    let dentry = Arc::new(Dentry::new_anonymous(String::from("socket"), Some(inode)));

    Ok(dentry)
}

/// socket(domain, type, protocol) - create a socket
pub fn sys_socket(domain: i32, sock_type: i32, protocol: i32) -> i64 {
    // Parse address family
    let family = match AddressFamily::from_i32(domain) {
        Some(AddressFamily::Inet) => AddressFamily::Inet,
        Some(_) | None => return errno::EAFNOSUPPORT,
    };

    // Extract type and flags
    let type_only = sock_type & 0xFF;
    let nonblock = sock_type & sock_flags::SOCK_NONBLOCK != 0;
    let cloexec = sock_type & sock_flags::SOCK_CLOEXEC != 0;

    // Parse socket type
    let stype = match SocketType::from_i32(type_only) {
        Some(SocketType::Stream) => SocketType::Stream,
        Some(SocketType::Dgram) => return errno::ESOCKTNOSUPPORT, // UDP not yet
        Some(SocketType::Raw) => return errno::ESOCKTNOSUPPORT,
        None => return errno::ESOCKTNOSUPPORT,
    };

    // Protocol: 0 means default for type
    if protocol != 0 && protocol != 6 {
        // 6 = IPPROTO_TCP
        return errno::EPROTONOSUPPORT;
    }

    // Create socket
    let socket = Socket::new(family, stype, protocol);

    // Apply flags
    if nonblock {
        socket.set_nonblocking(true);
    }

    // Create file operations (leaked for 'static lifetime like pipe.rs)
    let ops: &'static dyn FileOps = Box::leak(Box::new(SocketFileOps::new(socket)));

    // Create dummy dentry for socket
    let dentry = match create_socket_dentry() {
        Ok(d) => d,
        Err(_) => return errno::ENOMEM,
    };

    // Determine file flags
    let mut flags = file_flags::O_RDWR;
    if nonblock {
        flags |= file_flags::O_NONBLOCK;
    }
    if cloexec {
        flags |= file_flags::O_CLOEXEC;
    }
    let file = Arc::new(File::new(dentry, flags, ops));

    // Allocate fd
    let fd_table = match get_task_fd(current_tid()) {
        Some(t) => t,
        None => return errno::ENOMEM,
    };
    match fd_table.lock().alloc(file, get_nofile_limit()) {
        Ok(fd) => fd as i64,
        Err(_) => errno::ENOMEM,
    }
}

/// connect(fd, addr, addrlen) - connect to remote address
pub fn sys_connect(fd: i32, addr: u64, addrlen: u64) -> i64 {
    if addrlen < core::mem::size_of::<SockAddrIn>() as u64 {
        return errno::EINVAL;
    }

    // Get socket from fd
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Read sockaddr_in from user
    let sockaddr = match read_sockaddr_in(addr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Verify address family
    if sockaddr.sin_family != AddressFamily::Inet as u16 {
        return errno::EAFNOSUPPORT;
    }

    let remote_addr = sockaddr.addr();
    let remote_port = sockaddr.port();

    // Check TCP state
    if let Some(ref tcp) = socket.tcp {
        match tcp.state() {
            TcpState::Established => return errno::EISCONN,
            TcpState::SynSent | TcpState::SynReceived => {
                if socket.is_nonblocking() {
                    return errno::EALREADY;
                }
            }
            _ => {}
        }
    }

    // Initiate connection
    if let Err(e) = tcp::tcp_connect(&socket, remote_addr, remote_port) {
        return -(e.to_errno() as i64);
    }

    // Non-blocking: return EINPROGRESS
    if socket.is_nonblocking() {
        return errno::EINPROGRESS;
    }

    // Blocking: wait for connection
    loop {
        if let Some(ref tcp) = socket.tcp {
            match tcp.state() {
                TcpState::Established => return 0,
                TcpState::Closed => {
                    let err = socket.get_error();
                    if err != 0 {
                        return err as i64;
                    }
                    return errno::ENOTCONN;
                }
                _ => {}
            }
        }
        socket.connect_wait().wait();
    }
}

/// bind(fd, addr, addrlen) - bind to local address
pub fn sys_bind(fd: i32, addr: u64, addrlen: u64) -> i64 {
    if addrlen < core::mem::size_of::<SockAddrIn>() as u64 {
        return errno::EINVAL;
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let sockaddr = match read_sockaddr_in(addr) {
        Ok(s) => s,
        Err(e) => return e,
    };

    if sockaddr.sin_family != AddressFamily::Inet as u16 {
        return errno::EAFNOSUPPORT;
    }

    let local_addr = sockaddr.addr();
    let local_port = sockaddr.port();

    socket.set_local(local_addr, local_port);

    0
}

/// listen(fd, backlog) - start listening for connections
pub fn sys_listen(fd: i32, _backlog: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Set TCP state to Listen
    if let Some(ref tcp) = socket.tcp {
        tcp.set_state(TcpState::Listen);
        0
    } else {
        errno::EOPNOTSUPP
    }
}

/// accept(fd, addr, addrlen) - accept incoming connection
pub fn sys_accept(fd: i32, _addr: u64, _addrlen: u64) -> i64 {
    let _socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // TODO: Implement accept queue for listening sockets
    // For now, return not supported
    errno::EOPNOTSUPP
}

/// accept4(fd, addr, addrlen, flags) - accept with flags
pub fn sys_accept4(fd: i32, addr: u64, addrlen: u64, _flags: i32) -> i64 {
    sys_accept(fd, addr, addrlen)
}

/// shutdown(fd, how) - shutdown socket
pub fn sys_shutdown(fd: i32, how: i32) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
    match how {
        0 => {
            // SHUT_RD - mark EOF on receive side
            socket.set_eof();
            socket.wake_rx();
        }
        1 | 2 => {
            // SHUT_WR or SHUT_RDWR - close the connection
            if let Err(e) = tcp::tcp_close(&socket) {
                return -(e.to_errno() as i64);
            }
            if how == 2 {
                socket.set_eof();
                socket.wake_all();
            }
        }
        _ => return errno::EINVAL,
    }

    0
}

/// getsockname(fd, addr, addrlen) - get local socket address
pub fn sys_getsockname(fd: i32, addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let (local_addr, local_port) = match socket.local_addr() {
        Some(a) => a,
        None => (Ipv4Addr::new(0, 0, 0, 0), 0),
    };

    let sockaddr = SockAddrIn::new(local_addr, local_port);
    write_sockaddr_in(addr, addrlen, &sockaddr)
}

/// getpeername(fd, addr, addrlen) - get remote socket address
pub fn sys_getpeername(fd: i32, addr: u64, addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let (remote_addr, remote_port) = match socket.remote_addr() {
        Some(a) => a,
        None => return errno::ENOTCONN,
    };

    let sockaddr = SockAddrIn::new(remote_addr, remote_port);
    write_sockaddr_in(addr, addrlen, &sockaddr)
}

/// setsockopt(fd, level, optname, optval, optlen) - set socket option
pub fn sys_setsockopt(fd: i32, _level: i32, _optname: i32, _optval: u64, _optlen: u64) -> i64 {
    // Verify it's a socket
    match get_socket(fd) {
        Ok(_) => 0, // Silently accept but ignore options for now
        Err(e) => e,
    }
}

/// getsockopt(fd, level, optname, optval, optlen) - get socket option
pub fn sys_getsockopt(fd: i32, level: i32, optname: i32, optval: u64, optlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // SOL_SOCKET = 1, SO_ERROR = 4
    if level == 1 && optname == 4 {
        // SO_ERROR - get pending error
        let err = socket.get_error();
        if optval != 0 && optlen != 0 {
            // Write error value
            unsafe {
                let ptr = optval as *mut i32;
                if !ptr.is_null() {
                    *ptr = -err;
                }
                let len_ptr = optlen as *mut u32;
                if !len_ptr.is_null() {
                    *len_ptr = 4;
                }
            }
        }
        return 0;
    }

    // Other options: return 0 with empty result
    0
}

/// sendto(fd, buf, len, flags, dest_addr, addrlen) - send data
pub fn sys_sendto(fd: i32, buf: u64, len: u64, _flags: i32, _dest_addr: u64, _addrlen: u64) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // For connected TCP socket, use tcp_sendmsg
    if socket.tcp.is_some() {
        let data = unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) };
        match tcp::tcp_sendmsg(&socket, data) {
            Ok(n) => n as i64,
            Err(e) => -(e.to_errno() as i64),
        }
    } else {
        errno::EOPNOTSUPP
    }
}

/// recvfrom(fd, buf, len, flags, src_addr, addrlen) - receive data
pub fn sys_recvfrom(
    fd: i32,
    buf: u64,
    len: u64,
    _flags: i32,
    _src_addr: u64,
    _addrlen: u64,
) -> i64 {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let buffer = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };

    match socket.read(buffer) {
        Ok(n) => n as i64,
        Err(e) => e as i64,
    }
}

// Helper functions

/// Get socket from file descriptor
fn get_socket(fd: i32) -> Result<Arc<Socket>, i64> {
    if fd < 0 {
        return Err(errno::EBADF);
    }

    let fd_table = get_task_fd(current_tid()).ok_or(errno::EBADF)?;
    let file = fd_table.lock().get(fd).ok_or(errno::EBADF)?;

    // Try to downcast FileOps to SocketFileOps
    let ops = file.ops();
    let socket_ops = ops
        .as_any()
        .downcast_ref::<SocketFileOps>()
        .ok_or(errno::ENOTSOCK)?;

    Ok(Arc::clone(socket_ops.socket()))
}

/// Read sockaddr_in from user space
fn read_sockaddr_in(addr: u64) -> Result<SockAddrIn, i64> {
    if addr == 0 {
        return Err(errno::EFAULT);
    }

    let ptr = addr as *const SockAddrIn;
    let sockaddr = unsafe { *ptr };
    Ok(sockaddr)
}

/// Write sockaddr_in to user space
fn write_sockaddr_in(addr: u64, addrlen: u64, sockaddr: &SockAddrIn) -> i64 {
    if addr == 0 || addrlen == 0 {
        return errno::EFAULT;
    }

    unsafe {
        let ptr = addr as *mut SockAddrIn;
        *ptr = *sockaddr;

        let len_ptr = addrlen as *mut u32;
        if !len_ptr.is_null() {
            *len_ptr = core::mem::size_of::<SockAddrIn>() as u32;
        }
    }

    0
}
