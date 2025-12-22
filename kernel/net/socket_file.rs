//! Socket File Operations
//!
//! This module implements the FileOps trait for sockets,
//! allowing them to be used through the standard file API.

use alloc::sync::Arc;

use crate::fs::FsError;
use crate::fs::file::{File, FileOps, flags};
use crate::net::socket::Socket;
use crate::net::tcp::{self, TcpState};
use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM, PollTable};

/// File operations for sockets
pub struct SocketFileOps {
    socket: Arc<Socket>,
}

impl SocketFileOps {
    /// Create new socket file operations
    pub fn new(socket: Arc<Socket>) -> Self {
        Self { socket }
    }

    /// Get the underlying socket
    pub fn socket(&self) -> &Arc<Socket> {
        &self.socket
    }
}

impl FileOps for SocketFileOps {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn read(&self, file: &File, buf: &mut [u8]) -> Result<usize, FsError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || self.socket.is_nonblocking();

        loop {
            // Check for error
            let err = self
                .socket
                .error
                .load(core::sync::atomic::Ordering::Acquire);
            if err != 0 {
                self.socket
                    .error
                    .store(0, core::sync::atomic::Ordering::Release);
                return Err(FsError::from_errno(-err));
            }

            // Try to read from receive buffer
            {
                let mut rx = self.socket.rx_buffer.lock();
                if !rx.is_empty() {
                    let n = buf.len().min(rx.len());
                    for byte in buf[..n].iter_mut() {
                        *byte = rx.pop_front().unwrap();
                    }
                    return Ok(n);
                }
            }

            // Check for EOF
            if self.socket.is_eof() {
                return Ok(0);
            }

            // Check TCP state for connection closed
            if let Some(ref tcp) = self.socket.tcp {
                match tcp.state() {
                    TcpState::Closed | TcpState::TimeWait => {
                        return Ok(0);
                    }
                    _ => {}
                }
            }

            if nonblock {
                return Err(FsError::WouldBlock);
            }

            // Block waiting for data
            self.socket.rx_wait.wait();
        }
    }

    fn write(&self, file: &File, buf: &[u8]) -> Result<usize, FsError> {
        let nonblock = file.get_flags() & flags::O_NONBLOCK != 0 || self.socket.is_nonblocking();

        // Check for error
        let err = self
            .socket
            .error
            .load(core::sync::atomic::Ordering::Acquire);
        if err != 0 {
            self.socket
                .error
                .store(0, core::sync::atomic::Ordering::Release);
            return Err(FsError::from_errno(-err));
        }

        // For TCP sockets, use tcp_sendmsg
        if let Some(ref _tcp) = self.socket.tcp {
            match tcp::tcp_sendmsg(&self.socket, buf) {
                Ok(n) => Ok(n),
                Err(crate::net::NetError::WouldBlock) => {
                    if nonblock {
                        Err(FsError::WouldBlock)
                    } else {
                        // Block and retry
                        self.socket.tx_wait.wait();
                        // Retry once after wakeup
                        tcp::tcp_sendmsg(&self.socket, buf).map_err(|_| FsError::WouldBlock)
                    }
                }
                Err(e) => Err(FsError::from_errno(-e.to_errno())),
            }
        } else {
            Err(FsError::NotSupported)
        }
    }

    fn poll(&self, _file: &File, pt: Option<&mut PollTable>) -> u16 {
        // Register on wait queues
        if let Some(poll_table) = pt {
            poll_table.poll_wait(self.socket.rx_wait());
            poll_table.poll_wait(self.socket.tx_wait());
        }

        let mut mask = 0u16;

        // Check for readable
        if self.socket.poll_read() {
            mask |= POLLIN | POLLRDNORM;
        }

        // Check for writable
        if self.socket.poll_write() {
            mask |= POLLOUT | POLLWRNORM;
        }

        // Check for errors
        if self
            .socket
            .error
            .load(core::sync::atomic::Ordering::Acquire)
            != 0
        {
            mask |= POLLERR;
        }

        // Check for hangup (connection closed)
        if self.socket.is_eof() {
            mask |= POLLHUP;
        }

        if let Some(ref tcp) = self.socket.tcp {
            match tcp.state() {
                TcpState::Closed | TcpState::TimeWait => {
                    mask |= POLLHUP;
                }
                _ => {}
            }
        }

        mask
    }

    fn release(&self, _file: &File) -> Result<(), FsError> {
        // Close the TCP connection
        if self.socket.tcp.is_some() {
            let _ = tcp::tcp_close(&self.socket);
        }
        Ok(())
    }
}

impl FsError {
    /// Convert from errno
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            11 => FsError::WouldBlock,
            _ => FsError::IoError,
        }
    }
}
