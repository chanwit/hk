//! TCP Input Processing
//!
//! This module handles incoming TCP segments.

use alloc::sync::Arc;

use crate::net::ipv4::Ipv4Addr;
use crate::net::skb::SkBuff;
use crate::net::socket::Socket;
use crate::net::tcp::{
    TCP_HLEN_MIN, TcpFourTuple, TcpHdr, TcpState, flags, tcp_checksum, tcp_lookup_connection,
};

/// Receive a TCP segment
///
/// Called by IP layer after demultiplexing.
pub fn tcp_rcv(skb: SkBuff) {
    if skb.len() < TCP_HLEN_MIN {
        return;
    }

    // Get IP addresses from skb
    let saddr = match skb.saddr {
        Some(a) => a,
        None => return,
    };
    let daddr = match skb.daddr {
        Some(a) => a,
        None => return,
    };

    // Parse TCP header
    let hdr = unsafe { &*(skb.data().as_ptr() as *const TcpHdr) };
    let data_offset = hdr.data_offset();

    if data_offset < TCP_HLEN_MIN || data_offset > skb.len() {
        return;
    }

    // Verify checksum
    let checksum = tcp_checksum(saddr, daddr, skb.data());
    if checksum != 0 {
        return;
    }

    // Look up connection
    let tuple = TcpFourTuple {
        local_addr: daddr,
        local_port: hdr.dest_port(),
        remote_addr: saddr,
        remote_port: hdr.source_port(),
    };

    let socket = match tcp_lookup_connection(&tuple) {
        Some(s) => s,
        None => {
            // No connection - send RST if not RST
            if !hdr.has_flag(flags::RST) {
                // TODO: send RST
            }
            return;
        }
    };

    let tcp = match socket.tcp.as_ref() {
        Some(t) => t,
        None => return,
    };

    // Get payload
    let payload = &skb.data()[data_offset..];
    let _payload_len = payload.len();

    // Process based on state
    match tcp.state() {
        TcpState::SynSent => {
            process_syn_sent(&socket, hdr, payload);
        }
        TcpState::Established => {
            process_established(&socket, hdr, payload, saddr);
        }
        TcpState::FinWait1 => {
            process_fin_wait1(&socket, hdr, payload);
        }
        TcpState::FinWait2 => {
            process_fin_wait2(&socket, hdr, payload);
        }
        TcpState::CloseWait => {
            process_close_wait(&socket, hdr);
        }
        TcpState::LastAck => {
            process_last_ack(&socket, hdr);
        }
        TcpState::TimeWait => {
            // In TIME_WAIT, just ACK and restart timer
            if hdr.has_flag(flags::FIN) {
                // Re-ACK the FIN
            }
        }
        _ => {}
    }
}

/// Process segment in SYN-SENT state
fn process_syn_sent(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Expecting SYN-ACK
    if hdr.has_flag(flags::ACK) {
        // Check ACK validity
        let ack = hdr.ack_seq();
        let snd_nxt = tcp.snd_nxt();
        if ack != snd_nxt {
            // Invalid ACK
            if hdr.has_flag(flags::RST) {
                return;
            }
            // TODO: send RST
            return;
        }

        if hdr.has_flag(flags::RST) {
            // Connection refused
            tcp.set_state(TcpState::Closed);
            socket.set_error(-crate::net::libc::ECONNREFUSED);
            socket.wake_connect();
            return;
        }

        if hdr.has_flag(flags::SYN) {
            // SYN-ACK received - connection established
            tcp.irs
                .store(hdr.seq(), core::sync::atomic::Ordering::Release);
            tcp.set_rcv_nxt(hdr.seq().wrapping_add(1));
            tcp.snd_una
                .store(ack, core::sync::atomic::Ordering::Release);
            tcp.snd_wnd
                .store(hdr.window() as u32, core::sync::atomic::Ordering::Release);

            tcp.set_state(TcpState::Established);

            // Send ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);

            // Wake up connect() caller
            socket.wake_connect();

            crate::printkln!("tcp: connection established");
        }
    }
}

/// Process segment in ESTABLISHED state
fn process_established(socket: &Arc<Socket>, hdr: &TcpHdr, payload: &[u8], _saddr: Ipv4Addr) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Check RST
    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.set_error(-crate::net::libc::ECONNRESET);
        socket.wake_all();
        return;
    }

    // Process ACK
    if hdr.has_flag(flags::ACK) {
        let ack = hdr.ack_seq();
        let snd_una = tcp.snd_una.load(core::sync::atomic::Ordering::Acquire);
        let snd_nxt = tcp.snd_nxt();

        // Valid ACK: snd_una < ack <= snd_nxt
        if ack.wrapping_sub(snd_una) <= snd_nxt.wrapping_sub(snd_una) {
            tcp.snd_una
                .store(ack, core::sync::atomic::Ordering::Release);

            // Remove acknowledged segments from retransmit queue
            let mut rtx_queue = tcp.retransmit_queue.lock();
            rtx_queue.retain(|seg| seg.seq.wrapping_add(seg.data.len() as u32) > ack);

            // Update send window
            tcp.snd_wnd
                .store(hdr.window() as u32, core::sync::atomic::Ordering::Release);

            // Wake writers if space available
            socket.wake_tx();
        }
    }

    // Process data
    if !payload.is_empty() {
        let seq = hdr.seq();
        let rcv_nxt = tcp.rcv_nxt();

        if seq == rcv_nxt {
            // In-order data
            socket.deliver_data(payload);
            tcp.set_rcv_nxt(rcv_nxt.wrapping_add(payload.len() as u32));

            // Check for out-of-order data that's now in order
            // TODO: process OOO queue

            // Send ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);

            // Wake readers
            socket.wake_rx();
        } else if seq.wrapping_sub(rcv_nxt) < 0x80000000 {
            // Future data - queue for later
            let mut ooo = tcp.ooo_queue.lock();
            ooo.insert(seq, payload.to_vec());

            // Send duplicate ACK
            let _ = crate::net::tcp_output::tcp_send_ack(socket);
        }
        // Else: old data, ignore
    }

    // Process FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        tcp.set_state(TcpState::CloseWait);

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);

        // Signal EOF to readers
        socket.set_eof();
        socket.wake_rx();
    }
}

/// Process segment in FIN-WAIT-1 state
fn process_fin_wait1(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Check RST
    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
        return;
    }

    // Process ACK of our FIN
    if hdr.has_flag(flags::ACK) {
        let ack = hdr.ack_seq();
        let snd_nxt = tcp.snd_nxt();

        if ack == snd_nxt {
            // Our FIN was ACKed
            tcp.set_state(TcpState::FinWait2);
        }
    }

    // Process their FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        if tcp.state() == TcpState::FinWait2 {
            tcp.set_state(TcpState::TimeWait);
        } else {
            tcp.set_state(TcpState::Closing);
        }

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);
        socket.set_eof();
        socket.wake_rx();
    }
}

/// Process segment in FIN-WAIT-2 state
fn process_fin_wait2(socket: &Arc<Socket>, hdr: &TcpHdr, _payload: &[u8]) {
    let tcp = socket.tcp.as_ref().unwrap();

    // Process FIN
    if hdr.has_flag(flags::FIN) {
        let rcv_nxt = tcp.rcv_nxt();
        tcp.set_rcv_nxt(rcv_nxt.wrapping_add(1));

        tcp.set_state(TcpState::TimeWait);

        // Send ACK for FIN
        let _ = crate::net::tcp_output::tcp_send_ack(socket);
        socket.set_eof();
        socket.wake_all();
    }
}

/// Process segment in CLOSE-WAIT state
fn process_close_wait(socket: &Arc<Socket>, hdr: &TcpHdr) {
    let tcp = socket.tcp.as_ref().unwrap();

    if hdr.has_flag(flags::RST) {
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
    }
}

/// Process segment in LAST-ACK state
fn process_last_ack(socket: &Arc<Socket>, hdr: &TcpHdr) {
    let tcp = socket.tcp.as_ref().unwrap();

    if hdr.has_flag(flags::ACK) {
        // Our FIN was ACKed
        tcp.set_state(TcpState::Closed);
        socket.wake_all();
    }
}
