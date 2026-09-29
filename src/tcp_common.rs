// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2026, Western Digital Corporation or its affiliates.

use core::ffi::c_void;
use libmctp::mctp_traits::SMBusMCTPRequestResponse;
use libmctp::smbus::MCTPSMBusContext;
use libmctp::vendor_packets::VendorIDFormat;
use libspdm::libspdm_rs;
use libspdm::spdm::{LibspdmReturnStatus, TransportLayer};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ptr;

/// TCP Data Section header length (DSP0287)
const SPDM_TCP_HEADER_LEN: usize = 4;

/// Number of bytes in a PCI DOE data object header:
/// vendor_id (u16) + data_object_type (u8) + reserved (u8) + length (u32).
const DOE_HEADER_LEN: usize = 8;

/// Number of bytes in the SMBus binding header (including the MCTP
/// transport header) that precedes the MCTP message payload:
const MCTP_HEADER_LEN: usize = 8;

/// The number of bytes the SMBus binding appends to a message:
/// `MCTP_HEADER_LEN` plus a trailing PEC byte.
const MCTP_SMBUS_OVERHEAD: usize = MCTP_HEADER_LEN + 1;

/// Maximum SPDM message size when transmitting MCTP over TCP.
pub const MCTP_SPDM_MSG_LEN: usize = 240;

// These are just made up to create MCTPSMBusContext, they aren't
// actually important when sending the data over TCP.
const MCTP_SOURCE_ID: u8 = 0x23;
const MCTP_TARGET_ID: u8 = 0x22;
const MCTP_MSG_TYPES: [u8; 0] = [];
const MCTP_VENDOR_IDS: [VendorIDFormat; 1] = [VendorIDFormat {
    // PCI Vendor ID
    format: 0x00,
    // PCI VID
    data: 0x1234,
    // Extra data
    numeric_value: 0xAB,
}];

/// The maximum message size in PCI DOE data object length words (DW),
/// indicated by a length value of 0.
const DOE_MAX_LENGTH_DW: usize = 1 << 18;

/// State of the TCP device. Stored as part of `libspdm_context_t`
/// in the `app_context_data_ptr` and accessed via
/// `LIBSPDM_DATA_APP_CONTEXT_DATA`
///
/// The Rust attach_state() and state_from_context() functions save
/// and restore the state.
#[derive(Default)]
pub struct TcpDeviceState {
    /// The stream connected to the peer.
    pub stream: Option<TcpStream>,
    /// The accepted connection listener, used by the server to accept new
    /// connections if the client drops.
    pub listener: Option<TcpListener>,
    /// Server only: if the client drops, keep the server alive.
    pub server_persist: bool,
    /// The transport protocol used to frame the messages on the wire.
    pub transport: Option<TransportLayer>,
}

/// # Summary
///
/// Attaches the `TcpDeviceState` to the SPDM `context` via libspdm's
/// `app_context_data_ptr`, taking ownership of `state`.
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `state`: The `TcpDeviceState` to attach
///
/// # Panics
///
/// Panics if the state could not be attached to the SPDM context.
pub fn attach_state(context: *mut c_void, state: Box<TcpDeviceState>) {
    let parameter = libspdm_rs::libspdm_data_parameter_t::new_local(0);
    let state_ptr = Box::into_raw(state) as *mut c_void;

    let ret = unsafe {
        libspdm_rs::libspdm_set_data(
            context,
            libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_APP_CONTEXT_DATA,
            &parameter as *const libspdm_rs::libspdm_data_parameter_t,
            &state_ptr as *const *mut c_void as *const c_void,
            core::mem::size_of::<*mut c_void>(),
        )
    };

    assert!(
        !LibspdmReturnStatus::libspdm_status_is_error(ret),
        "Failed to attach TCP device state to the SPDM context"
    );
}

/// # Summary
///
/// Get the `TcpDeviceState` attached to the SPDM `context`, see
/// `attach_state()` for details.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// A pointer to the `TcpDeviceState`
///
/// # Panics
///
/// Panics if no `TcpDeviceState` is attached to the SPDM context.
pub fn state_from_context(context: *mut c_void) -> *mut TcpDeviceState {
    let parameter = libspdm_rs::libspdm_data_parameter_t::new_local(0);
    let mut state_ptr: *mut c_void = ptr::null_mut();
    let mut data_size = core::mem::size_of::<*mut c_void>();

    let ret = unsafe {
        libspdm_rs::libspdm_get_data(
            context,
            libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_APP_CONTEXT_DATA,
            &parameter as *const libspdm_rs::libspdm_data_parameter_t,
            &mut state_ptr as *mut *mut c_void as *mut c_void,
            &mut data_size,
        )
    };

    assert!(
        !LibspdmReturnStatus::libspdm_status_is_error(ret),
        "Failed to get TCP device state from the SPDM context"
    );
    assert!(!state_ptr.is_null(), "No TCP device state in SPDM context");

    state_ptr as *mut TcpDeviceState
}

/// # Summary
///
/// Whether the error means that the peer went away, as opposed to a
/// programmatic error.
fn connection_dropped(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// # Summary
///
/// Reads exactly `buf.len()` bytes from `stream`. This may block until
/// the buffer is filled, retrying interrupted reads and read timeout
/// expiry.
///
/// # Returns
///
/// The number of bytes read. This will be less than `buf.len()` only if
/// the peer closed the connection.
fn read_full(mut stream: &TcpStream, buf: &mut [u8]) -> usize {
    let mut received = 0;

    while received < buf.len() {
        match stream.read(&mut buf[received..]) {
            // Peer closed the connection
            Ok(0) => break,
            Ok(n) => received += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            // The peer went away, tell the caller what we got
            Err(e) if connection_dropped(&e) => break,
            Err(e) => panic!("Failed to read from TCP stream: {:?}", e),
        }
    }

    received
}

/// # Summary
///
/// Reads a single chunk of a message from `stream` into `buf`, retrying
/// interrupted reads and read timeout expiry.
///
/// # Returns
///
/// The number of bytes read, a value of 0 indicates that the peer closed
/// the connection. Note that this can return a partial message.
fn read_partial(mut stream: &TcpStream, buf: &mut [u8]) -> usize {
    loop {
        match stream.read(buf) {
            Ok(n) => return n,
            Err(e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            // The peer went away
            Err(e) if connection_dropped(&e) => return 0,
            Err(e) => panic!("Failed to read from TCP stream: {:?}", e),
        }
    }
}

/// # Summary
///
/// Reads a complete SPDM over TCP message (DSP0287) framed message from
/// `stream` into `buf`. This may block until the entire message has been
/// received.
///
/// # Returns
///
/// The size of the message in bytes (binding header + payload). A return
/// value of 0 indicates that the peer closed the connection before the
/// entire message was received.
///
/// # Panics
///
/// Panics if the message is malformed or to large for `buf`.
fn read_spdm_tcp_message(stream: &TcpStream, buf: &mut [u8]) -> usize {
    // Read the binding header first, it tells us the message size
    let header_len = read_full(stream, &mut buf[..SPDM_TCP_HEADER_LEN]);
    if header_len < SPDM_TCP_HEADER_LEN {
        // The connection was closed before the whole header arrived
        return 0;
    }

    // `payload_length` covers everything after the header
    let payload_len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let message_len = payload_len + SPDM_TCP_HEADER_LEN;
    assert!(
        message_len >= SPDM_TCP_HEADER_LEN,
        "malformed SPDM over TCP (DSP0287) binding header"
    );
    assert!(message_len <= buf.len(), "message larger than buffer");

    let rest_len = read_full(stream, &mut buf[SPDM_TCP_HEADER_LEN..message_len]);
    if rest_len != message_len - SPDM_TCP_HEADER_LEN {
        // The connection was closed before the whole message arrived
        return 0;
    }

    message_len
}

/// # Summary
///
/// Reads a complete PCI DOE framed message from `stream` into `buf`. This
/// may block until the entire message has been received.
///
/// # Returns
///
/// The size of the message in bytes (data object header + payload). A
/// return value of 0 indicates that the peer closed the connection before
/// the entire message was received.
///
/// # Panics
///
/// Panics if the message is malformed or to large for `buf`.
fn read_doe_message(stream: &TcpStream, buf: &mut [u8]) -> usize {
    // Read the data object header first, it tells us the message size
    let header_len = read_full(stream, &mut buf[..DOE_HEADER_LEN]);
    if header_len < DOE_HEADER_LEN {
        // The connection was closed before the whole header arrived
        return 0;
    }

    // The length is stored in DW (4 byte words) and includes the header
    // itself (2 DW). A value of 0 indicates the maximum size of 2^18 DWs.
    let length_dw = (u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) & 0x3_FFFF) as usize;
    let message_len = if length_dw == 0 {
        DOE_MAX_LENGTH_DW * 4
    } else {
        length_dw * 4
    };
    assert!(message_len >= DOE_HEADER_LEN, "malformed PCI DOE header");
    assert!(message_len <= buf.len(), "message larger than buffer");

    let rest_len = read_full(stream, &mut buf[DOE_HEADER_LEN..message_len]);
    if rest_len != message_len - DOE_HEADER_LEN {
        // The connection was closed before the whole message arrived
        return 0;
    }

    message_len
}

/// # Summary
///
/// Reads a complete MCTP message from `stream` into `buf`. This may block
/// until the entire message has been received.
///
/// # Returns
///
/// The size of the message in bytes (MCTP header + payload). A return
/// value of 0 indicates that the peer closed the connection before the
/// entire message was received.
///
/// # Panics
///
/// Panics if the message is malformed or to large for `buf`.
fn read_mctp_message(stream: &TcpStream, buf: &mut [u8]) -> usize {
    let ctx = MCTPSMBusContext::new(MCTP_SOURCE_ID, &MCTP_MSG_TYPES, &MCTP_VENDOR_IDS);

    // Read the SMBus header
    let header_len = read_full(stream, &mut buf[..MCTP_HEADER_LEN]);
    if header_len < MCTP_HEADER_LEN {
        // The connection was closed before the whole header arrived
        return 0;
    }

    // Calculate the total length of the packet
    let packet_len = ctx.get_length(buf).unwrap();
    assert!(packet_len <= buf.len(), "message larger than buffer");

    // Read the rest of the packet
    let rest_len = read_full(stream, &mut buf[MCTP_HEADER_LEN..packet_len]);
    if rest_len != packet_len - MCTP_HEADER_LEN {
        // The connection was closed before the whole message arrived
        return 0;
    }

    // Decode the packet
    let (_msg_type, payload) = ctx.decode_packet(&buf[..packet_len]).unwrap();
    // Prepend the message type to keep libspdm happy.
    let message_len = payload.len() + 1;
    buf.copy_within(MCTP_HEADER_LEN..(MCTP_HEADER_LEN + message_len), 0);

    message_len
}

/// # Summary
///
/// Reads a complete message from `stream` into `buf`, framed based on the
/// `transport` protocol in use. This may block until the entire message
/// has been received.
///
/// # Returns
///
/// The size of the message in bytes. A return value of 0 indicates that
/// the peer closed the connection before a new message was received.
///
/// # Panics
///
/// Panics if the message is malformed, to large for `buf` or if the
/// connection is closed mid-message.
pub fn read_message(stream: &TcpStream, buf: &mut [u8], transport: TransportLayer) -> usize {
    match transport {
        TransportLayer::Tcp => read_spdm_tcp_message(stream, buf),
        TransportLayer::Doe => read_doe_message(stream, buf),
        TransportLayer::Mctp => read_mctp_message(stream, buf),
        // SPDM storage binding messages don't carry obvious size information
        TransportLayer::Storage => read_partial(stream, buf),
    }
}

/// # Summary
///
/// Writes the libspdm transport message `msg_buf` to `stream`, framing it
/// based on the `transport` protocol in use.
///
/// TCP, PCI DOE and SPDM storage binding messages are already
/// framed by libspdm, so this function will only make changes for MCTP messages.
///
/// # Panics
///
/// Panics if the message could not be framed or written to the stream.
pub fn write_message(stream: &mut TcpStream, msg_buf: &[u8], transport: TransportLayer) {
    match transport {
        TransportLayer::Mctp => {
            let ctx = MCTPSMBusContext::new(MCTP_SOURCE_ID, &MCTP_MSG_TYPES, &MCTP_VENDOR_IDS);

            let message_type = match libmctp::MessageType::from(msg_buf[0]) {
                libmctp::MessageType::SpdmOverMctp => libmctp::MessageType::SpdmOverMctp,
                libmctp::MessageType::SecuredMessages => libmctp::MessageType::SecuredMessages,
                _ => unreachable!("unexpected mctp message type"),
            };

            // Wrap the libspdm MCTP message (message type + message data) in
            // the SMBus binding
            let mut packet = vec![0; msg_buf.len() + MCTP_SMBUS_OVERHEAD];
            let packet_len = ctx
                .get_request()
                .generate_spdm_msg_packet_bytes(
                    MCTP_TARGET_ID,
                    message_type,
                    &None,
                    &msg_buf[1..],
                    &mut packet,
                )
                .unwrap();
            assert!(packet_len <= packet.len());

            stream.write_all(&packet[..packet_len]).unwrap();
        }
        TransportLayer::Doe | TransportLayer::Tcp | TransportLayer::Storage => {
            // libspdm will add the complete headers for:
            // DOE -> pci_doe_data_object_header_t
            // TCP -> spdm_tcp_binding_header_t
            stream.write_all(msg_buf).unwrap();
        }
    }

    stream.flush().unwrap();
}
