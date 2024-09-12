// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides support for QEMU to connect to libspdm
//! to implement and emulate an SPDM responder.
//!

use crate::spdm::TransportLayer;
use crate::*;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use once_cell::sync::OnceCell;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::time::Duration;
use storage_standards::{NvmeCmdStatus, ScsiAsc, SpdmOperationCodes};

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x01;
const SOCKET_SPDM_STORAGE_IF_SEND: u32 = 0x02;
const SOCKET_SPDM_STORAGE_IF_RECV: u32 = 0x03;
const SOCKET_SPDM_STORAGE_ACK_STATUS: u32 = 0x04;

const SOCKET_TRANSPORT_TYPE_MCTP: u32 = 0x01;
const SOCKET_TRANSPORT_TYPE_PCI_DOE: u32 = 0x02;
const SOCKET_TRANSPORT_TYPE_SCSI: u32 = 0x03;
const SOCKET_TRANSPORT_TYPE_NVME: u32 = 0x04;

static mut SEND_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();

static mut CLIENT_CONNECTION: OnceCell<TcpStream> = OnceCell::new();

pub fn qemu_socket_transport_is_valid(spdm_trans: u32) -> bool {
    if !(spdm_trans == SOCKET_TRANSPORT_TYPE_PCI_DOE
        || spdm_trans == SOCKET_TRANSPORT_TYPE_MCTP
        || spdm_trans == SOCKET_TRANSPORT_TYPE_SCSI
        || spdm_trans == SOCKET_TRANSPORT_TYPE_NVME)
    {
        return false;
    }
    true
}

pub fn qemu_socket_spdm_cmd_is_valid(spdm_cmd: u32) -> bool {
    if !(spdm_cmd == SOCKET_SPDM_COMMAND_NORMAL
        || spdm_cmd == SOCKET_SPDM_STORAGE_IF_SEND
        || spdm_cmd == SOCKET_SPDM_STORAGE_IF_RECV
        || spdm_cmd == SOCKET_SPDM_STORAGE_ACK_STATUS)
    {
        return false;
    }
    true
}

pub fn qemu_socket_storage_transport_is_valid(spdm_trans: u32) -> bool {
    if !(spdm_trans == SOCKET_TRANSPORT_TYPE_SCSI || spdm_trans == SOCKET_TRANSPORT_TYPE_NVME) {
        return false;
    }
    true
}

pub fn qemu_socket_storage_cmd_is_valid(spdm_cmd: u32) -> bool {
    if !(spdm_cmd == SOCKET_SPDM_STORAGE_IF_SEND
        || spdm_cmd == SOCKET_SPDM_STORAGE_IF_RECV
        || spdm_cmd == SOCKET_SPDM_STORAGE_ACK_STATUS)
    {
        return false;
    }
    true
}

/// # Summary
///
/// Sends message to the QEMU by writing the
/// `message_ptr` data to the TCP stream used by QEMU. This also writes the
/// additional information expected by QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Number of elements in `message_ptr` to send
/// * `message_ptr`: A pointer to the data buffer to be sent
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_send_message_doe(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    timeout: u64,
) -> u32 {
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let message = message_ptr as *const u8;
    let msg_buf = unsafe { from_raw_parts(message, message_size) };

    // CMA required 32-bit alignment, ensure that we meet that
    // Note we can also pad with 0's if required
    assert!(message_size % 4 == 0);

    if timeout == 0 {
        stream
            .set_write_timeout(None)
            .expect("Couldn't set write timeout");
    } else {
        stream
            .set_write_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set write timeout");
    }

    // QEMU expects additional information regarding the message
    // Read them here so they don't go into the SPDM message buffer.
    let spdm_command: u32 = SOCKET_SPDM_COMMAND_NORMAL;
    let spdm_transport_type: u32 = SOCKET_TRANSPORT_TYPE_PCI_DOE;
    assert_eq!(
        stream.write(&spdm_command.to_be().to_ne_bytes()).unwrap(),
        4
    );
    assert_eq!(
        stream
            .write(&spdm_transport_type.to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    assert_eq!(
        stream
            .write(&(u32::try_from(message_size).unwrap()).to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    stream.write_all(msg_buf).unwrap();
    stream.flush().unwrap();
    CLIENT_CONNECTION.set(stream).unwrap();

    0
}

/// # Summary
///
/// Receives a message from QEMU into buffer pointed to by
/// the `message_ptr`. This may block until the socket has data ready. This will
/// also fetch the additional message data (non-spdm) sent from QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Returns the number of bytes received in this transaction
/// * `message_ptr`: A pointer to a data buffer of a minimum size of
///                 `SEND_RECEIVE_BUFFER_LEN` to capture the received bytes.
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_receive_message_doe(
    _context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let message = *msg_buf_ptr as *mut u8;
    let msg_buf = from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN);

    if timeout == 0 {
        stream
            .set_read_timeout(None)
            .expect("Couldn't set read timeout");
    } else {
        stream
            .set_read_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set read timeout");
    }

    // QEMU sends additional information regarding the message
    // Read them here so they don't go into the SPDM message buffer.
    let mut buf: [u8; 4] = [0; 4];
    // SPDM Command
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    assert_eq!(u32::from_be_bytes(buf), SOCKET_SPDM_COMMAND_NORMAL);
    // Transport Type
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    assert_eq!(u32::from_be_bytes(buf), SOCKET_TRANSPORT_TYPE_PCI_DOE);
    // Receive Size
    assert_eq!(stream.read(&mut buf).unwrap(), 4);

    let mut read_len = stream.read(msg_buf);
    while read_len.is_err() {
        read_len = stream.read(msg_buf);
    }
    let read_len = read_len.unwrap();
    CLIENT_CONNECTION.set(stream).unwrap();

    if read_len == 0 {
        // when read() return 0, the two likely cases are:
        // 1. socket shut down correctly
        // 2. reader has reached its “end of file” and will likely no longer be
        //    able to produce bytes
        warn!("Connection dropped to client, exiting...");
        std::process::exit(0);
    }

    *message_size = read_len;

    0
}

/// # Summary
///
/// Sends message to the QEMU by writing the
/// `message_ptr` data to the TCP stream used by QEMU. This also writes the
/// additional information expected by QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Number of elements in `message_ptr` to send
/// * `message_ptr`: A pointer to the data buffer to be sent
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_send_message_mctp(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    timeout: u64,
) -> u32 {
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let message = message_ptr as *const u8;
    let msg_buf = unsafe { from_raw_parts(message, message_size) };

    if timeout == 0 {
        stream
            .set_write_timeout(None)
            .expect("Couldn't set write timeout");
    } else {
        stream
            .set_write_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set write timeout");
    }

    // QEMU expects additional information regarding the message
    // Read them here so they don't go into the SPDM message buffer.
    let spdm_command: u32 = SOCKET_SPDM_COMMAND_NORMAL;
    let spdm_transport_type: u32 = SOCKET_TRANSPORT_TYPE_MCTP;
    assert_eq!(
        stream.write(&spdm_command.to_be().to_ne_bytes()).unwrap(),
        4
    );
    assert_eq!(
        stream
            .write(&spdm_transport_type.to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    assert_eq!(
        stream
            .write(&(u32::try_from(message_size).unwrap()).to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    stream.write_all(msg_buf).unwrap();
    stream.flush().unwrap();
    CLIENT_CONNECTION.set(stream).unwrap();

    0
}

/// # Summary
///
/// Receives a message from QEMU into buffer pointed to by
/// the `message_ptr`. This may block until the socket has data ready. This will
/// also fetch the additional message data (non-spdm) sent from QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Returns the number of bytes received in this transaction
/// * `message_ptr`: A pointer to a data buffer of a minimum size of
///                 `SEND_RECEIVE_BUFFER_LEN` to capture the received bytes.
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_receive_message_mctp(
    _context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let message = *msg_buf_ptr as *mut u8;
    let msg_buf = from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN);

    if timeout == 0 {
        stream
            .set_read_timeout(None)
            .expect("Couldn't set read timeout");
    } else {
        stream
            .set_read_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set read timeout");
    }

    // QEMU sends additional information regarding the message
    // Read them here so they don't go into the SPDM message buffer.
    let mut buf: [u8; 4] = [0; 4];
    // SPDM Command
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    assert_eq!(u32::from_be_bytes(buf), SOCKET_SPDM_COMMAND_NORMAL);
    // Transport Type
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    assert_eq!(u32::from_be_bytes(buf), SOCKET_TRANSPORT_TYPE_MCTP);
    // Receive Size
    assert_eq!(stream.read(&mut buf).unwrap(), 4);

    let mut read_len = stream.read(msg_buf);
    while read_len.is_err() {
        read_len = stream.read(msg_buf);
    }
    let read_len = read_len.unwrap();
    CLIENT_CONNECTION.set(stream).unwrap();

    if read_len == 0 {
        // when read() return 0, the two likely cases are:
        // 1. socket shut down correctly
        // 2. reader has reached its “end of file” and will likely no longer be
        //    able to produce bytes
        warn!("Connection dropped to client, exiting...");
        std::process::exit(0);
    }

    *message_size = read_len;

    0
}

/// # Summary
///
/// Get the next incoming storage command from the requester through QEMU.
///
/// # Parameter
///
/// * `stream`: Socket stream
/// * `msg_len`: On return, number of bytes received
/// * `msg_in`: Data buffer to capture incoming command (this must be of sufficient length)
///
/// # Returns
///
/// Storage Command, only valid types are IF_RECV/IF_SEND.
pub fn qemu_get_next_storage_cmd(
    stream: &mut TcpStream,
    msg_len: &mut usize,
    msg_in: &mut [u8],
) -> Option<(u32, u32)> {
    debug!("Receiving message");
    // QEMU sends additional information regarding the message
    // Read them here so they don't go into the SPDM message buffer.
    let mut buf: [u8; 4] = [0; 4];

    // SPDM Command
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    let cmd = u32::from_be_bytes(buf);
    assert!(qemu_socket_storage_cmd_is_valid(cmd));

    // Transport Type
    assert_eq!(stream.read(&mut buf).unwrap(), 4);
    let transport = u32::from_be_bytes(buf);
    assert!(qemu_socket_storage_transport_is_valid(transport));

    // Receive Size
    assert_eq!(stream.read(&mut buf).unwrap(), 4);

    let mut read_len = stream.read(msg_in);
    while read_len.is_err() {
        read_len = stream.read(msg_in);
    }
    let read_len = read_len.unwrap();

    debug!("SPDM Transport Receive: {:x?}", &msg_in[..read_len]);

    if read_len == 0 {
        // when read() return 0, the two likely cases are:
        // 1. socket shut down correctly
        // 2. reader has reached its “end of file” and will likely no longer be
        //    able to produce bytes
        warn!("Connection dropped to client, exiting...");
        std::process::exit(0);
    }

    assert!(read_len != 0);

    *msg_len = read_len;

    Some((cmd, transport))
}

/// # Summary
///
/// QEMU waits for a status reply for and IF_RECV/IF_SEND that shall be forwarded
/// back to the requester. This functions acks with `storage_cmd_status`
///
/// # Parameter
///
/// * `stream`: Socket stream
/// * `spdm_cmd`: Type of socket message (QEMU Specific)
/// * `spdm_trans`: SPDM transport type
/// * `storage_cmd_status`: Message status type
///
/// # Returns
///
/// Ok(()) on success
pub fn qemu_socket_storage_ack_msg(
    stream: &mut TcpStream,
    spdm_cmd: u32,
    spdm_trans: u32,
    storage_cmd_status: u16,
) -> Result<(), Errno> {
    if !qemu_socket_spdm_cmd_is_valid(spdm_cmd) {
        return Err(Errno::EINVAL);
    }

    if !qemu_socket_storage_transport_is_valid(spdm_trans) {
        return Err(Errno::EINVAL);
    }

    // Write out the data
    assert_eq!(stream.write(&spdm_cmd.to_be().to_ne_bytes()).unwrap(), 4);

    assert_eq!(stream.write(&spdm_trans.to_be().to_ne_bytes()).unwrap(), 4);

    // We are only writing back the cmd status
    let tx_len = core::mem::size_of::<u16>();
    assert_eq!(
        stream
            .write(&(u32::try_from(tx_len).unwrap()).to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    assert_eq!(
        stream
            .write(&storage_cmd_status.to_be().to_ne_bytes())
            .unwrap(),
        2
    );
    stream.flush().unwrap();

    Ok(())
}

/// # Summary
///
/// Write an response message back to QEMU
///
/// # Parameter
///
/// * `stream`: Socket stream
/// * `spdm_cmd`: Type of socket message (QEMU Specific)
/// * `spdm_trans`: SPDM transport type
/// * `msg_size`: size of message in bytes
/// * `msg_buf`: message data buffer
///
/// # Returns
///
/// Ok(()) on success
/// Err(Errno) on any failures
pub fn qemu_socket_xfer_to_requester(
    stream: &mut TcpStream,
    spdm_cmd: u32,
    spdm_trans: u32,
    msg_size: u32,
    msg_buf: &[u8],
) -> Result<(), Errno> {
    if !qemu_socket_spdm_cmd_is_valid(spdm_cmd) {
        return Err(Errno::EINVAL);
    }

    if !qemu_socket_transport_is_valid(spdm_trans) {
        return Err(Errno::EINVAL);
    }

    if msg_size as usize > msg_buf.len() {
        return Err(Errno::EINVAL);
    }

    // Write out the data
    assert_eq!(stream.write(&spdm_cmd.to_be().to_ne_bytes()).unwrap(), 4);

    assert_eq!(stream.write(&spdm_trans.to_be().to_ne_bytes()).unwrap(), 4);

    assert_eq!(
        stream
            .write(&(u32::try_from(msg_size).unwrap()).to_be().to_ne_bytes())
            .unwrap(),
        4
    );

    stream.write_all(msg_buf).unwrap();
    stream.flush().unwrap();

    Ok(())
}

pub fn qemu_ack_invalid_msg(
    stream: &mut TcpStream,
    spdm_cmd: u32,
    spdm_trans: u32,
) -> Result<(), Errno> {
    if !qemu_socket_storage_transport_is_valid(spdm_cmd) {
        return Err(Errno::EINVAL);
    }

    match spdm_trans {
        SOCKET_TRANSPORT_TYPE_NVME => {
            qemu_socket_storage_ack_msg(
                stream,
                SOCKET_SPDM_STORAGE_ACK_STATUS,
                spdm_trans,
                NvmeCmdStatus::NvmeInvalidFieldInCmd as u16 | NvmeCmdStatus::NvmeDoNotRetry as u16,
            )
            .unwrap();
            warn!(
                "Acked bad message with NVME status: {:?} & {:?} - Code: 0x{:x}",
                NvmeCmdStatus::NvmeInvalidFieldInCmd,
                NvmeCmdStatus::NvmeDoNotRetry,
                NvmeCmdStatus::NvmeInvalidFieldInCmd as u16 | NvmeCmdStatus::NvmeDoNotRetry as u16
            );
        }
        SOCKET_TRANSPORT_TYPE_SCSI => {
            qemu_socket_storage_ack_msg(
                stream,
                SOCKET_SPDM_STORAGE_ACK_STATUS,
                spdm_trans,
                ScsiAsc::InvalidFieldInCdb as u16,
            )
            .unwrap();

            warn!(
                "Acked bad message with SCSI ASC: {:?}",
                ScsiAsc::InvalidFieldInCdb
            );
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// # Summary
///
/// QEMU waits for a status reply for and IF_RECV/IF_SEND that shall be forwarded
/// back to the requester. This functions acks with NVMe CQE Success.
///
/// # Parameter
///
/// * `stream`: Socket stream
/// * `spdm_cmd`: Type of socket message (QEMU Specific)
/// * `spdm_trans`: SPDM transport type
///
/// # Returns
///
/// Ok(()) on success
/// Err(Errno) on any failures
pub fn qemu_ack_valid_msg(
    stream: &mut TcpStream,
    spdm_cmd: u32,
    spdm_trans: u32,
) -> Result<(), Errno> {
    if !qemu_socket_storage_transport_is_valid(spdm_cmd) {
        return Err(Errno::EINVAL);
    }

    match spdm_trans {
        SOCKET_TRANSPORT_TYPE_NVME => {
            qemu_socket_storage_ack_msg(
                stream,
                SOCKET_SPDM_STORAGE_ACK_STATUS,
                spdm_trans,
                NvmeCmdStatus::NvmeSuccess as u16,
            )
            .unwrap();

            debug!(
                "Acked message with NVME status: {:?}",
                NvmeCmdStatus::NvmeSuccess,
            );
        }
        SOCKET_TRANSPORT_TYPE_SCSI => {
            qemu_socket_storage_ack_msg(stream, SOCKET_SPDM_STORAGE_ACK_STATUS, spdm_trans, 0)
                .unwrap();
            debug!("Acked message with status OK");
        }
        _ => unreachable!(),
    }

    //

    Ok(())
}

struct QemuStorageTransportHeaderCompact {
    spsp0_op: u8,
    length: u32,
}

fn qemu_storage_decode_transport_header(
    transport_msg_len: usize,
    transport_msg: &mut [u8],
) -> Result<QemuStorageTransportHeaderCompact, ()> {
    let mut transport_cmd = 0;
    // Allocation length for an IF_RECV, Transfer length for an IF_SEND
    let mut len: u32 = 0;
    let rc = unsafe {
        libspdm_transport_storage_decode_management_cmd(
            transport_msg_len,
            transport_msg.as_mut_ptr() as *mut c_void,
            &mut transport_cmd,
            &mut len,
        )
    };

    if !spdm::LibspdmReturnStatus::libspdm_status_is_success(rc) {
        error!(
            "Malformed Storage Transport header: {:x?}",
            &transport_msg[..transport_msg_len]
        );
        error!("libspdm err: 0x{:X}", rc);
        return Err(());
    }

    Ok(QemuStorageTransportHeaderCompact {
        spsp0_op: transport_cmd,
        length: len,
    })
}

/// # Summary
///
/// Sends message to the QEMU by writing the
/// `message_ptr` data to the TCP stream used by QEMU. This also writes the
/// additional information expected by QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Number of elements in `message_ptr` to send
/// * `message_ptr`: A pointer to the data buffer to be sent
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_send_message_storage(
    _context: *mut c_void,
    libspdm_message_size: usize,
    libspdm_message_ptr: *const c_void,
    timeout: u64,
) -> u32 {
    warn!(
        "about to send a message of len: {}bytes",
        libspdm_message_size
    );
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let message = libspdm_message_ptr as *const u8;
    let libspdm_msg_buf = unsafe { from_raw_parts(message, libspdm_message_size) };

    if timeout == 0 {
        stream
            .set_write_timeout(None)
            .expect("Couldn't set write timeout");
    } else {
        stream
            .set_write_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set write timeout");
    }
    // TODO: Is there a better way to capture incoming commands?
    //       We are using a bunch of memory here.
    let mut incoming_msg: [u8; SEND_RECEIVE_BUFFER_LEN] = [0; SEND_RECEIVE_BUFFER_LEN];
    let mut incoming_msg_len = 0;

    loop {
        let (cmd, trans_type) =
            qemu_get_next_storage_cmd(&mut stream, &mut incoming_msg_len, &mut incoming_msg)
                .unwrap();
        let hdr = qemu_storage_decode_transport_header(incoming_msg_len, &mut incoming_msg);
        if hdr.is_err() {
            qemu_ack_invalid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                .expect("Failed to ack message");
            continue;
        }
        let hdr = hdr.unwrap();
        match cmd {
            SOCKET_SPDM_STORAGE_IF_SEND => {
                // We have an SPDM response to send, but the requester has sent
                // us another IF_SEND instead of receiving our pending response
                // with IF_RECV. The only valid spdm_storage_operations are
                // discovery and pending_info at in this context.

                // Ack the incoming message if valid
                match SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap() {
                    SpdmOperationCodes::SpdmStorageDiscovery => {
                        debug!("Storage Transport Discovery Command - Nothing to do (IF_SEND)");
                    }
                    SpdmOperationCodes::SpdmStoragePendingInfo => {
                        debug!("Handling Storage Transport Pending Info Command - Nothing to do (IF_SEND)");
                        debug!(
                            "    - Pending response length: {:} bytes",
                            libspdm_message_size
                        );
                    }
                    SpdmOperationCodes::SpdmStorageMessage
                    | SpdmOperationCodes::SpdmStorageSecMessage => {
                        error!(
                            "Unexpected IF_SEND with {:?}",
                            SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap()
                        );
                        qemu_ack_invalid_msg(
                            &mut stream,
                            SOCKET_SPDM_STORAGE_ACK_STATUS,
                            trans_type,
                        )
                        .expect("Failed to ack message");
                        continue;
                    }
                }
                // Message was valid, but we had no work to do
                qemu_ack_valid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                    .expect("Failed to ack message");
            }
            SOCKET_SPDM_STORAGE_IF_RECV => {
                // This IF_RECV could be for the SPDM response message or a transport
                // command
                if incoming_msg_len < LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize {
                    error!("Malformed transport header for IF_RECV!");
                    qemu_ack_invalid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                        .expect("Failed to ack message");
                    continue;
                }

                let mut transport_msg_len = 32;
                let mut transport_msg: [u8; 32] = [0; 32];

                match SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap() {
                    SpdmOperationCodes::SpdmStorageDiscovery => {
                        debug!("Handling Storage Transport Discovery Command (IF_RECV)");
                        assert!(spdm::LibspdmReturnStatus::libspdm_status_is_success(
                            libspdm_transport_storage_encode_discovery_response(
                                &mut transport_msg_len,
                                transport_msg.as_mut_ptr() as *mut c_void,
                            )
                        ));
                    }
                    SpdmOperationCodes::SpdmStoragePendingInfo => {
                        debug!("Handling Storage Transport Pending Info Command (IF_RECV)");
                        debug!(
                            "    - Pending response length: {:} bytes",
                            libspdm_message_size
                        );
                        assert!(spdm::LibspdmReturnStatus::libspdm_status_is_success(
                            libspdm_transport_storage_encode_pending_info_response(
                                &mut transport_msg_len,
                                transport_msg.as_mut_ptr() as *mut c_void,
                                true,
                                u32::try_from(libspdm_message_size).unwrap(),
                            )
                        ));
                    }
                    SpdmOperationCodes::SpdmStorageMessage
                    | SpdmOperationCodes::SpdmStorageSecMessage => {
                        if (hdr.length as usize) < libspdm_message_size {
                            error!(
                                "Requester allocation length too small to receive {:?} message.  Minimum required {:}, Got {:}",
                                SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap(),
                                libspdm_message_size,
                                hdr.length
                            );
                            qemu_ack_valid_msg(
                                &mut stream,
                                SOCKET_SPDM_STORAGE_ACK_STATUS,
                                trans_type,
                            )
                            .expect("Failed to ack message");
                            continue;
                        }
                        qemu_ack_valid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                            .expect("Failed to ack message");

                        qemu_socket_xfer_to_requester(
                            &mut stream,
                            SOCKET_SPDM_STORAGE_IF_RECV,
                            trans_type,
                            u32::try_from(libspdm_message_size).unwrap(),
                            &libspdm_msg_buf,
                        )
                        .expect("failed to write response to requester");

                        debug!("SPDM Send: {:x?}", libspdm_msg_buf);
                        break;
                    }
                }

                assert!(transport_msg_len <= transport_msg.len());

                // A valid transport command request, let's send the response
                // generated
                qemu_ack_valid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                    .expect("Failed to ack message");

                qemu_socket_xfer_to_requester(
                    &mut stream,
                    SOCKET_SPDM_STORAGE_IF_RECV,
                    trans_type,
                    u32::try_from(transport_msg_len).unwrap(),
                    &transport_msg[..transport_msg_len],
                )
                .expect("failed to write response to requester");
            }
            _ => unreachable!("Undefined qemu transport management command"),
        }
    }

    CLIENT_CONNECTION.set(stream).unwrap();
    0
}

/// # Summary
///
/// Receives a message from QEMU into buffer pointed to by
/// the `message_ptr`. This may block until the socket has data ready. This will
/// also fetch the additional message data (non-spdm) sent from QEMU.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Returns the number of bytes received in this transaction
/// * `message_ptr`: A pointer to a data buffer of a minimum size of
///                 `SEND_RECEIVE_BUFFER_LEN` to capture the received bytes.
/// * `timeout`: Transaction timeout
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the buffers passed in are invalid or for any other point of
/// failure.
#[no_mangle]
unsafe extern "C" fn qemu_receive_message_storage(
    _context: *mut c_void,
    libspdm_message_size: *mut usize,
    libspdm_msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let mut stream = CLIENT_CONNECTION.take().unwrap();
    let libspdm_message = *libspdm_msg_buf_ptr as *mut u8;
    // We are using this to cache any incoming temporary data,
    // When an SPDM message is received, it will be overwritten with that data
    // before being passed back to libspdm.
    let mut libspdm_message_buf = from_raw_parts_mut(libspdm_message, SEND_RECEIVE_BUFFER_LEN);

    if timeout == 0 {
        stream
            .set_read_timeout(None)
            .expect("Couldn't set read timeout");
    } else {
        stream
            .set_read_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set read timeout");
    }

    let mut incoming_msg_len = 0;

    loop {
        let (cmd, trans_type) =
            qemu_get_next_storage_cmd(&mut stream, &mut incoming_msg_len, &mut libspdm_message_buf)
                .unwrap();
        let hdr = qemu_storage_decode_transport_header(incoming_msg_len, &mut libspdm_message_buf);
        if hdr.is_err() {
            qemu_ack_invalid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                .expect("Failed to ack message");
            continue;
        }
        let hdr = hdr.unwrap();
        match cmd {
            SOCKET_SPDM_STORAGE_IF_SEND => {
                // Contextually, we are expecting an IF_SEND with a storage/secure msg.
                // But we could also get discovery/pending_info here.
                qemu_ack_valid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                    .expect("Failed to ack message");

                match SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap() {
                    SpdmOperationCodes::SpdmStorageDiscovery => {
                        debug!("Storage Transport Discovery Command - Nothing to do (IF_SEND)");
                        continue;
                    }
                    SpdmOperationCodes::SpdmStoragePendingInfo => {
                        debug!("Handling Storage Transport Pending Info Command - Nothing to do (IF_SEND)");
                        debug!("    - No pending response!");
                        continue;
                    }
                    SpdmOperationCodes::SpdmStorageMessage
                    | SpdmOperationCodes::SpdmStorageSecMessage => {
                        // Received an actual SPDM message
                        *libspdm_message_size = hdr.length as usize;
                        info!(
                            "SPDM Received {:?}: {:x?}",
                            SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap(),
                            &libspdm_message_buf[..(hdr.length as usize)]
                        );
                        // The data was received into the memory allocated by libspdm
                        // no more work to do.
                        break;
                    }
                };
            }
            SOCKET_SPDM_STORAGE_IF_RECV => {
                // We have no data to return in this context, an IF_RECV should
                // only mean that it was a transport Discovery/Pending Info
                // command.
                let mut transport_msg_len: usize = 32;
                let mut transport_msg: [u8; 32] = [0; 32];

                if (hdr.length as usize) < transport_msg_len {
                    error!(
                        "Requester allocation length too small to receive {:?} message. Minimum required {:?}, Got {:?}",
                        SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap(),
                        transport_msg_len,
                        hdr.length
                    );
                    qemu_ack_invalid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                        .expect("Failed to ack message");
                    continue;
                }

                let rc = match SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap() {
                    SpdmOperationCodes::SpdmStorageDiscovery => {
                        debug!("Handling Storage Transport Discovery Command (IF_RECV)");
                        libspdm_transport_storage_encode_discovery_response(
                            &mut transport_msg_len,
                            transport_msg.as_mut_ptr() as *mut c_void,
                        )
                    }
                    SpdmOperationCodes::SpdmStoragePendingInfo => {
                        debug!("Handling Storage Transport Pending Info Command (IF_RECV)");
                        debug!("    - No pending response!");
                        libspdm_transport_storage_encode_pending_info_response(
                            &mut transport_msg_len,
                            transport_msg.as_mut_ptr() as *mut c_void,
                            false,
                            0,
                        )
                    }
                    _ => {
                        error!(
                            "Unexpected IF_RECV with {:?}",
                            SpdmOperationCodes::try_from(hdr.spsp0_op).unwrap()
                        );
                        qemu_ack_invalid_msg(
                            &mut stream,
                            SOCKET_SPDM_STORAGE_ACK_STATUS,
                            trans_type,
                        )
                        .expect("Failed to ack message");
                        continue;
                    }
                };

                if !spdm::LibspdmReturnStatus::libspdm_status_is_success(rc) {
                    error!(
                        "Failed to generate transport response, libspdm err: {:x}",
                        rc
                    );
                    qemu_ack_invalid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                        .expect("Failed to ack message");
                    continue;
                }

                assert!(transport_msg_len <= transport_msg.len());

                // A valid transport command request, let's send the response
                // generated
                qemu_ack_valid_msg(&mut stream, SOCKET_SPDM_STORAGE_ACK_STATUS, trans_type)
                    .expect("Failed to ack message");

                qemu_socket_xfer_to_requester(
                    &mut stream,
                    SOCKET_SPDM_STORAGE_IF_RECV,
                    trans_type,
                    u32::try_from(transport_msg_len).unwrap(),
                    &transport_msg[..transport_msg_len],
                )
                .expect("Failed to write transport response to requester");
            }
            _ => unreachable!("Undefined qemu transport management command"),
        }
    }

    CLIENT_CONNECTION.set(stream).unwrap();
    0
}

/// # Summary
///
/// A helper function to capture the SEND_BUFFER into `msg_buf_ptr`
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `max_msg_size`: Returns the length of the sender buffer
/// * `msg_buf_ptr`: Returns a pointer to the sender buffer (mutable)
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the SEND_BUFFER is not available
#[no_mangle]
unsafe extern "C" fn qemu_acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = SEND_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

    0
}

/// # Summary
///
/// A helper function to reset the SEND_BUFFER from `msg_buf_ptr`
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `msg_buf_ptr`: A pointer representing the sender buffer.
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the `msg_buf_ptr` is invalid or has less elements
/// than `SEND_RECEIVE_BUFFER_LEN`
#[no_mangle]
unsafe extern "C" fn qemu_release_sender_buffer(_context: *mut c_void, msg_buf_ptr: *const c_void) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    SEND_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

/// # Summary
///
/// A helper function to capture the RECEIVE_BUFFER into `msg_buf_ptr`
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `max_msg_size`: Returns the length of the receiver buffer
/// * `msg_buf_ptr`: Returns a pointer to the receiver buffer (mutable)
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the SEND_BUFFER is not available
#[no_mangle]
unsafe extern "C" fn qemu_acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = RECEIVE_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

    0
}

/// # Summary
///
/// A helper function to reset the RECEIVE_BUFFER from `msg_buf_ptr`
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `msg_buf_ptr`: A pointer representing the receiver buffer.
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the `msg_buf_ptr` is invalid or has less elements
/// than `SEND_RECEIVE_BUFFER_LEN`
#[no_mangle]
unsafe extern "C" fn qemu_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    RECEIVE_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

/// # Summary
///
/// Registers the SPDM `context` for a `qemu_server` backend.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// Ok(()) on success
pub fn register_device(
    context: *mut c_void,
    port: u16,
    transport: TransportLayer,
) -> Result<(), ()> {
    let buffer_send = [0; SEND_RECEIVE_BUFFER_LEN];
    let buffer_receive = [0; SEND_RECEIVE_BUFFER_LEN];
    let ip = "127.0.0.1";
    let addr = format!("{}:{}", ip, port);

    debug!("Setting up a server on [port: {}, ip: {}]", port, ip);

    let listener = match TcpListener::bind(addr) {
        Err(_) => {
            error!("Failed to bind");
            return Err(());
        }
        Ok(stream) => stream,
    };

    info!("Server started, waiting for qemu on port: {}", port);
    for client in listener.incoming() {
        match client {
            Ok(client_conn) => {
                info!(
                    "New connection: {}",
                    client_conn.peer_addr().map_err(|e| {
                        error!("Failed to get socket address: {e:?}");
                        ()
                    })?
                );
                unsafe {
                    CLIENT_CONNECTION.set(client_conn).map_err(|e| {
                        error!("Failed to set/save client connection {e:?}");
                        ()
                    })?;
                }
                break;
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }

    unsafe {
        SEND_BUFFER.set(buffer_send).map_err(|e| {
            error!("Failed to set send buffer: {e:?}");
            ()
        })?;
        RECEIVE_BUFFER.set(buffer_receive).map_err(|e| {
            error!("Failed to receive buffer: {e:?}");
            ()
        })?;

        match transport {
            TransportLayer::Doe => {
                libspdm_register_device_io_func(
                    context,
                    Some(qemu_send_message_doe),
                    Some(qemu_receive_message_doe),
                );
            }
            TransportLayer::Mctp => {
                libspdm_register_device_io_func(
                    context,
                    Some(qemu_send_message_mctp),
                    Some(qemu_receive_message_mctp),
                );
            }
            TransportLayer::Storage => {
                libspdm_register_device_io_func(
                    context,
                    Some(qemu_send_message_storage),
                    Some(qemu_receive_message_storage),
                );
            }
        }

        libspdm_register_device_buffer_func(
            context,
            SEND_RECEIVE_BUFFER_LEN as u32,
            SEND_RECEIVE_BUFFER_LEN as u32,
            Some(qemu_acquire_sender_buffer),
            Some(qemu_release_sender_buffer),
            Some(qemu_acquire_receiver_buffer),
            Some(qemu_release_receiver_buffer),
        );
    }

    Ok(())
}
