// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides support for QEMU to connect to libspdm
//! to implement and emulate an SPDM responder.
//!

use crate::io_buffers;
use crate::spdm::TransportLayer;
use crate::*;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use once_cell::sync::Lazy;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Mutex;
use std::time::Duration;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

const SOCKET_SPDM_COMMAND_NORMAL: u32 = 0x01;

const SOCKET_TRANSPORT_TYPE_MCTP: u32 = 0x01;
const SOCKET_TRANSPORT_TYPE_PCI_DOE: u32 = 0x02;

static CLIENT_CONNECTION: Lazy<Mutex<Option<TcpStream>>> = Lazy::new(|| Mutex::new(None));

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
    match &mut *CLIENT_CONNECTION.lock().unwrap() {
        Some(stream) => {
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
        }
        None => {
            unreachable!("Client connection lost")
        }
    }

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
    match &mut *CLIENT_CONNECTION.lock().unwrap() {
        Some(stream) => {
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

            if read_len == 0 {
                // when read() return 0, the two likely cases are:
                // 1. socket shut down correctly
                // 2. reader has reached its “end of file” and will likely no longer be
                //    able to produce bytes
                warn!("Connection dropped to client, exiting...");
                std::process::exit(0);
            }

            *message_size = read_len;
        }
        None => {
            unreachable!("Client connection lost")
        }
    }
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
    match &mut *CLIENT_CONNECTION.lock().unwrap() {
        Some(stream) => {
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
        }
        None => {
            unreachable!("Client connection lost")
        }
    }
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
    match &mut *CLIENT_CONNECTION.lock().unwrap() {
        Some(stream) => {
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

            if read_len == 0 {
                // when read() return 0, the two likely cases are:
                // 1. socket shut down correctly
                // 2. reader has reached its “end of file” and will likely no longer be
                //    able to produce bytes
                warn!("Connection dropped to client, exiting...");
                std::process::exit(0);
            }

            *message_size = read_len;
        }
        None => {
            unreachable!("Client connection lost")
        }
    }

    0
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
                *(CLIENT_CONNECTION.lock().unwrap()) = Some(client_conn);
                break;
            }
            Err(e) => {
                error!("Error accepting connection: {}", e);
            }
        }
    }

    unsafe {
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
            TransportLayer::Storage => todo!(),
        }
        io_buffers::libspdm_setup_io_buffers(
            context,
            SEND_RECEIVE_BUFFER_LEN,
            SEND_RECEIVE_BUFFER_LEN,
        )?;
    }

    Ok(())
}
