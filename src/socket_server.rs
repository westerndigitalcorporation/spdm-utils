// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides support for the Linux backend. This allows setting up an
//! SPDM responder/requester server using unix sockets.
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use crate::*;
use core::ffi::c_void;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use once_cell::sync::Lazy;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Mutex;
use std::time::Duration;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;
static CLIENT_CONNECTION: Lazy<Mutex<Option<UnixStream>>> = Lazy::new(|| Mutex::new(None));
static mut SERVER_PERSIST: bool = false;

/// # Summary
///
/// Sends message to the `socket_client` by writing the
/// `message_ptr` data to the shared IPC socket initialized by the
/// `socket_server`.
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
unsafe extern "C" fn sserver_send_message(
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

            stream.write_all(msg_buf).unwrap();
            stream.flush().unwrap();
        }
        None => {
            unreachable!("Client connection lost");
        }
    }
    0
}

/// # Summary
///
/// Receives a message from the `socket_client` into buffer pointed to by
/// the `message_ptr`. This may block until the socket has data ready.
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
unsafe extern "C" fn sserver_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let mut server_reset = false;
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
                if !SERVER_PERSIST {
                    std::process::exit(0);
                } else {
                    server_reset = true;
                }
            }
            *message_size = read_len;
        }
        None => {
            unreachable!("Client connection lost")
        }
    }
    // Do the reset so we don't deadlock when attempting to lock on
    // CLIENT_CONNECTION in the subsequent call to `setup_socket_and_listen`
    if server_reset {
        setup_socket_and_listen().expect("failed to reset server");
    }
    0
}

fn setup_socket_and_listen() -> Result<(), ()> {
    let socket = Path::new(SOCKET_PATH);

    if socket.exists() {
        fs::remove_file(socket).map_err(|e| {
            error!("Failed to remove out socket file {:?}", e);
            ()
        })?;
    }

    let stream = match UnixListener::bind(socket) {
        Err(_) => {
            error!("Failed to bind socket");
            return Err(());
        }
        Ok(stream) => stream,
    };

    info!("Server started, waiting for clients");

    // Iterate over clients, blocks if no client available
    for client in stream.incoming() {
        match client {
            Ok(client_connection) => {
                /* connection succeeded */
                *(CLIENT_CONNECTION.lock().unwrap()) = Some(client_connection);
                info!("Client connected");
                break;
            }
            Err(err) => {
                /* connection failed, await next */
                warn!("Connection failed: {err:?}");
            }
        }
    }

    Ok(())
}

/// # Summary
///
/// Registers the SPDM `context` for a `socket_server` backend.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// Ok(()) on success
///
/// # Panics
///
/// Panics if `SEND_BUFFER/RECEIVE_BUFFER` is occupied
/// Panics on errors based on socket setup.
pub fn register_device(context: *mut c_void, server_persist: bool) -> Result<(), ()> {
    setup_socket_and_listen()?;

    unsafe {
        SERVER_PERSIST = server_persist;

        libspdm_register_device_io_func(
            context,
            Some(sserver_send_message),
            Some(sserver_receive_message),
        );
        io_buffers::libspdm_setup_io_buffers(
            context,
            SEND_RECEIVE_BUFFER_LEN,
            SEND_RECEIVE_BUFFER_LEN,
        )?;
    }

    Ok(())
}
