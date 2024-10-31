// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides support for the Linux backend. This allows setting up an
//! SPDM responder/requester client using unix sockets.
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use crate::*;
use core::ffi::c_void;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use once_cell::sync::OnceCell;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::time::Duration;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;
static mut CLIENT_CONNECTION: OnceCell<UnixStream> = OnceCell::new();

/// # Summary
///
/// Sends message to the `socket_server` by writing the
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
unsafe extern "C" fn sclient_send_message(
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

    stream.write_all(msg_buf).unwrap();
    stream.flush().unwrap();
    CLIENT_CONNECTION.set(stream).unwrap();

    0
}

/// # Summary
///
/// Receives a message from the `socket_server` into buffer pointed to by
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
unsafe extern "C" fn sclient_receive_message(
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
        warn!("Connection dropped to server, exiting...");
        std::process::exit(0);
    }

    *message_size = read_len;

    0
}

/// # Summary
///
/// Registers the SPDM `context` for a `socket_client` backend.
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
/// Panics if the `socket_server` hasn't initialized the socket.
pub fn register_device(context: *mut c_void) -> Result<(), ()> {
    let socket = Path::new(SOCKET_PATH);

    match UnixStream::connect(socket) {
        Err(_) => {
            error!("Server is not running");
            return Err(());
        }
        Ok(stream) => {
            unsafe {
                // TODO: It would be nice to somehow save this in libspdm
                // context
                CLIENT_CONNECTION.set(stream).unwrap();
            }
        }
    };

    info!("Connected to server");

    unsafe {
        libspdm_register_device_io_func(
            context,
            Some(sclient_send_message),
            Some(sclient_receive_message),
        );
        io_buffers::libspdm_setup_io_buffers(
            context,
            SEND_RECEIVE_BUFFER_LEN,
            SEND_RECEIVE_BUFFER_LEN,
        )?;
    }

    Ok(())
}
