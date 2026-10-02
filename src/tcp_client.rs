// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file allows connecting to an spdm-utils TCP server using TCP/IP.
//! Currently, this supports only the raw SPDM messages and does not comply with
//! the TCP transport binding.
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use crate::*;
use core::ffi::c_void;
use libspdm::spdm::{LIBSPDM_MAX_SPDM_MSG_SIZE, TransportLayer};
use std::net::TcpStream;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::time::Duration;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

/// # Summary
///
/// Sends message to the `tcp_server` by writing the
/// `message_ptr` data to the shared TCP stream.
///
/// # Parameter
///
/// * `context`: The SPDM context
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
#[unsafe(no_mangle)]
unsafe extern "C" fn tcp_client_send_message(
    context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    timeout: u64,
) -> u32 {
    let state = unsafe { &mut *tcp_common::state_from_context(context) };
    let stream = state.stream.as_mut().expect("No server connection");

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

    tcp_common::write_message(
        stream,
        msg_buf,
        state.transport.expect("Transport layer was never set"),
    );
    0
}

/// # Summary
///
/// Receives a message from the `tcp_server` into buffer pointed to by
/// the `message_ptr`. This may block until the stream has data ready.
///
/// # Parameter
///
/// * `context`: The SPDM context
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
#[unsafe(no_mangle)]
unsafe extern "C" fn tcp_client_receive_message(
    context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let state = unsafe { &mut *tcp_common::state_from_context(context) };
    let stream = state.stream.as_mut().expect("No server connection");
    let message = unsafe { *msg_buf_ptr as *mut u8 };
    let msg_buf = unsafe { from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN) };

    if timeout == 0 {
        stream
            .set_read_timeout(None)
            .expect("Couldn't set read timeout");
    } else {
        stream
            .set_read_timeout(Some(Duration::from_micros(timeout)))
            .expect("Couldn't set read timeout");
    }

    let read_len = tcp_common::read_message(
        stream,
        msg_buf,
        state.transport.expect("Transport layer was never set"),
    );

    if read_len == 0 {
        // when read() return 0, the two likely cases are:
        // 1. stream shut down correctly
        // 2. reader has reached its “end of file” and will likely no longer be
        //    able to produce bytes
        warn!("Connection dropped to server, exiting...");
        std::process::exit(0);
    }

    unsafe { *message_size = read_len };

    0
}

/// # Summary
///
/// Registers the SPDM `context` for a `tcp_client` backend.
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `trans`: The transport protocol used to frame messages on the wire
///
/// # Returns
///
/// Ok(()) on success
///
/// # Panics
///
/// Panics if `SEND_BUFFER/RECEIVE_BUFFER` is occupied
pub fn register_device(
    context: *mut c_void,
    port: u16,
    ip: Option<String>,
    trans: TransportLayer,
) -> Result<(), ()> {
    let ip_addr = ip.ok_or(())?;
    let ip_port = format!("{}:{}", ip_addr.clone(), port);

    info!("Connecting to server on {ip_port}");
    let stream = match TcpStream::connect(&ip_port) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to {} {}", ip_port, e);
            return Err(());
        }
    };

    info!("Connection success!");

    let mut state = Box::<tcp_common::TcpDeviceState>::default();
    state.stream = Some(stream);
    state.transport = Some(trans);

    tcp_common::attach_state(context, state);

    unsafe {
        libspdm_register_device_io_func(
            context,
            Some(tcp_client_send_message),
            Some(tcp_client_receive_message),
        );
        let spdm_msg_len = if trans == TransportLayer::Mctp {
            tcp_common::MCTP_SPDM_MSG_LEN
        } else {
            SEND_RECEIVE_BUFFER_LEN
        };

        io_buffers::libspdm_setup_io_buffers(context, SEND_RECEIVE_BUFFER_LEN, spdm_msg_len)?;
    }

    Ok(())
}
