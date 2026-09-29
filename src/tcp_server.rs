// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file allows setting up an spdm-utils TCP server using TCP/IP.
//! Currently, this supports only the raw SPDM messages and does not comply with
//! the TCP transport binding.
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use crate::*;
use core::ffi::c_void;
use libspdm::spdm::{LIBSPDM_MAX_SPDM_MSG_SIZE, TransportLayer};
use std::net::TcpListener;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::time::Duration;
use tcp_common::TcpDeviceState;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

/// # Summary
///
/// Sends message to the `tcp_client` by writing the
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
unsafe extern "C" fn tcp_server_send_message(
    context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    timeout: u64,
) -> u32 {
    let state = unsafe { &mut *tcp_common::state_from_context(context) };
    let stream = state.stream.as_mut().expect("No client connection");

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
/// Receives a message from the `tcp_client` into buffer pointed to by
/// the `message_ptr`. This may block until the stream has data ready.
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
#[unsafe(no_mangle)]
unsafe extern "C" fn tcp_server_receive_message(
    context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    timeout: u64,
) -> u32 {
    let state = unsafe { &mut *tcp_common::state_from_context(context) };
    let mut server_reset = false;
    let message = unsafe { *msg_buf_ptr as *mut u8 };
    let msg_buf = unsafe { from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN) };

    let stream = state.stream.as_mut().expect("No client connection");

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
        warn!("Connection dropped to client, exiting...");
        if !state.server_persist {
            std::process::exit(0);
        } else {
            server_reset = true;
        }
    }
    unsafe { *message_size = read_len };

    if server_reset {
        _ = tcp_server_listen(state);
    }

    0
}

fn tcp_server_bind(port: u16) -> Result<TcpListener, ()> {
    let args = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(args).map_err(|e| {
        error!("Failed to bind: {:?}", e);
    })?;

    Ok(listener)
}

fn tcp_server_listen(state: &mut TcpDeviceState) -> Result<(), ()> {
    let listener = state
        .listener
        .as_ref()
        .expect("TCP_LISTENER was not initialized");

    if let Ok(local_addr) = listener.local_addr() {
        info!(
            "Listening for TCP connections on port: {}",
            local_addr.port()
        );
    } else {
        info!("Listening for TCP connections...");
    }

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Ok(addr) = s.peer_addr() {
                    info!("Connection accepted from {}", addr);
                }
                state.stream = Some(s);
                break;
            }
            Err(e) => {
                /* connection failed, await next */
                warn!("Connection failed: {e:?}");
            }
        }
    }

    Ok(())
}

/// # Summary
///
/// Registers the SPDM `context` for a `tcp_server` backend.
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
    server_persist: bool,
    trans: TransportLayer,
) -> Result<(), ()> {
    let mut state = Box::<TcpDeviceState>::default();

    // Capture the listener for subsequent incoming connections if the
    // intiial connection drops but the user has asked us to persist
    state.listener = Some(tcp_server_bind(port)?);
    state.server_persist = server_persist;
    state.transport = Some(trans);

    tcp_server_listen(&mut state)?;

    tcp_common::attach_state(context, state);

    unsafe {
        libspdm_register_device_io_func(
            context,
            Some(tcp_server_send_message),
            Some(tcp_server_receive_message),
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
