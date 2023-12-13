// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! This file provides support for the libtock-rs MCTP backend. This allows
//! setting up an SPDM MCTP responder/requester on top of Tock
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use core::ffi::c_void;
use core::slice::from_raw_parts;
use libspdm::libspdm_rs::libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE;
use libspdm::libspdm_rs::{libspdm_data_parameter_t, libspdm_set_data};
use libspdm::libspdm_rs::{libspdm_register_device_buffer_func, libspdm_register_device_io_func};
use once_cell::sync::OnceCell;
use libtock::console::Console;
use libtock::alarm::{Alarm, Milliseconds};
use libtock::i2c_master_slave::I2CMasterSlave;
use core::fmt::Write;
use core::slice::from_raw_parts_mut;

const SEND_RECEIVE_BUFFER_LEN: usize = 0x100;
static mut SEND_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();

// TODO: We can get away with using the same ID for send/recv as the there's only
//       two devices and only writes are allowed. So only one should be listening
//       at a given time (check: might not be mctp compliant)
pub const TARGET_ID: u8   = 0x22;

/// # Summary
///
/// Sends message
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
unsafe extern "C" fn tock_send_message(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    _timeout: u64,
) -> u32 {
    let message = message_ptr as *const u8;
    let send_buf = unsafe { from_raw_parts(message, message_size) };
    // TODO: Use the libtock-rs I2C api to send the buffer
    // 1. Master bus
    // 2. Write out buffer to slave
    writeln!(Console::writer(), "mctp_send_message: {send_buf:x?}\r",).unwrap();
    // Allow some time for the receiving side to be listening
    Alarm::sleep_for(Milliseconds(250)).unwrap();
    if let Err(why) = I2CMasterSlave::i2c_master_slave_write_sync(TARGET_ID as u16, &send_buf, message_size as u16)
    {
        panic!(
            "mctp_send_message: i2c: write operation failed {:?}\r",
            why
        )
    }

    unimplemented!("mctp_send_message");
}

/// # Summary
///
/// Receives a message. This will block until data is ready.
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
unsafe extern "C" fn tock_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    msg_buf_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let recv = *msg_buf_ptr as *mut u8;
    let recv_buf = from_raw_parts_mut(recv, SEND_RECEIVE_BUFFER_LEN);
    writeln!(Console::writer(), "mctp_receive_message: receiving message\r",).unwrap();
    // TODO: Verify the slave address symantics due to only writes from both sides.
    // Setup slave mode
    I2CMasterSlave::i2c_master_slave_set_slave_address(TARGET_ID)
        .expect("mctp_receive_message: Failed to listen");

    let r = I2CMasterSlave::i2c_master_slave_write_recv_sync(recv_buf);

    if let Err(why) = r.1 {
        panic!(
            "mctp_receive_message: error to receiving data {:?}\r",
            why
        );
    }

    writeln!(
        Console::writer(),
        "{:} bytes received \n\r | buf: {:x?}\r",
        r.0,
        &recv_buf[0..r.0]
    )
    .unwrap();

    *message_size = r.0;
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
unsafe extern "C" fn tock_acquire_sender_buffer(
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
unsafe extern "C" fn tock_release_sender_buffer(_context: *mut c_void, msg_buf_ptr: *const c_void) {
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
unsafe extern "C" fn tock_acquire_receiver_buffer(
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
unsafe extern "C" fn tock_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    RECEIVE_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

/// # Summary
///
/// Registers the SPDM `context` for a tock MCTP backend.
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
pub fn register_device(context: *mut c_void) -> Result<(), ()> {
    let parameter = libspdm_data_parameter_t::new_local(0);
    let buffer_send = [0; SEND_RECEIVE_BUFFER_LEN];
    let buffer_receive = [0; SEND_RECEIVE_BUFFER_LEN];

    unsafe {
        let mut data: u32 = SEND_RECEIVE_BUFFER_LEN as u32;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );
    }

    unsafe {
        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_receive).unwrap();

        libspdm_register_device_io_func(
            context,
            Some(tock_send_message),
            Some(tock_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            SEND_RECEIVE_BUFFER_LEN as u32,
            SEND_RECEIVE_BUFFER_LEN as u32,
            Some(tock_acquire_sender_buffer),
            Some(tock_release_sender_buffer),
            Some(tock_acquire_receiver_buffer),
            Some(tock_release_receiver_buffer),
        );
    }

    Ok(())
}
