// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! This file provides support for the libtock-rs MCTP backend. This allows
//! setting up an SPDM MCTP responder/requester on top of Tock
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use alloc::alloc::alloc;
use core::alloc::Layout;
use core::ffi::c_void;
use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;
use libspdm::libspdm_rs::*;
use libspdm::spdm::LibspdmReturnStatus;
use libtock::i2c_master_slave::I2CMasterSlave;
use once_cell::sync::OnceCell;

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;
static mut SEND_BUFFER: OnceCell<*mut u8> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<*mut u8> = OnceCell::new();

pub const TARGET_ID: u8 = 0x22;

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
pub const LIBSPDM_MAX_SPDM_MSG_SIZE: u32 = 128;

/// # Summary
///
/// 1.3: Set capabilities and choose algorithms, based upon need
///
/// Note: This is a repeat implementation from `spdm-utils`
/// with the necessary changes for MCTP.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// Ok(()) on success
pub unsafe fn setup_transport_layer(context: *mut c_void) -> Result<(), ()> {
    libspdm_register_transport_layer_func(
        context,
        LIBSPDM_MAX_SPDM_MSG_SIZE,
        LIBSPDM_MCTP_TRANSPORT_HEADER_SIZE,
        LIBSPDM_MCTP_TRANSPORT_TAIL_SIZE,
        Some(libspdm_transport_mctp_encode_message),
        Some(libspdm_transport_mctp_decode_message),
    );

    let parameter = libspdm_data_parameter_t::new_connection(0);
    let mut data: u32 = LIBSPDM_MAX_SPDM_MSG_SIZE;
    let data_ptr = &mut data as *mut _ as *mut c_void;
    if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
        context,
        libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_MAX_SPDM_MSG_SIZE,
        &parameter as *const libspdm_data_parameter_t,
        data_ptr,
        core::mem::size_of::<u32>(),
    )) {
        panic!("Unable to set data");
    }

    let libspdm_scratch_buffer_size = libspdm_get_sizeof_required_scratch_buffer(context);
    let libspdm_scratch_buffer_layout =
        Layout::from_size_align(libspdm_scratch_buffer_size, 8).unwrap();
    let libspdm_scratch_buffer = alloc(libspdm_scratch_buffer_layout);

    if libspdm_scratch_buffer.is_null() {
        panic!("Unable to allocate libspdm scratch buffer");
    }

    let libspdm_scratch_buffer_ptr: *mut c_void = libspdm_scratch_buffer as *mut _ as *mut c_void;

    libspdm_set_scratch_buffer(
        context,
        libspdm_scratch_buffer_ptr,
        libspdm_scratch_buffer_size,
    );

    Ok(())
}
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

    // Allow some time for the receiving side to be listening
    if let Err(why) = I2CMasterSlave::i2c_master_slave_write_sync(
        TARGET_ID as u16,
        &send_buf,
        message_size as u16,
    ) {
        panic!("mctp_send_message: i2c: write operation failed {:?}\r", why)
    }

    0
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
    let recv_buf: &mut [u8] = from_raw_parts_mut(recv, SEND_RECEIVE_BUFFER_LEN);

    let r = I2CMasterSlave::i2c_master_slave_write_recv_sync(recv_buf);
    if let Err(why) = r.1 {
        panic!("mctp_receive_message: error to receiving data {:?}\r", why);
    }

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
    let buf_ptr = SEND_BUFFER.take().unwrap();
    *msg_buf_ptr = buf_ptr as *mut c_void;

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
    SEND_BUFFER.set(message as *mut u8).unwrap();
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
    let buf_ptr = RECEIVE_BUFFER.take().unwrap();
    *msg_buf_ptr = buf_ptr as *mut c_void;

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
    RECEIVE_BUFFER.set(message as *mut u8).unwrap();
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
    unsafe {
        let parameter = libspdm_data_parameter_t::new_local(0);
        let layout = Layout::array::<u8>(SEND_RECEIVE_BUFFER_LEN).unwrap();
        let buffer_send = alloc(layout);
        let buffer_receive = alloc(layout);

        let mut data: u32 = SEND_RECEIVE_BUFFER_LEN as u32;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_DATA_TRANSFER_SIZE,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

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

    I2CMasterSlave::i2c_master_slave_set_slave_address(TARGET_ID)
        .expect("mctp_receive_message: Failed to listen");

    Ok(())
}
