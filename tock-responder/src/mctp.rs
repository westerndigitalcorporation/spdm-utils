// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! This file provides support for the libtock-rs MCTP backend. This allows
//! setting up an SPDM MCTP responder/requester on top of Tock
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::ffi::c_void;
#[allow(unused_imports)]
use core::fmt::Write;
use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;
use libmctp;
use libmctp::mctp_traits::SMBusMCTPRequestResponse;
use libmctp::vendor_packets::VendorIDFormat;
use libspdm::libspdm_rs::*;
use libspdm::spdm::LibspdmReturnStatus;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
#[allow(unused_imports)]
use libtock::console::Console;
use libtock::i2c_master_slave::I2CMasterSlave;
use once_cell::sync::OnceCell;

/// We will use CHUNKING support from libspdm, SEND_RECEIVE_BUFFER_LEN will also
/// dictate the number of max bytes per transport layer send/recv
/// operation.
///
/// Note: The kernel I2C buffers initialized by <board>/src/main.rs must
///       be of length > SEND_RECEIVE_BUFFER_LEN.
const SEND_RECEIVE_BUFFER_LEN: usize = 255 as usize;
static mut SEND_BUFFER: OnceCell<*mut u8> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<*mut u8> = OnceCell::new();

const MCTP_HEADER_LEN: usize = 10;
const LIBSPDM_BUFFER_LEN: usize = SEND_RECEIVE_BUFFER_LEN - MCTP_HEADER_LEN;

static mut MCTPCONTEXT: OnceCell<libmctp::MCTPSMBusContext> = OnceCell::new();

// TODO: Make configurable
/// The address of the target device
pub const TARGET_ID: u8 = 0x34;
/// The address of this device
pub const SOURCE_ID: u8 = 0x22;

pub const MCTP_PAYLOAD_OFFSET: usize = 9;

const MSG_TYPES: [u8; 0] = [0; 0];
const VENDOR_IDS: [VendorIDFormat; 1] = [VendorIDFormat {
    // PCI Vendor ID
    format: 0x00,
    // PCI VID
    data: 0x1234,
    // Extra data
    numeric_value: 0xAB,
}];

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
    let message_buf = unsafe { from_raw_parts(message, message_size) };
    let send_buf_layout = Layout::array::<u8>(message_size + 20).unwrap();
    let send_buf_alloc = alloc(send_buf_layout);
    let send_buf = from_raw_parts_mut(send_buf_alloc, message_size + 20);
    let ctx = MCTPCONTEXT.take().unwrap();

    let libspdm_msg_header_type = match libmctp::MessageType::from(message_buf[0]) {
        libmctp::MessageType::SpdmOverMctp => libmctp::MessageType::SpdmOverMctp,
        libmctp::MessageType::SecuredMessages => libmctp::MessageType::SecuredMessages,
        _ => unreachable!("unexpected mctp/spdm message type"),
    };

    let len = ctx
        .get_request()
        .generate_spdm_msg_packet_bytes(
            TARGET_ID,
            libspdm_msg_header_type,
            &None,
            &message_buf[1..],
            send_buf,
        )
        .unwrap();

    #[cfg(feature = "spdm_debug")]
    {
        writeln!(
            Console::writer(),
            "--mctp_send_message: sending message--\r",
        )
        .unwrap();
        writeln!(
            Console::writer(),
            "mctp_send_message: {len}/{message_size}: {:x?}\r",
            &send_buf[0..len]
        )
        .unwrap();
    }

    // Allow some time for the receiving side to be listening
    if let Err(why) = I2CMasterSlave::i2c_master_slave_write_sync(
        TARGET_ID as u16,
        &send_buf[1..len],
        len as u16 - 1,
    ) {
        panic!("mctp_send_message: i2c: write operation failed {:?}\r", why);
    }

    let _ = MCTPCONTEXT.set(ctx);
    dealloc(send_buf_alloc, send_buf_layout);
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
    recv_buf.fill(0);
    let ctx = MCTPCONTEXT.take().unwrap();

    #[cfg(feature = "spdm_debug")]
    {
        writeln!(
            Console::writer(),
            "--mctp_receive_message: receiving message--\r",
        )
        .unwrap();
    }

    I2CMasterSlave::i2c_master_slave_set_slave_address(SOURCE_ID)
        .expect("mctp_receive_message: Failed to listen");

    let r = I2CMasterSlave::i2c_master_slave_write_recv_sync(recv_buf);
    if let Err(why) = r.1 {
        panic!("mctp_receive_message: error to receiving data {:?}\r", why);
    }

    // Ammed our address to create a valid MCTP packet
    let mut message_len = r.0;
    recv_buf.copy_within(0..message_len, 1);
    recv_buf[0] = SOURCE_ID << 1;
    message_len = message_len + 1;

    #[cfg(feature = "spdm_debug")]
    {
        writeln!(
            Console::writer(),
            "{:} bytes received \n\r buf: {:x?}\r",
            message_len,
            &recv_buf[0..message_len]
        )
        .unwrap();
    }

    let (_msg_type, payload) = ctx.decode_packet(&recv_buf[..message_len]).unwrap();

    let _ = MCTPCONTEXT.set(ctx);

    let len = payload.len();
    // The `MCTP_PAYLOAD_OFFSET-1`` is the SPDM MCTP Message type, lets retain this
    recv_buf.copy_within(
        MCTP_PAYLOAD_OFFSET - 1..((MCTP_PAYLOAD_OFFSET - 1) + len),
        0,
    );

    #[cfg(feature = "spdm_debug")]
    {
        writeln!(Console::writer(), "recv_buf: {:x?}", &recv_buf[0..len]).unwrap();
    }

    *message_size = len;
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

        let _ = MCTPCONTEXT.set(libmctp::MCTPSMBusContext::new(
            SOURCE_ID,
            &MSG_TYPES,
            &VENDOR_IDS,
        ));

        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_receive).unwrap();

        libspdm_register_device_io_func(
            context,
            Some(tock_send_message),
            Some(tock_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            LIBSPDM_BUFFER_LEN as u32,
            LIBSPDM_BUFFER_LEN as u32,
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
