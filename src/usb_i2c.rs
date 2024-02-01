// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! This file provides support for interfacing to an USB-I2C/SMBUS device.
//! Note: Currently, it designed to work exclusively with the libtock-rs
//! [TODO: ADD REF WHEN UPSTREAM] app. However, can be modified easily to
//! work with similar tools.
//!
//! The following topology is used:
//!
//! [HOST MACHINE] <--UART--> [USB_I2C_BRIDGE_DEVICE] <--I2C/SmBus--> [TARGET_ENDPOiNT]
//!
//! Where SPDM data messages are transported from the host to the bridge device
//! over UART.It is then that devices responsibility to forward the SPDM
//! messages to the target endpoint. This can be used on platforms for
//! testing SPDM/MCTP over SMBUS. Particularly useful for machines that do not
//! have I2C/SMBUS pinouts exposed.
//!
//! This depends on `-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=1`, see README for how to
//! enable chunking support when building libspdm.
//!
//! SAFETY: This file includes unsafe Rust.
//!
use crate::*;
use core::ffi::c_void;
use lazy_static::lazy_static;
use libmctp;
use libmctp::mctp_traits::*;
use libmctp::vendor_packets::VendorIDFormat;
use once_cell::sync::OnceCell;
use serialport::SerialPort;
use std::io::Read;
use std::slice::{from_raw_parts, from_raw_parts_mut};
use std::sync::Mutex;
use std::time::Duration;

// We are using libspdm chunking, so let's use smaller transfer chunks at the hardware
// layer.
const SEND_RECEIVE_BUFFER_LEN: usize = 128;
static mut SEND_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();

const MCTP_HEADER_LEN: usize = 10;
const LIBSPDM_BUFFER_LEN: usize = SEND_RECEIVE_BUFFER_LEN - MCTP_HEADER_LEN;

/// The length of the packet header sent prior to the SPDM data message by the
/// usb-i2c bridge device. This packet is used to determine the exact length
/// of the next incoming data set which contains only the SPDM message data.
pub const HEADER_LEN: usize = 0x4;

pub const MCTP_BYTE_COUNT: usize = 2;
pub const MCTP_PAYLOAD_OFFSET: usize = 9;

// TODO: Make these configurable
/// The address of the target device
pub const TARGET_ID: u8 = 0x22;
/// The address of this device
pub const SOURCE_ID: u8 = 0x34;

const MSG_TYPES: [u8; 0] = [0; 0];
const VENDOR_IDS: [VendorIDFormat; 1] = [VendorIDFormat {
    // PCI Vendor ID
    format: 0x00,
    // PCI VID
    data: 0x1234,
    // Extra data
    numeric_value: 0xAB,
}];

static mut MCTPCONTEXT: OnceCell<libmctp::MCTPSMBusContext> = OnceCell::new();

lazy_static! {
    // Let's lock down the serial port, so we don't have to keep opening and
    // closing it on every send/recv. Avoid the syscall overhead.
    static ref SERIAL_PORT: Mutex<Option<Box<dyn SerialPort>>> = Mutex::new(None);
}

/// # Summary
///
/// Write the SPDM message buffer to the serial port specified by @SERIAL_PORT
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Number of elements in `message_ptr` to send
/// * `message_ptr`: A pointer to the data buffer to be sent
/// * `_timeout`: Transaction timeout (Unsupported)
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
unsafe extern "C" fn usb_i2c_send_message(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    _timeout: u64,
) -> u32 {
    assert!(message_size < SEND_RECEIVE_BUFFER_LEN as usize);
    let message = message_ptr as *const u8;
    let msg_buf = unsafe { from_raw_parts(message, message_size) };
    let mut send_buf: [u8; (SEND_RECEIVE_BUFFER_LEN + HEADER_LEN) as usize] =
        [0; (SEND_RECEIVE_BUFFER_LEN + HEADER_LEN) as usize];
    send_buf.fill(0);
    let ctx = MCTPCONTEXT.take().unwrap();

    let libspdm_msg_header_type = match libmctp::MessageType::from(msg_buf[0]) {
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
            &msg_buf[1..],
            &mut send_buf,
        )
        .unwrap();

    // We drop the first byte, which is the target address
    send_buf.copy_within(0..len, 4);

    send_buf[0] = 0xAA; // Preamble
    send_buf[1] = TARGET_ID; // Target Address
    send_buf[2..=3].copy_from_slice(&u16::to_be_bytes(len as u16)); // Set the 16-bit length value [2] -> upper byte, [3] -> lower byte

    // For writes, we transfer the entire buffer of fixed length.
    debug!(
        "MCTP message Length {:} || SPDM Len: {:} || Total TX Length {:?}",
        len,
        message_size,
        send_buf.len()
    );

    debug!("Sending message {:x?}", send_buf);

    // Write out the data buffer
    let mut port = SERIAL_PORT.lock().unwrap().take().unwrap();
    port.write(&send_buf).expect("Write failed!");
    info!("Sent!");

    let _ = MCTPCONTEXT.set(ctx);
    *SERIAL_PORT.lock().unwrap() = Some(port);

    0
}

/// # Summary
///
/// Read data from @SERIAL_PORT until we hit end of line.
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Returns the number of bytes received in this transaction
/// * `message_ptr`: A pointer to a data buffer of a minimum size of
///                 `SEND_RECEIVE_BUFFER_LEN` to capture the received bytes.
/// * `_timeout`: Transaction timeout (Unsupported)
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
unsafe extern "C" fn usb_i2c_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    message_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let message = *message_ptr as *mut u8;
    let spdm_msg_buf = from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN);
    let ctx = MCTPCONTEXT.take().unwrap();

    info!("Receiving message");

    let mut port = SERIAL_PORT.lock().unwrap().take().unwrap();
    let mut header: Vec<u8> = vec![0; HEADER_LEN];
    _ = port.read_exact(&mut header).unwrap();

    // Assert the header first
    debug!("packet_header: {:x?}", header);
    assert_eq!(header[0], 0xBB); // Receive Preamble 1
    assert_eq!(header[1], 0xFF); // Receive Preamble 2 (This is just misc)

    // Copy in the 2 bytes (Big Endian as set by target) that corresponds to the
    // message length
    let mut message_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    assert!(message_len <= SEND_RECEIVE_BUFFER_LEN);
    assert_ne!(message_len, 0x00);

    // Read the next set of data, which is just the SPDM message
    port.read_exact(&mut spdm_msg_buf[0..message_len]).unwrap();

    // Ammed our address to create a valid MCTP packet
    spdm_msg_buf.copy_within(0..message_len, 1);
    spdm_msg_buf[0] = SOURCE_ID << 1;
    message_len = message_len + 1;

    // Get the total length from the MCTP packet
    let mctp_len = spdm_msg_buf[MCTP_BYTE_COUNT] as usize + 4;
    assert!(mctp_len <= message_len);
    assert!(mctp_len <= SEND_RECEIVE_BUFFER_LEN);

    let (_msg_type, payload) = ctx.decode_packet(&spdm_msg_buf[0..mctp_len]).unwrap();

    // Extract the payload and add the mesasge type to please libspdm
    let len = payload.len() + 1;
    // The `MCTP_PAYLOAD_OFFSET-1`` is the SPDM MCTP Message type, lets retain this
    spdm_msg_buf.copy_within(
        (MCTP_PAYLOAD_OFFSET - 1)..((MCTP_PAYLOAD_OFFSET - 1) + len),
        0,
    );

    debug!("mctp_buf: {:x?}", &spdm_msg_buf[0..len]);

    *message_size = len;

    let _ = MCTPCONTEXT.set(ctx);
    *SERIAL_PORT.lock().unwrap() = Some(port);

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
unsafe extern "C" fn usb_i2c_acquire_sender_buffer(
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
unsafe extern "C" fn usb_i2c_release_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
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
unsafe extern "C" fn usb_i2c_acquire_receiver_buffer(
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
unsafe extern "C" fn usb_i2c_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    RECEIVE_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

/// # Summary
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
pub fn register_device(
    context: *mut c_void,
    usb_dev: Option<String>,
    usb_baud: u32,
) -> Result<(), ()> {
    let buffer_send = [0; SEND_RECEIVE_BUFFER_LEN];
    let buffer_receive = [0; SEND_RECEIVE_BUFFER_LEN];

    let udev = usb_dev.expect("USB device path not specified");

    let port = serialport::new(&udev, usb_baud)
        .timeout(Duration::from_secs(30))
        .open()
        .expect("Failed to open port");

    // Clear I/O buffers to drop any misc/lingering data
    port.clear(serialport::ClearBuffer::All)
        .expect("Failed to clear buffer for {udev}");
    assert_eq!(port.bytes_to_read().unwrap(), 0);
    assert_eq!(port.bytes_to_write().unwrap(), 0);

    info!("Serial Port {:} at {:} bits/s", &udev, usb_baud);

    SERIAL_PORT.lock().unwrap().replace(port);

    unsafe {
        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_receive).unwrap();

        let _ = MCTPCONTEXT.set(libmctp::MCTPSMBusContext::new(
            SOURCE_ID,
            &MSG_TYPES,
            &VENDOR_IDS,
        ));

        libspdm_register_device_io_func(
            context,
            Some(usb_i2c_send_message),
            Some(usb_i2c_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            LIBSPDM_BUFFER_LEN as u32,
            LIBSPDM_BUFFER_LEN as u32,
            Some(usb_i2c_acquire_sender_buffer),
            Some(usb_i2c_release_sender_buffer),
            Some(usb_i2c_acquire_receiver_buffer),
            Some(usb_i2c_release_receiver_buffer),
        );
    }

    Ok(())
}
