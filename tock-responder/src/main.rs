// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! A simple libtock-rs SPDM example

#![no_main]
#![no_std]

use core::ffi::{c_int, c_void};
use core::fmt::Write;
use critical_section::RawRestoreState;
use embedded_alloc::Heap;
use libspdm::libspdm_rs::{
    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
    libspdm_register_device_io_func,
    libspdm_register_device_buffer_func
};
use libspdm::responder;
use libspdm::spdm;
use libtock::console::Console;
use libtock::runtime::{set_main, stack_size};

mod mctp;

set_main! {main}
stack_size! {0xE00}

#[global_allocator]
static HEAP: Heap = Heap::empty();

struct MyCriticalSection;
critical_section::set_impl!(MyCriticalSection);

unsafe impl critical_section::Impl for MyCriticalSection {
    unsafe fn acquire() -> RawRestoreState {
        // Tock is single threaded, so this can only be preempted by interrupts
        // The kernel won't schedule anything from our app unless we yield
        // so as long as we don't yield we won't concurrently run with
        // other critical sections from our app.
        // The kernel might schedule itself or other applications, but there
        // is nothing we can do about that.
    }

    unsafe fn release(_token: RawRestoreState) {}
}

// Based on https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/builtins/bswapsi2.c
#[no_mangle]
pub extern "C" fn __bswapsi2(u: u32) -> u32 {
    (((u) & 0xff000000) >> 24)
        | (((u) & 0x00ff0000) >> 8)
        | (((u) & 0x0000ff00) << 8)
        | (((u) & 0x000000ff) << 24)
}

extern "C" {
    // Provided by libtock-c
    fn gettimeasticks(tv: *mut libspdm::libspdm_rs::timeval, tzvp: *mut c_void) -> c_int;
}

#[no_mangle]
pub unsafe extern "C" fn _gettimeofday(
    tv: *mut libspdm::libspdm_rs::timeval,
    tzvp: *mut c_void,
) -> c_int {
    gettimeasticks(tv, tzvp)
}

// Setup the heap and the global allocator.
unsafe fn setup_heap() {
    use core::mem::MaybeUninit;
    // TODO: We can achieve ~118KB heap on the nrf52840, just need to bump the ram address in
    // libtock-rs `build_scripts/src/lib.rs:22 to 0x20010000`. This forces MPU alignment to the next
    // available MPU region calculated by the kernel. This may change as the kernel grows etc...
    const HEAP_SIZE: usize = 1024 * 82;
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
}

fn main() {
    unsafe {
        setup_heap();
    }

    writeln!(Console::writer(), "spdm-sample: app start\r",).unwrap();
    let cntx_ptr = spdm::initialise_spdm_context();

    mctp::register_device(cntx_ptr).unwrap();

    unsafe {
        spdm::setup_transport_layer(cntx_ptr).unwrap();
    }
    writeln!(
        Console::writer(),
        "spdm-sample: setup_transport_layer [ok]\r",
    )
    .unwrap();

    responder::setup_capabilities(
        cntx_ptr,
        0,
        Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_12).unwrap()),
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
    )
    .unwrap();
    writeln!(Console::writer(), "spdm-sample: setup_capabilities [ok]\r",).unwrap();
    writeln!(Console::writer(), "spdm-sample: starting response_loop...\r",).unwrap();
    responder::response_loop(cntx_ptr);
}

///! Transport Layer Support
/// !!!!!!!!!!!!!!!!!!!!!!!!!
/// !!!!!!!!!!!!!!!!!!!!!!!!!
///! 


// The address of the requester device
pub const SEND_ID: u8 = 0x22;
// The address of the responder device
pub const RECV_ID: u8 = 0x23;

const SEND_RECEIVE_BUFFER_LEN: usize = 512 as usize;
static mut SEND_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();

#[no_mangle]
unsafe extern "C" fn mctp_send_message(
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
    if let Err(why) = I2CMasterSlave::i2c_master_slave_write_sync(RECV_ID as u16, &send_buf, message_size as u16)
    {
        panic!(
            "mctp_send_message: i2c: write operation failed {:?}\r",
            why
        )
    }

    unimplemented!("mctp_send_message");
}

#[no_mangle]
unsafe extern "C" fn mctp_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    message_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let recv = *message_ptr as *mut u8;
    let recv_buf = from_raw_parts_mut(recv, SEND_RECEIVE_BUFFER_LEN);
    writeln!(Console::writer(), "mctp_receive_message: receiving message\r",).unwrap();
    // TODO: Verify the slave address symantics due to only writes from both sides.
    // Setup slave mode
    I2CMasterSlave::i2c_master_slave_set_slave_address(RECV_ID)
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

#[no_mangle]
unsafe extern "C" fn mctp_acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = SEND_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

    0
}

#[no_mangle]
unsafe extern "C" fn mctp_release_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    SEND_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

#[no_mangle]
unsafe extern "C" fn mctp_acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = RECEIVE_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

    0
}

#[no_mangle]
unsafe extern "C" fn mctp_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    RECEIVE_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

pub fn register_device(context: *mut c_void) -> Result<(), ()> {
    let buffer_send = [0; SEND_RECEIVE_BUFFER_LEN];
    let buffer_receive = [0; SEND_RECEIVE_BUFFER_LEN];

    unsafe {
        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_receive).unwrap();

        libspdm_register_device_io_func(
            context,
            Some(mctp_send_message),
            Some(mctp_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            SEND_RECEIVE_BUFFER_LEN as u32,
            SEND_RECEIVE_BUFFER_LEN as u32,
            Some(mctp_acquire_sender_buffer),
            Some(mctp_release_sender_buffer),
            Some(mctp_acquire_receiver_buffer),
            Some(mctp_release_receiver_buffer),
        );
    }

    Ok(())
}