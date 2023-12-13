// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! A simple libtock-rs SPDM example

#![no_main]
#![no_std]
extern crate alloc;

use core::ffi::{c_int, c_void};
use core::fmt::Write;
use critical_section::RawRestoreState;
use embedded_alloc::Heap;
use libspdm::libspdm_rs::{
    SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
    SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
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

    const HEAP_SIZE: usize = 1024 * 64;
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
        mctp::setup_transport_layer(cntx_ptr).unwrap();
    }
    writeln!(
        Console::writer(),
        "spdm-sample: setup_transport_layer [ok]\r",
    )
    .unwrap();

    responder::setup_capabilities(
        cntx_ptr,
        0,
        Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_13).unwrap()),
        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
    )
    .unwrap();
    writeln!(Console::writer(), "spdm-sample: setup_capabilities [ok]\r",).unwrap();
    writeln!(
        Console::writer(),
        "spdm-sample: starting response_loop...\r",
    )
    .unwrap();
    responder::response_loop(cntx_ptr);
}
