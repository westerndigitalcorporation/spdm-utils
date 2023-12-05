//! A simple libtock-rs SPDM example

#![no_main]
#![no_std]

use core::ffi::{c_int, c_void};
use core::fmt::Write;
use emballoc;
use libspdm::spdm;
use libtock::console::Console;
use libtock::runtime::{set_main, stack_size};

set_main! {main}
stack_size! {0x400}

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<4096> = emballoc::Allocator::new();

fn main() {
    writeln!(Console::writer(), "spdm-sample app start\r",).unwrap();
    let cntx_ptr = spdm::initialise_spdm_context();
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
