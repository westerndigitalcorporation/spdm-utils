// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2023, Western Digital Corporation or its affiliates.

//! Implementation of the libc functions required by libspdm

use alloc::alloc::{alloc, dealloc, Layout};
use core::ffi::{c_char, c_void};
use libtock::rng::Rng;

#[no_mangle]
fn libspdm_get_random_number_64(rand_data: *mut u64) -> bool {
    if let Err(why) = Rng::exists() {
        panic!("rng error: {:?}", why);
    }
    // Request 8 bytes of RNG.
    let mut rng_buf: [u8; 8] = [0; 8];
    if let Err(why) = Rng::get_bytes_sync(&mut rng_buf, 8) {
        panic!("rng error: {:?}", why);
    }
    let rng = u64::from_be_bytes(rng_buf);
    assert_ne!(rng, 0);
    unsafe {
        *rand_data = rng;
    }
    true
}

#[no_mangle]
/// Return a random integer between [0 and i32::MAX].
pub extern "C" fn rand() -> i32 {
    if let Err(why) = Rng::exists() {
        panic!("rng error: {:?}", why);
    }
    // Request 4 bytes of RNG.
    let mut rng_buf: [u8; 4] = [0; 4];
    if let Err(why) = Rng::get_bytes_sync(&mut rng_buf, 4) {
        panic!("rng error: {:?}", why);
    }

    let mut rng = i32::from_be_bytes(rng_buf);
    // The valid output range is [0, i32::MAX], so if the signed bit is
    // set from HW RNG, invert it.
    if rng < 0 {
        rng = rng.wrapping_neg();
    }
    assert_ne!(rng, 0);
    rng
}

// Based on https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/builtins/bswapsi2.c
#[no_mangle]
pub extern "C" fn __bswapsi2(u: u32) -> u32 {
    (((u) & 0xff000000) >> 24)
        | (((u) & 0x00ff0000) >> 8)
        | (((u) & 0x0000ff00) << 8)
        | (((u) & 0x000000ff) << 24)
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    // We want to keep track of the Layout so it can be used to dealloc() later.
    // So allocate some extra-space for this metadata.
    let layout_size = core::mem::size_of::<Layout>();
    let layout = Layout::array::<u8>(size + layout_size).unwrap();
    let ptr = alloc(layout);
    if ptr == core::ptr::null_mut() {
        // Use this to catch excessive heap usage, ideally return NULL
        panic!("failed to heap allocate of size: {:} bytes", size);
    }
    core::ptr::write(ptr as *mut Layout, layout);
    return ptr.offset(layout_size as isize) as *mut c_void;
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    let layout_size = core::mem::size_of::<Layout>();
    // The layout is stored before the data address see malloc() stub above
    let layout_addr = ptr.offset(-(layout_size as isize));
    // Note: Cloning just to be on the safe side here, incase of use after free.
    //       probably not needed though.
    let layout: Layout = core::ptr::read(layout_addr as *const Layout).clone();
    dealloc(layout_addr as *mut u8, layout);
}

#[no_mangle]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *const c_char {
    let mut haystack_ptr = haystack;

    if unsafe { *haystack_ptr } == 0 {
        if unsafe { *needle } == 0 {
            return haystack_ptr;
        } else {
            return core::ptr::null();
        }
    }

    // This is quadratic performance in the worst case.
    // TODO: Optimize for speed
    while unsafe { *haystack_ptr != 0 } {
        let mut i = 0;

        loop {
            if unsafe { *needle.offset(i as isize) } == 0 {
                return haystack_ptr;
            }

            if unsafe { *needle.offset(i as isize) } != *haystack_ptr.offset(i as isize) {
                break;
            }

            i += 1;
        }
        haystack_ptr = unsafe { haystack_ptr.offset(1) };
    }

    core::ptr::null()
}

#[no_mangle]
pub extern "C" fn time() {
    todo!("libc/stub: time(): not yet implemented");
}

#[no_mangle]
/// Compare no more than N characters of S1 and S2,
/// returning less than, equal to or greater than zero
/// if S1 is lexicographically less than, equal to or
/// greater than S2.
/// Based on: https://github.com/zerovm/glibc/blob/3f07350498160f552350dc39f6fe6d237c7c3b03/string/strncmp.c#L28C4-L29C20
pub extern "C" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    let mut s1 = s1;
    let mut s2 = s2;
    let mut n = n;

    let mut c1: u8 = b'\0';
    let mut c2: u8 = b'\0';

    if n >= 4 {
        let mut n4 = n >> 2;
        while n4 > 0 {
            c1 = unsafe { *s1 as u8 };
            s1 = unsafe { s1.offset(1) };
            c2 = unsafe { *s2 as u8 };
            s2 = unsafe { s2.offset(1) };
            if c1 == b'\0' || c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
            c1 = unsafe { *s1 as u8 };
            s1 = unsafe { s1.offset(1) };
            c2 = unsafe { *s2 as u8 };
            s2 = unsafe { s2.offset(1) };
            if c1 == b'\0' || c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
            c1 = unsafe { *s1 as u8 };
            s1 = unsafe { s1.offset(1) };
            c2 = unsafe { *s2 as u8 };
            s2 = unsafe { s2.offset(1) };
            if c1 == b'\0' || c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }
            c1 = unsafe { *s1 as u8 };
            s1 = unsafe { s1.offset(1) };
            c2 = unsafe { *s2 as u8 };
            s2 = unsafe { s2.offset(1) };
            if c1 == b'\0' || c1 != c2 {
                return (c1 as i32) - (c2 as i32);
            }

            n4 -= 1;
        }
        n &= 3;
    }

    while n > 0 {
        c1 = unsafe { *s1 as u8 };
        s1 = unsafe { s1.offset(1) };
        c2 = unsafe { *s2 as u8 };
        s2 = unsafe { s2.offset(1) };
        if c1 == b'\0' || c1 != c2 {
            return (c1 as i32) - (c2 as i32);
        }

        n -= 1;
    }

    (c1 as i32) - (c2 as i32)
}

#[no_mangle]
pub extern "C" fn gmtime() {
    todo!("libc/stub: gmtime(): not yet implemented");
}

#[no_mangle]
pub extern "C" fn strchr() {
    todo!("libc/stub: strchr(): not yet implemented");
}

#[no_mangle]
pub extern "C" fn strcmp() {
    todo!("libc/stub: strcmp(): not yet implemented");
}
