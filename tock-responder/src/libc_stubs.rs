use alloc::alloc::{alloc, dealloc, Layout};
use core::ffi::{c_char, c_void};

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
pub extern "C" fn strncmp() {
    todo!("libc/stub: strncmp(): not yet implemented");
}

#[no_mangle]
pub extern "C" fn gmtime() {
    todo!("libc/stub: gmtime(): not yet implemented");
}
