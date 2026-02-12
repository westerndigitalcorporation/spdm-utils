use nix::errno::Errno;
use once_cell::sync::Lazy;
use std::alloc::dealloc;
use std::alloc::{Layout, alloc_zeroed};
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Mutex;

type IoBuffer = Option<(Vec<u8>, Layout)>;
static SEND_BUFFER: Lazy<Mutex<IoBuffer>> = Lazy::new(|| Mutex::new(None));
static RECEIVE_BUFFER: Lazy<Mutex<IoBuffer>> = Lazy::new(|| Mutex::new(None));

pub fn libspdm_setup_io_buffers(
    context: *mut c_void,
    send_recv_len: usize,
    libsdpm_buff_len: usize,
) -> Result<(), ()> {
    // NVMe requires page aligned buffers
    if !send_recv_len.is_multiple_of(page_size::get()) {
        error!("Requested SEND/RECV buffer size is not system page size aligned");
        return Err(());
    }

    fn page_aligned_buffer(size: usize) -> Result<(Vec<u8>, Layout), Errno> {
        let layout = Layout::from_size_align(size, page_size::get()).map_err(|_| Errno::EINVAL)?;
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).ok_or(Errno::ENOMEM)?;
        let vec = unsafe { Vec::from_raw_parts(ptr.as_ptr(), 0, size) };
        Ok((vec, layout))
    }

    let buffer_send = page_aligned_buffer(send_recv_len).map_err(|e| {
        error!("Failed to allocate SEND buffer: {e}");
    })?;
    let buffer_recv = page_aligned_buffer(send_recv_len).map_err(|e| {
        error!("Failed to allocate RECV buffer: {e}");
    })?;

    *(SEND_BUFFER.lock().unwrap()) = Some((buffer_send.0, buffer_send.1));
    *(RECEIVE_BUFFER.lock().unwrap()) = Some((buffer_recv.0, buffer_recv.1));

    unsafe {
        libspdm::libspdm_rs::libspdm_register_device_buffer_func(
            context,
            libsdpm_buff_len as u32,
            libsdpm_buff_len as u32,
            Some(acquire_sender_buffer),
            Some(release_sender_buffer),
            Some(acquire_receiver_buffer),
            Some(release_receiver_buffer),
        )
    };

    Ok(())
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    if let Some(ref mem) = *SEND_BUFFER.lock().unwrap() {
        let buf_ptr = mem.0.as_ptr() as *mut c_void;
        unsafe { *msg_buf_ptr = buf_ptr };
        return 0;
    }
    error!("Sender buffer is lost or not initialized");
    1
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    if let Some(ref mem) = *RECEIVE_BUFFER.lock().unwrap() {
        let buf_ptr = mem.0.as_ptr() as *mut c_void;
        unsafe { *msg_buf_ptr = buf_ptr };
        return 0;
    }
    error!("Receiver buffer is lost or not initialized");
    1
}

/// We are only passing a reference to heap allocated memory, no-op required
#[unsafe(no_mangle)]
pub unsafe extern "C" fn release_receiver_buffer(
    _context: *mut c_void,
    _msg_buf_ptr: *const c_void,
) {
}

/// We are only passing a reference to heap allocated memory, no-op required
#[unsafe(no_mangle)]
pub unsafe extern "C" fn release_sender_buffer(_context: *mut c_void, _msg_buf_ptr: *const c_void) {
}

/// # Summary
///
/// Drop the IO buffers out of scope, this should release the underlying
/// memory.
pub unsafe fn libspdm_drop_io_buffers() {
    let free = |buf: &mut IoBuffer, err: &str| {
        if let Some(mut mem) = buf.take() {
            let ptr = mem.0.as_mut_ptr();
            let layout = mem.1;
            std::mem::forget(mem.0);
            unsafe { dealloc(ptr, layout) };
        } else {
            error!("{}", err);
        }
    };

    {
        let mut send_buf = SEND_BUFFER.lock().unwrap();
        free(&mut send_buf, "Send buffer is lost or not initialized");
    }

    {
        let mut recv_buf = RECEIVE_BUFFER.lock().unwrap();
        free(&mut recv_buf, "Receive buffer is lost or not initialized");
    }
}
