use once_cell::sync::OnceCell;
use std::ffi::c_void;

static mut SEND_BUFFER: OnceCell<Vec<u8>> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<Vec<u8>> = OnceCell::new();

pub fn libspdm_setup_io_buffers(
    context: *mut c_void,
    send_recv_len: usize,
    libsdpm_buff_len: usize,
) -> Result<(), ()> {
    let result = std::panic::catch_unwind(|| {
        let buffer_send = vec![0; send_recv_len];
        let buffer_receive = vec![0; send_recv_len];
        (buffer_send, buffer_receive)
    });

    match result {
        Ok(buffers) => {
            unsafe {
                SEND_BUFFER.set(buffers.0).map_err(|_| {
                    error!("Failed to set send buffer");
                    ()
                })?;
                RECEIVE_BUFFER.set(buffers.1).map_err(|_| {
                    error!("Failed to set receive buffer");
                    ()
                })?;
            }

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
            }
            Ok(())
        }
        Err(_) => {
            error!("Failed to allocate transport buffers");
            Err(())
        }
    }
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
#[no_mangle]
pub unsafe extern "C" fn acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    if let Some(buffer) = SEND_BUFFER.get() {
        let buf_ptr = buffer.as_ptr() as *mut c_void;
        *msg_buf_ptr = buf_ptr;
        return 0;
    }
    error!("Sender buffer is lost or not initialized");
    return 1;
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
#[no_mangle]
pub unsafe extern "C" fn acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    if let Some(buffer) = RECEIVE_BUFFER.get() {
        let buf_ptr = buffer.as_ptr() as *mut c_void;
        *msg_buf_ptr = buf_ptr;
        return 0;
    }
    error!("Receiver buffer is lost or not initialized");
    return 1;
}

/// We are only passing a reference to heap allocated memory, no-op required
#[no_mangle]
pub unsafe extern "C" fn release_receiver_buffer(
    _context: *mut c_void,
    _msg_buf_ptr: *const c_void,
) {
}

/// We are only passing a reference to heap allocated memory, no-op required
#[no_mangle]
pub unsafe extern "C" fn release_sender_buffer(_context: *mut c_void, _msg_buf_ptr: *const c_void) {
}

/// # Summary
///
/// Take ownership of the IO buffer and drop them out of context allowing the
/// underlying memory to be freed.
pub unsafe fn libspdm_drop_io_buffers() {
    if let Some(_) = SEND_BUFFER.take() {}
    if let Some(_) = RECEIVE_BUFFER.take() {}
}
