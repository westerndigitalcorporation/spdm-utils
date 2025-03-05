use once_cell::sync::Lazy;
use std::ffi::c_void;
use std::sync::Mutex;

static SEND_BUFFER: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));
static RECEIVE_BUFFER: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

pub fn libspdm_setup_io_buffers(
    context: *mut c_void,
    send_len: usize,
    recv_len: usize,
) -> Result<(), ()> {
    let result = std::panic::catch_unwind(|| {
        let buffer_send = vec![0; send_len];
        let buffer_receive = vec![0; recv_len];
        (buffer_send, buffer_receive)
    });

    match result {
        Ok(buffers) => {
            *(SEND_BUFFER.lock().unwrap()) = Some(buffers.0);
            *(RECEIVE_BUFFER.lock().unwrap()) = Some(buffers.1);

            unsafe {
                libspdm::libspdm_rs::libspdm_register_device_buffer_func(
                    context,
                    send_len as u32,
                    recv_len as u32,
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    if let Some(ref buf) = *SEND_BUFFER.lock().unwrap() {
        let buf_ptr = buf.as_ptr() as *mut c_void;
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
    if let Some(ref buf) = *RECEIVE_BUFFER.lock().unwrap() {
        let buf_ptr = buf.as_ptr() as *mut c_void;
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
    let mut send_buf = SEND_BUFFER.lock().unwrap();
    if send_buf.is_some() {
        *send_buf = None;
    } else {
        warn!("Send buffer is lost or not initialized");
    }

    let mut recv_buf = RECEIVE_BUFFER.lock().unwrap();
    if recv_buf.is_some() {
        *recv_buf = None;
    } else {
        warn!("Receive buffer is lost or not initialized");
    }
}
