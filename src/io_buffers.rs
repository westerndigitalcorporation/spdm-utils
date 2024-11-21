use nix::errno::Errno;
use once_cell::sync::OnceCell;
use std::ffi::c_void;

static mut SEND_BUFFER: OnceCell<BufferType> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<BufferType> = OnceCell::new();

enum BufferType {
    MemAligned(Vec<u8>),
    Default(Vec<u8>),
}

impl BufferType {
    fn into(&self) -> &Vec<u8> {
        match self {
            BufferType::MemAligned(data) | BufferType::Default(data) => data,
        }
    }
}

pub unsafe fn libspdm_setup_pagealigned_io_buffers(
    context: *mut c_void,
    send_recv_len: usize,
    libsdpm_buff_len: usize,
) -> Result<(), Errno> {
    let mut buffer_send: *mut c_void = std::ptr::null_mut();
    let mut buffer_recv: *mut c_void = std::ptr::null_mut();

    if send_recv_len % page_size::get() != 0 {
        error!("Requested SEND/RECV buffer size is not target page size aligned");
        return Err(Errno::EINVAL);
    }

    // The buffers are page aligned, useful for NVMe userspace API buffers.
    if nix::libc::posix_memalign(
        &mut buffer_recv as *mut *mut c_void,
        page_size::get(),
        send_recv_len,
    ) != 0
    {
        error!("Failed to allocate an aligned receive buffer");
        return Err(Errno::ENOMEM);
    }
    if nix::libc::posix_memalign(
        &mut buffer_send as *mut *mut c_void,
        page_size::get(),
        send_recv_len,
    ) != 0
    {
        error!("Failed to allocate an aligned send buffer");
        return Err(Errno::ENOMEM);
    }

    nix::libc::memset(buffer_send, 0, send_recv_len);
    nix::libc::memset(buffer_recv, 0, send_recv_len);

    let buffer_send = Vec::from_raw_parts(buffer_send as *mut u8, send_recv_len, send_recv_len);
    let buffer_recv = Vec::from_raw_parts(buffer_recv as *mut u8, send_recv_len, send_recv_len);

    SEND_BUFFER
        .set(BufferType::MemAligned(buffer_send))
        .map_err(|_| {
            error!("Failed to set aligned send buffer");
            Errno::EFAULT
        })?;
    RECEIVE_BUFFER
        .set(BufferType::MemAligned(buffer_recv))
        .map_err(|_| {
            error!("Failed to set aligned receive buffer");
            Errno::EFAULT
        })?;

    libspdm::libspdm_rs::libspdm_register_device_buffer_func(
        context,
        libsdpm_buff_len as u32,
        libsdpm_buff_len as u32,
        Some(acquire_sender_buffer),
        Some(release_sender_buffer),
        Some(acquire_receiver_buffer),
        Some(release_receiver_buffer),
    );

    Ok(())
}

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
                SEND_BUFFER
                    .set(BufferType::Default(buffers.0))
                    .map_err(|_| {
                        error!("Failed to set send buffer");
                        ()
                    })?;
                RECEIVE_BUFFER
                    .set(BufferType::Default(buffers.1))
                    .map_err(|_| {
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
        let buf_ptr = buffer.into().as_ptr() as *mut c_void;
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
        let buf_ptr = buffer.into().as_ptr() as *mut c_void;
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
    if let Some(buffer) = SEND_BUFFER.take() {
        match buffer {
            BufferType::MemAligned(mut data) => {
                // SAFETY: This must be manually allocated
                nix::libc::free(data.as_mut_ptr() as *mut c_void);
                // SAFETY: Don't run the destructor => Double free
                std::mem::forget(data);
            }
            BufferType::Default(_) => {}
        }
    }

    if let Some(buffer) = RECEIVE_BUFFER.take() {
        match buffer {
            BufferType::MemAligned(mut data) => {
                // SAFETY: This must be manually allocated
                nix::libc::free(data.as_mut_ptr() as *mut c_void);
                // SAFETY: Don't run the destructor => Double free
                std::mem::forget(data);
            }
            BufferType::Default(_) => {}
        }
    }
}
