// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! This file provides support for SPDM interfacing to a NVMe device
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.
//!

use crate::*;
use core::ffi::c_void;
use core::ptr;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::{fstat, FileStat, Mode, SFlag};
use nix::unistd::close;
use once_cell::sync::OnceCell;
use std::slice::from_raw_parts;
use storage_standards::{SpcSecurityProtocols, SpdmOperationCodes};

/// Limit maximum transfers to 4k, if we allocate bigger IO buffers, we then need
/// to rely on kernel support mmap(2) with MAP_HUGETLB. To allocate aligned
/// and contiguos buffers.
const NVME_STORAGE_MSG_MAX_SIZE: usize = 4096;
const LIBSPDM_MAX_TRANSPORT_MSG_LEN: usize = NVME_STORAGE_MSG_MAX_SIZE;

static mut SEND_BUFFER: OnceCell<*mut c_void> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<*mut c_void> = OnceCell::new();
static mut NVME_DEV: OnceCell<NvmeDev> = OnceCell::new();
/// Transfer lengths must be DWORD Aligned.
const LIBNVME_RECV_ARG_MIN_AL_LEN: usize = 32;

/// # Summary
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
unsafe extern "C" fn nvme_send_message(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    timeout_us: u64,
) -> u32 {
    debug!("Sending NVMe Security Send: SPDM Message");
    let message = message_ptr as *const u8;
    let mut dptr = unsafe { from_raw_parts(message, message_size) }.to_vec();

    let mut dev = NVME_DEV
        .take()
        .expect("NVMe device lost or not initialized");

    // Setup a security receive command for security protocol discovery
    let mut cmd = match NvmeSecSendCmds::gen_libspdm_encoded_sec_send_args(&mut dptr, dev.nsid) {
        Ok(cmd) => cmd,
        Err(why) => {
            panic!("Failed to generate SPDM Message Command: {:?}", why)
        }
    };

    debug!("NVME Storage Message Cmd: {:?}", cmd);
    debug!("SPDM Request: {:x?}", &dptr[..message_size]);

    if let Err(why) = dev.nvme_sec_send(&mut cmd, timeout_us) {
        panic!("Failed to security send: {:?}", why);
    }

    NVME_DEV.set(dev).unwrap();

    0
}

/// # Summary
///
///
/// # Parameter
///
/// * `_context`: The SPDM context
/// * `message_size`: Returns the number of bytes received in this transaction
/// * `message_ptr`: A pointer to a data buffer of a minimum size of
///                 `LIBSPDM_MAX_TRANSPORT_MSG_LEN` to capture the received bytes.
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
unsafe extern "C" fn nvme_receive_message(
    context: *mut c_void,
    message_size: *mut usize,
    message_ptr: *mut *mut c_void,
    timeout_us: u64,
) -> u32 {
    debug!("Sending NVMe Security Receive: SPDM Message");

    let message = *message_ptr as *mut u8;
    let mut dev = NVME_DEV
        .take()
        .expect("NVMe device lost or not initialized");

    // Setup a security receive command for security protocol discovery
    let mut cmd = match NvmeSecRecvCmds::gen_libspdm_encoded_sec_recv_args(
        context,
        dev.nsid,
        message,
        *message_size,
    ) {
        Ok(cmd) => cmd,
        Err(why) => {
            panic!("Failed to generate SPDM Message Command: {:?}", why)
        }
    };

    debug!("NVME Storage Message Cmd: {:?}", cmd);

    if let Err(why) = dev.nvme_sec_recv(&mut cmd, timeout_us) {
        panic!("Failed to security receive: {:?}", why);
    }
    // Allow libspdm to do top-bottom SPDM message parsing, we don't know the
    // number of valid bytes in the reception buffer.
    *message_size = LIBSPDM_MAX_TRANSPORT_MSG_LEN;
    NVME_DEV.set(dev).unwrap();
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
/// (ENOMEM) if the buffer is not found
#[no_mangle]
unsafe extern "C" fn nvme_acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    match SEND_BUFFER.take() {
        Some(ptr) => *msg_buf_ptr = ptr,
        _ => {
            *msg_buf_ptr = ptr::null_mut();
            return Errno::ENOMEM as u32;
        }
    }
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
#[no_mangle]
unsafe extern "C" fn nvme_release_sender_buffer(_context: *mut c_void, msg_buf_ptr: *const c_void) {
    SEND_BUFFER.set(msg_buf_ptr as *mut c_void).unwrap();
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
/// (ENOMEM) if the buffer is not found
#[no_mangle]
unsafe extern "C" fn nvme_acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    match RECEIVE_BUFFER.take() {
        Some(ptr) => *msg_buf_ptr = ptr,
        _ => {
            *msg_buf_ptr = ptr::null_mut();
            return Errno::ENOMEM as u32;
        }
    }
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
#[no_mangle]
unsafe extern "C" fn nvme_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    RECEIVE_BUFFER.set(msg_buf_ptr as *mut c_void).unwrap();
}

/// # Summary
///
/// Free NVMe device IO buffers allocated, this shall only be called after an
/// SPDM session has been terminated.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// Ok(()) on success
/// Err(Errno) on failure to free either buffer
pub fn nvme_free_io_buffers() -> Result<(), Errno> {
    let mut buffer_lost = false;
    match unsafe { SEND_BUFFER.take() } {
        Some(ptr) => unsafe { nix::libc::free(ptr) },
        _ => {
            error!("Lost reference to NVMe Send Buffer");
            buffer_lost = true
        }
    }
    match unsafe { RECEIVE_BUFFER.take() } {
        Some(ptr) => unsafe { nix::libc::free(ptr) },
        _ => {
            error!("Lost reference to NVMe Receive Buffer");
            buffer_lost = true
        }
    }

    if buffer_lost {
        return Err(Errno::ENXIO);
    }
    Ok(())
}

/// # Summary
///
/// Setup device IO buffers and register the transport/IO functions to the
/// given libspdm @context.
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
pub fn register_device(context: *mut c_void, dev_path: &String, nsid: u32) -> Result<(), Errno> {
    let mut buffer_send: *mut c_void = ptr::null_mut();
    let mut buffer_recv: *mut c_void = ptr::null_mut();

    if LIBSPDM_MAX_TRANSPORT_MSG_LEN % page_size::get() != 0 {
        error!("Requested SEND/RECV buffer size is not target page size aligned");
        return Err(Errno::EINVAL);
    }

    if LIBSPDM_MAX_TRANSPORT_MSG_LEN > LIBSPDM_MAX_SPDM_MSG_SIZE as usize {
        error!("NVMe Transport buffers bigger than libspdm max supported");
        return Err(Errno::EINVAL);
    }

    let dev = NvmeDev::new(dev_path, nsid, OFlag::O_EXCL | OFlag::O_RDWR)
        .expect("Failed to establish a connection to the NVMe Controller");

    unsafe {
        // The buffers used for NVMe must be page aligned, hence we manually
        // allocate them here and keep a reference.
        if nix::libc::posix_memalign(
            &mut buffer_recv as *mut *mut c_void,
            page_size::get(),
            LIBSPDM_MAX_TRANSPORT_MSG_LEN,
        ) != 0
        {
            error!("Failed to allocate an aligned receive buffer");
            return Err(Errno::ENOMEM);
        }
        if nix::libc::posix_memalign(
            &mut buffer_send as *mut *mut c_void,
            page_size::get(),
            LIBSPDM_MAX_TRANSPORT_MSG_LEN,
        ) != 0
        {
            error!("Failed to allocate an aligned send buffer");
            return Err(Errno::ENOMEM);
        }

        nix::libc::memset(buffer_send, 0, LIBSPDM_MAX_TRANSPORT_MSG_LEN);
        nix::libc::memset(buffer_recv, 0, LIBSPDM_MAX_TRANSPORT_MSG_LEN);

        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_recv).unwrap();
        NVME_DEV.set(dev).unwrap();

        libspdm_register_device_io_func(
            context,
            Some(nvme_send_message),
            Some(nvme_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            LIBSPDM_MAX_TRANSPORT_MSG_LEN as u32,
            LIBSPDM_MAX_TRANSPORT_MSG_LEN as u32,
            Some(nvme_acquire_sender_buffer),
            Some(nvme_release_sender_buffer),
            Some(nvme_acquire_receiver_buffer),
            Some(nvme_release_receiver_buffer),
        );
    }

    Ok(())
}

#[derive(Debug)]
#[allow(dead_code)]
struct NvmeDev {
    fd: i32,
    nsid: u32,
    flags: OFlag,
    stat: Option<FileStat>,
}

impl NvmeDev {
    pub fn new(path: &String, nsid: u32, flags: OFlag) -> Result<NvmeDev, Errno> {
        let path = Path::new(path);

        info!("Getting device info for: {:?}", path);

        match open(path, flags, Mode::S_IRUSR) {
            Ok(fd) => {
                let mut dev = NvmeDev {
                    fd: fd,
                    nsid: nsid,
                    flags: flags,
                    stat: None,
                };

                match fstat(fd) {
                    Ok(fs) => {
                        let st_mode = fs.st_mode;
                        if !((SFlag::S_IFMT.bits() & st_mode) == SFlag::S_IFCHR.bits())
                            && !((SFlag::S_IFMT.bits() & st_mode) == SFlag::S_IFBLK.bits())
                        {
                            error!("{:?} is not a block or character device", path);
                            close(fd)?;
                            return Err(Errno::ENODEV);
                        }
                        dev.stat = Some(fs);
                    }
                    Err(e) => {
                        error!("Failed to do file stat for {:?}: {:?}", path, e);
                        close(fd)?;
                        return Err(e);
                    }
                }

                return Ok(dev);
            }
            Err(e) => {
                error!("Failed to open file {:?}: {:?}", path, e);
                return Err(e);
            }
        }
    }

    /// # Summary
    ///
    /// The Security Send command transfers the security protocol data to the
    /// controller. The data structure transferred to the controller as a part
    /// of this command contains security protocol specific commands to be
    /// performed by the controller.
    ///
    /// # Parameter
    ///
    /// * `cmd`: An initialized @nvme_security_send_args structure containing
    ///          all required security protocol data.
    /// * `timeout`: timeout to wait for in micro-seconds
    ///
    /// # Returns
    ///
    /// Ok(()) on success
    /// Err(error_code, nvme_cmd_completion_status):
    ///                   -1 with errno set, or if the response was received,
    ///                   nvme_cmd_completion_status set to indicate the failure.
    pub fn nvme_sec_send(
        &mut self,
        cmd: &mut nvme_security_send_args,
        timeout_us: u64,
    ) -> Result<(), i32> {
        cmd.fd = self.fd;
        if timeout_us == 0 || u32::try_from(timeout_us / 1_000).is_err() {
            cmd.timeout = NVME_DEFAULT_IOCTL_TIMEOUT;
        } else {
            // In nvme_security_send_args, timeout is represented in milliseconds
            // https://github.com/linux-nvme/libnvme/blob/5585f06a4f849a1b43b1a04f387d2f9b5829744f/src/nvme/api-types.h#L313
            cmd.timeout = u32::try_from(timeout_us / 1_000).unwrap();
        }
        // Call into libnvme
        let rc = unsafe { nvme_security_send(cmd as *mut nvme_security_send_args) };
        if rc != 0 {
            error!("Security send: rc: {:} errno: {:}", rc, Errno::last());
            return Err(rc);
        }
        debug!("Security Send Success");
        Ok(())
    }

    /// # Summary
    ///
    /// The Security Receive command is used to obtain a security response from
    /// the controller. This maybe used without a prior security send for actions
    /// such as storage security discovery (Mandatory support by specification).
    /// However, to obtain an SPDM response, it must follow a security send that
    /// issues an SPDM request to the controller.
    ///
    /// # Parameter
    ///
    /// * `cmd`: An initialized @nvme_security_receive_args structure
    ///          containing all required security protocol data.
    /// * `timeout_us`: Timeout in micro-seconds
    ///
    /// # Returns
    ///
    /// Ok(()) on success
    /// Err(error_code, nvme_cmd_completion_status):
    ///                   -1 with errno set, or if the response was received,
    ///                   nvme_cmd_completion_status set to indicate the failure.
    pub fn nvme_sec_recv(
        &mut self,
        cmd: &mut nvme_security_receive_args,
        timeout_us: u64,
    ) -> Result<(), i32> {
        cmd.fd = self.fd;
        if timeout_us == 0 || u32::try_from(timeout_us / 1_000).is_err() {
            cmd.timeout = NVME_DEFAULT_IOCTL_TIMEOUT;
        } else {
            // In nvme_security_send_args, timeout is represented in milliseconds
            // https://github.com/linux-nvme/libnvme/blob/5585f06a4f849a1b43b1a04f387d2f9b5829744f/src/nvme/api-types.h#L313
            cmd.timeout = u32::try_from(timeout_us / 1_000).unwrap();
        }
        // Call into libnvme
        let rc = unsafe { nvme_security_receive(cmd as *mut nvme_security_receive_args) };
        if rc != 0 {
            error!("Security receive: CQE: {:} errno: {:}", rc, Errno::last());
            return Err(rc);
        }
        debug!("Security Receive Success");
        Ok(())
    }
}

impl Drop for NvmeDev {
    /// # Summary
    ///
    /// Close the underlying file-descriptor when this instance goes out of scope
    ///
    /// # Panics
    ///
    /// If the device file-descriptor was not set.
    fn drop(&mut self) {
        // This fd is valid as `self` does not exist on any failures
        // to `open()` the NVMe device.
        close(self.fd).expect("failed to NVMe close device file-descriptor");
        debug!("NVMe device file-descriptor successfully closed");
    }
}

struct NvmeSecSendCmds;
struct NvmeSecRecvCmds;

impl NvmeSecSendCmds {
    /// # Summary
    ///
    /// Generates an @nvme_security_send_args suitable for an `SPDM Storage
    /// Message`. @dptr shall be the message buffer that contains the SPDM
    /// request data (with transport encoding from libspdm).
    ///
    /// # Note
    ///
    ///  A mutable reference to @dptr is stored within the returned struct, thus,
    ///  the underlying memory pointed to by @dptr must not be free(d) until
    ///  after the data is transferred. Ex: after invoking `nvme_security_send()`.
    ///
    /// # Parameter
    ///
    /// * `dptr`: A vector containing the SPDM request message (crosses FFI,
    ///           i.e must be heap allocated).
    /// * `nsid`: NVMe namespace identifier.
    ///
    /// # Returns
    ///
    /// Returns an initialised @nvme_security_send_args suitable for use for an
    /// `NVMe Security Receive` command for an SPDM request.
    ///
    /// Returns Err(ENOMSG), if @dptr is empty
    pub fn gen_libspdm_encoded_sec_send_args(
        dptr: &mut Vec<u8>,
        nsid: u32,
    ) -> Result<nvme_security_send_args, Errno> {
        if dptr.len() == 0 || dptr.len() < LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize {
            // Nothing to send
            return Err(Errno::ENOMSG);
        }

        let trans_hdr = unsafe { *(dptr.as_mut_ptr() as *mut storage_spdm_transport_header) };
        assert_eq!(
            trans_hdr.security_protocol,
            u8::from(SpcSecurityProtocols::DmtfSpdm)
        );
        assert_eq!(trans_hdr.inc_512, false);
        let spsp0: u8;
        let spsp1: u8;
        if cfg!(target_endian = "big") {
            spsp0 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
            spsp1 = (trans_hdr.security_protocol_specific >> 8) as u8;
        } else {
            spsp0 = (trans_hdr.security_protocol_specific >> 8) as u8;
            spsp1 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
        }
        // Strip the transport header, only send the SPDM message.
        // The transport relevant SPDM data is passed through the storage API.
        let transfer_len = u32::from_be(trans_hdr.length) as usize
            - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize;
        if transfer_len <= 0 {
            return Err(Errno::ENOMSG);
        }
        // Setup a security send command for an SPDM message
        let args = nvme_security_send_args {
            args_size: core::ffi::c_int::try_from(std::mem::size_of::<nvme_security_send_args>())
                .unwrap(),
            fd: 0, // Set at transport level
            nsid: nsid,
            nssf: 0, //RSVD
            spsp0: spsp0,
            spsp1: spsp1,
            secp: trans_hdr.security_protocol,
            tl: u32::try_from(transfer_len).unwrap(),
            data_len: u32::try_from(transfer_len).unwrap(),
            data: unsafe {
                dptr.as_mut_ptr()
                    .add(LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize)
                    as *mut c_void
            },
            timeout: 0, // Set at transport
            result: ptr::null_mut(),
        };

        Ok(args)
    }
}

impl NvmeSecRecvCmds {
    /// # Summary
    ///
    /// Generates an @nvme_security_receive_args suitable for an `SPDM Storage
    /// Message` by using `libspdm` for transport encoding. This is suitable for
    /// use in the libspdm message receive handler.
    ///
    /// @dptr shall be the message buffer into to which an SPDM response shall
    /// be copied to, from the NVMe controller. As an SPDM Response maybe of
    /// arbitrary size, a vector of capacity `LIBSPDM_MAX_TRANSPORT_MSG_LEN` is
    /// enforced, to accommodate the worst case scenario.
    ///
    /// # Note
    ///
    ///  A mutable reference to @dptr is stored within the returned struct, thus,
    ///  the underlying memory pointed to by @dptr must not be free(d) until
    ///  after the data is received. Ex: after invoking `nvme_security_receive()`.
    ///
    /// # Parameter
    ///
    /// * `dptr`: A vector containing the SPDM request message (crosses FFI,
    ///           i.e must be heap allocated).
    /// * `nsid`: NVMe namespace identifier.
    /// * `message`: libspdm message buffer
    /// * `message_size`: libspdm message buffer size
    ///
    /// # Returns
    ///
    /// Returns an initialised @nvme_security_receive_args suitable for use for an
    /// `NVMe Security Receive` command for an SPDM request.
    ///
    /// Returns Err(ENOMEM) if @dptr does not mean size requirements.
    pub fn gen_libspdm_encoded_sec_recv_args(
        context: *mut c_void,
        nsid: u32,
        message: *mut u8,
        message_size: usize,
    ) -> Result<nvme_security_receive_args, Errno> {
        // Setup a security receive command for an SPDM message
        let mut args = nvme_security_receive_args {
            args_size:
                core::ffi::c_int::try_from(std::mem::size_of::<nvme_security_receive_args>())
                    .unwrap(),
            fd: 0, // Set at transport level
            nsid: nsid,
            nssf: 0, //RSVD
            spsp0: 0,
            spsp1: 0, // RSVD
            secp: 0,
            al: LIBSPDM_MAX_TRANSPORT_MSG_LEN as u32,
            data_len: 0,
            data: message as *mut c_void,
            timeout: 0, // Set at transport
            result: ptr::null_mut(),
        };

        let mut transport_message_len = message_size;
        let mut transport_message = ptr::null_mut();

        unsafe {
            let context = context as *mut libspdm_context_t;
            assert!(
                libspdm_transport_storage_encode_message(
                    context as *mut c_void,
                    ptr::null(),
                    false,
                    true,
                    message_size - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize,
                    message as *mut _ as *mut c_void,
                    &mut transport_message_len,
                    &mut transport_message as *mut *mut c_void,
                ) == 0
            );
        }

        assert!(transport_message_len >= LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize);
        let trans_hdr =
            unsafe { *(transport_message as *const u8 as *mut storage_spdm_transport_header) };
        assert_eq!(
            trans_hdr.security_protocol,
            u8::from(SpcSecurityProtocols::DmtfSpdm)
        );
        assert_eq!(trans_hdr.inc_512, false);
        // Update based on libspdm encoded data
        args.secp = trans_hdr.security_protocol;
        // libspdm uses the host-byte order.
        if cfg!(target_endian = "big") {
            args.spsp0 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
            args.spsp1 = (trans_hdr.security_protocol_specific >> 8) as u8;
        } else {
            args.spsp0 = (trans_hdr.security_protocol_specific >> 8) as u8;
            args.spsp1 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
        }

        assert!(args.spsp0 != 0);
        assert!(args.spsp1 == 0);
        assert!(LIBSPDM_MAX_TRANSPORT_MSG_LEN % page_size::get() == 0);
        args.data_len = LIBSPDM_MAX_TRANSPORT_MSG_LEN as u32;

        Ok(args)
    }

    pub fn gen_libspdm_encoded_discovery_request_args(
        dptr: &mut Vec<u8>,
        nsid: u32,
    ) -> Result<nvme_security_receive_args, Errno> {
        if dptr.len() < LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize {
            return Err(Errno::ENOMEM);
        }

        if dptr.len() < LIBNVME_RECV_ARG_MIN_AL_LEN {
            // Quirk: The dptr allocation length must be atleast 32 bytes,
            // seeems to be an api limitation (?). The cmd will timeout otherwise.
            return Err(Errno::ENOMEM);
        }

        let conn_id: u8 = 0;
        // Setup a security send command for an SPDM message
        let mut args = nvme_security_receive_args {
            args_size:
                core::ffi::c_int::try_from(std::mem::size_of::<nvme_security_receive_args>())
                    .unwrap(),
            fd: 0, // Set at transport level
            nsid: nsid,
            nssf: 0, //RSVD
            spsp0: 0,
            spsp1: 0, // RSVD
            secp: 0,
            al: 0,
            data_len: 0,
            data: dptr.as_mut_ptr() as *mut c_void,
            timeout: 0, // Set at transport
            result: ptr::null_mut(),
        };

        let mut transport_message_len: usize = dptr.len() as usize;
        let mut allocation_len: usize = 0;

        let rc = unsafe {
            libspdm_transport_storage_encode_management_cmd(
                u8::try_from(LIBSPDM_STORAGE_CMD_DIRECTION_IF_RECV).unwrap(),
                SpdmOperationCodes::SpdmStorageDiscovery as u8,
                conn_id,
                &mut transport_message_len,
                &mut allocation_len,
                dptr.as_mut_ptr() as *mut c_void,
            )
        };

        if !spdm::LibspdmReturnStatus::libspdm_status_is_success(rc) {
            panic!("libspdm failed to encode transport: {:x}", rc);
        }

        let trans_hdr = unsafe { *(dptr.as_mut_ptr() as *mut storage_spdm_transport_header) };

        // Update based on libspdm encoded data
        args.secp = trans_hdr.security_protocol;
        // libspdm uses the host-byte order.
        if cfg!(target_endian = "big") {
            args.spsp0 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
            args.spsp1 = (trans_hdr.security_protocol_specific >> 8) as u8;
        } else {
            args.spsp0 = (trans_hdr.security_protocol_specific >> 8) as u8;
            args.spsp1 = (trans_hdr.security_protocol_specific & 0xFF) as u8;
        }
        let transport_message_len = u32::from_be(trans_hdr.length);
        assert!(args.spsp0 != 0);
        assert!(args.spsp1 == 0);
        assert!(transport_message_len as usize <= dptr.len());
        assert!(transport_message_len != 0);
        assert!(transport_message_len != 0);

        args.al = std::cmp::max(allocation_len as u32, LIBNVME_RECV_ARG_MIN_AL_LEN as u32);
        args.data_len = std::cmp::max(transport_message_len, LIBNVME_RECV_ARG_MIN_AL_LEN as u32);

        Ok(args)
    }
}

/// # Summary
///
/// Fetch supported security protocols from the NVMe device. This should be used
/// prior to `register_device()` to ensure that the NVMe controller supports
/// SPDM over storage.
///
/// # Note
///
/// This function operates independantely, that is, when it returns it closes
/// the `fd` associated with the controller.
///
/// # Parameter
///
/// * `path: path to the device
/// * `nsid`: name-space identifier
///
/// # Returns
///
/// Ok(()), on success
/// Err(Errno::ENOTSUP), is DMTF SPDM is not supported
pub fn nvme_get_sec_info(path: &String, nsid: u32) -> Result<(), Errno> {
    let mut dev = NvmeDev::new(path, nsid, OFlag::O_EXCL | OFlag::O_RDONLY)?;
    let mut dptr = vec![0; 64];

    let mut sec_recv_args =
        NvmeSecRecvCmds::gen_libspdm_encoded_discovery_request_args(&mut dptr, nsid)?;

    debug!(
        "Security Receive Command Discovery Request: {:?}",
        sec_recv_args
    );

    // Receive the discovery response
    if dev.nvme_sec_recv(&mut sec_recv_args, 0).is_err() {
        return Err(Errno::EIO);
    }

    info!("--- SPDM Storage Discovery Start ---");

    let data_len = u16::from_be_bytes(dptr[..2].try_into().unwrap());
    let storage_binding_version = u16::from_be_bytes(dptr[2..4].try_into().unwrap());
    let max_connection_id = dptr[4] & 0b11;
    let supported_operations = dptr[8];

    info!(" Available bytes in SPDM Storage Data: {:}", data_len);
    info!(" Storage Binding Version: 0x{:x}", storage_binding_version);
    info!(" Max num connections: {:}", max_connection_id);
    if max_connection_id == 0 {
        info!("     - A value of 0 indicates 1 connection");
    }
    info!(" Supported Opertations:");

    if supported_operations & (1 << SpdmOperationCodes::SpdmStorageDiscovery as u8) != 0 {
        info!("     SpdmStorageDiscovery - Supported");
    } else {
        error!("    Device does not support mandatory SpdmStorageDiscovery");
        return Err(Errno::ENOTSUP);
    }

    if supported_operations & (1 << SpdmOperationCodes::SpdmStorageMessage as u8) != 0 {
        info!("     SpdmStorageMessage - Supported");
    } else {
        error!("    Device does not support mandatory SpdmStorageMessage");
        return Err(Errno::ENOTSUP);
    }

    if supported_operations & (1 << SpdmOperationCodes::SpdmStoragePendingInfo as u8) != 0 {
        info!("     SpdmStoragePendingInfo - Supported");
    }
    if supported_operations & (1 << SpdmOperationCodes::SpdmStorageSecMessage as u8) != 0 {
        info!("     SpdmStorageSecMessage - Supported");
    }

    info!("--- SPDM Storage Discovery Response End ---");

    Ok(())
}