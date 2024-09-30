// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! This file provides support for SPDM interfacing to a SCSI device
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.
//!

// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

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
use nix::libc::ioctl;
use nix::sys::stat::{stat, Mode, SFlag};
use nix::unistd::close;
use once_cell::sync::OnceCell;
use std::slice::{from_raw_parts, from_raw_parts_mut};

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;
static mut SEND_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
static mut RECEIVE_BUFFER: OnceCell<[u8; SEND_RECEIVE_BUFFER_LEN]> = OnceCell::new();
// Global reference to the device instance to reduce sys-call overhead.
// The execution context is already unsafe, what's the worst that could happen!
static mut SCSI_DEV: OnceCell<BlkDev> = OnceCell::new();

const SG_SENSE_MAX_LENGTH: u8 = 64;
const SG_BUF_MAX_SIZE: u32 = SEND_RECEIVE_BUFFER_LEN as u32;
const SG_CDB_MAX_SIZE: u8 = 32;
const SG_CDB_DEFAULT_SIZE: u8 = 16;
const SCSI_SEC_IN_OUT_CDB_LEN: usize = 12;

/*
 * Status codes.
 */
const _SG_CHECK_CONDITION: u8 = 0x02;

/*
 * Host status codes.
 */
const SG_DID_OK: u16 = 0x00; /* No error */
const _SG_DID_NO_CONNECT: u16 = 0x01; /* Couldn't connect before timeout period */
const _SG_DID_BUS_BUSY: u16 = 0x02; /* BUS stayed busy through time out period */
const SG_DID_TIME_OUT: u16 = 0x03; /* Timed out for other reason */
const _SG_DID_BAD_TARGET: u16 = 0x04; /* Bad target, device not responding? */
const _SG_DID_ABORT: u16 = 0x05; /* Told to abort for some other reason. */
const _SG_DID_PARITY: u16 = 0x06; /* Parity error. */
const _SG_DID_ERROR: u16 = 0x07; /* Internal error detected in the host adapter. */
const _SG_DID_RESET: u16 = 0x08; /* The SCSI bus (or this device) has been reset. */
const _SG_DID_BAD_INTR: u16 = 0x09; /* Got an unexpected interrupt */
const _SG_DID_PASSTHROUGH: u16 = 0x0a; /* Forced command past mid-layer. */
const _SG_DID_SOFT_ERROR: u16 = 0x0b; /* The low level driver wants a retry. */

/*
 * Driver status codes.
 */
const _SG_DRIVER_OK: u16 = 0x00;
const _SG_DRIVER_BUSY: u16 = 0x01;
const _SG_DRIVER_SOFT: u16 = 0x02;
const _SG_DRIVER_MEDIA: u16 = 0x03;
const _SG_DRIVER_ERROR: u16 = 0x04;
const _SG_DRIVER_INVALID: u16 = 0x05;
const _SG_DRIVER_TIMEOUT: u16 = 0x06;
const _SG_DRIVER_HARD: u16 = 0x07;
const SG_DRIVER_SENSE: u16 = 0x08;
const SG_DRIVER_STATUS_MASK: u16 = 0x0f;

/*
* Device Flags
*/
const DEV_VENDOR_LEN: usize = 9;
const DEV_ID_LEN: usize = 17;
const DEV_REV_LEN: usize = 5;

static mut DEV_PATH: OnceCell<String> = OnceCell::new();

#[allow(dead_code)]
struct SgCmd {
    bufsz: u32,
    io_hdr: sg_io_hdr_t,
    sense_key: u8,
    asc_ascq: u16,
    cmdp: Vec<u8>,
    dxferp: Vec<u8>,
    sbp: Vec<u8>,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct BlkDev<'a> {
    fd: Option<i32>,
    flags: OFlag,
    path: &'a Path,
}

impl BlkDev<'_> {
    /// # Summary
    ///
    /// Create and return device structure to the SCSI device pointed to by
    /// @path, where the underlying fd is opened with @flags.
    ///
    /// # Parameter
    ///
    /// * `path: path to the device
    /// * `flags`: flags for the device to use on `open()`
    ///
    /// # Returns
    ///
    /// Err(Errno) on failure
    /// Ok(BlkDev) on success, containing the file-descriptor for the device
    fn new(path: &String, flags: OFlag) -> Result<BlkDev, Errno> {
        let path = Path::new(path);
        let st = stat(path);
        info!("Getting device info for: {:?}", path);
        if let Err(e) = st {
            error!("Failed to get stat at {:?}: {}:?", path, e);
            return Err(e);
        }

        let st = st.unwrap();
        let st_mode = st.st_mode;

        if !((SFlag::S_IFMT.bits() & st_mode) == SFlag::S_IFCHR.bits())
            && !((SFlag::S_IFMT.bits() & st_mode) == SFlag::S_IFBLK.bits())
        {
            error!("Invalid device file {:?}", path);
            return Err(Errno::EIO);
        }

        match open(path, flags, Mode::S_IRWXU) {
            Ok(fd) => {
                return Ok(BlkDev {
                    fd: Some(fd),
                    flags: flags,
                    path: path,
                });
            }
            Err(e) => {
                error!("Failed to open file {:?}: {:?}", path, e);
                return Err(e);
            }
        }
    }
}

impl Drop for BlkDev<'_> {
    /// # Summary
    ///
    /// Close the underlying file-descriptor when this instance goes out of scope
    fn drop(&mut self) {
        if let Some(fd) = self.fd {
            close(fd).expect("failed to close device fd");
            return;
        }
        unreachable!("device fd was not set!");
    }
}

/// SCSI Primary Commands
pub enum CmdType {
    /// Inquire the device server for basic device information
    Inquiry,
    /// Requests the device server to return security protocol information
    /// For SPDM: this is IF-RECV:
    /// "Generic term for a security related command that transfers data
    /// from the target to the initiator. For NVMe, this is Security
    /// Receive. For SAS, this is SECURITY PROTOCOL IN. For SATA, this is
    /// TRUSTED RECEIVE and TRUSTED RECEIVE DMA." -
    /// https://github.com/DMTF/SPDM-WG/blob/master/docs/DSP0286/DSP0286.md#SPC-6
    SecurityProtocolIn,
    /// Requests the device server to process the specified parameter
    /// list using the specified security protocol. For SPDM:
    /// this is IF-SEND: "Generic term for a security related command that
    /// transfers data from the initiator to the target.
    /// For NVMe, this is Security Send. For SAS, this is
    /// SECURITY PROTOCOL OUT. For SATA, this is TRUSTED SEND and
    /// TRUSTED SEND DMA." -
    /// https://github.com/DMTF/SPDM-WG/blob/master/docs/DSP0286/DSP0286.md#SPC-6
    SecurityProtocolOut,
}

impl From<CmdType> for u8 {
    fn from(c: CmdType) -> Self {
        match c {
            CmdType::Inquiry => 0x12,
            CmdType::SecurityProtocolIn => 0xA2,
            CmdType::SecurityProtocolOut => 0xB5,
        }
    }
}

/// Relevant Security Protocols as specified in Working Draft SCSI Primary
/// Commands - 6 (SPC-6)
#[derive(Debug, PartialEq)]
pub enum SpcSecurityProtocols {
    SecurityProtocolInformation,
    DmtfSpdm,
}

impl From<SpcSecurityProtocols> for u8 {
    fn from(c: SpcSecurityProtocols) -> Self {
        match c {
            SpcSecurityProtocols::SecurityProtocolInformation => 0x00,
            SpcSecurityProtocols::DmtfSpdm => 0xE8,
        }
    }
}

impl TryFrom<u8> for SpcSecurityProtocols {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x00 => Ok(SpcSecurityProtocols::SecurityProtocolInformation),
            0xE8 => Ok(SpcSecurityProtocols::DmtfSpdm),
            _ => Err(()),
        }
    }
}

impl SgCmd {
    fn new(cdb_len: u8, direction: i32, bufsz: u32) -> Result<SgCmd, Errno> {
        if bufsz > SG_BUF_MAX_SIZE {
            return Err(Errno::EINVAL);
        }
        /* Setup SGIO header. sg_io_hdr_t has no Default type but can be zero
         * initialize and update it's internal references later.
         */
        let mut sg_io_hdr: sg_io_hdr_t = unsafe { std::mem::zeroed() };
        // 'S' for SCSI generic/SG (required)
        sg_io_hdr.interface_id = b'S' as i32;
        sg_io_hdr.timeout = 30000;
        // At tail
        sg_io_hdr.flags = 0x10;

        if cdb_len != 0 {
            if cdb_len > SG_CDB_MAX_SIZE {
                return Err(Errno::E2BIG);
            }
            sg_io_hdr.cmd_len = cdb_len;
        } else {
            sg_io_hdr.cmd_len = SG_CDB_DEFAULT_SIZE;
        }

        sg_io_hdr.dxfer_direction = direction;
        sg_io_hdr.dxfer_len = bufsz;
        sg_io_hdr.mx_sb_len = SG_SENSE_MAX_LENGTH;

        let mut sg_cmd = SgCmd {
            bufsz,
            io_hdr: sg_io_hdr,
            sense_key: 0,
            asc_ascq: 0,
            // Must be heap allocated for FFI compatibility with C
            // io_hdr.cmdp = cdb
            cmdp: vec![0; SG_CDB_MAX_SIZE as usize],
            // io_hdr.dxferp = buf
            dxferp: vec![0; SG_BUF_MAX_SIZE as usize],
            // io_hdr.sbp = sense_buf
            sbp: vec![0; SG_SENSE_MAX_LENGTH as usize],
        };

        sg_cmd.set_io_buffer_ptrs();

        Ok(sg_cmd)
    }

    /// # Summary
    ///
    /// Generate an Inquiry commands to retrieve basic information from the
    /// device.
    ///
    /// # Parameter
    ///
    /// * `cdb_len`: Command data block length
    /// * `direction`: SG IO direction
    /// * `bufsz`: Data buffer size
    ///
    /// # Returns
    ///
    /// Ok(SgCmd), An initialised command structure
    /// Err(Errno), An error representing the cause of failure
    fn gen_dev_inquiry_info(cdb_len: u8, direction: i32, bufsz: u16) -> Result<SgCmd, Errno> {
        let mut sg_cmd = SgCmd::new(cdb_len, direction, bufsz as u32)?;

        // Setup Inquiry Command
        // OpCode
        sg_cmd.cmdp[0] = CmdType::Inquiry.into();
        // Allocation Bytes
        sg_cmd.cmdp[3..=4].copy_from_slice(&(bufsz.to_be_bytes()));

        Ok(sg_cmd)
    }

    /// # Summary
    ///
    /// Generate an IF-SEND/SECURITY_IN command with the subcommand argument
    /// specified to fetch the list of supported security protocols from the
    /// device.
    ///
    /// # Parameter
    ///
    /// * `cdb_len`: Command data block length
    /// * `direction`: SG IO direction
    /// * `bufsz`: Data buffer size
    ///
    /// # Returns
    ///
    /// Ok(SgCmd), An initialised command structure
    /// Err(Errno), An error representing the cause of failure
    fn gen_security_protocols_list(
        cdb_len: u8,
        direction: i32,
        bufsz: u32,
    ) -> Result<SgCmd, Errno> {
        let mut sg_cmd = SgCmd::new(cdb_len, direction, bufsz)?;

        // Setup Security In Command for protocol inquiry
        // OpCode
        sg_cmd.cmdp[0] = CmdType::SecurityProtocolIn.into();
        // Security Protocol
        sg_cmd.cmdp[1] = SpcSecurityProtocols::SecurityProtocolInformation.into();
        // Security Protocol Specific
        // https://github.com/DMTF/SPDM-WG/blob/master/docs/DSP0286/DSP0286.md#command-management
        // Table: 4 and 5 in Command management.
        // This should be updated at the transport level, at this stage
        // we don't know the message type/connection type.
        sg_cmd.cmdp[2] = 0x00; // Operation - TBD (unknown at this stage)
        sg_cmd.cmdp[3] = 0x00; // Reserved
        sg_cmd.cmdp[4] = 0x00; // Not using increments of 512B in allocation length
                               // Allocation Length Bytes
        sg_cmd.cmdp[6..=9].copy_from_slice(&((bufsz as u32).to_be_bytes()));
        // Control, TODO: Don't need (?)
        sg_cmd.cmdp[11] = 0x00;

        Ok(sg_cmd)
    }

    /// # Summary
    ///
    /// Use the transport header generated by `libspdm` to generate a SCSI
    /// Security Protocol Out command.
    ///
    /// # Parameter
    ///
    /// * `cdb_len`: Command data block length
    /// * `direction`: SG IO direction
    /// * `bufsz`: Data buffer size
    /// * `header`: libspdm encoded spdm storage transport header
    ///
    /// # Returns
    ///
    /// Ok(SgCmd), An initialised command structure
    /// Err(Errno), An error representing the cause of failure
    fn gen_libspdm_request(
        cdb_len: u8,
        direction: i32,
        bufsz: u32,
        header: &mut [u8; LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize],
    ) -> Result<SgCmd, Errno> {
        let mut sg_cmd = SgCmd::new(cdb_len, direction, bufsz)?;
        let hdr = unsafe { *(header.as_mut_ptr() as *mut storage_spdm_transport_header) };

        // Setup Security Out Command for SPDM request [IF-SEND]
        // OpCode
        sg_cmd.cmdp[0] = CmdType::SecurityProtocolOut.into();
        sg_cmd.cmdp[1] = hdr.security_protocol;
        // TODO: these will need to be `to_be()` when libspdm is updated
        sg_cmd.cmdp[2] = (hdr.security_protocol_specific & 0xFF) as u8;
        sg_cmd.cmdp[3] = (hdr.security_protocol_specific >> 8) as u8;
        sg_cmd.cmdp[4] = 0;
        sg_cmd.cmdp[5] = 0;

        // Transfer Length
        let length = u32::from_be(hdr.length);
        assert!(length > LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE);
        let transfer_len = length as usize - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize;
        sg_cmd.cmdp[6] = (transfer_len >> 24) as u8;
        sg_cmd.cmdp[7] = (transfer_len >> 16) as u8;
        sg_cmd.cmdp[8] = (transfer_len >> 8) as u8;
        sg_cmd.cmdp[9] = (transfer_len & 0xFF) as u8;
        sg_cmd.cmdp[10] = 0;
        sg_cmd.cmdp[11] = 0;

        Ok(sg_cmd)
    }

    /// # Summary
    ///
    /// Generate an IF-RECV/SECURITY_IN command to fetch an SPDM response.
    /// This should be used when a response is expected from the target device.
    ///
    /// * `cdb_len`: Command data block length
    /// * `direction`: SG IO direction
    /// * `bufsz`: Data buffer size
    /// * `message`: response buffer
    /// * `message_size`: response buffer size
    ///
    /// # Returns
    ///
    /// Ok(SgCmd), An initialised command structure
    /// Err(Errno), An error representing the cause of failure
    fn gen_libspdm_response(
        cdb_len: u8,
        direction: i32,
        bufsz: u32,
        message: *mut u8,
        message_size: usize,
    ) -> Result<SgCmd, Errno> {
        let mut sg_cmd = SgCmd::new(cdb_len, direction, bufsz)?;
        let header_len = LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize;
        let mut transport_message_len = message_size;
        // We pass a pointer to this pointer when calling `libspdm_storage_encode_message()`
        // and buf_ptr ends up being changed to point at a section of `reply` in libspdm.
        let mut transport_message = ptr::null_mut();

        unsafe {
            libspdm_storage_encode_message(
                ptr::null_mut(),
                0,
                message_size - header_len,
                message as *mut _ as *mut c_void,
                &mut transport_message_len,
                &mut transport_message as *mut *mut c_void,
            )
        };

        let transp_msg = unsafe { from_raw_parts_mut(transport_message, transport_message_len) };
        let hdr = unsafe { *(transp_msg.as_mut_ptr() as *mut storage_spdm_transport_header) };

        // Setup Security In Command for SPDM response [IF-RECV]
        // OpCode
        sg_cmd.cmdp[0] = CmdType::SecurityProtocolIn.into();
        sg_cmd.cmdp[1] = hdr.security_protocol;
        // TODO: these will need to be `to_be()` when libspdm is updated
        sg_cmd.cmdp[2] = (hdr.security_protocol_specific & 0xFF) as u8;
        sg_cmd.cmdp[3] = (hdr.security_protocol_specific >> 8) as u8;
        sg_cmd.cmdp[4] = 0;
        sg_cmd.cmdp[5] = 0;

        // Allocation Length
        let length = u32::from_be(hdr.length);
        assert!(length > LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE);
        let allocation_len = length as usize - LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize;
        sg_cmd.cmdp[6] = (allocation_len >> 24) as u8;
        sg_cmd.cmdp[7] = (allocation_len >> 16) as u8;
        sg_cmd.cmdp[8] = (allocation_len >> 8) as u8;
        sg_cmd.cmdp[9] = (allocation_len & 0xFF) as u8;
        sg_cmd.cmdp[10] = 0;
        sg_cmd.cmdp[11] = 0;

        Ok(sg_cmd)
    }

    /// # Summary
    ///
    /// Sets the buffer pointers in SgCmd.io_hdr to point to heap allocated
    /// io buffers in SgCmd. These buffers must be heap allocated for FFI
    /// compatibility with C. Behavior maybe undefined otherwise.
    ///
    /// # Returns
    ///
    /// Ok(()), on success
    /// Err(()), if io_hdr is None
    fn set_io_buffer_ptrs(&mut self) {
        self.io_hdr.cmdp = self.cmdp.as_mut_ptr();
        self.io_hdr.dxferp = self.dxferp.as_mut_ptr() as *mut c_void;
        self.io_hdr.sbp = self.sbp.as_mut_ptr();
    }

    /// # Summary
    ///
    /// Execute a command to the device using `ioctl`. The command must be
    /// setup/generated prior invoking this method.
    ///
    /// # Parameter
    ///
    /// * `fd: file-descriptor to the device, not that is must be opened
    ///         with the correct flags for the command.
    ///
    /// # Returns
    ///
    /// Err(Errno), on failure
    /// Ok(()), on success
    fn scsi_cmd_exec(&mut self, fd: i32) -> Result<(), Errno> {
        let rc = unsafe { ioctl(fd, SG_IO as u64, &mut self.io_hdr as *mut _ as *mut c_void) };
        if rc != 0 {
            let rc = Errno::last();
            error!("SG_IO ioctl failed: {}", rc);
            return Err(rc);
        }

        if self.io_hdr.status != 0
            || self.io_hdr.host_status != SG_DID_OK
            || ((self.io_hdr.driver_status & SG_DRIVER_STATUS_MASK != 0)
                && (self.io_hdr.driver_status & SG_DRIVER_STATUS_MASK != SG_DRIVER_SENSE))
        {
            if self.io_hdr.host_status == SG_DID_TIME_OUT {
                error!("SCSI command failed (timeout)");
                return Err(Errno::ETIMEDOUT);
            }

            error!("SCSI command failed");
            return Err(Errno::EIO);
        }

        if self.io_hdr.resid != 0 {
            self.bufsz = self.bufsz
                - u32::try_from(self.io_hdr.resid)
                    .expect("unexpected overflow converting i32 to u32");
        }
        return Ok(());
    }
}

/// # Summary
///
/// Given a fulfilled sense response from the device, log the Sense Key, ASC
/// and ASCQ and return the sense_key and asc_ascq concatenated.
///
/// # Parameter
///
/// * `path: path to the device
///
/// # Returns
///
/// Some<(sense_key, asc_ascq)>, if valid
/// None, if not set
fn log_and_get_sense(cmd: &SgCmd) -> Option<(u8, u16)> {
    if ((cmd.sbp[0] & 0x7F) == 0x72) || ((cmd.sbp[0] & 0x7F) == 0x73) {
        let sense_key = cmd.sbp[1] & 0x0F;
        let asc_ascq = ((cmd.sbp[2] as u16) << 8) | cmd.sbp[3] as u16;
        warn!("sense_key: 0x{sense_key:x?}");
        warn!("asc_ascq: 0x{asc_ascq:x?}");
        return Some((sense_key, asc_ascq));
    }

    if ((cmd.sbp[0] & 0x7F) == 0x70) || ((cmd.sbp[0] & 0x7F) == 0x71) {
        let sense_key = cmd.sbp[2] & 0x0F;
        let asc_ascq = ((cmd.sbp[12] as u16) << 8) | cmd.sbp[13] as u16;
        warn!("sense_key: 0x{sense_key:x?}");
        warn!("asc_ascq: 0x{asc_ascq:x?}");
        return Some((sense_key, asc_ascq));
    }
    debug!("No sense detected");
    None
}

/// # Summary
///
/// Generate a command to request a list of supported security protocols by the
/// device. We check for SPDM support.
///
/// # Parameter
///
/// * `path: path to the device
///
/// # Returns
///
/// Ok(()), on success
/// Err(Errno), on any errors
pub fn cmd_scsi_get_sec_info(path: &String) -> Result<(), Errno> {
    // 1. Open device
    let dev = BlkDev::new(path, OFlag::O_RDWR)?;
    // The actual buffer has a fixed length much larger
    let bufsz = 256;
    // 2. Generate command
    let mut cmd = SgCmd::gen_security_protocols_list(0, SG_DXFER_FROM_DEV, bufsz)?;
    // 3. Execute CMD
    if let Some(fd) = &dev.fd {
        if let Err(e) = cmd.scsi_cmd_exec(*fd) {
            if let Some((sense_key, asc_ascq)) = log_and_get_sense(&cmd) {
                if sense_key == 0x06 && asc_ascq == 0x2900 {
                    // This is a Power ON/Reset/Bus Reset condition, maybe the drive
                    // wasn't initialized. Retry the command, if it fails again,
                    // let the caller handle it.
                    warn!("Sense Condition: Power On/Reset detected");
                    cmd.scsi_cmd_exec(*fd)?;
                } else {
                    return Err(Errno::ENXIO);
                }
            } else {
                return Err(e);
            }
        }
    } else {
        return Err(Errno::ENXIO);
    }

    let sec_prot_list_len: u16 = u16::from_be_bytes(
        cmd.dxferp[6..=7]
            .try_into()
            .expect("failed to split slice into constant size array"),
    );

    info!("--- Security Info List ---");
    info!("  Length of Security Protocol List: {}", sec_prot_list_len);
    // As per SFCR: Table 27 — Supported security protocols SECURITY PROTOCOL IN parameter data
    // Protocol list start at offset 8...N, where N indicates the total length, in bytes,
    // N = sec_prot_list_len
    // bufsz - 8 => the remaining bytes in this header
    assert!((sec_prot_list_len as u32) < bufsz - 8);
    // If `SUPPORTED SECURITY PROTOCOL` is supported, this length shall be
    // greater than 0.
    assert!(sec_prot_list_len > 0);

    if sec_prot_list_len <= 1 {
        warn!("No security protocols supported by: {:?}", path);
    }
    let mut spdm_support = false;
    for i in 0..sec_prot_list_len {
        if let Ok(sec_prot) = SpcSecurityProtocols::try_from(cmd.dxferp[(8 + i) as usize] as u8) {
            info!("  {:?}  - Supported", sec_prot);
            if sec_prot == SpcSecurityProtocols::DmtfSpdm {
                spdm_support = true;
            }
        }
    }
    info!("--- End of Security Information List ---");

    if !spdm_support {
        // Device does not support SPDM
        return Err(Errno::ENOTSUP);
    }

    Ok(())
}

/// # Summary
///
/// Generate a command to get basic device information from the device pointed
/// to by @path, then print the information returned.
///
/// # Parameter
///
/// * `path: path to the device
///
/// # Returns
///
/// Ok(()), on success
/// Err(Errno), on any errors
pub fn cmd_scsi_get_info(path: &String) -> Result<(), Errno> {
    // 1. Open device
    let dev = BlkDev::new(path, OFlag::O_RDONLY)?;
    // 2. Generate command
    let mut cmd = SgCmd::gen_dev_inquiry_info(0, SG_DXFER_FROM_DEV, 64)?;
    // 3. Execute CMD
    if let Some(fd) = &dev.fd {
        cmd.scsi_cmd_exec(*fd).map_err(|e| {
            error!("Failure to issue get info command: {e:?}");
            e
        })?;
    } else {
        return Err(Errno::ENXIO);
    }

    // 4. Display results
    let vendor = String::from_utf8(cmd.dxferp[8..8 + (DEV_VENDOR_LEN - 1)].to_vec()).unwrap();
    let id = String::from_utf8(cmd.dxferp[16..16 + (DEV_ID_LEN - 1)].to_vec()).unwrap();
    let rev = String::from_utf8(cmd.dxferp[8..32 + (DEV_REV_LEN - 1)].to_vec()).unwrap();

    info!("vendor: {vendor}");
    info!("id: {id}");
    info!("rev: {rev}");

    Ok(())
}

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
unsafe extern "C" fn scsi_send_message(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    _timeout: u64,
) -> u32 {
    let message = message_ptr as *const u8;
    let msg_buf = unsafe { from_raw_parts(message, message_size) };

    info!("Sending SCSI SECURITY_OUT SPDM Command (request)");

    // 1. Open device
    let dev = SCSI_DEV.take().unwrap();

    // 2. Generate Request Header
    let header_len = LIBSPDM_STORAGE_TRANSPORT_HEADER_SIZE as usize;
    let mut cmd = SgCmd::gen_libspdm_request(
        0,
        SG_DXFER_TO_DEV,
        SG_BUF_MAX_SIZE,
        &mut msg_buf[0..header_len].try_into().unwrap(),
    )
    .unwrap();

    assert!(message_size < cmd.dxferp.capacity());
    // Copy in SPDM buffer to the SG command IO buffer
    for i in 0..message_size - header_len {
        cmd.dxferp[i] = msg_buf[i + header_len];
    }

    // 3. Execute CMD
    debug!(
        "spdm-sending: IF_SEND: cmdp:   {:x?}",
        &cmd.cmdp[0..SCSI_SEC_IN_OUT_CDB_LEN]
    );
    debug!(
        "spdm-sending: dxferp: {:x?}",
        &cmd.dxferp[0..(message_size - header_len)]
    );

    if let Some(fd) = &dev.fd {
        cmd.scsi_cmd_exec(*fd)
            .expect("Failed to execute cmd, security in failed");
    }
    SCSI_DEV.set(dev).unwrap();
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
///                 `SEND_RECEIVE_BUFFER_LEN` to capture the received bytes.
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
unsafe extern "C" fn scsi_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    message_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let message = *message_ptr as *mut u8;
    let msg_buf = from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN);

    info!("Sending SCSI SECURITY_IN SPDM Command (receive response)");

    // 1. Open device
    let dev = SCSI_DEV.take().unwrap();

    // 2. Generate Response Header
    let mut cmd = SgCmd::gen_libspdm_response(
        0,
        SG_DXFER_FROM_DEV,
        SG_BUF_MAX_SIZE,
        message,
        *message_size,
    )
    .unwrap();

    // 3. Execute CMD
    debug!(
        "spdm-sending: IF_RECV: cmdp:   {:x?}",
        &cmd.cmdp[0..SCSI_SEC_IN_OUT_CDB_LEN]
    );

    if let Some(fd) = &dev.fd {
        cmd.scsi_cmd_exec(*fd)
            .expect("Failed to execute cmd, security in failed");
    }

    // 4. Copy in the received buffer
    assert!(cmd.bufsz > 0);
    assert!(msg_buf.len() >= cmd.bufsz as usize);
    assert!(cmd.dxferp.len() >= cmd.bufsz as usize);

    for i in 0..cmd.bufsz as usize {
        msg_buf[i] = cmd.dxferp[i];
    }

    // Allow libspdm to do top-bottom SPDM message parsing, we don't know the
    // number of valid bytes in the reception buffer.
    *message_size = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;

    info!("recvd_bytes: {:?}", *message_size);
    info!("spdm-recvd: {:x?}", &msg_buf[0..*message_size]);
    SCSI_DEV.set(dev).unwrap();
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
///
/// # Panics
///
/// Panics if the SEND_BUFFER is not available
#[no_mangle]
unsafe extern "C" fn scsi_acquire_sender_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = SEND_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

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
///
/// # Returns
///
/// (0) on success
///
/// # Panics
///
/// Panics if the `msg_buf_ptr` is invalid or has less elements
/// than `SEND_RECEIVE_BUFFER_LEN`
#[no_mangle]
unsafe extern "C" fn scsi_release_sender_buffer(_context: *mut c_void, msg_buf_ptr: *const c_void) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    SEND_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
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
///
/// # Panics
///
/// Panics if the SEND_BUFFER is not available
#[no_mangle]
unsafe extern "C" fn scsi_acquire_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *mut *mut c_void,
) -> u32 {
    let mut buf = RECEIVE_BUFFER.take().unwrap();
    let buf_ptr = buf.as_mut_ptr() as *mut _ as *mut c_void;

    *msg_buf_ptr = buf_ptr;

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
///
/// # Panics
///
/// Panics if the `msg_buf_ptr` is invalid or has less elements
/// than `SEND_RECEIVE_BUFFER_LEN`
#[no_mangle]
unsafe extern "C" fn scsi_release_receiver_buffer(
    _context: *mut c_void,
    msg_buf_ptr: *const c_void,
) {
    let message = msg_buf_ptr as *const u8;
    let msg_buf = from_raw_parts(message, SEND_RECEIVE_BUFFER_LEN);

    RECEIVE_BUFFER.set(msg_buf.try_into().unwrap()).unwrap();
}

/// # Summary
///
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
pub fn register_device(context: *mut c_void, dev_path: &String) -> Result<(), ()> {
    let buffer_send = [0; SEND_RECEIVE_BUFFER_LEN];
    let buffer_receive = [0; SEND_RECEIVE_BUFFER_LEN];

    unsafe {
        SEND_BUFFER.set(buffer_send).unwrap();
        RECEIVE_BUFFER.set(buffer_receive).unwrap();
        DEV_PATH.set(dev_path.clone()).unwrap();
        SCSI_DEV
            .set(BlkDev::new(DEV_PATH.get().unwrap(), OFlag::O_RDWR).unwrap())
            .unwrap();

        libspdm_register_device_io_func(
            context,
            Some(scsi_send_message),
            Some(scsi_receive_message),
        );
        libspdm_register_device_buffer_func(
            context,
            SEND_RECEIVE_BUFFER_LEN as u32,
            SEND_RECEIVE_BUFFER_LEN as u32,
            Some(scsi_acquire_sender_buffer),
            Some(scsi_release_sender_buffer),
            Some(scsi_acquire_receiver_buffer),
            Some(scsi_release_receiver_buffer),
        );
    }

    Ok(())
}
