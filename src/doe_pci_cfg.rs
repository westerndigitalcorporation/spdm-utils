// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides support for accessing a PCIe DOE device using the
//! DOE mailbox exposed over a PCIe extended configuration space.
//!
//! This is generally run on the Linux host machine to communicate
//! with a DOE device.
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm behaves in a manor we don't expect this will be very bad,
//! so we are trusting libspdm here.
//!

use crate::*;
use core::ffi::c_void;
use libspdm::libspdm_status_construct;
use libspdm::spdm::LIBSPDM_MAX_SPDM_MSG_SIZE;
use once_cell::sync::OnceCell;
use std::fmt;
use std::slice::{from_raw_parts, from_raw_parts_mut};

const SEND_RECEIVE_BUFFER_LEN: usize = LIBSPDM_MAX_SPDM_MSG_SIZE as usize;
const LIBSPDM_STATUS_ERROR_PEER: u32 =
    libspdm_status_construct!(LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE, 0x000a);

const DOE_CONTROL: i32 = 0x08;
const DOE_CONTROL_GO: u32 = 1 << 31;
const DOE_CONTROL_ABORT: u32 = 1 << 0;

const DOE_STATUS: i32 = 0x0c;
const DOE_STATUS_BUSY: u32 = 1 << 0;
const DOE_STATUS_DOR: u32 = 1 << 31;
const DOE_STATUS_ERR: u32 = 1 << 2;

const DOE_WRITE_DATA_MAILBOX: i32 = 0x10;
const DOE_READ_DATA_MAILBOX: i32 = 0x14;

/// PCIE Identifiers
static mut PCIE_IDENTIFIERS: OnceCell<PcieIdentifiers> = OnceCell::new();

#[derive(Debug)]
struct PcieIdentifiers {
    vid: u16,
    devid: u16,
}

/// # Summary
///
/// Sends message using the PCIe DOE extended capability by writing the
/// `message_ptr` data to the targets `DOE_WRITE_DATA_MAILBOX`.
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
unsafe extern "C" fn doe_pci_cfg_send_message(
    _context: *mut c_void,
    message_size: usize,
    message_ptr: *const c_void,
    _timeout: u64,
) -> u32 {
    let message = message_ptr as *const u8;
    let msg_buf = unsafe { from_raw_parts(message, message_size) };

    info!("Sending message {msg_buf:x?}");
    let pcie_ids = PCIE_IDENTIFIERS.get().unwrap();
    let (pacc, device, doe_offset) = get_pcie_dev(pcie_ids.vid, pcie_ids.devid).unwrap();
    if let Err(e) = doe_wait_not_busy(device, doe_offset) {
        match e {
            DoeStatus::DoeStatusErr => {
                doe_issue_abort(device, doe_offset, true);
                return LIBSPDM_STATUS_ERROR_PEER;
            }
        }
    };

    for chunk in msg_buf.chunks(4) {
        let data = u32::from_le_bytes(chunk[0..4].try_into().unwrap());

        pci_write_long(device, doe_offset + DOE_WRITE_DATA_MAILBOX, data);
    }

    // Set the DOE Go bit to indicate we are all done
    let doe_control = pci_read_long(device, doe_offset + DOE_CONTROL);
    pci_write_long(
        device,
        doe_offset + DOE_CONTROL,
        doe_control | DOE_CONTROL_GO,
    );

    pci_cleanup(pacc);

    info!("Sent!\n");
    0
}

/// # Summary
///
/// Receives a message using the PCIe DOE extended capability by polling the
/// targets DOE Data Object Ready (DOR) bit until it is cleared by the device
/// or if the `message_ptr` is full. During this loop, we copy all data in
/// `DOE_READ_DATA_MAILBOX` and write back to this register to pop the FIFO as
/// per the DOE specification.
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
unsafe extern "C" fn doe_pci_cfg_receive_message(
    _context: *mut c_void,
    message_size: *mut usize,
    message_ptr: *mut *mut c_void,
    _timeout: u64,
) -> u32 {
    let message = *message_ptr as *mut u8;
    let msg_buf = from_raw_parts_mut(message, SEND_RECEIVE_BUFFER_LEN);

    info!("Receiving message");
    let pcie_ids = PCIE_IDENTIFIERS.get().unwrap();
    let (pacc, device, doe_offset) = get_pcie_dev(pcie_ids.vid, pcie_ids.devid).unwrap();
    if let Err(e) = doe_wait_status_dor(device, doe_offset) {
        match e {
            DoeStatus::DoeStatusErr => {
                doe_issue_abort(device, doe_offset, true);
                return LIBSPDM_STATUS_ERROR_PEER;
            }
        }
    };

    let mut bytes_received = 0;
    let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

    // Read data until there is no more
    while doe_status & DOE_STATUS_DOR == DOE_STATUS_DOR && (bytes_received + 4) < msg_buf.len() {
        let data = pci_read_long(device, doe_offset + DOE_READ_DATA_MAILBOX);
        msg_buf[bytes_received..(bytes_received + 4)].copy_from_slice(&data.to_le_bytes());
        bytes_received += 4;

        // Clear the data by writing to the FIFO (note we can write anything)
        pci_write_long(device, doe_offset + DOE_READ_DATA_MAILBOX, 0xDEADBEEF);

        doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
    }

    *message_size = bytes_received;

    info!("Received: {:x?}", &msg_buf[0..bytes_received]);

    pci_cleanup(pacc);

    0
}

/// # Summary
///
/// Registers the SPDM `context` for a PCIe DOE backend.
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `pcie_vid`: PCIe Identifier, Vendor ID of the device in use
/// * `pcie_devid`: PCIe Identifier, Device ID of the device in use
///
/// # Returns
///
/// Ok(()) on success
///
/// # Panics
///
/// Panics if `SEND_BUFFER/RECEIVE_BUFFER` is occupied
pub fn register_device(context: *mut c_void, pcie_vid: u16, pcie_devid: u16) -> Result<(), ()> {
    let pcie_ids = PcieIdentifiers {
        vid: pcie_vid,
        devid: pcie_devid,
    };
    unsafe {
        PCIE_IDENTIFIERS.set(pcie_ids).map_err(|e| {
            error!("Failed to set device PCIe Identifiers: {e:?}");
            ()
        })?;

        libspdm_register_device_io_func(
            context,
            Some(doe_pci_cfg_send_message),
            Some(doe_pci_cfg_receive_message),
        );
        io_buffers::libspdm_setup_io_buffers(
            context,
            SEND_RECEIVE_BUFFER_LEN,
            SEND_RECEIVE_BUFFER_LEN,
        )?;
    }

    Ok(())
}

/// # Summary
///
/// A helper function to scan PCIe devices and to fetch the PCIe device.
///
/// # Parameter
///
/// * `dev_vid`: PCIe Vendor ID
/// * `dev_id`: PCIe device ID
///
/// # Returns
///
/// On success returns a tuple containing:
/// * `pacc`: A pointer to a `pci_access` struct
/// * `device`: `pci_dev` pointing to the device
/// * `doe_offset`: The offset to the DOE capability in the extended
///                 capabilities list
///
/// *  Err(()): On device not found
pub unsafe fn get_pcie_dev(
    dev_vid: u16,
    dev_id: u16,
) -> Result<(*mut pci_access, *mut pci_dev, i32), ()> {
    let pacc = pci_alloc();
    if pacc.is_null() {
        return Err(());
    }
    pci_init(pacc);
    pci_scan_bus(pacc);

    let mut device = (*pacc).devices;

    while !device.is_null() {
        pci_fill_info(
            device,
            (PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS | PCI_FILL_EXT_CAPS) as i32,
        );

        if (*device).vendor_id == dev_vid && (*device).device_id == dev_id {
            // Device found
            break;
        }
        device = (*device).next;
    }

    if device.is_null() {
        // We didn't find anything, return
        pci_cleanup(pacc);
        error!("Device [VID: {} | DevID: {}] not found!", dev_vid, dev_id);
        return Err(());
    }

    if let Ok(doe_offset) = get_doe_offset(device) {
        Ok((pacc, device, doe_offset))
    } else {
        pci_cleanup(pacc);
        error!("DOE not found in the extended capability list");
        Err(())
    }
}

/// # Summary
///
/// Traverse the PCIe extended capabilities linked list for this `pci_dev`
/// and find DOE. If found, return the offset at which it exists or return
/// and Err(()).
///
/// # Parameter
///
/// * `device`: `pci_dev` pointing to the target device
/// * `doe_offset`: offset at which doe sits in the extended capability list
///
/// # Returns
///
/// Ok(doe_offset) on success, indicating the DOE offset position in the extended
/// capabilities list.
///
/// Err(()) if DOE is not found.
unsafe fn get_doe_offset(pdev: *mut pci_dev) -> Result<i32, ()> {
    let mut current = (*pdev).first_cap;
    while !current.is_null() {
        // Check if this is a DOE Capability (0x2E)
        if (*current).id == 0x2E {
            // Get the offset, note this is a u32 but all the pci functions take
            // an int as the offset argument. So return as int.
            return Ok(i32::try_from((*current).addr).unwrap());
        }
        current = (*current).next;
    }
    Err(())
}

/// # Summary
///
/// A helper function to wait until the PCIe DOE_STATUS_BUSY bit is cleared,
/// indicating the target device has transitioned out of it's BUSY state.
///
/// # Parameter
///
/// * `device`: `pci_dev` pointing to the target device
/// * `doe_offset`: offset at which doe sits in the extended capability list
///
/// # Returns
///
/// OK(()) on success, indicating the device is no longer busy
/// Err(DoeStatusErr) if the device has set the Status::Err bit.
///
/// # Panics
///
/// Panics if `pci_dev` is invalid
unsafe fn doe_wait_not_busy(device: *mut pci_dev, doe_offset: i32) -> Result<(), DoeStatus> {
    let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

    while doe_status & DOE_STATUS_BUSY == DOE_STATUS_BUSY {
        if doe_status & DOE_STATUS_ERR == DOE_STATUS_ERR {
            error!("Device DOE status error");
            return Err(DoeStatus::DoeStatusErr);
        }
        doe_status = pci_read_long(device, doe_offset + DOE_STATUS)
    }
    Ok(())
}

#[derive(PartialEq)]
enum DoeStatus {
    DoeStatusErr,
}

/// # Summary
///
/// A helper function to wait until the PCIe DOE_STATUS_DOR bit is set,
/// indicating the target device has data object ready to be read.
///
/// # Parameter
///
/// * `device`: `pci_dev` pointing to the target device
/// * `doe_offset`: offset at which doe sits in the extended capability list
///
/// # Returns
///
/// OK(()) on success, host may attempt read the data from the target now.
/// Err(DoeStatusErr) if the device has set the Status::Err bit.
///
/// # Panics
///
/// Panics if `pci_dev` is invalid
unsafe fn doe_wait_status_dor(device: *mut pci_dev, doe_offset: i32) -> Result<(), DoeStatus> {
    let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

    // Wait for the data object ready to be true
    while doe_status & DOE_STATUS_DOR != DOE_STATUS_DOR {
        if doe_status & DOE_STATUS_ERR == DOE_STATUS_ERR {
            error!("Device DOE status error");
            return Err(DoeStatus::DoeStatusErr);
        }
        doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
    }
    Ok(())
}

/// # Summary
///
/// A helper function to issue DOE Abort
///
/// # Parameter
///
/// * `device`: `pci_dev` pointing to the target device
/// * `doe_offset`: offset at which doe sits in the extended capability list
/// * `block_on_status_err`: block until DoE Status Error has  cleared
///
/// # Panics
///
/// Panics if `pci_dev` is invalid
unsafe fn doe_issue_abort(device: *mut pci_dev, doe_offset: i32, block_on_status_err: bool) {
    let doe_control = pci_read_long(device, doe_offset + DOE_CONTROL);
    warn!("Issuing DOE Control abort");
    pci_write_long(
        device,
        doe_offset + DOE_CONTROL,
        doe_control | DOE_CONTROL_ABORT,
    );

    if block_on_status_err {
        debug!("Waiting for DOE status error to clear");
        let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
        while doe_status & DOE_STATUS_ERR == DOE_STATUS_ERR {
            doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
        }
    }
    debug!("DOE Status error Cleared");
}

/// # Summary
///
/// A helper function to retrieve the DOE version,
///
/// # Parameter
///
/// * `device`: `pci_dev` pointing to the target device
/// * `doe_offset`: offset at which doe sits in the extended capability list
///
/// # Returns
///
/// The capability version
///
/// # Panics
///
/// Panics if `pci_dev` is invalid
unsafe fn doe_capability_version(device: *mut pci_dev, doe_offset: i32) -> u8 {
    let doe_extended_cap = pci_read_long(device, doe_offset);

    ((doe_extended_cap & 0xF0000) >> 16) as u8
}

//---------------------FOLLOWING CODE IS FOR TESTING--------------------------//

/// DOE Header
const DOE_HEADER1_OFST_VID: u32 = 0;
const DOE_HEADER1_OFST_TYPE: u32 = 15;

const DOE_HEADER2_OFST_LEN: u32 = 0;

/// Discovery Protocol
const DOE_DISC_OFST_SHIFT: u32 = 0;

// DOE Discovery Types
const PCI_VENDOR_ID_PCI_SIG: u32 = 0x01;
const PCI_DOE_PROTOCOL_DISCOVERY: u32 = 0x00;

// Masks for Discovery Response
const DOE_RESPONSE_VID_MASK: u32 = 0x0000_FFFF;
const DOE_RESPONSE_PROTOCOL_MASK: u32 = 0x00FF_0000;
const DOE_RESPONSE_NEXT_INDEX_MASK: u32 = 0xFF00_0000;
const DOE_RESPONSE_LEN_MASK: u32 = 0x0001_FFFF;
const DOE_RESPONSE_MAX_DO_LEN_MASK: u32 = 0x0003_FFFF;
const DOE_RESPONSE_ADD_INFO_MASK: u32 = 0xFFFC_0000;

// Shifts for Discovery Response
const DOE_RESPONSE_VID_SHIFT: u32 = 0;
const DOE_RESPONSE_PROTOCOL_SHIFT: u32 = 16;
const DOE_RESPONSE_NEXT_INDEX_SHIFT: u32 = 24;
const DOE_RESPONSE_ADD_INFO_SHIFT: u32 = 18;

// Masks for Discovery Request
const DOE_REQUEST_INDEX: u32 = 0x0000_00FF;
const DOE_REQUEST_VID_MASK: u32 = 0x0000_FFFF;
const DOE_REQUEST_PROTOCOL_MASK: u32 = 0x00FF_0000;
const DOE_REQUEST_LEN_MASK: u32 = 0x0001_FFFF;

const DOE_VERSION: u8 = 2;
const DOE_REQUEST_VERSION_MASK: u32 = 0x0000_FF00;
const DOE_REQUEST_VERSION_SHIFT: u32 = 8;

// Shifts for Discovery Request
const _DOE_REQUEST_VID_SHIFT: u32 = 0;
const DOE_REQUEST_PROTOCOL_SHIFT: u32 = 16;

#[repr(C)]
pub struct DoeDiscoveryPacket {
    header1: u32,
    /// Length field is 2 DW of header + length of payload in DW
    header2: u32,
    dw0: u32,
}

impl DoeDiscoveryPacket {
    pub fn as_array(&self) -> [u32; 3] {
        [self.header1, self.header2, self.dw0]
    }
}

pub struct DoeDiscoveryResponse(Vec<u32>);

impl fmt::Display for DoeDiscoveryResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if !(self.0.len() == 3 || self.0.len() == 4) {
            return writeln!(f, "inner vector invalid");
        }
        let header1 = self.0[0];
        let header2 = self.0[1];
        let dw0 = self.0[2];

        writeln!(f, "{{")?;
        writeln!(
            f,
            "\tH1: [RSVD, DO_TYPE: {}, VID: {}]",
            (header1 & DOE_RESPONSE_PROTOCOL_MASK) >> DOE_RESPONSE_PROTOCOL_SHIFT,
            header1 & DOE_RESPONSE_VID_MASK
        )?;
        writeln!(f, "\tH2: [RSVD, LEN: {}]", header2 & DOE_RESPONSE_LEN_MASK)?;
        writeln!(
            f,
            "\tDISC_RESP: [NEXT_INDEX: {}, DO_PROT: {}, VID: {}]",
            (dw0 & DOE_RESPONSE_NEXT_INDEX_MASK) >> DOE_RESPONSE_NEXT_INDEX_SHIFT,
            (dw0 & DOE_RESPONSE_PROTOCOL_MASK) >> DOE_RESPONSE_PROTOCOL_SHIFT,
            dw0 & DOE_RESPONSE_VID_MASK
        )?;
        if self.0.len() == 4 {
            let dw1 = self.0[3];
            writeln!(
                f,
                "\tDISC_RESP: [ADDITIONAL_INFO: {}, MAX_DO_LEN: {}]",
                (dw1 & DOE_RESPONSE_ADD_INFO_MASK) >> DOE_RESPONSE_ADD_INFO_SHIFT,
                dw1 & DOE_RESPONSE_MAX_DO_LEN_MASK
            )?;
        }
        writeln!(f, "}}")
    }
}

impl fmt::Display for DoeDiscoveryPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{{")?;
        writeln!(
            f,
            "\tH1: [RSVD, DO_TYPE: {}, VID: {}]",
            (self.header1 & DOE_REQUEST_PROTOCOL_MASK) >> DOE_REQUEST_PROTOCOL_SHIFT,
            self.header1 & DOE_REQUEST_VID_MASK
        )?;
        writeln!(
            f,
            "\tH2: [RSVD, LEN: {}]",
            self.header2 & DOE_REQUEST_LEN_MASK
        )?;
        writeln!(
            f,
            "\tDISC_REQ: [RSVD, VERSION: {}, INDEX:{}]",
            (self.dw0 & DOE_REQUEST_VERSION_MASK) >> DOE_REQUEST_VERSION_SHIFT,
            self.dw0 & DOE_REQUEST_INDEX,
        )?;
        writeln!(f, "}}")
    }
}

/// # Summary
///
/// Basic test case to issue a single DOE discovery request
///
/// # Returns
///
/// OK(()) on success
///
/// # Panics
///
/// Panics if test setup fails
/// Panics if the tests assertions fail
pub unsafe fn test_discovery_basic() -> Result<(), ()> {
    info!("--- Testing Discovery: Basic ---");
    let pcie_ids = PCIE_IDENTIFIERS.get().unwrap();
    let (pacc, device, doe_offset) = get_pcie_dev(pcie_ids.vid, pcie_ids.devid).unwrap();
    doe_wait_not_busy(device, doe_offset).map_err(|e| match e {
        DoeStatus::DoeStatusErr => {
            doe_issue_abort(device, doe_offset, true);
            ()
        }
    })?;

    let doe_version = doe_capability_version(device, doe_offset);
    let doe_discovery_index: u32 = 0;

    let discovery_packet = if doe_version == DOE_VERSION {
        DoeDiscoveryPacket {
            header1: (PCI_DOE_PROTOCOL_DISCOVERY << DOE_HEADER1_OFST_TYPE)
                | (PCI_VENDOR_ID_PCI_SIG << DOE_HEADER1_OFST_VID),
            // We are sending 3DWs (inc 2 for header)
            header2: 3 << DOE_HEADER2_OFST_LEN,
            dw0: doe_discovery_index << DOE_DISC_OFST_SHIFT
                | (DOE_VERSION as u32) << DOE_REQUEST_VERSION_SHIFT,
        }
    } else {
        DoeDiscoveryPacket {
            header1: (PCI_DOE_PROTOCOL_DISCOVERY << DOE_HEADER1_OFST_TYPE)
                | (PCI_VENDOR_ID_PCI_SIG << DOE_HEADER1_OFST_VID),
            // We are sending 3DWs (inc 2 for header)
            header2: 3 << DOE_HEADER2_OFST_LEN,
            dw0: doe_discovery_index << DOE_DISC_OFST_SHIFT,
        }
    };
    info!("Discovery Request: {}", discovery_packet);
    for data in discovery_packet.as_array().iter() {
        pci_write_long(device, doe_offset + DOE_WRITE_DATA_MAILBOX, *data);
    }

    // Set the DOE Go bit to indicate we are all done
    let doe_control = pci_read_long(device, doe_offset + DOE_CONTROL);
    pci_write_long(
        device,
        doe_offset + DOE_CONTROL,
        doe_control | DOE_CONTROL_GO,
    );

    // Wait for a response
    doe_wait_status_dor(device, doe_offset).map_err(|e| match e {
        DoeStatus::DoeStatusErr => {
            doe_issue_abort(device, doe_offset, true);
            ()
        }
    })?;

    // Read and Print Response
    let mut recv = DoeDiscoveryResponse(Vec::new());

    let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

    while doe_status & DOE_STATUS_DOR == DOE_STATUS_DOR {
        recv.0
            .push((pci_read_long(device, doe_offset + DOE_READ_DATA_MAILBOX)).to_le());
        // Clear the data by writing to the FIFO (note we can write anything)
        pci_write_long(device, doe_offset + DOE_READ_DATA_MAILBOX, 0xDEADBEEF);
        doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
    }
    assert_eq!(
        recv.0.len(),
        3,
        "Response expected bytes mismatch, expected 12bytes got {}bytes",
        recv.0.len() * 4
    );
    info!("Discovery Response: {}", recv);
    pci_cleanup(pacc);
    info!("[OK]\n");
    Ok(())
}

/// # Summary
///
/// Test case to issue a continuous DOE discovery requests to probe all
/// discoverable objects. Checks for:
///     1. Discovery Support
///     2. CMA/SPDM Support
///     3. Secured CMA/SPDM Support
///
/// # Returns
///
/// OK(()) on success
///
/// # Panics
///
/// Panics if test setup fails
/// Panics if the tests assertions fail
pub unsafe fn test_discovery_all() -> Result<(), ()> {
    info!("--- Testing Discovery: All Discoverable objects ---");
    let pcie_ids = PCIE_IDENTIFIERS.get().unwrap();
    let (pacc, device, doe_offset) = get_pcie_dev(pcie_ids.vid, pcie_ids.devid).unwrap();
    doe_wait_not_busy(device, doe_offset).map_err(|e| match e {
        DoeStatus::DoeStatusErr => {
            doe_issue_abort(device, doe_offset, true);
            ()
        }
    })?;

    let doe_version = doe_capability_version(device, doe_offset);

    let mut doe_discovery_index: u32 = 0;
    let mut discovery_packet = DoeDiscoveryPacket {
        header1: (PCI_DOE_PROTOCOL_DISCOVERY << DOE_HEADER1_OFST_TYPE)
            | (PCI_VENDOR_ID_PCI_SIG << DOE_HEADER1_OFST_VID),
        // We are sending 3DWs (inc 2 for header)
        header2: 3 << DOE_HEADER2_OFST_LEN,
        dw0: doe_discovery_index << DOE_DISC_OFST_SHIFT,
    };

    loop {
        // We want to loop till we hit the end of discoverable objects on the
        // doe instance. Response `next_index` = 0 to indicate the final entry.
        discovery_packet.dw0 = doe_discovery_index << DOE_DISC_OFST_SHIFT;
        if doe_version == DOE_VERSION {
            discovery_packet.dw0 |= (DOE_VERSION as u32) << DOE_REQUEST_VERSION_SHIFT;
        }

        info!("Discovery Request: {}", discovery_packet);

        for data in discovery_packet.as_array().iter() {
            pci_write_long(device, doe_offset + DOE_WRITE_DATA_MAILBOX, *data);
        }
        // Set the DOE Go bit to indicate we are all done
        let doe_control = pci_read_long(device, doe_offset + DOE_CONTROL);
        pci_write_long(
            device,
            doe_offset + DOE_CONTROL,
            doe_control | DOE_CONTROL_GO,
        );
        // Wait for a response
        doe_wait_status_dor(device, doe_offset).map_err(|e| match e {
            DoeStatus::DoeStatusErr => {
                doe_issue_abort(device, doe_offset, true);
                ();
            }
        })?;
        // Read and Print Response
        let mut recv = DoeDiscoveryResponse(Vec::new());

        let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

        while doe_status & DOE_STATUS_DOR == DOE_STATUS_DOR {
            recv.0
                .push((pci_read_long(device, doe_offset + DOE_READ_DATA_MAILBOX)).to_le());
            // Clear the data by writing to the FIFO (note we can write anything)
            pci_write_long(device, doe_offset + DOE_READ_DATA_MAILBOX, 0xDEADBEEF);
            doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
        }

        // This is the 3rd dword which is the response data (see table 6-42)
        doe_discovery_index =
            (recv.0[2] & DOE_RESPONSE_NEXT_INDEX_MASK) >> DOE_RESPONSE_NEXT_INDEX_SHIFT;
        let vid = (recv.0[2] & DOE_RESPONSE_VID_MASK) >> DOE_RESPONSE_VID_SHIFT;

        match (recv.0[2] & DOE_RESPONSE_PROTOCOL_MASK) >> DOE_RESPONSE_PROTOCOL_SHIFT {
            0 => {
                info!("VID: {} - Discovery Support [OK]", vid);
                assert_eq!(
                    recv.0.len(),
                    3,
                    "Response expected bytes mismatch, expected 12bytes got {}bytes",
                    recv.0.len() * 4
                );
            }
            1 => {
                info!("VID: {} - CMA/SPDM Support [OK]", vid);
                assert!(
                    recv.0.len() == 3 || recv.0.len() == 4,
                    "Response expected bytes mismatch, expected 12 or 16bytes got {}bytes",
                    recv.0.len() * 4
                );
            }
            2 => {
                info!("VID: {} - Secured CMA/SPDM Support [OK]", vid);
                assert!(
                    recv.0.len() == 3 || recv.0.len() == 4,
                    "Response expected bytes mismatch, expected 12 or 16bytes got {}bytes",
                    recv.0.len() * 4
                );
            }
            _ => info!("Reserved/Unsupported by SPDM-Utils"),
        }
        // Print the receive buffer.
        info!("Discovery Response: {}", recv);
        // Clear the receive buffer
        recv.0.clear();

        if doe_discovery_index == 0 {
            info!("All discoverable objects found, finishing up...");
            break;
        }
    }

    pci_cleanup(pacc);
    info!("[OK]\n");
    Ok(())
}

/// # Summary
///
/// Tests that the doe instance properly handles a request with an invalid index
///
/// # Returns
///
/// OK(()) on success
///
/// # Panics
///
/// Panics if test setup fails
/// Panics if the tests assertions fail
pub unsafe fn test_discovery_error() -> Result<(), ()> {
    info!("--- Testing Discovery: Error Cases ---");
    let pcie_ids = PCIE_IDENTIFIERS.get().unwrap();
    let (pacc, device, doe_offset) = get_pcie_dev(pcie_ids.vid, pcie_ids.devid).unwrap();

    doe_wait_not_busy(device, doe_offset).map_err(|e| match e {
        DoeStatus::DoeStatusErr => {
            doe_issue_abort(device, doe_offset, true);
            ()
        }
    })?;

    let doe_version = doe_capability_version(device, doe_offset);

    // Note that this index is invalid
    let doe_discovery_index: u32 = 32;
    let discovery_packet = if doe_version == DOE_VERSION {
        DoeDiscoveryPacket {
            header1: (PCI_DOE_PROTOCOL_DISCOVERY << DOE_HEADER1_OFST_TYPE)
                | (PCI_VENDOR_ID_PCI_SIG << DOE_HEADER1_OFST_VID),
            // We are sending 3DWs (inc 2 for header)
            header2: 3 << DOE_HEADER2_OFST_LEN,
            dw0: doe_discovery_index << DOE_DISC_OFST_SHIFT
                | (DOE_VERSION as u32) << DOE_REQUEST_VERSION_SHIFT,
        }
    } else {
        DoeDiscoveryPacket {
            header1: (PCI_DOE_PROTOCOL_DISCOVERY << DOE_HEADER1_OFST_TYPE)
                | (PCI_VENDOR_ID_PCI_SIG << DOE_HEADER1_OFST_VID),
            // We are sending 3DWs (inc 2 for header)
            header2: 3 << DOE_HEADER2_OFST_LEN,
            dw0: doe_discovery_index << DOE_DISC_OFST_SHIFT,
        }
    };

    info!("Discovery Request: {}", discovery_packet);

    for data in discovery_packet.as_array().iter() {
        pci_write_long(device, doe_offset + DOE_WRITE_DATA_MAILBOX, *data);
    }

    // Set the DOE Go bit to indicate we are all done
    let doe_control = pci_read_long(device, doe_offset + DOE_CONTROL);
    pci_write_long(
        device,
        doe_offset + DOE_CONTROL,
        doe_control | DOE_CONTROL_GO,
    );

    // Wait for a response
    doe_wait_status_dor(device, doe_offset).map_err(|e| match e {
        DoeStatus::DoeStatusErr => {
            doe_issue_abort(device, doe_offset, true);
            ()
        }
    })?;

    // Read and Print Response
    let mut recv = DoeDiscoveryResponse(Vec::new());

    let mut doe_status = pci_read_long(device, doe_offset + DOE_STATUS);

    while doe_status & DOE_STATUS_DOR == DOE_STATUS_DOR {
        recv.0
            .push((pci_read_long(device, doe_offset + DOE_READ_DATA_MAILBOX)).to_le());
        // Clear the data by writing to the FIFO (note we can write anything)
        pci_write_long(device, doe_offset + DOE_READ_DATA_MAILBOX, 0xDEADBEEF);
        doe_status = pci_read_long(device, doe_offset + DOE_STATUS);
    }
    assert_eq!(
        recv.0.len(),
        3,
        "Response expected bytes mismatch, expected 12bytes got {}bytes",
        recv.0.len() * 4
    );
    // Expected vid = 0xffff, DOP == Next Index == Undefined
    assert_eq!(
        (recv.0[2] & DOE_RESPONSE_VID_MASK) >> DOE_RESPONSE_VID_SHIFT,
        0xffff,
        "DOE instance must return VID=0xFFFF on an invalid `index`"
    );

    info!("Discovery Response: {}", recv);
    pci_cleanup(pacc);
    info!("[OK]\n");
    Ok(())
}
