// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM requests.

/// SCSI SPDM Related ADDITIONAL SENSE CODE (ASQ)
#[derive(Debug)]
pub enum ScsiAsc {
    InvalidFieldInCdb = 0x24, // ASCQ = 0x00
}

/// Defines the SPDM return status (upper byte) and error (lower byte)
/// for ATA as defined in DSP0284.
#[derive(Debug)]
pub enum AtaStatusErr {
    Success = 0x5000,
    InvalidCommand = 0x5104,
}

/// NVME Completion Queue Command Completion Status
#[derive(Debug)]
pub enum NvmeCmdStatus {
    NvmeSuccess = 0x0000,
    NvmeInvalidFieldInCmd = 0x0002,
    NvmeDoNotRetry = 0x4000,
}

/// Spdm Storage Operations as defined in DMTF DSP0286
#[derive(Debug, PartialEq)]
pub enum SpdmOperationCodes {
    SpdmStorageDiscovery = 0x01,
    SpdmStoragePendingInfo = 0x02,
    SpdmStorageMessage = 0x05,
    SpdmStorageSecMessage = 0x06,
}

impl TryFrom<u8> for SpdmOperationCodes {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SpdmOperationCodes::SpdmStorageDiscovery),
            0x02 => Ok(SpdmOperationCodes::SpdmStoragePendingInfo),
            0x05 => Ok(SpdmOperationCodes::SpdmStorageMessage),
            0x06 => Ok(SpdmOperationCodes::SpdmStorageSecMessage),
            _ => Err(()),
        }
    }
}

impl From<SpdmOperationCodes> for u8 {
    fn from(op: SpdmOperationCodes) -> Self {
        match op {
            SpdmOperationCodes::SpdmStorageDiscovery => 0x01,
            SpdmOperationCodes::SpdmStoragePendingInfo => 0x02,
            SpdmOperationCodes::SpdmStorageMessage => 0x05,
            SpdmOperationCodes::SpdmStorageSecMessage => 0x06,
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
