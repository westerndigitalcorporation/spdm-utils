// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM requests.

/// SCSI SPDM Related ADDITIONAL SENSE CODE (ASQ)
#[allow(dead_code)]
#[derive(Debug)]
pub enum ScsiAsc {
    InvalidFieldInCdb = 0x24, // ASCQ = 0x00
}

/// Defines the SPDM return status (upper byte) and error (lower byte)
/// for ATA as defined in DSP0284.
#[allow(dead_code)]
#[derive(Debug)]
pub enum AtaStatusErr {
    Success = 0x5000,
    InvalidCommand = 0x5104,
}

/// NVME Completion Queue Command Completion Status
#[allow(dead_code)]
#[derive(Debug)]
pub enum NvmeCmdStatus {
    Success = 0x0000,
    InvalidFieldInCmd = 0x0002,
    DoNotRetry = 0x4000,
}

/// Spdm Storage Operations as defined in DMTF DSP0286
#[derive(Debug, PartialEq)]
pub enum SpdmStorageOperationCodes {
    Discovery = 0x01,
    PendingInfo = 0x02,
    Message = 0x05,
    SecMessage = 0x06,
}

impl TryFrom<u8> for SpdmStorageOperationCodes {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(SpdmStorageOperationCodes::Discovery),
            0x02 => Ok(SpdmStorageOperationCodes::PendingInfo),
            0x05 => Ok(SpdmStorageOperationCodes::Message),
            0x06 => Ok(SpdmStorageOperationCodes::SecMessage),
            _ => Err(()),
        }
    }
}

impl From<SpdmStorageOperationCodes> for u8 {
    fn from(op: SpdmStorageOperationCodes) -> Self {
        match op {
            SpdmStorageOperationCodes::Discovery => 0x01,
            SpdmStorageOperationCodes::PendingInfo => 0x02,
            SpdmStorageOperationCodes::Message => 0x05,
            SpdmStorageOperationCodes::SecMessage => 0x06,
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
