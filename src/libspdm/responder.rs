// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM responder.

use crate::libspdm_rs::*;
use crate::spdm::get_local_certchain;
use crate::spdm::LibspdmReturnStatus;
use core::ffi::c_void;
#[cfg(not(feature = "no_std"))]
use std::fs::OpenOptions;
#[cfg(not(feature = "no_std"))]
use std::io::{BufRead, BufReader};
#[cfg(not(feature = "no_std"))]
use std::path::Path;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum CertModel {
    Alias,
    Device,
}

/// # Summary
///
/// Setup the capabilities of the responder. This matches the minimum required
/// by the CMA spec, see PCIe spec section 6.31.3 CMA/SPDM Rules
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `slot_id`: slot id for this session
/// * `ver`: SPDM Version
/// * `asym_algo`: Asymmetric algorithm used
/// * `hash_algo`: Hashing algorithm used
/// * `heartbeat_period`: Specifies the `HeartbeatPeriod` in units of seconds.
///    This value is communicated to the Requester in the `KEY_EXCHANGE_RSP` and
///    `PSK_EXCHANGE_RSP` messages. A value of 0 disables the heart beat.
///
/// # Returns
///
/// Ok(()) on success
///
/// # Panics
///
/// Panics on any errors returned by `libspdm`
/// Panics on unsupported/invalid `slot_id`
/// Panics on invalid `context`
pub fn setup_capabilities(
    context: *mut c_void,
    slot_id: u8,
    spdm_ver: Option<u8>,
    asym_algo: u32,
    hash_algo: u32,
    cert_mode: CertModel,
    heartbeat_period: u8,
) -> Result<(), ()> {
    assert!(slot_id < 8);
    unsafe {
        let parameter = libspdm_data_parameter_t::new_local(slot_id);

        let mut data: u32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP;

        if cert_mode == CertModel::Alias {
            data |= SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP;
        }

        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_FLAGS,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

        if let Some(ver) = spdm_ver {
            let mut data: u16 = (ver as u16)
                .checked_shl(SPDM_VERSION_NUMBER_SHIFT_BIT)
                .expect("SPDM version shift overflow");
            let data_ptr = &mut data as *mut _ as *mut c_void;
            libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_SPDM_VERSION,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<u16>(),
            );
        } else {
            warn!("libspdm data SPDM version not specified");
        }

        let mut data: u8 = 0x00;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u8 = 0x00;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_RTT_US,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u8 = 0x00;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_SPEC,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u8 = heartbeat_period;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_HEARTBEAT_PERIOD,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u32 = asym_algo;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_BASE_ASYM_ALGO,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

        let mut data: u32 = hash_algo;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_BASE_HASH_ALGO,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

        let mut data: u16 = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 as u16;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_DHE_NAME_GROUP,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u16>(),
        )) {
            error!("Failed to set [LIBSPDM_DATA_DHE_NAME_GROUP]");
            return Err(());
        }

        let mut data: u16 = SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM as u16;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_AEAD_CIPHER_SUITE,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u16>(),
        );

        let mut data: u16 = 0x00;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u16>(),
        );

        let mut data: u16 = SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH as u16;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_KEY_SCHEDULE,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u16>(),
        );

        let mut data: u8 = SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1 as u8;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_OTHER_PARAMS_SUPPORT,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u8 = SPDM_MEASUREMENT_SPECIFICATION_DMTF as u8;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_SPEC,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        );

        let mut data: u32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

        let mut data: u8 = LIBSPDM_MAX_CT_EXPONENT as u8;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        )) {
            error!("Failed to set [LIBSPDM_DATA_CAPABILITY_CT_EXPONENT]");
            return Err(());
        }

        let (cert_chain_buffer, cert_chain_size);
        #[cfg(feature = "no_std")]
        {
            assert!(slot_id == 0);
            if cert_mode == CertModel::Alias {
                let buffer =
                    include_bytes!("../../certs/alias/slot0/bundle_responder.certchain.der");
                (cert_chain_buffer, cert_chain_size) =
                    get_local_certchain(buffer, asym_algo, hash_algo, false);
            } else {
                let buffer =
                    include_bytes!("../../certs/device/slot0/bundle_responder.certchain.der");
                (cert_chain_buffer, cert_chain_size) =
                    get_local_certchain(buffer, asym_algo, hash_algo, false);
            }
        }
        #[cfg(not(feature = "no_std"))]
        {
            let file_path = if cert_mode == CertModel::Alias {
                format!("certs/alias/slot{}/bundle_responder.certchain.der", slot_id)
            } else {
                format!(
                    "certs/device/slot{}/bundle_responder.certchain.der",
                    slot_id
                )
            };
            let path = Path::new(&file_path);

            let file = match OpenOptions::new().read(true).write(false).open(path) {
                Err(why) => panic!("couldn't open {}: {}", path.display(), why),
                Ok(file) => file,
            };

            let mut reader = BufReader::new(file);
            let buffer = reader.fill_buf().unwrap();

            (cert_chain_buffer, cert_chain_size) =
                get_local_certchain(buffer, asym_algo, hash_algo, false);
        }

        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
            &parameter as *const libspdm_data_parameter_t,
            cert_chain_buffer,
            cert_chain_size,
        )) {
            error!("Failed to set [LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN]");
            return Err(());
        }
    }

    Ok(())
}

/// # Summary
///
/// Sets the SupportedSlotMask to indicate that the certificate slots described by,
/// up-to and including @slots_supported are supported. That is @slots_supported is 3,
/// then slots 0, 1, 2 and 3 MUST already be provisioned.
///
/// # Parameter
///
/// * `cntx_ptr`: The SPDM context
/// * `slots_supported`: Number of certificate slots supported.
/// * `spdm_ver`: SPDM version
///
/// # Returns
///
/// Ok(()) if the slot mask was set, Err(()), otherwise.
pub fn set_supported_slots_mask(
    slots_supported: u8,
    spdm_ver: Option<u8>,
    context: *mut c_void,
) -> Result<(), ()> {
    assert!(slots_supported < 8);
    // As per SPDM version 1.3, SupportedSlotMask field indicates which slots
    // the responding SPDM endpoint supports.
    // "SupportedSlotMask. If certificate slot X exists in the responding SPDM
    // endpoint, the bit in position X of this byte shall be
    // set. (Bit 0 is the least significant bit of the byte.)
    // Likewise, if certificate slot X does not exist in the
    // responding SPDM endpoint, bit X of this byte shall
    // not be set and certificate slot X shall be an invalid
    // value in various slot ID fields ( SlotID ) across all
    // SPDM request messages that contain this field." - SPDM 1.3, 374
    if spdm_ver
        .map(|v| v >= u8::try_from(SPDM_MESSAGE_VERSION_13).unwrap())
        .is_some()
    {
        let mut data: u8 =
            u8::try_from((1u16 << (slots_supported + 1)) - 1).expect("arithemtic overflow");
        let data_ptr = &mut data as *mut _ as *mut c_void;
        // Note: The slot_id for local param doesn't matter here, libspdm ignores it for
        // `LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK`, we just want to say it's for the local context
        let parameter = libspdm_data_parameter_t::new_local(0);
        let rc = unsafe {
            libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_LOCAL_SUPPORTED_SLOT_MASK,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<u8>(),
            )
        };
        if LibspdmReturnStatus::libspdm_status_is_error(rc) {
            error!("failed to set supported slot mask: rc: 0x{:x}", rc);
            return Err(());
        }
        return Ok(());
    }
    Err(())
}

/// # Summary
///
/// Starts the responders response-loop. Will initially wait for a request from
/// requestor.
///
/// # Parameter
///
/// * `cntx_ptr`: The SPDM context
///
/// # Returns
///
/// This function does not return.
pub fn response_loop(cntx_ptr: *mut c_void) -> ! {
    info!("Running in a response loop");

    loop {
        unsafe {
            let status = libspdm_responder_dispatch_message(cntx_ptr);
            if LibspdmReturnStatus::libspdm_status_is_error(status) {
                continue;
            }
        }
    }
}
