// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM responder.

use crate::*;
use core::ffi::c_void;
use libspdm::spdm::LibspdmReturnStatus;
use std::path::Path;

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
) -> Result<(), ()> {
    unsafe {
        let parameter = libspdm_data_parameter_t::new_local(slot_id);

        let mut data: u32 = SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP;
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

        let file_path = format!("certs/slot{}/bundle_responder.certchain.der", slot_id);
        let path = Path::new(&file_path);

        let (cert_chain_buffer, cert_chain_size) =
            libspdm::spdm::get_local_certchain(path, asym_algo, hash_algo, false);
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
