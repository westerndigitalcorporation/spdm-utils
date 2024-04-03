// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM requests.

use crate::tcg_concise_evidence_binding::check_tcg_dice_evidence_binding;
use crate::*;
use core::ffi::c_void;
use libspdm::libspdm_rs::libspdm_data_parameter_t;
use libspdm::spdm::{
    get_base_asym_algo, get_base_hash_algo, get_local_certchain, LibspdmReturnStatus,
    SpdmSessionInfo,
};
use libspdm::{libspdm_status_code, libspdm_status_source};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use std::ptr;

const LIBSPDM_MAX_CSR_SIZE: usize = 0x1000;

/// # Summary
/// Setup the capabilities of the requester
///
/// Setup the capabilities of the requester. This matches the minimum required
/// by the CMA spec, see PCIe spec section 6.31.3 CMA/SPDM Rules
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `slot_id`: slot id for this session
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
    asym_algo: u32,
    hash_algo: u32,
    dhe_groups: u16,
    aead_cipher_suites: u16,
) -> Result<(), ()> {
    unsafe {
        let parameter = libspdm_data_parameter_t::new_local(slot_id);

        let mut data: u32 = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP
            | SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_CAPABILITY_FLAGS,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        );

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

        let mut data: u16 = dhe_groups;
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

        let mut data: u16 = aead_cipher_suites;
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
        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_SPEC,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u8>(),
        )) {
            error!("Failed to set [LIBSPDM_DATA_MEASUREMENT_SPEC]");
            return Err(());
        }

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

        let mut data: u32 = SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384
            | SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u32>(),
        )) {
            error!("Failed to set [LIBSPDM_DATA_MEASUREMENT_HASH_ALGO]");
            return Err(());
        }

        // First, let's see if there is a `slot_id` file, that
        // means we have been provided our own custom cert from SET_CERTIFICATE
        let file_name = format!("slot_id{}", slot_id);
        let mut path = Path::new(&file_name);

        if OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .is_err()
        {
            // Only support slot0
            path = match slot_id {
                0 => Path::new("certs/slot0/end_requester.cert.der"),
                _ => unimplemented!(),
            };
        }

        let file = match OpenOptions::new().read(true).write(false).open(path) {
            Err(why) => panic!("couldn't open {}: {}", path.display(), why),
            Ok(file) => file,
        };

        let mut reader = BufReader::new(file);
        let buffer = reader.fill_buf().unwrap();

        let (cert_chain_buffer, cert_chain_size) =
            libspdm::spdm::get_local_certchain(buffer, asym_algo, hash_algo, true);
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
/// Setup the capabilities of the requester. This matches the minimum required
/// by the CMA spec, see PCIe spec section 6.31.3 CMA/SPDM Rules
///
/// # Parameter
///
/// * `cntx_ptr`: The SPDM context
/// * `code`: Request code as specified by CLI arguments
/// * `session_info`: Struct containing current session information
///
/// # Returns
///
/// Ok(()) on success
/// Err(error_code) on `libspdm` failures
///
/// # Panics
///
/// Panics on any errors related to failed file I/Os
/// Panics on any unsupported `cert_slot_id`
/// Panics on invalid `cntx_ptr`
pub fn prepare_request(
    cntx_ptr: *mut c_void,
    code: RequestCode,
    cert_slot_id: u8,
    cert_path: Option<String>,
    session_info: &mut SpdmSessionInfo,
) -> Result<(), u32> {
    unsafe {
        match code {
            RequestCode::GetDigests {} => {
                let mut total_digest_buffer: [u8; 64 * 8] = [0; 64 * 8];
                let total_digest_buffer_ptr = &mut total_digest_buffer as *mut _ as *mut c_void;
                let mut slot_mask = 0;

                let ret = libspdm_get_digest(
                    cntx_ptr,
                    ptr::null_mut(),
                    &mut slot_mask,
                    total_digest_buffer_ptr,
                );

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }

                info!("Device digest: {total_digest_buffer:x?}");
            }
            RequestCode::GetCertificate {
                tcg_dice_evidence_binding_checks,
            } => {
                if cert_slot_id >= 8 {
                    error!(
                        "Requested slot-id({}) exceeds supported slots (0-7)",
                        cert_slot_id
                    );
                    return Err(1);
                }
                let mut cert_chain_size: usize = LIBSPDM_MAX_CERT_CHAIN_SIZE as usize;
                let mut cert_chain: [u8; LIBSPDM_MAX_CERT_CHAIN_SIZE as usize] =
                    [0; LIBSPDM_MAX_CERT_CHAIN_SIZE as usize];
                let cert_chain_ptr: *mut c_void = &mut cert_chain as *mut _ as *mut c_void;

                let ret = libspdm_get_certificate(
                    cntx_ptr,
                    &session_info.session_id,
                    cert_slot_id,
                    &mut cert_chain_size,
                    cert_chain_ptr,
                );

                // sizeof(spdm_cert_chain_t) + libspdm_get_hash_size(base_hash_algo)
                let hash_algo = get_base_hash_algo(cntx_ptr, cert_slot_id).unwrap().0;
                let cert_offset = libspdm_get_hash_size(hash_algo) as usize + 4;

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }
                // Write the cert_chain to a file, this can be used to compare against the original
                let file_name = format!("retrieved_slot_id{}", cert_slot_id);
                let path = Path::new(&file_name);

                let file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)
                {
                    Err(why) => {
                        error!("couldn't open {}: {}", path.display(), why);
                        return Err(1);
                    }
                    Ok(file) => file,
                };

                let mut writer = BufWriter::new(file);
                writer
                    .write_all(&cert_chain[cert_offset..cert_chain_size])
                    .unwrap();
                writer.flush().unwrap();

                if tcg_dice_evidence_binding_checks {
                    match check_tcg_dice_evidence_binding(cert_slot_id) {
                        Ok(_usage) => {}
                        Err(_e) => return Err(0),
                    }
                }
            }
            RequestCode::Challenge { challenge_request } => {
                let mut measurement_hash: [u8; LIBSPDM_MAX_HASH_SIZE as usize] =
                    [0; LIBSPDM_MAX_HASH_SIZE as usize];
                let measurement_hash_ptr: *mut c_void =
                    &mut measurement_hash as *mut _ as *mut c_void;

                if let Some(c_req) = challenge_request {
                    let libspdm_request_type = match c_req.as_str() {
                        "NO_MEASUREMENT_SUMMARY_HASH" => {
                            SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH as u8
                        }
                        "TCB_COMPONENT_MEASUREMENT_HASH" => {
                            SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH as u8
                        }
                        "ALL_MEASUREMENTS_HASH" => {
                            SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH as u8
                        }
                        _ => {
                            error!("Unsupported challenge request type ({})", c_req);
                            return Err(1);
                        }
                    };
                    let ret = libspdm_challenge(
                        cntx_ptr,
                        ptr::null_mut(),
                        session_info.slot_id,
                        libspdm_request_type,
                        measurement_hash_ptr,
                        ptr::null_mut(),
                    );
                    if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                        println!("Failed to authenticate endpoint through the challenge-response protocol. libspdm error: 0x{:x}", ret);
                        return Err(ret);
                    }
                } else {
                    panic!("Challenge request not specified");
                }
            }
            RequestCode::GetVersion {} => {
                let parameter = libspdm_data_parameter_t::new_connection(session_info.slot_id);
                let mut spdm_version = spdm::SpdmVersionNumber(0);
                let mut data_size: usize = core::mem::size_of::<u32>();
                let data_ptr = &mut spdm_version.0 as *mut _ as *mut c_void;

                let ret = libspdm_get_data(
                    cntx_ptr,
                    libspdm_data_type_t_LIBSPDM_DATA_SPDM_VERSION,
                    &parameter as *const libspdm_data_parameter_t,
                    data_ptr,
                    &mut data_size,
                );
                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }
                info!("Responder {}", spdm_version);
            }
            RequestCode::GetMeasurement { index } => {
                let mut measurement_record: [u8; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize] =
                    [0; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize];
                info!("Fetching measurement Index: 0x{:X}", index);

                if index as u32 == libspdm::libspdm_rs::SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS {
                    let num_meas_block = spdm::get_num_meas_blocks(
                        cntx_ptr,
                        session_info.slot_id,
                        &mut measurement_record,
                    )
                    .unwrap();
                    info!(
                        "Device has {} measurement block(s) available",
                        num_meas_block
                    );
                } else if index as u32 == libspdm::libspdm_rs::SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS {
                    error!("Use `get-measurements` to fetch all measurement blocks");
                    return Err(1);
                } else {
                    let (_, measurement_record_length) = spdm::get_measurement(
                        cntx_ptr,
                        session_info.slot_id,
                        index as u32,
                        &mut measurement_record,
                    )?;

                    info!("Measurement index: 0x{:X}", index);
                    info!("Measurement: {:x?}", &measurement_record[..measurement_record_length as usize]);
                }
            }
            RequestCode::GetMeasurements {} => {
                spdm::get_measurements(cntx_ptr, session_info.slot_id)?;
            }
            RequestCode::GetCapabilities {} => {
                get_responder_capabilities(cntx_ptr);
            }
            RequestCode::NegotiateAlgorithms {} => {}
            RequestCode::Heartbeat {} => {
                let ret = libspdm_heartbeat(cntx_ptr, session_info.session_id);
                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    if libspdm_status_source!(ret) == LIBSPDM_SOURCE_CORE
                        && libspdm_status_code!(ret) == spdm::LIBSPDM_STATUS_UNSUPPORTED_CAP
                    {
                        // Don't need to error here since it's the responder
                        // that does not support this feature.
                        error!("Responder does not support heartbeat capability");
                    } else {
                        return Err(ret);
                    }
                }
            }
            RequestCode::KeyUpdate { single_direction } => {
                let ret = libspdm_key_update(cntx_ptr, session_info.session_id, single_direction);

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    if libspdm_status_source!(ret) == LIBSPDM_SOURCE_CORE
                        && libspdm_status_code!(ret) == spdm::LIBSPDM_STATUS_UNSUPPORTED_CAP
                    {
                        // Don't need to error here since it's the responder
                        // that does not support this feature.
                        error!("Responder does not support key update capability");
                    } else {
                        return Err(ret);
                    }
                }
            }
            RequestCode::EncapsulatedSendReceive { secure_msg } => {
                let ret = if secure_msg {
                    let session_id_ptr = &mut session_info.session_id as *mut u32;
                    // session_id is not NULL, it is a secured message
                    libspdm_send_receive_encap_request(cntx_ptr, session_id_ptr)
                } else {
                    // session_id is NULL, it is a normal message
                    libspdm_send_receive_encap_request(cntx_ptr, ptr::null_mut())
                };

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    if libspdm_status_source!(ret) == LIBSPDM_SOURCE_CORE
                        && libspdm_status_code!(ret) == spdm::LIBSPDM_STATUS_UNSUPPORTED_CAP
                    {
                        // Don't need to error here since it's the responder
                        // that does not support this feature.
                        if secure_msg {
                            error!("Responder does not support Encapsulated Request capability with secure messages");
                        } else {
                            error!("Responder does not support Encapsulated Request capability with non-secure messages");
                        }
                    } else {
                        return Err(ret);
                    }
                }
            }
            RequestCode::EndSession {} => {
                let end_session_attributes = 0;
                let ret =
                    libspdm_stop_session(cntx_ptr, session_info.session_id, end_session_attributes);
                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }
                // END_SESSION is sent and the END_SESSION_ACK is received
                info!("SPDM session successfully ended");
            }
            RequestCode::GetCsr {} => {
                let mut csr_form_get_buffer: [u8; LIBSPDM_MAX_CSR_SIZE] = [0; LIBSPDM_MAX_CSR_SIZE];
                let csr_form_get_ptr = &mut csr_form_get_buffer as *mut _ as *mut c_void;
                let mut csr_form_len = csr_form_get_buffer.len();

                let ret = libspdm_get_csr(
                    cntx_ptr,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    0,
                    csr_form_get_ptr,
                    &mut csr_form_len,
                );

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }

                let path = Path::new("csr_response.der");

                let file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)
                {
                    Err(why) => {
                        error!("couldn't open {}: {}", path.display(), why);
                        return Err(1);
                    }
                    Ok(file) => file,
                };

                let mut writer = BufWriter::new(file);
                writer
                    .write_all(&csr_form_get_buffer[0..csr_form_len])
                    .unwrap();

                info!("CSR Response: {:x?}", &csr_form_get_buffer[0..csr_form_len]);
            }
            RequestCode::SetCertificate {} => {
                if cert_slot_id >= 8 {
                    error!(
                        "Requested slot-id({}) exceeds supported slots (0-7)",
                        cert_slot_id
                    );
                    return Err(1);
                }
                let asym_algo = get_base_asym_algo(cntx_ptr, cert_slot_id).unwrap().0;
                let hash_algo = get_base_hash_algo(cntx_ptr, cert_slot_id).unwrap().0;
                let file_path =
                    cert_path.expect("Certificate path was not specified for SetCertificate");
                let path = Path::new(&file_path);

                let file = match OpenOptions::new().read(true).write(false).open(path) {
                    Err(why) => panic!("couldn't open {}: {}", path.display(), why),
                    Ok(file) => file,
                };

                let mut reader = BufReader::new(file);
                let buffer = reader.fill_buf().unwrap();

                let (cert_chain_buffer, cert_chain_size) =
                    get_local_certchain(buffer, asym_algo, hash_algo, true);

                let ret = libspdm_set_certificate(
                    cntx_ptr,
                    ptr::null_mut(),
                    cert_slot_id,
                    cert_chain_buffer,
                    cert_chain_size,
                );

                // Check if the device responded with ResetRequired
                // If it did, let's respond with an Ok()
                if libspdm_status_code!(ret) == 0x12 {
                    info!("Certificate has been set, device requires a restart");
                    return Ok(());
                }

                if LibspdmReturnStatus::libspdm_status_is_error(ret) {
                    return Err(ret);
                }

                info!(
                    "Certificate has been set for slot-id (zero-based): {}",
                    cert_slot_id
                );
            }
            RequestCode::VendorDefinedRequest {} => {
                unimplemented!()
            }
            RequestCode::RespondIfReady {} => {
                return spdm::requester_respond_if_ready(cntx_ptr, session_info, 0);
            }
            RequestCode::Custom { value: _ } => {
                unimplemented!()
            }
        }
    }

    Ok(())
}

/// # Summary
///
/// Using the established SPDM context (`cntx_ptr`), probe all responder
/// capabilities and print only the supported capabilities.
///
/// # Parameter
///
/// * `cntx_ptr`: The SPDM context
///
/// # Panics
///
/// Panics on invalid `cntx_ptr`
pub unsafe fn get_responder_capabilities(cntx_ptr: *mut c_void) {
    info!("The responder supports the following capabilities:");
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP");
    }
    if libspdm_is_capabilities_flag_supported(
        cntx_ptr as *const libspdm_context_t,
        true,
        0,
        SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP,
    ) {
        info!(" -SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP");
    }
}
