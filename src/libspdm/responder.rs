// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! Contains all of the handlers for creating SPDM responder.

use crate::libspdm_rs;
use crate::libspdm_rs::*;
use crate::spdm::LibspdmReturnStatus;
use crate::spdm::get_local_certchain;
#[cfg(feature = "no_std")]
use alloc::vec::Vec;
use core::ffi::c_void;
#[cfg(not(feature = "no_std"))]
use std::fs;
use std::fs::OpenOptions;
#[cfg(not(feature = "no_std"))]
use std::path::Path;
#[cfg(not(feature = "no_std"))]
use std::sync::OnceLock;

/// Certificate model stored by [`register_algs_negotiated_callback`] and
/// consumed inside [`device_connection_state_callback`]. All other PQC
/// parameters are read directly from the SPDM context at callback time.
#[cfg(not(feature = "no_std"))]
static PQC_CERT_MODE: OnceLock<CertModel> = OnceLock::new();

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
/// * `pqc_asym_algo`: PQC asymmetric algorithm bitmask (SPDM 1.4); 0 means none
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
    spdm_ver: Option<&Vec<u16>>,
    asym_algo: u32,
    pqc_asym_algo: u32,
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
            | SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT
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
            let v: Vec<u16> = ver
                .iter()
                .map(|&x| x.checked_shl(SPDM_VERSION_NUMBER_SHIFT_BIT))
                .collect::<Option<Vec<u16>>>()
                .unwrap();
            let data_ptr = v.as_ptr() as *mut c_void;
            libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_SPDM_VERSION,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<u16>() * v.len(),
            );
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

        if pqc_asym_algo != 0 {
            let mut data: u32 = pqc_asym_algo;
            let data_ptr = &mut data as *mut _ as *mut c_void;
            if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_PQC_ASYM_ALGO,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<u32>(),
            )) {
                error!("Failed to set [LIBSPDM_DATA_PQC_ASYM_ALGO]");
                return Err(());
            }

            let mut data: u32 = pqc_asym_algo;
            let data_ptr = &mut data as *mut _ as *mut c_void;
            if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_REQ_PQC_ASYM_ALG,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<u32>(),
            )) {
                error!("Failed to set [LIBSPDM_DATA_PQC_ASYM_ALGO]");
                return Err(());
            }

            let mut data: bool = true;
            let data_ptr = &mut data as *mut _ as *mut c_void;
            if LibspdmReturnStatus::libspdm_status_is_error(libspdm_set_data(
                context,
                libspdm_data_type_t_LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST,
                &parameter as *const libspdm_data_parameter_t,
                data_ptr,
                core::mem::size_of::<bool>(),
            )) {
                error!("Failed to set [LIBSPDM_DATA_ALGO_PRIORITY_PQC_FIRST]");
                return Err(());
            }
        }

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

        let mut data: u16 = asym_algo as u16;
        let data_ptr = &mut data as *mut _ as *mut c_void;
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_REQ_BASE_ASYM_ALG,
            &parameter as *const libspdm_data_parameter_t,
            data_ptr,
            core::mem::size_of::<u16>(),
        );

        let mut data: u16 = SPDM_ALGORITHMS_KEY_SCHEDULE_SPDM as u16;
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
                let buffer = include_bytes!(
                    "../../certs/bank-ecc384/alias/slot0/bundle_responder.certchain.der"
                );
                (cert_chain_buffer, cert_chain_size) =
                    get_local_certchain(buffer, asym_algo, hash_algo, false);
            } else {
                let buffer = include_bytes!(
                    "../../certs/bank-ecc384/device/slot0/bundle_responder.certchain.der"
                );
                (cert_chain_buffer, cert_chain_size) =
                    get_local_certchain(buffer, asym_algo, hash_algo, false);
            }
        }
        #[cfg(not(feature = "no_std"))]
        {
            let file_path = if cert_mode == CertModel::Alias {
                format!(
                    "certs/bank-ecc384/alias/slot{}/bundle_responder.certchain.der",
                    slot_id
                )
            } else {
                format!(
                    "certs/bank-ecc384/device/slot{}/bundle_responder.certchain.der",
                    slot_id
                )
            };
            let path = Path::new(&file_path);

            let buffer = match fs::read(path) {
                Err(why) => panic!("couldn't open {}: {}", path.display(), why),
                Ok(data) => data,
            };

            (cert_chain_buffer, cert_chain_size) =
                get_local_certchain(&buffer, asym_algo, hash_algo, false);
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

/// Returns the `certs/bank-*/` directory name for the given PQC algorithm bitmask.
fn pqc_bank_dir(pqc_asym_algo: u32) -> &'static str {
    match pqc_asym_algo {
        libspdm_rs::SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44 => "bank-mldsa44",
        libspdm_rs::SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65 => "bank-mldsa65",
        libspdm_rs::SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87 => "bank-mldsa87",
        _ => panic!("unsupported pqc_asym_algo: 0x{:x}", pqc_asym_algo),
    }
}

/// # Summary
///
/// Provisions a certificate slot with the PQC cert chain from the matching
/// `certs/bank-<algo>/` directory.
///
/// # Parameter
///
/// * `context`: The SPDM context
/// * `slot_id`: Slot to provision (0–7)
/// * `pqc_asym_algo`: PQC algorithm bitmask (e.g. `SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87`)
/// * `hash_algo`: Hash algorithm bitmask used for the cert-chain header digest
/// * `cert_mode`: Alias or Device cert model
///
/// # Returns
///
/// `Ok(())` on success, `Err(())` otherwise.
#[cfg(not(feature = "no_std"))]
pub fn setup_pqc_cert_bank(
    context: *mut c_void,
    slot_id: u8,
    pqc_asym_algo: u32,
    hash_algo: u32,
    cert_mode: CertModel,
) -> Result<(), ()> {
    let bank = pqc_bank_dir(pqc_asym_algo);
    let file_path = if cert_mode == CertModel::Alias {
        format!(
            "certs/{}/alias/slot{}/bundle_responder.certchain.der",
            bank, slot_id
        )
    } else {
        format!(
            "certs/{}/device/slot{}/bundle_responder.certchain.der",
            bank, slot_id
        )
    };

    let path = Path::new(&file_path);
    let buffer = match fs::read(path) {
        Err(why) => {
            error!("couldn't open {}: {}", path.display(), why);
            return Err(());
        }
        Ok(data) => data,
    };

    let (cert_chain_buffer, cert_chain_size) =
        unsafe { get_local_certchain(&buffer, 0, hash_algo, false) };
    let parameter = libspdm_data_parameter_t::new_local(slot_id);
    if LibspdmReturnStatus::libspdm_status_is_error(unsafe {
        libspdm_set_data(
            context,
            libspdm_data_type_t_LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN,
            &parameter as *const libspdm_data_parameter_t,
            cert_chain_buffer,
            cert_chain_size,
        )
    }) {
        error!(
            "Failed to set PQC [LIBSPDM_DATA_LOCAL_PUBLIC_CERT_CHAIN] for slot {}",
            slot_id
        );
        return Err(());
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
    spdm_ver: &Vec<u16>,
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
        .iter()
        .any(|&v| v >= libspdm_rs::SPDM_MESSAGE_VERSION_13 as u16)
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

/// Callback invoked by libspdm on every connection-state transition.
///
/// This is currently used to implement the SPDM Banked Architecture once
/// `LIBSPDM_CONNECTION_STATE_NEGOTIATED` is reached. If a PQC algorithm was
/// selected the PQC certificate chain is loaded into the slot designated
/// during [`register_algs_negotiated_callback`]. This is used to emulate
/// the banked architecture in SPDM 1.4.
/// ECC sessions need no action because ECC chains are provisioned upfront.
///
/// # Safety
///
/// Called directly by libspdm with a valid `spdm_context`.
#[cfg(not(feature = "no_std"))]
pub unsafe extern "C" fn device_connection_state_callback(
    spdm_context: *mut c_void,
    connection_state: libspdm_connection_state_t,
) {
    if connection_state != libspdm_connection_state_t_LIBSPDM_CONNECTION_STATE_NEGOTIATED {
        return;
    }

    let conn = libspdm_data_parameter_t {
        location: 1, // LIBSPDM_DATA_LOCATION_CONNECTION
        additional_data: [0; 4],
    };

    // PQC algorithms are only available in SPDM 1.4+.
    let mut spdm_version: u16 = 0;
    let mut data_size = core::mem::size_of::<u16>();
    unsafe {
        libspdm_get_data(
            spdm_context,
            libspdm_data_type_t_LIBSPDM_DATA_SPDM_VERSION,
            &conn as *const libspdm_data_parameter_t,
            &mut spdm_version as *mut _ as *mut c_void,
            &mut data_size,
        );
    }
    spdm_version = spdm_version >> 8;

    if spdm_version < SPDM_MESSAGE_VERSION_14 as u16 {
        debug!(
            "device_connection_state_callback: SPDM 0x{:04x} < 1.4, skipping PQC",
            spdm_version
        );
        return;
    }

    // Read negotiated PQC asymmetric algorithm.
    let mut pqc_asym_algo: u32 = 0;
    data_size = core::mem::size_of::<u32>();
    let ret = unsafe {
        libspdm_get_data(
            spdm_context,
            libspdm_data_type_t_LIBSPDM_DATA_PQC_ASYM_ALGO,
            &conn as *const libspdm_data_parameter_t,
            &mut pqc_asym_algo as *mut _ as *mut c_void,
            &mut data_size,
        )
    };
    debug!(
        "device_connection_state_callback: PQC_ASYM_ALGO ret=0x{:x} algo=0x{:x}",
        ret, pqc_asym_algo
    );
    if pqc_asym_algo == 0 {
        debug!("device_connection_state_callback: ECC negotiated, nothing to do");
        return;
    }

    // Read negotiated base hash algorithm.
    let mut hash_algo: u32 = 0;
    data_size = core::mem::size_of::<u32>();
    unsafe {
        libspdm_get_data(
            spdm_context,
            libspdm_data_type_t_LIBSPDM_DATA_BASE_HASH_ALGO,
            &conn as *const libspdm_data_parameter_t,
            &mut hash_algo as *mut _ as *mut c_void,
            &mut data_size,
        );
    }

    let cert_mode = match PQC_CERT_MODE.get() {
        Some(m) => *m,
        None => {
            error!("device_connection_state_callback: PQC_CERT_MODE not initialised");
            return;
        }
    };

    let bank = pqc_bank_dir(pqc_asym_algo);
    let mut num_provisioned_slots = 0;

    for slot_id in 1..8 {
        let file_name = if cert_mode == CertModel::Alias {
            format!(
                "certs/{}/alias/slot{}/bundle_responder.certchain.der",
                bank, slot_id
            )
        } else {
            format!(
                "certs/{}/device/slot{}/bundle_responder.certchain.der",
                bank, slot_id
            )
        };
        let path = Path::new(&file_name);

        if OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .is_ok()
        {
            setup_pqc_cert_bank(spdm_context, slot_id, pqc_asym_algo, hash_algo, cert_mode)
                .unwrap();
            num_provisioned_slots += 1;
        }
    }

    setup_pqc_cert_bank(spdm_context, 0, pqc_asym_algo, hash_algo, cert_mode).unwrap();
    num_provisioned_slots += 1;

    let mut spdm_ver = Vec::new();
    spdm_ver.push(spdm_version);

    set_supported_slots_mask(num_provisioned_slots, &spdm_ver, spdm_context)
        .map_err(|_| {
            error!("failed to set supported slot mask");
        })
        .unwrap();
}

/// Register [`device_connection_state_callback`] with libspdm and record the
/// certificate model so the callback can select the correct cert path.
/// All other PQC parameters (`hash_algo`, `pqc_slot`) are read directly from
/// the SPDM context at callback time.
///
/// # Parameter
///
/// * `context`   - The SPDM context.
/// * `cert_mode` - Certificate chain model (alias or device).
#[cfg(not(feature = "no_std"))]
pub fn register_algs_negotiated_callback(context: *mut c_void, cert_mode: CertModel) {
    if let Err(e) = PQC_CERT_MODE.set(cert_mode) {
        error!("Unable to set the PQC certificate mode {e:?}");
    }
    unsafe {
        libspdm_register_connection_state_callback_func(
            context,
            Some(device_connection_state_callback),
        );
    }
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
