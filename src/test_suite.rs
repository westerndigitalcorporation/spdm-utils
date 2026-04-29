// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! This file provides a test harness for testing backends by running
//! the `SPDM-Responder-Validator` test suite and any other backend specific
//! conformance tests (as required).
//!
//! SAFETY: This file includes a lot of unsafe Rust.
//! If libspdm/SPDM-Responder-Validator behaves in a manor we don't expect
//! this will be very bad, so we are trusting libspdm here.

use crate::RequestCode;
use crate::cli_helpers;
use crate::doe_pci_cfg::*;
use crate::request;
use crate::spdm;
use crate::spdm::SpdmSessionInfo;
use crate::spdm::get_measurement;
use crate::tcg_concise_evidence_binding::check_tcg_dice_evidence_binding;
#[cfg(feature = "libspdm_tests")]
use crate::*;
use core::ffi::c_void;
use libspdm::libspdm_rs::{
    LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE, LIBSPDM_SEVERITY_ERROR, LIBSPDM_SOURCE_CORE,
};
use libspdm::libspdm_status_construct;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;

/// Defines the type of backend to be used in testing
pub enum TestBackend {
    DoeBackend,
    SocketBackend,
}

/// # Summary
///
/// Setup a spdm session in preperation for testing
///
/// # Parameter
///
/// * `cntx`: The SPDM context
///
/// # Returns
///
/// SpdmSessionInfo on Success, or any errors returned by the request.
pub fn setup_test_backend(cntx: *mut c_void) -> Result<SpdmSessionInfo, u32> {
    let slot_id = 0;

    // Setup Basic Requester, this is the default config we use for spdm-utils.
    request::setup_capabilities(
        cntx,
        slot_id,
        cli_helpers::parse_asym_algos(Some("ECDSA_ECC_NIST_P384".to_string())).unwrap(),
        cli_helpers::parse_hash_algos(Some("SHA_384".to_string())).unwrap(),
        cli_helpers::parse_dhe_named_groups(Some("SECP_384_R1,SECP_521_R1".to_string())).unwrap(),
        cli_helpers::parse_aead_cipher_suite(Some("AES_256_GCM".to_string())).unwrap(),
    )
    .unwrap();
    unsafe {
        spdm::initialise_connection(cntx, slot_id).unwrap();
    }
    let session_info = unsafe { spdm::start_session(cntx, slot_id, false).unwrap() };
    // Print out the negotiated algorithms
    unsafe {
        spdm::get_negotiated_algos(cntx, slot_id).unwrap();
    }

    info!("[{slot_id}] Listing Responder Capabilities");
    request::get_responder_capabilities(cntx);

    Ok(session_info)
}

/// # Summary
///
/// Send SPDM requests to the endpoint and automate the request process, such that
/// any assertions within the requests can be validated. This function does not
/// do any additional testing outside of the what the requests do.
///
/// This will only pass when run against a device that meets the
/// "TCG DICE Concise Evidence Binding for SPDM" specification.
///
/// # Parameter
///
/// * `cntx`: The SPDM context
///
/// # Returns
///
/// Success, or any errors returned by the request.
pub fn do_tcg_dice_evidence_binding_request_checks(
    cntx: *mut c_void,
    session_info: &mut SpdmSessionInfo,
) -> Result<(), u32> {
    let slot_id = 0;

    info!("[{slot_id}] Start RequestCode::GetDigests");
    request::prepare_request(
        cntx,
        RequestCode::GetDigests {},
        slot_id,
        None,
        session_info,
    )?;
    info!(" RequestCode::GetDigests ... [OK]");

    info!("[{slot_id}] Start RequestCode::GetCertificate");
    request::prepare_request(
        cntx,
        RequestCode::GetCertificate {
            tcg_dice_evidence_binding_checks: true,
        },
        slot_id,
        None,
        session_info,
    )?;
    let cert_usage = check_tcg_dice_evidence_binding(0).unwrap();
    info!(" RequestCode::GetCertificate ... [OK]");

    info!("[{slot_id}] Start RequestCode::Challenge");
    request::prepare_request(
        cntx,
        RequestCode::Challenge {
            challenge_request: Some("ALL_MEASUREMENTS_HASH".to_string()),
        },
        slot_id,
        None,
        session_info,
    )?;
    info!(" RequestCode::Challenge ... [OK]");

    // Setup a PSK session
    let mut session_info_psk;
    if cert_usage.sign_responses {
        session_info_psk = unsafe { spdm::start_session(cntx, slot_id, true).unwrap() };
    } else {
        error!("[{slot_id}] Unable to sign Responses");
        return Err(0);
    }

    // The DICE specifications describe Evidence as measurements that are to
    // be matched to Reference Values. Everything else seems to be called
    // attestation information.
    if cert_usage.sign_evidence || cert_usage.sign_attestation {
        info!("[{slot_id}] Start RequestCode::GetMeasurements");

        for measurement_index in 1..0xFF {
            let mut measurement_record: [u8; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize] =
                [0; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize];

            let ret = unsafe {
                get_measurement(
                    cntx,
                    slot_id,
                    true,
                    measurement_index,
                    &mut measurement_record,
                )
            };

            match ret {
                Ok((dmtf_spec_measure_type, _measurement_record_length)) => {
                    // This is a bit of a guess. The spec isn't clear about
                    // which is which. We are classifying measurements that don't have
                    // reference values as attestation and data that does have
                    // reference values as evidence.
                    // There doesn't seem to be an easy way to know if there are/aren't
                    // reference values, so we just guess based on what the measurement
                    // type is.
                    // This *could* lead to false positives/negatives, but at least it
                    // is something.
                    match dmtf_spec_measure_type as u32 & libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK {
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HARDWARE_CONFIGURATION |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_FIRMWARE_CONFIGURATION |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL => {
                            if !cert_usage.sign_attestation {
                                return Err(0);
                            }
                        },
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HASH_EXTEND_MEASUREMENT |
                        libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_STRUCTURED_MEASUREMENT_MANIFEST
                         => {
                            if !cert_usage.sign_evidence {
                                return Err(0);
                            }
                        },
                        _ => unreachable!()
                    }
                }
                Err(e) => {
                    if e == libspdm_status_construct!(
                        LIBSPDM_SEVERITY_ERROR,
                        LIBSPDM_SOURCE_CORE,
                        0x000a
                    ) {
                        // Wrong index, just continue
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        info!(" RequestCode::GetMeasurements ... [OK]");
    } else {
        error!("[{slot_id}] Unable to sign Evidence");
    }

    info!("[{slot_id}] Start RequestCode::Challenge");
    request::prepare_request(
        cntx,
        RequestCode::Challenge {
            challenge_request: Some("ALL_MEASUREMENTS_HASH".to_string()),
        },
        slot_id,
        None,
        &mut session_info_psk,
    )?;
    info!(" RequestCode::Challenge ... [OK]");

    Ok(())
}

/// Request all measurement from the requester as both the measurement hash
/// and raw-bitstream value of the measurement.
pub fn request_all_measurements(cntx: *mut c_void) -> Result<(), u32> {
    info!("---Probing all measurements as both hash and raw-bitstreams---");
    let mut measurement_record: [u8; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize] =
        [0; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize];
    let slot_id = 0;
    for measurement_index in 0..=0xFE {
        for request_iter in 0..2 {
            let (raw_bitstream, format) = if request_iter == 0 {
                (true, "raw-bitstream")
            } else {
                (false, "hash")
            };
            unsafe {
                let ret = get_measurement(
                    cntx,
                    slot_id,
                    raw_bitstream,
                    measurement_index,
                    &mut measurement_record,
                );

                if let Ok(measures) = ret {
                    let (_, measurement_record_length) = measures;
                    // measurement_record shall point to the measurement block,
                    // which contains the DMTF measurement specification format
                    let dmtf_spec_measurement_value_type_index = core::mem::size_of::<
                        libspdm::libspdm_rs::spdm_measurement_block_common_header_t,
                    >();
                    assert!(dmtf_spec_measurement_value_type_index == 4);
                    let measurement_value_type =
                        measurement_record[dmtf_spec_measurement_value_type_index] as u32;
                    // Reference SPDM Spec 1.3: 489 Table 50 — GET_MEASUREMENTS request attributes
                    if raw_bitstream && (measurement_value_type & libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM == 0) {
                        // Bit [7] not set -> Responder returned a hash
                        warn!("Requested {format} for index {measurement_index}, responder returned hash only!");
                    } else if !raw_bitstream && (measurement_value_type & libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM == libspdm::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) {
                        // Bit [7] set -> Responder returned a Raw-bitstream
                        warn!("Requested {format} for index {measurement_index}, responder returned raw-bitstream!");
                    }

                    info!("Measurement found at index 0x{:X?}", measurement_index);
                    info!(
                        "Measurement as {format}: {:x?}",
                        &measurement_record[..measurement_record_length as usize]
                    );
                } else {
                    warn!(
                        "No measurement at index 0x{:x?} as {format}",
                        measurement_index
                    );
                }
            }
        }
    }

    info!(" Probing Measurements ... [OK]");
    Ok(())
}

/// # Summary
///
/// Request a CSR from the responder, sign it, then set the signed certificate
/// in `slot_id` of the specified responder established by the `cntx`
///
/// # Parameter
///
/// * `cntx`: The SPDM context
/// * `cert_slot_id`: Slot ID in which to set certificate [1, 7] are valid.
///
/// # Returns
///
/// Ok() Iff there were no error in setting the certificate, `reset-required`
///      error return case is treated as success.
/// Panics on any other error in attempt to set-certificate.
pub fn test_set_certificate(cntx: *mut c_void, cert_slot_id: u8) -> Result<(), ()> {
    if cert_slot_id >= 8 || cert_slot_id == 0 {
        error!("Invalid cert-slot-id {cert_slot_id} specified for set-certificate");
        return Err(());
    }
    let session_slot_id = 0;

    let mut session_info = unsafe { spdm::start_session(cntx, session_slot_id, false).unwrap() };

    let alias_cert = unsafe {
        crate::libspdm_is_capabilities_flag_supported(
            cntx as *const crate::libspdm_context_t,
            true,
            0,
            crate::SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP,
        )
    };

    // Do GetCsr
    if let Err(rc) = request::prepare_request(
        cntx,
        RequestCode::GetCsr {},
        0,    // Unused
        None, // Unused
        &mut session_info,
    ) {
        error!("Get CSR failed with libspdm error: 0x{:x}", rc);
        return Err(());
    }

    let csr_response_path = std::path::Path::new("./csr_response.der");
    if !csr_response_path.exists() {
        error!("CSR Response does not exist!");
        return Err(());
    }

    // Process the CSR, See `README: Getting a Certificate Signing Request` for
    // more details on this process.

    // 1. Convert the CSR Response to PEM
    assert!(
        Command::new("openssl")
            .arg("req")
            .arg("-inform")
            .arg("der")
            .arg("-in")
            .arg("./csr_response.der")
            .arg("-out")
            .arg("csr_response.req")
            .output()
            .expect("Failed to convert the CSR Response to PEM")
            .status
            .success()
    );

    // 2. Sign the CSR
    if alias_cert {
        assert!(
            Command::new("openssl")
                .arg("x509")
                .arg("-req")
                .arg("-in")
                .arg("csr_response.req")
                .arg("-out")
                .arg("csr_response.cert")
                .arg("-CA")
                .arg("./certs/slot0/inter.der")
                .arg("-sha384")
                .arg("-days")
                .arg("3650")
                .arg("-set_serial")
                .arg("2")
                .arg("-extensions")
                .arg("device_ca")
                .arg("-extfile")
                .arg("./certs/alias/openssl.cnf")
                .output()
                .expect("Failed to Sign the CSR")
                .status
                .success()
        );
    } else {
        assert!(
            Command::new("openssl")
                .arg("x509")
                .arg("-req")
                .arg("-in")
                .arg("csr_response.req")
                .arg("-out")
                .arg("csr_response.cert")
                .arg("-CA")
                .arg("./certs/slot0/inter.der")
                .arg("-sha384")
                .arg("-days")
                .arg("3650")
                .arg("-set_serial")
                .arg("2")
                .arg("-extensions")
                .arg("leaf")
                .arg("-extfile")
                .arg("./certs/device/openssl.cnf")
                .output()
                .expect("Failed to Sign the CSR")
                .status
                .success()
        );
    }

    // 3. Convert the Certificate back to DER format
    assert!(
        Command::new("openssl")
            .arg("asn1parse")
            .arg("-in")
            .arg("csr_response.cert")
            .arg("-out")
            .arg("csr_response.cert.der")
            .output()
            .expect("Failed to execute openssl command")
            .status
            .success()
    );

    // 4. Combine all the immutable certificates
    let immutables_certs = [
        "./certs/slot0/ca.cert.der",
        "./certs/slot0/inter.cert.der",
        "./csr_response.cert.der",
    ];

    let output_cert_chain = "set-cert.der";
    let mut output_file =
        File::create(output_cert_chain).expect("Failed to create immutable cert-chain file");

    for file in &immutables_certs {
        let content = std::fs::read(file).expect("failed to read {file}");
        output_file
            .write_all(&content)
            .expect("failed to write {file} to {output_file}");
    }

    // Do SetCertificate
    let cert_path = "./set-cert.der".to_string();
    if let Err(rc) = request::prepare_request(
        cntx,
        RequestCode::SetCertificate {},
        cert_slot_id,
        Some(cert_path),
        &mut session_info,
    ) {
        // This cannot be the `reset-required` error case, as it is checked by
        // 'prepare_request()` and treated as success.
        panic!("Failed to set certificate with libspdm error: 0x{:x}", rc);
    }

    info!("Device Certificate successfully set for slot {cert_slot_id}");
    info!("Set Certificate ... [OK]");

    // Cleanup after test slot
    let cleanup_path = if alias_cert {
        format!("./certs/alias/slot{}", cert_slot_id)
    } else {
        format!("./certs/device/slot{}", cert_slot_id)
    };
    if Path::new(&cleanup_path).is_dir() {
        std::fs::remove_dir_all(cleanup_path).expect("Failed to cleanup test slot");
    }

    let csr_artifacts = [
        "./csr_response.cert",
        "./csr_response.cert.der",
        "./csr_response.der",
        "./csr_response.req",
        "./set-cert.der",
    ];

    for artifact in csr_artifacts {
        if let Err(e) = std::fs::remove_file(artifact)
            && e.kind() == std::io::ErrorKind::NotFound
        {
            warn!("{:?}: does not exist", artifact)
        }
    }

    Ok(())
}

/// # Summary
///
/// Entry point for the test suite. Run the tests required to tests a
/// specified `TestBackend`
///
/// # Parameter
///
/// * `cntx`: The SPDM context
/// * `backend`: Backend for this test (DOE/Socket...etc)
///
/// # Returns
///
/// Does not return, the process will exit after tests are complete.
pub fn start_tests(cntx: *mut c_void, backend: TestBackend) -> ! {
    match backend {
        TestBackend::DoeBackend => {
            // Run DOE conformance tests
            test_discovery_basic().unwrap();
            test_discovery_all().unwrap();
            test_discovery_error().unwrap();
        }
        TestBackend::SocketBackend => {}
    }

    responder_validator_tests(cntx).unwrap();

    let mut session_info = setup_test_backend(cntx).unwrap();

    let alias_cert = unsafe {
        crate::libspdm_is_capabilities_flag_supported(
            cntx as *const crate::libspdm_context_t,
            true,
            0,
            crate::SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP,
        )
    };

    if alias_cert
        && let Err(libpsm_err) =
            do_tcg_dice_evidence_binding_request_checks(cntx, &mut session_info)
    {
        panic!("    request failed with libspdm err: {:x}", libpsm_err);
    }
    if let Err(e) = request_all_measurements(cntx) {
        panic!("    failed to request all measurements err:  {:x}", e);
    }

    test_set_certificate(cntx, 1).unwrap();

    info!("Testing Complete ...");
    std::process::exit(0);
}

/// # Summary
///
/// Set up and run the tests suite in SPDM-Responder-Validator.
///
/// # Parameter
///
/// * `context`: The SPDM context
///
/// # Returns
///
/// OK(()) on completing the tests (this does not mean all the tests passed,
/// the test log is written to `test.log` once completed. See there for results)
///
/// # SPDM-Responder-Validator Assertions
///
/// The tests below calls into the SPDM-Responder-Validator library, which
/// should be built in `debug` mode to ensure that assertions trigger a hang on
/// failure. If during tests, the tests hang (do not complete), the `test.log`
/// should be looked at to find the point of failure.
#[allow(unused_variables)]
pub fn responder_validator_tests(context: *mut c_void) -> Result<(), ()> {
    #[cfg(feature = "libspdm_tests")]
    {
        let mut m_spdm_test_group_capabilities_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_11,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_SUCCESS_12,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CAPABILITIES_UNEXPECTED_REQUEST_NON_IDENTICAL,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_algorithms_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_11,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_SUCCESS_12,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST_NON_IDENTICAL,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_digests_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_certificate_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CERTIFICATE_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CERTIFICATE_SPDM_X509_CERTIFICATE,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_challenge_auth_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B1C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B2C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_10_A1B3C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B1C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B2C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B3C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A1B4C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B1C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B2C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B3C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_SUCCESS_12_A2B4C1,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_measurements_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SPDM_MEASUREMENT_BLOCK,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_11,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_11_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_12,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_SUCCESS_12_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_key_exchange_rsp_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_11_HS_CLEAR,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST_IN_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_SUCCESS_12_HS_CLEAR,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_finish_rsp_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_11_HS_CLEAR,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_VERSION_MISMATCH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST_IN_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id:
                    SPDM_RESPONDER_TEST_CASE_FINISH_RSP_DECRYPT_ERROR_INVALID_VERIFY_DATA_HS_CLEAR,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SUCCESS_12_HS_CLEAR,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_SESSION_REQUIRED,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_heartbeat_ack_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_SUCCESS_11_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_VERSION_MISMATCH_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id:
                    SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_HEARTBEAT_ACK_SESSION_REQUIRED,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
        ];

        let mut m_spdm_test_group_key_update_ack_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SUCCESS_11_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_VERSION_MISMATCH_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_INVALID_REQUEST_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id:
                    SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_UPDATE_ACK_SESSION_REQUIRED,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_end_session_ack_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_SUCCESS_11_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_VERSION_MISMATCH_IN_DHE_SESSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id:
                    SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_UNEXPECTED_REQUEST_IN_DHE_SESSION_HS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_END_SESSION_ACK_SESSION_REQUIRED,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

        let mut m_spdm_test_group_configs = [
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_CAPABILITIES,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_capabilities_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_ALGORITHMS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_algorithms_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_DIGESTS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_digests_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_CERTIFICATE,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_certificate_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_CHALLENGE_AUTH,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_challenge_auth_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_MEASUREMENTS,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_measurements_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_KEY_EXCHANGE_RSP,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_key_exchange_rsp_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_FINISH_RSP,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_finish_rsp_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_HEARTBEAT_ACK,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_heartbeat_ack_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_KEY_UPDATE_ACK,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_key_update_ack_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: SPDM_RESPONDER_TEST_GROUP_END_SESSION_ACK,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_end_session_ack_configs
                    as *mut common_test_case_config_t,
            },
            common_test_group_config_t {
                group_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
                test_case_configs: std::ptr::null_mut(),
            },
        ];

        let cfg_name = std::ffi::CString::new("spdm_responder_validator default config").unwrap();
        let m_spdm_responder_validator_config = common_test_suite_config_t {
            config_name: cfg_name.as_ptr() as *mut i8,
            test_group_configs: &mut m_spdm_test_group_configs as *mut common_test_group_config_t,
        };

        unsafe {
            spdm_responder_conformance_test(
                context,
                &m_spdm_responder_validator_config as *const common_test_suite_config_t,
            );
        }

        info!(
            "\n---- Responder-Validator Tests Complete. See `log` to check the results of libspdm tests ----\n"
        );
    }

    Ok(())
}
