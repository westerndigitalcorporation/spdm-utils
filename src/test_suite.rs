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

use crate::doe_pci_cfg::*;
#[cfg(libspdm_tests)]
use crate::*;
use core::ffi::c_void;

/// Defines the type of backend to be used in testing
pub enum TestBackend {
    DoeBackend,
    SocketBackend,
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
pub unsafe fn start_tests(cntx: *mut c_void, backend: TestBackend) -> ! {
    match backend {
        TestBackend::DoeBackend => {
            responder_validator_tests(cntx).unwrap();
            // Run DOE conformance tests
            test_discovery_basic().unwrap();
            test_discovery_all().unwrap();
            test_discovery_error().unwrap();
        }
        TestBackend::SocketBackend => {
            responder_validator_tests(cntx).unwrap();
        }
    }
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
pub unsafe fn responder_validator_tests(context: *mut c_void) -> Result<(), ()> {
    #[cfg(libspdm_tests)]
    {
        let mut m_spdm_test_group_version_configs = [
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_VERSION_SUCCESS_10,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: SPDM_RESPONDER_TEST_CASE_VERSION_INVALID_REQUEST,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
            },
            common_test_case_config_t {
                case_id: COMMON_TEST_ID_END,
                action: common_test_action_t_COMMON_TEST_ACTION_SKIP,
            },
        ];

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
                case_id: SPDM_RESPONDER_TEST_CASE_ALGORITHMS_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_DIGESTS_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_CHALLENGE_AUTH_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_MEASUREMENTS_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_KEY_EXCHANGE_RSP_UNEXPECTED_REQUEST,
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
                case_id: SPDM_RESPONDER_TEST_CASE_FINISH_RSP_UNEXPECTED_REQUEST,
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
                group_id: SPDM_RESPONDER_TEST_GROUP_VERSION,
                action: common_test_action_t_COMMON_TEST_ACTION_RUN,
                test_case_configs: &mut m_spdm_test_group_version_configs
                    as *mut common_test_case_config_t,
            },
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

        spdm_responder_conformance_test(
            context,
            &m_spdm_responder_validator_config as *const common_test_suite_config_t,
        );
    }

    info!("\n---- Responder-Validator Tests Complete. See `log` to check the results of libspdm tests ----\n");

    Ok(())
}
