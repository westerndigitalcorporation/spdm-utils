// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! Contains helper functions used in parsing the CLI arguments

use crate::*;

/// # Summary
///
/// Parses the string arguments that specifies the PCIe Vendor ID and Device ID.
///
/// # Parameter
///
/// * `vid`: specified as a hex string "0xCAF3" or as base 10 "1234".
/// * `dev_id`: specified as a hex string "0xCAF3" or as base 10 "1234".
///
/// # Returns
///
/// On success, OK((vid, dev_id)) or Err(()) on failure to parse.
pub fn parse_pcie_identifiers(vid: String, dev_id: String) -> Result<(u16, u16), ()> {
    fn parse_identifier(id: String, id_type: &str) -> Result<u16, ()> {
        let (id, base) = if id.starts_with("0x") {
            (id.trim_start_matches("0x"), 16)
        } else {
            (id.as_str(), 10)
        };

        u16::from_str_radix(id, base).map_err(|e| {
            error!("Invalid PCIe {id_type}: {:} - err {:?}", id, e);
            ()
        })
    }

    let vid = parse_identifier(vid, "vendor ID")?;
    let dev_id = parse_identifier(dev_id, "device ID")?;

    Ok((vid, dev_id))
}

/// # Summary
///
/// Parses the CLI argument for the SPDM version used by a responder.
///
/// # Parameter
///
/// * `spdm_ver`: String option containing the version (1.0, 1,1 ...etc)
///
/// # Returns
///
/// The corresponding libspdm value for the version, None if not found.
pub fn parse_spdm_responder_version(spdm_ver: Option<String>) -> Option<u8> {
    if let Some(ver) = spdm_ver {
        match ver.as_str() {
            "1.0" => {
                return Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_10).unwrap())
            }
            "1.1" => {
                return Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_11).unwrap())
            }
            "1.2" => {
                return Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_12).unwrap())
            }
            "1.3" => {
                return Some(u8::try_from(libspdm::libspdm_rs::SPDM_MESSAGE_VERSION_13).unwrap())
            }
            _ => return None,
        }
    }
    None
}

/// # Summary
///
/// Parses the CLI based AEAD Cipher Suites
///
/// # Parameter
///
/// * `aead_cipher_suites`: A comma delimited string containing AEAD Cipher suites
///
/// # Returns
///
/// Returns a `u16` containing the libspdm AEAD cipher suite bitmasks.
pub fn parse_aead_cipher_suite(aead_cipher_suites: Option<String>) -> Result<u16, ()> {
    let mut libspdm_aead_cipher_suites: u16 = 0;

    let suites = match aead_cipher_suites {
        Some(aead_cipher_suites) => aead_cipher_suites
            .split(',')
            // remove leading/trailing whitespace
            .map(|elem| elem.trim().to_string())
            .collect::<Vec<String>>(),
        None => {
            error!("No AEAD Cipher Suites specified");
            return Err(());
        }
    };

    for suite in suites {
        match suite.as_str() {
            "AES_128_GCM" => {
                libspdm_aead_cipher_suites |=
                    u16::try_from(SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM).unwrap();
            }
            "AES_256_GCM" => {
                libspdm_aead_cipher_suites |=
                    u16::try_from(SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM).unwrap();
            }
            "CHACHA20_POLY1305" => {
                libspdm_aead_cipher_suites |=
                    u16::try_from(SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305).unwrap();
            }
            "AEAD_SM4_GCM" => {
                libspdm_aead_cipher_suites |=
                    u16::try_from(SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM).unwrap();
            }
            _ => {
                error!("Unsupported AEAD Cipher Suite ({})", suite);
                return Err(());
            }
        }
    }
    if libspdm_aead_cipher_suites == 0 {
        error!("No valid AEAD Cipher Suites Specified");
        return Err(());
    }
    debug!(
        "Specified aead cipher suites: {}",
        libspdm_aead_cipher_suites
    );
    Ok(libspdm_aead_cipher_suites)
}

/// # Summary
///
/// Parses the CLI based DHE Named groups
///
/// # Parameter
///
/// * `dhe_groups`: A comma delimited string containing the DHE named groups
///
/// # Returns
///
/// Returns a `u16` containing the libspdm DHE named groups bitmasks.
pub fn parse_dhe_named_groups(dhe_groups: Option<String>) -> Result<u16, ()> {
    let mut libspdm_dhe_groups: u16 = 0;

    let groups = match dhe_groups {
        Some(dhe_groups) => dhe_groups
            .split(',')
            // remove leading/trailing whitespace
            .map(|elem| elem.trim().to_string())
            .collect::<Vec<String>>(),
        None => {
            error!("No DHE groups specified");
            return Err(());
        }
    };

    for group in groups {
        match group.as_str() {
            "FFDHE_2048" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048).unwrap();
            }
            "FFDHE_3072" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072).unwrap();
            }
            "FFDHE_4096" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096).unwrap();
            }
            "SECP_256_R1" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1).unwrap();
            }
            "SECP_384_R1" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1).unwrap();
            }
            "SECP_521_R1" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1).unwrap();
            }
            "SM2_P256" => {
                libspdm_dhe_groups |=
                    u16::try_from(SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256).unwrap();
            }
            _ => {
                error!("Unsupported DHE group ({})", group);
                return Err(());
            }
        }
    }

    if libspdm_dhe_groups == 0 {
        error!("No valid DHE Named groups specified");
        return Err(());
    }
    debug!("Specified dhe groups: {}", libspdm_dhe_groups);
    Ok(libspdm_dhe_groups)
}

/// # Summary
///
/// Parses the CLI based asymmetric algorithms specified
///
/// # Parameter
///
/// * `asym_algos`: A comma delimited string containing the asym algos
///
/// # Returns
///
/// Returns a `u32` containing the libspdm asym algorithm bitmasks.
pub fn parse_asym_algos(asym_algos: Option<String>) -> Result<u32, ()> {
    let mut specified_algos: u32 = 0;
    let algos = match asym_algos {
        Some(algos) => algos
            .split(',')
            // remove leading/trailing whitespace
            .map(|elem| elem.trim().to_string())
            .collect::<Vec<String>>(),
        None => {
            error!("No asymmetric algorithms specified");
            return Err(());
        }
    };

    for algo in algos {
        match algo.as_str() {
            "RSASSA_2048" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
            "RSAPSS_2048" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
            "RSASSA_3072" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
            "RSAPSS_3072" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
            "ECDSA_ECC_NIST_P256" => {
                specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256
            }
            "RSASSA_4096" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
            "RSAPSS_4096" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
            "ECDSA_ECC_NIST_P384" => {
                specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384
            }
            "ECDSA_ECC_NIST_P521" => {
                specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521
            }
            "SM2_ECC_SM2_P256" => {
                specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256
            }
            "EDDSA_ED25519" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519,
            "EDDSA_ED448" => specified_algos |= SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448,
            _ => {
                error!("Unsupported asymmetric algorithm {}", algo);
                return Err(());
            }
        }
    }

    if specified_algos == 0 {
        error!("No valid asymmetric algorithms specified");
        return Err(());
    }
    debug!("Specified Algos: {}", specified_algos);
    Ok(specified_algos)
}

/// # Summary
///
/// Parses the CLI based hashing algorithms specified
///
/// # Parameter
///
/// * `hash_algos`: A comma delimited string containing the asym algos
///
/// # Returns
///
/// Returns a `u32` containing the libspdm hash algorithm bitmasks.
pub fn parse_hash_algos(hash_algos: Option<String>) -> Result<u32, ()> {
    let mut specified_algos: u32 = 0;
    let algos = match hash_algos {
        Some(algos) => algos
            .split(',')
            // remove leading/trailing whitespace
            .map(|elem| elem.trim().to_string())
            .collect::<Vec<String>>(),
        None => {
            error!("No hashing algorithms specified");
            return Err(());
        }
    };

    for algo in algos {
        match algo.as_str() {
            "SHA_256" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
            "SHA_384" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            "SHA_512" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
            "SHA3_256" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256,
            "SHA3_384" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384,
            "SHA3_512" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512,
            "SM3_256" => specified_algos |= SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256,
            _ => {
                error!("Unsupported hashing algorithm {}", algo);
                return Err(());
            }
        }
    }

    if specified_algos == 0 {
        error!("No valid hashing algorithms specified");
        return Err(());
    }
    debug!("Specified hashing Algos: {}", specified_algos);
    Ok(specified_algos)
}
