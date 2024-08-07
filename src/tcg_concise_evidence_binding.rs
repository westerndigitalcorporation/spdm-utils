// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

//! This file provides helper functions and support for the
//! "TCG DICE Concise Evidence Binding for SPDM" specification
//! https://trustedcomputinggroup.org/wp-content/uploads/TCG-DICE-Concise-Evidence-Binding-for-SPDM-Version-1.0-Revision-54_pub.pdf

use asn1_rs::{ParseResult, Sequence};
use std::fs::OpenOptions;
use std::io::BufReader;
use std::path::Path;
use std::process::Command;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::{oid, Oid};
use x509_parser::pem::Pem;

const ID_SPDM_CERT_OIDS: Oid = oid!(1.3.6 .1 .4 .1 .412 .274 .6);
const ID_DMTF_HARDWARE_IDENTITY: Oid = oid!(1.3.6 .1 .4 .1 .412 .274 .2);
const ID_DMTF_MUTABLE_CERTIFICATE: Oid = oid!(1.3.6 .1 .4 .1 .412 .274 .5);

const TCG_DICE_KP_ECA: Oid = oid!(2.23.133 .5 .4 .100 .12);

const TCG_DICE_KP_IDENTITYINIT: Oid = oid!(2.23.133 .5 .4 .100 .6);
const TCG_DICE_KP_ATTESTINIT: Oid = oid!(2.23.133 .5 .4 .100 .8);
const TCG_DICE_KP_ASSERTINIT: Oid = oid!(2.23.133 .5 .4 .100 .10);

const TCG_DICE_KP_IDENTITYLOC: Oid = oid!(2.23.133 .5 .4 .100 .7);
const TCG_DICE_KP_ATTESTLOC: Oid = oid!(2.23.133 .5 .4 .100 .9);
const TCG_DICE_KP_ASSERTLOC: Oid = oid!(2.23.133 .5 .4 .100 .11);

const ID_DMTF_EKU_RESPONDER_AUTH: Oid = oid!(1.3.6 .1 .4 .1 .412 .274 .3);
const ID_DMTF_EKU_REQUESTER_AUTH: Oid = oid!(1.3.6 .1 .4 .1 .412 .274 .4);

#[derive(Debug, PartialEq)]
enum SPDMCertificateType {
    NonDeviceCAChain,
    DeviceCertCA,
    AlisasCertCA,
    LeafCert,
}

#[derive(Debug)]
/// A list of approved uses for the certificate based on OIDs
/// set in the chain. See section 5.3 in the
/// "TCG DICE Concise Evidence Binding for SPDM" specification for full
/// details.
pub struct CertificateUsage {
    pub sign_evidence: bool,
    pub sign_attestation: bool,
    pub sign_identity_challenge: bool,
    pub sign_responses: bool,
    pub sign_requests: bool,
}

// TODO: Handle multiple entries
fn spdm_cert_oids_parser(i: &[u8]) -> ParseResult<Oid> {
    Sequence::from_der_and_then(i, |i| {
        return Ok((i, Oid::new(std::borrow::Cow::Borrowed(&i[4..]))));
    })
}

fn check_for_extended_key_usage(
    x509: &X509Certificate,
    name: &str,
    extension: &Oid,
) -> Result<(), ()> {
    match x509.extended_key_usage() {
        Ok(Some(extended_key_usage)) => {
            println!(
                "extended_key_usage.other: {:?}",
                extended_key_usage.value.other
            );

            if extended_key_usage.value.other.contains(extension) {
                Ok(())
            } else {
                error!("'{}' Certificate doesn't contain {name}", x509.subject());
                Err(())
            }
        }
        Ok(None) => {
            error!("Certificate doesn't contain extendedKeyUsage");
            Err(())
        }
        Err(_e) => {
            error!("Duplicate extendedKeyUsage");
            Err(())
        }
    }
}

fn check_for_basic_contraints_ca(x509: &X509Certificate, value: bool) -> Result<(), ()> {
    match x509.basic_constraints() {
        Ok(Some(extension)) => {
            let ca = extension.value.ca;

            if ca != value {
                error!("'{}' basicConstraints:CA incorrectly set", x509.subject());
                return Err(());
            }
        }
        Ok(None) => {
            error!(
                "'{}' Certificate doesn't contain basicConstraints",
                x509.subject()
            );
            return Err(());
        }
        Err(_e) => {
            error!("Duplicate basicConstraints");
            return Err(());
        }
    }

    Ok(())
}

/// # Summary
///
/// Check the full certificate in `retrieved_slot_id{cert_slot_id}` against the
/// TCG requirements. This doesn't do any certificate validataion, as that should
/// have already happened. This is just checking for specific OIDs, as specified
/// in chapter 5.3.
///
/// TODO: We currently don't check that the certificate is only used for what
/// is specified, for example requester/responder or attest/assert. That
/// currently still needs to be manually checked.
///
/// # Parameter
///
/// * `cert_slot_id`: The certificate slot to check and that GetCertificate
///                   was called on
///
/// # Returns
///
/// Ok(CertificateUsage) on success, where CertificateUsage contains details
/// on where the certificate should be used.
///
/// # Panics
///
/// Panics on any errors related to failed file I/Os
pub fn check_tcg_dice_evidence_binding(cert_slot_id: u8) -> Result<CertificateUsage, ()> {
    // The Rust APIs in x509-parser, x509-certificate and openssl are unable
    // to process the X509 chain we recieve. While the openssl applications
    // can easily handle it.
    //
    // So, at this point we call `openssl` from the shell to generate a file
    // of PEM certs. Which we can then parse with X509Certificate.
    let cmd = format!(
        "while openssl x509 -outform PEM; do :; done < retrieved_slot_id{cert_slot_id} > pem_file"
    );
    Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("failed to execute process");

    let path = Path::new("pem_file");
    let file = match OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(path)
    {
        Err(why) => {
            error!("couldn't open {}: {}", path.display(), why);
            return Err(());
        }
        Ok(file) => file,
    };

    let reader = BufReader::new(file);
    let mut pem_iterator = Pem::iter_from_reader(reader).peekable();
    let mut cert_type = SPDMCertificateType::NonDeviceCAChain;

    let mut usage = CertificateUsage {
        sign_evidence: false,
        sign_attestation: false,
        sign_identity_challenge: false,
        sign_responses: false,
        sign_requests: false,
    };

    while let Some(pem) = pem_iterator.next() {
        let pem = pem.unwrap();
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");

        if pem_iterator.peek().is_none() {
            cert_type = SPDMCertificateType::LeafCert;
        }

        match cert_type {
            // First we want to find the Device Certificate CA
            // It *should* be the last certificate with the 'Hardware identity OID'.
            // The certificates should all be immutable
            SPDMCertificateType::NonDeviceCAChain | SPDMCertificateType::DeviceCertCA => {
                match x509.get_extension_unique(&ID_SPDM_CERT_OIDS) {
                    Ok(Some(extension)) => {
                        // This contains id-spdm-cert-oids
                        cert_type = SPDMCertificateType::DeviceCertCA;

                        let seq = spdm_cert_oids_parser(extension.value).unwrap();

                        if seq.1 == ID_DMTF_HARDWARE_IDENTITY {
                            // This contains id-DMTF-hardware-identity
                            info!("'{}' contains id-DMTF-hardware-identity", x509.subject());

                            // Assert that mutable isn't set
                            // TODO: Support multiple entries in id-spdm-cert-oids
                            assert!(seq.1 != ID_DMTF_MUTABLE_CERTIFICATE);

                            // Check if the next certificate contains id-DMTF-hardware-identity
                            // If it doesn't then it must be an Alias Intermediate Certificate
                            if let Some(next_pem) = pem_iterator.peek() {
                                let next_pem = next_pem.as_ref().unwrap();
                                let next_x509 =
                                    next_pem.parse_x509().expect("X.509: decoding DER failed");

                                match next_x509.get_extension_unique(&ID_SPDM_CERT_OIDS) {
                                    Ok(Some(extension)) => {
                                        // This contains id-spdm-cert-oids
                                        let seq = spdm_cert_oids_parser(extension.value).unwrap();

                                        // TODO: Support multiple entries in id-spdm-cert-oids
                                        if seq.1 != ID_DMTF_HARDWARE_IDENTITY {
                                            cert_type = SPDMCertificateType::AlisasCertCA;

                                            // As the next certificate is an Alias Intermediate
                                            // Certificate, then this certificate is used to issue
                                            // Intermediate CA certificates.
                                            info!("    Used to sign ECA");
                                            check_for_extended_key_usage(
                                                &x509,
                                                "tcg-dice-kp-eca",
                                                &TCG_DICE_KP_ECA,
                                            )?;
                                            check_for_basic_contraints_ca(&x509, true)?;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            error!("Extension {:?} is invalid", seq.1);
                            return Err(());
                        }
                    }
                    Ok(None) => {
                        if cert_type == SPDMCertificateType::NonDeviceCAChain {
                            // We are still processing the Root CA or Intermediate CA
                            // We just ignore these as they aren't governed by the TCG
                            // spec.
                            continue;
                        }

                        error!(
                            "'{}' Certificate doesn't contain id-spdm-cert-oids",
                            x509.subject()
                        );
                    }
                    Err(_e) => {
                        error!("Duplicate Hardware identity OID");
                        return Err(());
                    }
                }

                // Check for extensions that we should contain
                check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-identityInit",
                    &TCG_DICE_KP_IDENTITYINIT,
                )?;

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-attestInit",
                    &TCG_DICE_KP_ATTESTINIT,
                ) {
                    // This chain is used to sign evidence
                    info!("    Used to sign Evidence");
                    usage.sign_evidence = true;
                } else {
                    if usage.sign_evidence {
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-attestInit",
                    &TCG_DICE_KP_ATTESTINIT,
                ) {
                    // This chain is used to sign evidence
                    info!("    Used to sign Evidence");
                    usage.sign_evidence = true;
                } else {
                    if usage.sign_evidence {
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-assertInit",
                    &TCG_DICE_KP_ASSERTINIT,
                ) {
                    // This chain is used to sign attestation
                    info!("    Used to sign Attestation");
                    usage.sign_attestation = true;
                } else {
                    if usage.sign_attestation {
                        return Err(());
                    }
                }
            }

            SPDMCertificateType::AlisasCertCA => {
                // The next section is Alias Intermediate Certificates
                match x509.get_extension_unique(&ID_SPDM_CERT_OIDS) {
                    Ok(Some(extension)) => {
                        // This contains id-spdm-cert-oids
                        let seq = spdm_cert_oids_parser(extension.value).unwrap();

                        if seq.1 == ID_DMTF_MUTABLE_CERTIFICATE {
                            // This contains id-DMTF-mutable-certificate
                            info!("'{}' contains id-DMTF-mutable-certificate", x509.subject());
                        }

                        assert!(seq.1 == ID_DMTF_MUTABLE_CERTIFICATE);
                        // TODO: Support multiple entries in id-spdm-cert-oids
                        assert!(seq.1 != ID_DMTF_HARDWARE_IDENTITY);
                    }
                    Ok(None) => {
                        info!(
                            "'{}' Certificate doesn't contain id-spdm-cert-oids",
                            x509.subject()
                        );
                    }
                    Err(_e) => {
                        error!("Duplicate Hardware identity OID");
                        return Err(());
                    }
                }

                // As the next certificate is an Alias Intermediate
                // Certificate, then this certificate is used to issue
                // Intermediate CA certificates.
                // Therefore TCG requires these
                info!("    Used to sign ECA");
                check_for_extended_key_usage(&x509, "tcg-dice-kp-eca", &TCG_DICE_KP_ECA)?;
                check_for_basic_contraints_ca(&x509, true)?;

                // Check for certificates that we should contain
                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-identityLoc",
                    &TCG_DICE_KP_IDENTITYLOC,
                ) {
                    // This chain is used to sign a device identity challenge
                    info!("    Used to sign Device Identity Challenge");
                    usage.sign_identity_challenge = true;
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-attestLoc",
                    &TCG_DICE_KP_ATTESTLOC,
                ) {
                    // This chain is used to sign evidence
                    info!("    Used to sign Evidence");
                    // This should already be set
                    if !usage.sign_evidence {
                        return Err(());
                    }
                } else {
                    if usage.sign_evidence {
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-assertLoc",
                    &TCG_DICE_KP_ASSERTLOC,
                ) {
                    // This chain is used to sign attestation
                    info!("    Used to sign Attestation");
                    if !usage.sign_attestation {
                        return Err(());
                    }
                } else {
                    if usage.sign_attestation {
                        return Err(());
                    }
                }
            }
            SPDMCertificateType::LeafCert => {
                info!("'{}' is the Leaf Cert", x509.subject());

                match x509.extended_key_usage() {
                    Ok(Some(extension)) => {
                        let other_key_usage = &extension.value.other;

                        if other_key_usage
                            .iter()
                            .find(|eku| **eku == ID_DMTF_EKU_RESPONDER_AUTH)
                            .is_some()
                        {
                            info!("    Used as a responder");
                            usage.sign_responses = true;
                        }

                        if other_key_usage
                            .iter()
                            .find(|eku| **eku == ID_DMTF_EKU_REQUESTER_AUTH)
                            .is_some()
                        {
                            info!("    Used as a requester");
                            usage.sign_requests = true;
                        }
                    }
                    Ok(None) => {
                        info!(
                            "'{}' Certificate doesn't contain Extended Key Usage",
                            x509.subject()
                        );
                    }
                    Err(_e) => {
                        error!("Duplicate Extended Key Usage");
                        return Err(());
                    }
                }

                match x509.get_extension_unique(&ID_SPDM_CERT_OIDS) {
                    Ok(Some(extension)) => {
                        // This contains id-spdm-cert-oids
                        let seq = spdm_cert_oids_parser(extension.value).unwrap();

                        assert!(seq.1 == ID_DMTF_MUTABLE_CERTIFICATE);
                        // TODO: Support multiple entries in id-spdm-cert-oids
                        assert!(seq.1 != ID_DMTF_HARDWARE_IDENTITY);
                    }
                    Ok(None) => {
                        info!(
                            "'{}' Certificate doesn't contain id-spdm-cert-oids",
                            x509.subject()
                        );
                    }
                    Err(_e) => {
                        error!("Duplicate Hardware identity OID");
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-identityLoc",
                    &TCG_DICE_KP_IDENTITYLOC,
                ) {
                    // This chain is used to sign a device identity challenge
                    info!("    Used to sign Device Identity Challenge");
                    // This should already be set
                    if !usage.sign_identity_challenge {
                        return Err(());
                    }
                } else {
                    if usage.sign_identity_challenge {
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-attestLoc",
                    &TCG_DICE_KP_ATTESTLOC,
                ) {
                    // This chain is used to sign evidence
                    info!("    Used to sign Evidence");
                    // This should already be set
                    if !usage.sign_evidence {
                        return Err(());
                    }
                } else {
                    if usage.sign_evidence {
                        return Err(());
                    }
                }

                if let Ok(_extension) = check_for_extended_key_usage(
                    &x509,
                    "tcg-dice-kp-assertLoc",
                    &TCG_DICE_KP_ASSERTLOC,
                ) {
                    // This chain is used to sign attestation
                    info!("    Used to sign Attestation");
                    if !usage.sign_attestation {
                        return Err(());
                    }
                } else {
                    if usage.sign_attestation {
                        return Err(());
                    }
                }
            }
        }
    }

    Ok(usage)
}
