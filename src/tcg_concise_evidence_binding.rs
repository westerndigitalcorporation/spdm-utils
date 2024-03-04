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

const TCG_DICE_KP_IDENTITYINIT: Oid = oid!(2.23.133 .5 .4 .100 .6);
const TCG_DICE_KP_ECA: Oid = oid!(2.23.133 .5 .4 .100 .12);
const TCG_DICE_KP_ATTESTINIT: Oid = oid!(2.23.133 .5 .4 .100 .8);
const TCG_DICE_KP_ASSERTINIT: Oid = oid!(2.23.133 .5 .4 .100 .10);

#[derive(Debug)]
enum SPDMCertificateType {
    DeviceCertCA,
    AlisasCertCA,
    LeadCert,
}

// TODO: Handle multiple entries
fn spdm_cert_oids_parser(i: &[u8]) -> ParseResult<Oid> {
    Sequence::from_der_and_then(i, |i| {
        return Ok((i, Oid::new(std::borrow::Cow::Borrowed(&i[2..]))));
    })
}

fn check_for_extensions(x509: &X509Certificate, name: &str, extension: &Oid) -> Result<(), ()> {
    match x509.get_extension_unique(extension) {
        Ok(Some(_extension)) => {}
        Ok(None) => {
            error!("'{}' Certificate doesn't contain {name}", x509.subject());
            return Err(());
        }
        Err(_e) => {
            error!("Duplicate {name}");
            return Err(());
        }
    }

    Ok(())
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
/// # Parameter
///
/// * `cert_slot_id`: The certificate slot to check and that GetCertificate
///                   was called on
///
/// # Returns
///
/// Ok() on success
///
/// # Panics
///
/// Panics on any errors related to failed file I/Os
pub fn check_tcg_dice_evidence_binding(cert_slot_id: u8) -> Result<(), ()> {
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
    let mut cert_type = SPDMCertificateType::DeviceCertCA;

    let mut evidence_signing = false;
    let mut assert_signing = false;

    while let Some(pem) = pem_iterator.next() {
        let pem = pem.unwrap();
        let x509 = pem.parse_x509().expect("X.509: decoding DER failed");

        if pem_iterator.peek().is_none() {
            cert_type = SPDMCertificateType::LeadCert;
        }

        match cert_type {
            // First we want to find the Device Certificate CA
            // It *should* be the last certificate with the 'Hardware identity OID'.
            // The certificates should all be immutable
            SPDMCertificateType::DeviceCertCA => {
                match x509.get_extension_unique(&ID_SPDM_CERT_OIDS) {
                    Ok(Some(extension)) => {
                        // This contains id-spdm-cert-oids
                        let seq = spdm_cert_oids_parser(extension.value).unwrap();

                        if seq.1 == ID_DMTF_HARDWARE_IDENTITY {
                            // This contains id-DMTF-hardware-identity
                            debug!("'{}' contains id-DMTF-hardware-identity", x509.subject());

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
                                            // There fore TCG requires these
                                            info!("    Used to sign ECA");
                                            check_for_extensions(
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
                            // This is the first Alias Intermediate Certificate
                            cert_type = SPDMCertificateType::AlisasCertCA;

                            debug!("{:?}", x509);
                        }
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

                // Check for extensions that we should contain
                check_for_extensions(&x509, "tcg-dice-kp-identityInit", &TCG_DICE_KP_IDENTITYINIT)?;

                if let Ok(_attest_init) =
                    check_for_extensions(&x509, "tcg-dice-kp-attestInit", &TCG_DICE_KP_ATTESTINIT)
                {
                    // This chain is used to sign evidence
                    info!("    Used to sign Evidence");
                    evidence_signing = true;
                } else {
                    if !evidence_signing {
                        return Err(());
                    }
                }

                if let Ok(_attest_init) =
                    check_for_extensions(&x509, "tcg-dice-kp-assertInit", &TCG_DICE_KP_ASSERTINIT)
                {
                    // This chain is used to sign attestation
                    info!("    Used to sign Attestation");
                    assert_signing = true;
                } else {
                    if !assert_signing {
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
                            debug!("'{}' contains id-DMTF-mutable-certificate", x509.subject());
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
            }
            SPDMCertificateType::LeadCert => {
                debug!("'{}' is the Leaf Cert", x509.subject());
            }
        }
    }

    Ok(())
}