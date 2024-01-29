// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! The starting point for SPDM-Utils.
//!
//! For more details see the help information printed by the binary
//! (which is generated from here) or the README
//!

use clap::{Parser, Subcommand};
use libspdm::libspdm_rs::*;
use std::fs::OpenOptions;
use std::path::Path;
#[macro_use]
extern crate log;
use env_logger::Env;
use libspdm::{responder, spdm};

pub static SOCKET_PATH: &str = "SPDM-Utils-loopback-socket";

mod cli_helpers;
mod doe_pci_cfg;
mod qemu_server;
mod request;
mod socket_client;
mod socket_server;
mod test_suite;
mod usb_i2c;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Use the Linux PCIe extended configuration backend
    /// This is generally run on the Linux host machine
    #[arg(short, long, requires_ifs([("true", "pcie_vid"), ("true", "pcie_devid")]))]
    doe_pci_cfg: bool,

    /// PCIe Identifier, Vendor ID of the SPDM supported device
    #[arg(long, default_value_t = 0)]
    pcie_vid: u16,

    /// PCIe Identifier, Device ID of the SPDM supported device
    #[arg(long, default_value_t = 0)]
    pcie_devid: u16,

    /// Use the Socket Server backend
    #[arg(long)]
    socket_server: bool,

    /// Use the usb-i2c transport layer (for mctp)
    #[arg(long)]
    usb_i2c: bool,

    /// Path to the USB/UART device
    #[arg(long, default_value = "/dev/ttyUSB0")]
    usb_i2c_dev: Option<String>,

    /// Baud-rate for the USB/UART device
    #[arg(long, default_value_t = 115200)]
    usb_i2c_baud: u32,

    /// Use the Socket Client backend
    #[arg(long)]
    socket_client: bool,

    /// Allow QEMU to connect to SPDM-Utils SPDM server (Responder only)
    #[arg(long)]
    qemu_server: bool,

    /// Port on which to create a server for QEMU.
    /// option is not specified.
    #[arg(long, default_value_t = 2323)]
    qemu_port: u16,

    /// Transport layer used by QEMU. The following are currently supported
    ///
    /// QEMU_DOE
    #[arg(long, default_value = "TRANS_DOE")]
    qemu_transport: Option<String>,
}

#[derive(Subcommand, PartialEq)]
enum Commands {
    /// initiate a SPDM request
    Request {
        /// the type of request
        #[command(subcommand)]
        code: RequestCode,

        /// the slot ID to use
        #[arg(long, default_value_t = 0)]
        slot_id: u8,

        /// the slot ID in which to set/get a certificate.
        /// this is only used in set-certificate/get-certificate commands.
        /// defaults to slot-0 and is ignored for all other commands.
        #[arg(long, default_value_t = 0)]
        cert_slot_id: u8,

        /// path to the certificate to set (default = None),
        /// required when setting a certificate with
        /// the `set-certificate` command.
        /// this is ignored for all other commands.
        #[arg(long)]
        cert_path: Option<String>,

        /// Supported asymmetric algorithms
        ///
        /// Multiple algorithms may be specified in this form
        /// [RSASSA_2048,SM2_ECC_SM2_P256,RSASSA_3072]
        ///
        /// RSASSA_2048
        /// RSAPSS_2048
        /// RSASSA_3072
        /// RSAPSS_3072
        /// ECDSA_ECC_NIST_P256
        /// RSASSA_4096
        /// RSAPSS_4096
        /// ECDSA_ECC_NIST_P384
        /// ECDSA_ECC_NIST_P521
        /// SM2_ECC_SM2_P256
        /// EDDSA_ED25519
        /// EDDSA_ED448
        #[arg(long, default_value = "ECDSA_ECC_NIST_P384")]
        asym_algos: Option<String>,

        /// Supported hashing algorithms
        ///
        /// Multiple algorithms may be specified in this form
        /// [SHA_256,SHA_384,SM3_512]
        ///
        /// SHA_256
        /// SHA_384
        /// SHA_512
        /// SHA3_256
        /// SHA3_384
        /// SHA3_512
        /// SM3_256
        #[arg(long, default_value = "SHA_384")]
        hash_algos: Option<String>,

        /// Supported DHE Named Group
        ///
        /// Multiple algorithms may be specified in this form
        /// [FFDHE_2048,FFDHE_4096,SM2_P256]
        ///
        ///  FFDHE_2048
        ///  FFDHE_3072
        ///  FFDHE_4096
        ///  SECP_256_R1
        ///  SECP_384_R1
        ///  SECP_521_R1
        ///  SM2_P256
        #[arg(long, default_value = "SECP_384_R1,SECP_521_R1")]
        dhe_named_groups: Option<String>,

        /// Supported AEAD Cipher Suites
        ///
        /// Multiple algorithms may be specified in this form
        /// [AES_128_GCM,CHACHA20_POLY1305]
        ///
        ///  AES_128_GCM
        ///  AES_256_GCM
        ///  CHACHA20_POLY1305
        ///  AEAD_SM4_GCM
        #[arg(long, default_value = "AES_256_GCM")]
        aead_cipher_suites: Option<String>,

        /// Setting this flag allows starting a libspdm session by using
        /// PSK_EXCHANGE/PSK_FINISH instead of the default KEY_EXCHANGE/FINISH.
        #[clap(long, default_value_t = false)]
        use_psk_exchange: bool,
    },
    /// initiate a SPDM response
    Response {
        /// The SPDM (DSP0274) version(s) (1.0, 1.1, 1.2 or 1.3) of an endpoint.
        /// These are communicated through the `GET_VERSION / VERSION` messages.
        #[arg(long, default_value = "1.3")]
        spdm_ver: Option<String>,
    },
    Tests,
}

/// SPDM commands available for an SPDM Requestor
#[derive(Subcommand, PartialEq)]
pub enum RequestCode {
    GetDigests {},
    GetCertificate {},
    Challenge {
        /// Supported Challenge request types
        ///
        /// NO_MEASUREMENT_SUMMARY_HASH,
        /// TCB_COMPONENT_MEASUREMENT_HASH,
        /// ALL_MEASUREMENTS_HASH
        #[clap(default_value = "ALL_MEASUREMENTS_HASH")]
        challenge_request: Option<String>,
    },
    GetVersion {},
    GetMeasurements {},
    GetCapabilities {},
    NegotiateAlgorithms {},
    Heartbeat {},
    KeyUpdate {
        /// Setting this flag means that the key update operation is
        /// `UPDATE_KEY` (single) only. Default means that UPDATE_ALL_KEYS is used where
        /// all keys are updated and verified.
        #[clap(long, default_value_t = false)]
        single_direction: bool,
    },
    EncapsulatedSendReceive {
        /// Setting this flag ensures that the encapsulated request is a secured
        /// message. By default it sends a 'normal' (non-secure) message.
        #[clap(long, default_value_t = false)]
        secure_msg: bool,
    },
    EndSession {},
    GetCsr {},
    SetCertificate {},
    VendorDefinedRequest {},
    RespondIfReady {},
    Custom {
        value: u32,
    },
}

/// # Summary
///
/// Initialize the logger.
/// Default to trace log level if LOG_LEVEL environment variable is not set
/// Default to always log style if LOG_STYLE environment variable is not set
fn init_logger() {
    let env = Env::default()
        .filter_or("LOG_LEVEL", "trace")
        .write_style_or("LOG_STYLE", "always");

    env_logger::init_from_env(env);

    debug!("Logger initialisation [OK]")
}

/// # Summary
///
/// Entry point to SPDM-Utils.
///
/// Parses the CLI commands and initialises an SPDM context. Then registers this
/// SPDM context to the specified backend (for example pcie_doe).
///
/// Once registered, if we are a requestor:
/// Initialize an SPDM session with the target and process the request as
/// specified by CLI.
///
/// If we a responder:
/// Setup supported capabilities then begin the response loop, this will
/// wait indefinitely for a request.
///
/// If we are running tests:
/// Setup test cases for SPDM-Responder-Validator and run them.
fn main() -> Result<(), ()> {
    init_logger();
    let cli = Args::parse();

    let cntx_ptr = spdm::initialise_spdm_context();

    let mut count = 0;

    cli.doe_pci_cfg.then(|| {
        count += 1;
    });
    cli.socket_server.then(|| {
        count += 1;
    });
    cli.usb_i2c.then(|| {
        count += 1;
    });
    cli.socket_client.then(|| {
        count += 1;
    });
    cli.qemu_server.then(|| {
        count += 1;
    });

    if count > 1 {
        error!("Only a single backend can be used");
        return Err(());
    }

    if cli.doe_pci_cfg {
        // Check that a device exists with provided vid/devid
        unsafe {
            let (pacc, _, _) = doe_pci_cfg::get_pcie_dev(cli.pcie_vid, cli.pcie_devid).unwrap();
            pci_cleanup(pacc);
            doe_pci_cfg::register_device(cntx_ptr, cli.pcie_vid, cli.pcie_devid).unwrap();
        }
    } else if cli.socket_server {
        socket_server::register_device(cntx_ptr).unwrap();
    } else if cli.socket_client {
        socket_client::register_device(cntx_ptr).unwrap();
    } else if cli.usb_i2c {
        usb_i2c::register_device(cntx_ptr, cli.usb_i2c_dev, cli.usb_i2c_baud).unwrap();
    } else if cli.qemu_server {
        if let Commands::Request { .. } = cli.command {
            error!("QEMU Server does not support running an SPDM requester");
            return Err(());
        }
        let qemu_transport = cli_helpers::parse_qemu_transport_layer(cli.qemu_transport).unwrap();
        qemu_server::register_device(cntx_ptr, cli.qemu_port, qemu_transport).unwrap();
    } else {
        error!("No supported backend specified");
        return Err(());
    }

    unsafe {
        if cli.usb_i2c {
            spdm::setup_transport_layer(
                cntx_ptr,
                spdm::TransportLayer::Mctp,
                usb_i2c::LIBSPDM_MAX_SPDM_MSG_SIZE,
            )
            .unwrap();
        } else {
            spdm::setup_transport_layer(
                cntx_ptr,
                spdm::TransportLayer::Doe,
                spdm::LIBSPDM_MAX_SPDM_MSG_SIZE,
            )
            .unwrap();
        }
    }

    match cli.command {
        Commands::Request {
            code,
            slot_id,
            cert_slot_id,
            cert_path,
            asym_algos,
            hash_algos,
            dhe_named_groups,
            aead_cipher_suites,
            use_psk_exchange,
        } => {
            request::setup_capabilities(
                cntx_ptr,
                slot_id,
                cli_helpers::parse_asym_algos(asym_algos).unwrap(),
                cli_helpers::parse_hash_algos(hash_algos).unwrap(),
                cli_helpers::parse_dhe_named_groups(dhe_named_groups).unwrap(),
                cli_helpers::parse_aead_cipher_suite(aead_cipher_suites).unwrap(),
            )
            .unwrap();
            unsafe {
                spdm::initialise_connection(cntx_ptr, slot_id).unwrap();
            }
            let mut session_info =
                unsafe { spdm::start_session(cntx_ptr, slot_id, use_psk_exchange).unwrap() };
            // Print out the negotiated algorithms
            unsafe {
                spdm::get_negotiated_algos(cntx_ptr, slot_id).unwrap();
            }
            request::prepare_request(cntx_ptr, code, cert_slot_id, cert_path, &mut session_info)
                .unwrap();
        }
        Commands::Response { spdm_ver } => {
            let mut num_provisioned_slots = 0;
            for slot_id in 1..8 {
                let file_name = format!("certs/slot{}/immutable.der", slot_id);
                let path = Path::new(&file_name);

                if OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(path)
                    .is_ok()
                {
                    responder::setup_capabilities(
                        cntx_ptr,
                        slot_id,
                        None,
                        SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                        SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
                    )
                    .unwrap();
                    num_provisioned_slots += 1;
                }
            }
            // Check if version was specified
            let ver = cli_helpers::parse_spdm_responder_version(spdm_ver);
            if ver.is_none() {
                // spdm_ver has a default value set, if None was returned, it means
                // the user argument was invalid.
                error!("Unsupported libspdm data spdm version");
                return Err(());
            }
            responder::setup_capabilities(
                cntx_ptr,
                0,
                ver,
                SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
                SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
            )
            .unwrap();
            num_provisioned_slots += 1;
            assert!(num_provisioned_slots < 8);
            responder::set_supported_slots_mask(num_provisioned_slots, ver, cntx_ptr).expect("failed to set supported slot mask");

            responder::response_loop(cntx_ptr);
        }
        Commands::Tests {} => {
            if cli.doe_pci_cfg {
                unsafe {
                    test_suite::start_tests(cntx_ptr, test_suite::TestBackend::DoeBackend);
                }
            } else if cli.socket_server || cli.socket_client {
                unsafe {
                    test_suite::start_tests(cntx_ptr, test_suite::TestBackend::SocketBackend);
                }
            } else {
                error!("The backend is not supported for testing");
                return Err(());
            }
        }
    }
    Ok(())
}
