// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

//! The starting point for SPDM-Utils.
//!
//! For more details see the help information printed by the binary
//! (which is generated from here) or the README
//!

use async_std::task;
use clap::{Parser, Subcommand};
use futures::future::join_all;
use libspdm::libspdm_rs::*;
use nix::unistd::geteuid;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::copy;
use std::path::Path;
#[macro_use]
extern crate log;
use env_logger::Env;
use libspdm::{responder, responder::CertModel, spdm};
use once_cell::sync::Lazy;

pub static SOCKET_PATH: &str = "SPDM-Utils-loopback-socket";

mod cli_helpers;
mod doe_pci_cfg;
mod qemu_server;
mod request;
mod socket_client;
mod socket_server;
mod tcg_concise_evidence_binding;
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
    #[arg(long, default_value = "")]
    pcie_vid: String,

    /// PCIe Identifier, Device ID of the SPDM supported device
    #[arg(long, default_value = "")]
    pcie_devid: String,

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

    /// The transport layer used for communication, by default it will
    /// be dependent on the transport layer used.
    #[arg(long)]
    spdm_transport_protocol: Option<spdm::TransportLayer>,

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

    /// Do not initialize an SPDM session with the responder, instead, only
    /// send the requests specified
    #[arg(long, default_value_t = false)]
    no_session: bool,
}

#[derive(Subcommand, PartialEq)]
enum Commands {
    /// initiate a SPDM request
    Request {
        /// The type of SPDM request(s). A list can be specified in the following
        /// format. The following SPDM requests are supported:
        ///
        /// The following requests can be issued.
        ///
        ///  - [GET_DIGESTS or get-digest]
        ///
        ///  - [GET_CERTIFICATE or get-certificate]
        ///
        ///  - [CHALLENGE or challenge]
        ///
        ///  - [GET_VERSION or get-version]
        ///
        ///  - [GET_MEASUREMENT or get-measurement]:
        ///     `get-measurement[index=<measurement-index>,raw-bitstream]`
        ///
        ///     This request takes an index argument to specify
        ///     the measurement index. `raw-bitstream` can also be specified
        ///     to request the raw-bitstream of the measurement.
        ///
        ///  - [GET_MEASUREMENTS or get-measurements]
        ///
        ///  - [GET_CAPABILITIES or get-capabilities]
        ///
        ///  - [NEGOTIATE_ALGORITHMS or negotiate-algorithms]
        ///
        ///  - [HEARTBEAT or heartbeat]
        ///
        ///  - [KEY_UPDATE or key-update]
        ///     `key-update[single-direction]`
        ///
        ///     single direction can be specified  such that the key update
        ///     operation is `UPDATE_KEY` (single) only. Default means that
        ///     UPDATE_ALL_KEYS is used where all keys are updated and verified.
        ///
        ///  - [ENCAPSULATED_SEND_RECEIVE or encapsulated-send-receive]
        ///     `encapsulated-send-receive[secure-msg]`
        ///
        ///     Setting this flag ensures that the encapsulated request is a
        ///     secured message. By default it sends a 'normal' (non-secure)
        ///     message.
        ///
        ///  - [END_SESSION or end-session],
        ///
        ///  - [GET_CSR or get-csr]
        ///
        ///  - [RESPOND_IF_READY or respond-if-ready]
        ///
        ///  - [CUSTOM or custom]
        ///     `custom[1234]`
        ///
        ///     Sub-argument is a user specified u32 value. This feature is
        ///     currently unsupported.
        ///
        ///  A list of request maybe specified in the following format:
        ///
        ///     - get-version,get-capabilities,negotiate-algorithms
        ///
        ///     - get-version,get-measurements[index=2,raw-bitstream]
        ///
        ///     - get-version,get-capabilities,get-measurement[index=4]
        #[clap(value_parser = parse_request_codes)]
        requests: std::vec::Vec<RequestCode>,

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

        /// The SPDM certificate model to use. See `Figure 1 — SPDM certificate chain models`
        /// in SPDM (DSP0274) version 1.3 for details.
        /// Supports:
        ///     - device: DeviceCert Model
        ///     - alias: AliasCert Model (the default)
        #[arg(long, default_value = "alias")]
        certificate_model: String,

        /// By default the responder will use hardcoded values for the image
        /// measurements (index 1 and 2). Setting this to true will instead
        /// generate hashes dynamically for these measurements.
        ///
        /// The default option is a simpler model, that is useful for testing.
        /// Setting this to true is more realistic of a real device. SPDM-Utils
        /// will generate hashes at startup and use those for the image
        /// mesaurements. In this case raw bitstreams aren't supported as we
        /// are modelling a responder that is protecting it's firmware blobs
        #[clap(long, default_value_t = false)]
        dynamic_image_measurements: bool,
    },
    Tests,
}

/// SPDM commands available for an SPDM Requestor
#[derive(Subcommand, PartialEq, Clone, Debug)]
pub enum RequestCode {
    GetDigests {},
    GetCertificate {
        /// Setting this flag enables extra checks based on the
        /// "TCG DICE Concise Evidence Binding for SPDM" spec
        #[clap(long, default_value_t = false)]
        tcg_dice_evidence_binding_checks: bool,
    },
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
    GetMeasurement {
        index: u8,
        #[clap(long, default_value_t = false)]
        raw_bitstream: bool,
    },
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

impl std::str::FromStr for RequestCode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Support only the requests that can either function with default
        // options, or does not require any arguments.
        let (request_code, subargs) = if s.find('[').is_some() && s.find(']').is_some() {
            // This request has sub-arguments specified
            let (req_code, subarg) = s.split_at(s.find('[').unwrap());
            let subarg_len = subarg.len();
            (req_code, Some(&subarg[1..subarg_len - 1]))
        } else {
            (s, None)
        };

        match request_code {
            "GET_DIGESTS" | "get-digests" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::GetDigests {})
            }
            "GET_CERTIFICATE" | "get-certificate" => {
                if let Some(args) = subargs {
                    if args.contains("tcg-dice-evidence-binding-checks") {
                        return Ok(RequestCode::GetCertificate {
                            tcg_dice_evidence_binding_checks: true,
                        });
                    } else {
                        error!("Invalid request option : {args}");
                        Err(format!("{}", s))
                    }
                } else {
                    Ok(RequestCode::GetCertificate {
                        tcg_dice_evidence_binding_checks: false,
                    })
                }
            }
            "CHALLENGE" | "challenge" => {
                if let Some(arg) = subargs {
                    Ok(RequestCode::Challenge {
                        challenge_request: Some(arg.to_string()),
                    })
                } else {
                    Ok(RequestCode::Challenge {
                        challenge_request: Some("ALL_MEASUREMENTS_HASH".to_string()),
                    })
                }
            }
            "GET_VERSION" | "get-version" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::GetVersion {})
            }
            "GET_MEASUREMENT" | "get-measurement" => {
                if let Some(args) = subargs {
                    if !args.contains("index=") {
                        error!("Index not specified for {request_code}");
                        return Err(format!("{}", s));
                    }

                    let meas_index: u8 = args
                        .split(',')
                        .find(|t: &&str| t.starts_with("index="))
                        .and_then(|t| t.split('=').nth(1))
                        .and_then(|index_str| index_str.parse().ok())
                        .ok_or_else(|| {
                            error!("Failed to parse index");
                            format!("{}", s)
                        })?;

                    let raw_bitstream = args.contains("raw-bitstream");
                    Ok(RequestCode::GetMeasurement {
                        index: meas_index,
                        raw_bitstream: raw_bitstream,
                    })
                } else {
                    error!("Index not specified for {request_code}");
                    Err(format!("{}", s))
                }
            }
            "GET_MEASUREMENTS" | "get-measurements" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::GetMeasurements {})
            }
            "GET_CAPABILITIES" | "get-capabilities" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::GetCapabilities {})
            }
            "NEGOTIATE_ALGORITHMS" | "negotiate-algorithms" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::NegotiateAlgorithms {})
            }
            "HEARTBEAT" | "heartbeat" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::Heartbeat {})
            }
            "KEY_UPDATE" | "key-update" => {
                if let Some(args) = subargs {
                    if args.contains("single-direction") {
                        return Ok(RequestCode::KeyUpdate {
                            single_direction: true,
                        });
                    } else {
                        error!("Invalid sub-argument specified");
                        Err(format!("{}", s))
                    }
                } else {
                    Ok(RequestCode::KeyUpdate {
                        single_direction: true,
                    })
                }
            }
            "ENCAPSULATED_SEND_RECEIVE" | "encapsulated-send-receive" => {
                if let Some(args) = subargs {
                    if args.contains("secure-msg") {
                        return Ok(RequestCode::EncapsulatedSendReceive { secure_msg: true });
                    } else {
                        error!("Invalid sub-argument specified");
                        return Err(format!("{}", s));
                    }
                }
                Ok(RequestCode::EncapsulatedSendReceive { secure_msg: false })
            }
            "END_SESSION" | "end-session" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::EndSession {})
            }
            "GET_CSR" | "get-csr" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::GetCsr {})
            }
            "SET_CERTIFICATE" | "set-certificate" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::SetCertificate {})
            }
            "RESPOND_IF_READY" | "respond-if-ready" => {
                if subargs.is_some() {
                    error!("Unexpected subargument");
                    return Err(format!("{}", s));
                }
                Ok(RequestCode::RespondIfReady {})
            }
            "CUSTOM" | "custom" => {
                if let Some(args) = subargs {
                    let val: u32 = args
                        .parse()
                        .map_err(|e| format!("Failed to parse '{args}' to u32, {e:?}"))?;
                    Ok(RequestCode::Custom { value: val })
                } else {
                    error!("Invalid sub-argument specified");
                    return Err(format!("{}", s));
                }
            }
            _ => {
                error!("Unsupported request code: {}", s);
                Err(format!("{}", s))
            }
        }
    }
}

fn parse_request_codes(s: &str) -> Result<Vec<RequestCode>, String> {
    let mut prev_req_start_at = 0;
    let mut subarg_start = false;
    let mut purse: Vec<RequestCode> = Vec::new();
    let mut skip_next_delim = false;
    let input_len = s.len();

    for (i, c) in s.chars().enumerate() {
        if c == '[' && !subarg_start {
            subarg_start = true;
            continue;
        } else if c == '[' && subarg_start {
            error!(
                "Invalid request argument formatting, unexpected {c} at {:?}X",
                &s[..i]
            );
            return Err(format!("Failed to parse requests"));
        } else if c != ']' && subarg_start {
            continue;
        }

        // End of the sub arguments for the request
        if c == ']' && subarg_start {
            let request_parsed = &s[prev_req_start_at..=i]
                .trim()
                .parse::<RequestCode>()
                .map_err(|e| format!("Failed to parse request: {e}"))?;
            subarg_start = false;
            purse.push(request_parsed.clone());
            if let Some(delim) = s.chars().nth(i + 1) {
                if delim != ',' {
                    error!("Expected ',' after ']'");
                    return Err(format!("Failed to parse requests"));
                }
                if let Some(_) = s.chars().nth(i + 2) {
                    prev_req_start_at = i + 2;
                    // We want to ignore the next ',' because it denotes the
                    // beginning of a new request and not the end of one.
                    skip_next_delim = true;
                } else {
                    error!("Request expected after ','");
                    return Err(format!("Failed to parse requests"));
                }
            }

            continue;
        }

        if c == ',' || i == input_len - 1 {
            if skip_next_delim {
                skip_next_delim = false;
                continue;
            }
            subarg_start = false;
            // i is at the ','
            let last_index = if i == input_len - 1 {
                i
            } else {
                match i.checked_sub(1) {
                    Some(idx) => idx,
                    None => {
                        error!("Unexpected '{c}' at position {i:?}");
                        return Err("Failed to parse requests".into());
                    }
                }
            };
            let request_parsed = &s[prev_req_start_at..=last_index]
                .trim()
                .parse::<RequestCode>()
                .map_err(|e| format!("Failed to parse request: {e}"))?;
            // Track the index after the ','
            prev_req_start_at = i + 1;
            purse.push(request_parsed.clone());
        }
    }

    Ok(purse)
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
#[async_std::main]
async fn main() -> Result<(), ()> {
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

    if (cli.doe_pci_cfg || cli.usb_i2c) && u32::from(geteuid()) != 0 {
        error!("This transport operation requires root privileges");
        return Err(());
    }

    if cli.doe_pci_cfg {
        // Check that a device exists with provided vid/devid
        unsafe {
            let (vid, dev_id) = cli_helpers::parse_pcie_identifiers(cli.pcie_vid, cli.pcie_devid)?;
            let (pacc, _, _) = doe_pci_cfg::get_pcie_dev(vid, dev_id)?;
            pci_cleanup(pacc);
            doe_pci_cfg::register_device(cntx_ptr, vid, dev_id)?;
        }
    } else if cli.socket_server {
        socket_server::register_device(cntx_ptr)?;
    } else if cli.socket_client {
        socket_client::register_device(cntx_ptr)?;
    } else if cli.usb_i2c {
        if let Some(proto) = cli.spdm_transport_protocol {
            if proto != spdm::TransportLayer::Mctp {
                error!("Only MCTP supported over USB I2C");
                return Err(());
            }
        }

        usb_i2c::register_device(cntx_ptr, cli.usb_i2c_dev, cli.usb_i2c_baud)?;
    } else if cli.qemu_server {
        if let Commands::Request { .. } = cli.command {
            error!("QEMU Server does not support running an SPDM requester");
            return Err(());
        }
        if let Some(proto) = cli.spdm_transport_protocol {
            qemu_server::register_device(cntx_ptr, cli.qemu_port, proto)?;
        } else {
            qemu_server::register_device(cntx_ptr, cli.qemu_port, spdm::TransportLayer::Doe)?;
        }
    } else {
        error!("No supported backend specified");
        return Err(());
    }

    unsafe {
        if let Some(proto) = cli.spdm_transport_protocol {
            spdm::setup_transport_layer(cntx_ptr, proto, spdm::LIBSPDM_MAX_SPDM_MSG_SIZE)?;
        } else {
            if cli.usb_i2c {
                spdm::setup_transport_layer(
                    cntx_ptr,
                    spdm::TransportLayer::Mctp,
                    spdm::LIBSPDM_MAX_SPDM_MSG_SIZE,
                )?;
            } else {
                spdm::setup_transport_layer(
                    cntx_ptr,
                    spdm::TransportLayer::Doe,
                    spdm::LIBSPDM_MAX_SPDM_MSG_SIZE,
                )?;
            }
        }
    }

    match cli.command {
        Commands::Request {
            requests,
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

            let mut session_info = if cli.no_session {
                spdm::SpdmSessionInfo {
                    use_psk: use_psk_exchange,
                    measurement_hash_type: SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH
                        as u8,
                    slot_id,
                    session_policy: 0,
                    session_id: 0,
                    heartbeat_period: 0,
                }
            } else {
                unsafe {
                    spdm::initialise_connection(cntx_ptr, slot_id).unwrap();
                    spdm::start_session(cntx_ptr, slot_id, use_psk_exchange).unwrap()
                }
            };
            // Print out the negotiated algorithms
            unsafe {
                spdm::get_negotiated_algos(cntx_ptr, slot_id).unwrap();
            }
            // Process one or more requests specified
            for req in requests {
                request::prepare_request(
                    cntx_ptr,
                    req.clone(),
                    cert_slot_id,
                    cert_path.clone(),
                    &mut session_info,
                )
                .map_err(|e| {
                    error!("Failed to do {:?} - 0x{e:x}", req);
                    ()
                })?;
            }
        }
        Commands::Response {
            spdm_ver,
            certificate_model,
            dynamic_image_measurements,
        } => {
            let mut num_provisioned_slots = 0;

            let tasks = if dynamic_image_measurements {
                Some([
                    task::spawn(generate_kernel_hash()),
                    task::spawn(generate_app_hash()),
                ])
            } else {
                None
            };

            let model = if certificate_model == "alias" {
                CertModel::Alias
            } else if certificate_model == "device" {
                CertModel::Device
            } else {
                error!("Unsupported certificate model");
                return Err(());
            };

            for slot_id in 1..8 {
                let file_name = if certificate_model == "alias" {
                    format!("certs/alias/slot{}/immutable.der", slot_id)
                } else if certificate_model == "device" {
                    format!(
                        "certs/device/slot{}/bundle_responder.certchain.der",
                        slot_id
                    )
                } else {
                    error!("Unsupported certificate model");
                    return Err(());
                };
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
                        model,
                        1,
                    )?;
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
                model,
                1,
            )?;
            num_provisioned_slots += 1;
            assert!(num_provisioned_slots < 8);
            responder::set_supported_slots_mask(num_provisioned_slots, ver, cntx_ptr).map_err(
                |_| {
                    error!("failed to set supported slot mask");
                    ()
                },
            )?;

            // We need to make sure the hashes are generated before starting the
            // response loop
            if let Some(t) = tasks {
                let results = join_all(t).await;

                if results.iter().find(|&res| res.is_err()).is_some() {
                    error!("Error generating image measurements");
                    return Err(());
                }
            }

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

/// Generate a hash of the "kernel"
/// We try to generate a hash of "/boot/Image", if that doesn't
/// work we fall back to "/etc/hostname". Hashes are generated on startup
/// and not re-calculated.
async fn generate_kernel_hash() -> Result<(), std::io::Error> {
    let supported_hashes = [
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
    ];

    let kernel_path = if Path::new("/boot/Image").exists() {
        Path::new("/boot/Image")
    } else {
        Path::new("/etc/hostname")
    };
    let mut file = File::open(kernel_path)?;

    let mut dyn_image_measure = match spdm::DYN_IMAGE_MEASURE.write() {
        Ok(val) => val,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RwLock error",
            ))
        }
    };

    for (i, measurement_hash_algo) in supported_hashes.iter().enumerate() {
        match *measurement_hash_algo {
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 => {
                let mut hasher = Sha256::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).kernel_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 => {
                let mut hasher = Sha384::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).kernel_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 => {
                let mut hasher = Sha512::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).kernel_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            _ => continue,
        };
    }

    Lazy::force_mut(&mut dyn_image_measure).kernel_hashes_populated = true;

    Ok(())
}

/// Generate a hash of the app
/// Hashes are generated on startup and not re-calculated.
async fn generate_app_hash() -> Result<(), std::io::Error> {
    let supported_hashes = [
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
        SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
    ];

    // Get the current running file.
    // NOTE: This is NOT secure or guaranteed, the file could be changed
    // behind our back, see https://doc.rust-lang.org/std/env/fn.current_exe.html
    // For a PoC this is fine though
    let current_exe_path = std::env::current_exe()?;
    let mut file = File::open(current_exe_path)?;

    let mut dyn_image_measure = match spdm::DYN_IMAGE_MEASURE.write() {
        Ok(val) => val,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "RwLock error",
            ))
        }
    };

    for (i, measurement_hash_algo) in supported_hashes.iter().enumerate() {
        match *measurement_hash_algo {
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256 => {
                let mut hasher = Sha256::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).app_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 => {
                let mut hasher = Sha384::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).app_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 => {
                let mut hasher = Sha512::new();

                copy(&mut file, &mut hasher)?;
                let hash_bytes = hasher.finalize();
                let slice_len = hash_bytes.as_slice().len();

                Lazy::force_mut(&mut dyn_image_measure).app_hashes[i][0..slice_len]
                    .copy_from_slice(hash_bytes.as_slice());
            }
            _ => continue,
        };
    }

    Lazy::force_mut(&mut dyn_image_measure).app_hashes_populated = true;

    Ok(())
}

#[test]
fn test_parse_request_codes_valid() {
    assert_eq!(
        parse_request_codes("get-version").unwrap(),
        vec![RequestCode::GetVersion {}]
    );
    assert_eq!(
        parse_request_codes("get-version,get-capabilities,negotiate-algorithms").unwrap(),
        vec![
            RequestCode::GetVersion {},
            RequestCode::GetCapabilities {},
            RequestCode::NegotiateAlgorithms {}
        ]
    );
    assert_eq!(
        parse_request_codes("get-version,get-measurement[index=255,raw-bitstream]").unwrap(),
        vec![
            RequestCode::GetVersion {},
            RequestCode::GetMeasurement {
                index: 255,
                raw_bitstream: true
            }
        ]
    );
    assert_eq!(
        parse_request_codes("get-version,get-measurement[index=32]").unwrap(),
        vec![
            RequestCode::GetVersion {},
            RequestCode::GetMeasurement {
                index: 32,
                raw_bitstream: false
            }
        ]
    );
    // Test all valid sub arguments
    assert_eq!(
        parse_request_codes(
            "get-certificate[tcg-dice-evidence-binding-checks],
             challenge[MEAS_HASH_TYPE],key-update[single-direction],
             encapsulated-send-receive[secure-msg],
             custom[1234]"
        )
        .unwrap(),
        vec![
            RequestCode::GetCertificate {
                tcg_dice_evidence_binding_checks: true
            },
            RequestCode::Challenge {
                challenge_request: Some("MEAS_HASH_TYPE".to_string())
            },
            RequestCode::KeyUpdate {
                single_direction: true
            },
            RequestCode::EncapsulatedSendReceive { secure_msg: true },
            RequestCode::Custom { value: 1234 }
        ]
    );
}

#[test]
fn test_parse_request_codes_invalid() {
    // Negative test for invalid user inputs
    // Unexpected ',' at the end
    assert!(parse_request_codes("get-version,").is_err());
    // Missing ',' delimeter
    assert!(parse_request_codes("get-versionget-capabilities").is_err());
    // Missing required "index=<measurement_index>"
    assert!(parse_request_codes("get-measurement[raw-bitsream]").is_err());
    // Missing required subargument
    assert!(parse_request_codes("get-measurement").is_err());
    // Invalid measurement index specified
    assert!(parse_request_codes("get-measurement[index=wompwomp,raw-bitstream]").is_err());
    // Invalid subarguments
    assert!(parse_request_codes("get-certificate[tcg-blah...]").is_err());
    assert!(parse_request_codes("key-update[double-direction]").is_err());
    assert!(parse_request_codes("encapsulated-send-receive[blah]").is_err());
    assert!(parse_request_codes("custom[decaf]").is_err());
    // Unexpected subarguments
    assert!(parse_request_codes("get-digests[]").is_err());
    assert!(parse_request_codes("get-version[deadpool]").is_err());
    // Total Nonsense
    assert!(parse_request_codes(",get-version.cpp").is_err());
    assert!(parse_request_codes("[]").is_err());
}
