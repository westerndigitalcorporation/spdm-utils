// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

use crate::libspdm_rs;
use crate::libspdm_rs::LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE;
use crate::spdm::{get_base_hash_algo, get_measurement};
use core::ffi::c_void;
use core::slice::from_raw_parts;
use minicbor::bytes::ByteSlice;
use minicbor::data::Tagged;
use minicbor_derive::{CborLen, Decode, Encode};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use which::which;

struct Manifest {}

impl Manifest {
    /// # Summary
    ///
    /// Reads the manifest from a file as specified by @path
    /// This manifest must be in serialised CBOR form. This function
    /// does not guarantee the correctness of the data read from @path. It simply
    /// loads it
    ///
    /// # Parameter
    ///
    /// * `buffer`: A buffer to create a manifest into, should be a minimum
    ///             size of LIBSPDM_MEASUREMENT_MANIFEST_SIZE.
    ///
    /// * `path`: Relative path the manifest file
    ///
    /// # Returns
    ///
    /// Ok(()) on success
    ///
    /// # Panics
    ///
    /// Panics on any errors related to failed file I/Os
    /// Panics if the buffer size is less than required
    fn read_manifest_from_file(buffer: &mut [u8], path: &Path) -> Result<usize, std::io::Error> {
        let mut manifest = match File::open(path) {
            Ok(manifest) => manifest,
            Err(e) => {
                println!("Error opening manifest file at {:?}, {:?}", path, e);
                return Err(e);
            }
        };

        let bytes_read = manifest.read(buffer).expect("failed reading manifest file");
        Ok(bytes_read)
    }
}

/// # Summary
///
/// Reads the manifest from a file as specified by @path
/// This manifest must be in serialised CBOR form. This function
/// does not guarantee the correctness of the data read from @path. It simply
/// loads it
///
/// # Parameter
///
/// * `buffer`: A buffer to create a manifest into, should be a minimum size of
///             LIBSPDM_MEASUREMENT_MANIFEST_SIZE.
/// * `path`: Relative path to the manifest file
///
/// # Returns
///
/// Ok(size) on success, where size is the num bytes of the manifest
///
/// # Panics
///
/// Panics on any errors related to failed file I/Os
pub fn fetch_local_manifest(buffer: &mut [u8], path: &Path) -> Result<usize, ()> {
    let len = Manifest::read_manifest_from_file(buffer, &path).expect("failed to read manifest");
    Ok(len)
}

/// # Summary
///
/// Saves the manifest buffer pointed to by @manifest into a new file
/// located at @path. This does not do any decoding.
///
/// # Parameter
///
/// * `buffer`: A buffer containing the raw cbor bit-stream data of the measurement manifest
/// * `path`: Path to where to create the output file
///
/// # Returns
///
/// Ok(()) on success, panics on file IO errors
pub fn save_manifest_to_file(buffer: &[u8], path: &Path) -> Result<(), ()> {
    let mut file = File::create(path).expect("failed to create output manifest file");
    file.write_all(&buffer)
        .expect("failed to write manifest to file");
    Ok(())
}

/// # Summary
///
/// Decodes the manifest pointed to by @buffer and returns the decoded cbor
/// data in a byte vector. Note: This function depends on `cbor-diag`, see
/// README for more details.
///
/// # Parameter
///
/// * `buffer`: A buffer containing the raw cbor bit-stream data of the measurement manifest
/// * `use_pretty`: If true, then convert into `pretty` format.
///
/// # Returns
///
/// Ok(()) on success, or Err(()) otherwise
///
/// # Panics
///
/// Panics on any errors related invoking `cbor-diag`
pub fn decode_cbor_manifest(buffer: &[u8], use_pretty: bool) -> Result<Vec<u8>, ()> {
    let script;

    if use_pretty {
        script = "cbor2pretty.rb";
    } else {
        script = "cbor2diag.rb";
    }

    match which(script) {
        Ok(_) => {
            let mut child = Command::new(script)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("failed to start script");

            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(buffer).unwrap();
            } else {
                return Err(());
            }

            let mut decoded_cbor = Vec::new();
            if let Some(mut stdout) = child.stdout.take() {
                stdout
                    .read_to_end(&mut decoded_cbor)
                    .expect("failed to read stdout");
            } else {
                return Err(());
            }

            _ = child.wait().unwrap();

            return Ok(decoded_cbor);
        }
        Err(e) => {
            error!("Ruby script {script} not found : error {}", e);
            return Err(());
        }
    }
}

pub type SpdmToc<'a> = Tagged<570, TaggedEvidence<'a>>;

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct TaggedEvidence<'a> {
    #[b(0)]
    tagged_evidence: [Tagged<571, CeEvTriples<'a>>; 1],
    #[b(1)]
    rim_locators: Vec<CorimLocatorMap<'a>>,
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct CeEvTriples<'a> {
    #[b(0)]
    ce_ev_triples: CeMembershipTriples<'a>,
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct CeMembershipTriples<'a> {
    #[b(0)]
    ce_membership_triples: [(EnvironmentMap<'a>, Vec<MeasurementMap<'a>>); 1],
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct EnvironmentMap<'a> {
    #[b(0)]
    class: Class<'a>,
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct Class<'a> {
    #[b(0)]
    id: Tagged<111, &'a ByteSlice>,
    #[b(1)]
    vendor: &'a str,
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct MeasurementMap<'a> {
    // mkey
    #[n(1)]
    mval: MeasurementValuesMap<'a>,
    #[b(2)]
    authorised_by: [Tagged<554, &'a str>; 1],
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
/// https://github.com/ietf-rats-wg/draft-ietf-rats-corim/blob/main/cddl/measurement-values-map.cddl
pub struct MeasurementValuesMap<'a> {
    #[b(0)]
    version: Option<&'a str>,
    #[b(1)]
    svn: Option<Tagged<552, i64>>,
    #[b(2)]
    digest: Option<(i64, &'a ByteSlice)>,
    // ? &(flags: 3) => flags-map
    #[b(4)]
    raw_value: Option<Tagged<560, &'a ByteSlice>>,
    // ? (
    //     &(raw-value: 4) => $raw-value-type-choice,
    //     ? &(raw-value-mask: 5) => raw-value-mask-type
    //   )
    // ? &(mac-addr: 6) => mac-addr-type-choice
    // ? &(ip-addr: 7) =>  ip-addr-type-choice
    // ? &(serial-number: 8) => text
    // ? &(ueid: 9) => ueid-type
    // ? &(uuid: 10) => uuid-type
    #[b(11)]
    name: Option<&'a str>,
    #[b(12)]
    spdm_indirect: Option<Index>, // ? &(cryptokeys: 13) => [ + $crypto-key-type-choice ]
                                  // ? &(integrity-registers: 14) => integrity-registers
}

#[derive(Debug, Encode, Decode, CborLen)]
#[cbor(map)]
pub struct CorimLocatorMap<'a> {
    #[b(0)]
    link: Tagged<32, &'a str>,
}

#[derive(Debug, Encode, Decode, Clone, Copy, CborLen)]
#[cbor(map)]
pub struct Index {
    #[n(0)]
    index: [u8; 1],
}

const DEBUG_INFORMATION: u8 =
    (crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE
        | crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) as u8;
const VERSION: u8 = (crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION
    | crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM)
    as u8;
const SVN: u8 = (crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER
    | crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM)
    as u8;
const RAW_BIT_STREAM: u8 =
    crate::libspdm_rs::SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM as u8;
const DIGESTS: u8 = RAW_BIT_STREAM - 1;

/// This function converts indirect tagged-concise-evidence bindings to
/// direct measurements.
///
/// The TCG Concise Evidence Binding for SPDM spec states that
/// "If a lead Attester supports tagged-concise-evidence and an spdm-indirect
/// measurement is used, the DMTFMeasurementValueType to CoMID measurement
/// mapping SHOULD be applied according to Table 7."
///
/// This function will parse a Concise Evidence Binding manifest and replace
/// the `spdm-indirect` entries with measurements.
pub fn generate_direct_manifest(
    context: *mut c_void,
    slot_id: u8,
    measurement_manifest: &[u8],
) -> Result<SpdmToc, minicbor::decode::Error> {
    let mut spdm_toc: SpdmToc<'_> = minicbor::decode(&measurement_manifest)?;
    let ce_ev_triples = &mut spdm_toc
        .value_mut()
        .tagged_evidence
        .first_mut()
        .unwrap()
        .value_mut()
        .ce_ev_triples;
    let measurement_maps = &mut ce_ev_triples.ce_membership_triples[0].1;

    for measurement_map in measurement_maps {
        if let Some(measurement_index) = measurement_map.mval.spdm_indirect {
            let mut measurement_record = [0; LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as usize];
            let (dmtf_spec_measure_type, _measurement_record_length) = unsafe {
                get_measurement(
                    context,
                    slot_id,
                    true,
                    measurement_index.index[0] as u32,
                    &mut measurement_record,
                )
                .unwrap()
            };

            let measurement_offset =
                core::mem::size_of::<libspdm_rs::spdm_measurement_block_dmtf_t>();
            let measurement_block =
                &measurement_record as *const _ as *const libspdm_rs::spdm_measurement_block_dmtf_t;
            let measurement_size = unsafe {
                (*measurement_block)
                    .measurement_block_dmtf_header
                    .dmtf_spec_measurement_value_size
            };

            match dmtf_spec_measure_type {
                0..=DIGESTS => {
                    // digests
                    let msg_buf = unsafe {
                        from_raw_parts(
                            measurement_block.add(1) as *const u8,
                            measurement_size.min(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as u16)
                                as usize,
                        )
                    };
                    let hash_algo = unsafe { get_base_hash_algo(context, slot_id).unwrap().0 };
                    measurement_map.mval.digest = Some((hash_algo as i64, msg_buf.into()));
                }
                DEBUG_INFORMATION => {
                    let msg_buf = unsafe {
                        from_raw_parts(
                            measurement_block.add(1) as *const u8,
                            measurement_size.min(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as u16)
                                as usize,
                        )
                    };
                    measurement_map.mval.raw_value = Some(Tagged::new(msg_buf.into()));
                }
                VERSION => {
                    let msg_buf = unsafe {
                        from_raw_parts(
                            measurement_block.add(1) as *const u8,
                            measurement_size.min(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as u16)
                                as usize,
                        )
                    };
                    measurement_map.mval.version = Some(std::str::from_utf8(msg_buf).unwrap());
                }
                SVN => {
                    let value = measurement_record[measurement_offset + 0] as i64
                        | (measurement_record[measurement_offset + 1] as i64) << 8
                        | (measurement_record[measurement_offset + 2] as i64) << 16
                        | (measurement_record[measurement_offset + 3] as i64) << 24;

                    measurement_map.mval.svn = Some(Tagged::<552, i64>::new(value));
                }
                RAW_BIT_STREAM | 0xFF => {
                    // raw-value
                    let msg_buf = unsafe {
                        from_raw_parts(
                            measurement_block.add(1) as *const u8,
                            measurement_size.min(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE as u16)
                                as usize,
                        )
                    };
                    measurement_map.mval.raw_value = Some(Tagged::new(msg_buf.into()));
                }
                _ => {}
            }

            measurement_map.mval.spdm_indirect = None;
        }
    }

    Ok(spdm_toc)
}
