// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

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
        Err(e) => panic!("Ruby script {script} not found : error {}", e),
    }
}
