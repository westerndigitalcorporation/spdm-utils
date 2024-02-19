// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2024, Western Digital Corporation or its affiliates.

use std::fs::File;
use std::io::Read;
use std::path::Path;

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

        let mut temp_buffer = Vec::new();
        manifest.read_to_end(&mut temp_buffer)?;

        assert!(temp_buffer.len() <= buffer.len());

        // Copy over the manifest bytes to the actual buffer
        for i in 0..temp_buffer.len() {
            buffer[i] = temp_buffer[i];
        }

        Ok(temp_buffer.len())
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
