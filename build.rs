// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

extern crate bindgen;
extern crate which;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use which::which;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=manifest/manifest.in.cbor");
    println!("cargo:rerun-if-changed=certs/alias/slot0/device.der");
    println!("cargo:rerun-if-changed=certs/alias/slot0/immutable.der");

    // cargo:rustc-link-lib doesn't seem to support start-group/end-group
    // so we manually pass the arguments
    println!("cargo:rustc-link-arg=-Wl,--start-group");

    println!("cargo:rustc-link-arg=-lpci");

    println!("cargo:rustc-link-arg=-lmemlib");
    println!("cargo:rustc-link-arg=-lmalloclib");
    println!("cargo:rustc-link-arg=-ldebuglib");
    println!("cargo:rustc-link-arg=-lplatform_lib");
    println!("cargo:rustc-link-arg=-lssl");
    println!("cargo:rustc-link-arg=-lcrypto");
    println!("cargo:rustc-link-arg=-lcryptlib_openssl");
    println!("cargo:rustc-link-arg=-lrnglib");

    println!("cargo:rustc-link-arg=-lspdm_common_lib");
    println!("cargo:rustc-link-arg=-lspdm_requester_lib");
    println!("cargo:rustc-link-arg=-lspdm_responder_lib");
    println!("cargo:rustc-link-arg=-lspdm_secured_message_lib");
    println!("cargo:rustc-link-arg=-lspdm_secured_message_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_ext_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_pcidoe_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_mctp_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_storage_lib");

    // Link SPDM Test Libraries
    let mut builder = if cfg!(feature = "libspdm_tests") {
        println!("cargo:rustc-link-arg=-lcommon_test_utility_lib");
        println!("cargo:rustc-link-arg=-lspdm_responder_conformance_test_lib");

        bindgen::Builder::default()
            .clang_arg("-DLIBSPDM_TESTS")
            .clang_arg("-DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1")
            .header("wrapper.h")
            .clang_arg("-Ithird-party/libspdm/include")
            .clang_arg("-Ithird-party/libspdm")
            .clang_arg("-Ithird-party/SPDM-Responder-Validator/include")
            .clang_arg("-Ithird-party/SPDM-Responder-Validator/common_test_framework/include/")
    } else {
        bindgen::Builder::default()
            .clang_arg("-DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1")
            .header("wrapper.h")
            .clang_arg("-Ithird-party/libspdm/include")
            .clang_arg("-Ithird-party/libspdm")
    };

    if let Ok(sysroot) = env::var("STAGING_DIR") {
        let sysroot_arg = format!("--sysroot={sysroot}");
        builder = builder.clang_arg(sysroot_arg);

        let include_arg = format!("-I{sysroot}/usr/include/libspdm");
        builder = builder.clang_arg(include_arg);

        println!("cargo:rustc-link-search={sysroot}/usr/lib/");
    } else {
        println!("cargo:rustc-link-search=third-party/libspdm/build/lib/");
        #[cfg(feature = "libspdm_tests")]
        {
            println!("cargo:rustc-link-search=third-party/SPDM-Responder-Validator/build/lib/");
        }
    }

    let bindings = builder
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .rustfmt_bindings(true)
        .use_core()
        .blocklist_item("max_align_t")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qgcvt")
        .blocklist_function("strtold")
        .blocklist_type("_Float64x")
        .clang_arg(format!("--target={}", env::var("HOST").unwrap()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-arg=-Wl,--end-group");

    if !Path::new("certs/alias/slot0/bundle_responder.certchain.der").is_file() {
        Command::new("./setup_certs.sh")
            .current_dir(env::current_dir().unwrap().join("certs"))
            .output()
            .expect("Failed to execute command");
    }

    // This script generates a `manifest.out.cbor` file that
    // is the serialised measurement manifest, to be used
    // by spdm-utils in response to a `get-measuremets`
    // SPDM request.
    let script = "diag2cbor.rb";
    match which(script) {
        Ok(_) => {
            let cmd = format!("{} manifest/manifest.in.cbor", script);
            let rc = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .stdout(Stdio::piped())
                .output()
                .expect("Failed to execute command");

            if !rc.status.success() {
                panic!("Failed serialising manifest, {:?}", rc);
            }

            let serialised_cbor = rc.stdout;
            let mut file = File::create("manifest/manifest.out.cbor")
                .expect("failed to create manifest.out.cbor");
            file.write_all(&serialised_cbor)
                .expect("failed to write save serialised data to `manifest.out.cbor`");

            // Save the pretty format also for debug purposes, this can also catch
            // formatting errors in the `manifest.in.cbor`.
            let script = "cbor2pretty.rb";
            match which(script) {
                Ok(_) => {
                    let cmd = format!("{} manifest/manifest.out.cbor", script);
                    let rc = Command::new("sh")
                        .arg("-c")
                        .arg(&cmd)
                        .stdout(Stdio::piped())
                        .output()
                        .expect("Failed to execute command");

                    if !rc.status.success() {
                        panic!("Failed in converting serialised form to pretty, {:?}", rc);
                    }

                    let pretty_format = rc.stdout;
                    let mut file = File::create("manifest/manifest.pretty")
                        .expect("failed to create manifest.pretty");
                    file.write_all(&pretty_format)
                        .expect("failed to write to `manifest.pretty`");
                }
                Err(e) => {println!("\x1b[33mcargo:warning=Ruby script {script} not found : error {}\x1b[0m", e)},
            }
        }
        Err(e) => println!("\x1b[33mcargo:warning=Ruby script {script} not found : error {}\nSkipping fresh manifest generation\x1b[0m", e),
    }
}
