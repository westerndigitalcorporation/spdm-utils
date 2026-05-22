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

    // cargo:rustc-link-lib doesn't seem to support start-group/end-group
    // so we manually pass the arguments
    println!("cargo:rustc-link-arg=-Wl,--start-group");

    if cfg!(feature = "pci") {
        println!("cargo:rustc-link-arg=-lpci");
    }

    if cfg!(feature = "nvme") {
        println!("cargo:rustc-link-arg=-lnvme");
    }

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
    println!("cargo:rustc-link-arg=-lspdm_transport_tcp_lib");

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

    if cfg!(feature = "std") {
        builder = builder.clang_arg("-DRUST_STD");

        if cfg!(feature = "pci") {
            builder = builder.clang_arg("-DPCI");
        }

        if cfg!(feature = "nvme") {
            builder = builder.clang_arg("-DNVME");
        }

        if cfg!(feature = "scsi") {
            builder = builder.clang_arg("-DSCSI");
        }
    }

    if let Ok(sysroot) = env::var("STAGING_DIR") {
        // Append the `STAGING_DIR` information, used for buildroot
        let sysroot_arg = format!("--sysroot={sysroot}");
        builder = builder.clang_arg(sysroot_arg);

        let include_arg = format!("-I{sysroot}/usr/include/libspdm");
        builder = builder.clang_arg(include_arg);

        println!("cargo:rustc-link-search={sysroot}/usr/lib/");
    } else if let Ok(staging_incdir) = env::var("STAGING_INCDIR") {
        // Append the `STAGING_INCDIR` information, used for Open-Embedded/Yocto
        builder = builder.clang_arg(format!("-I{staging_incdir}/libspdm"));
    } else {
        // Append the local build and tests, used for local manual builds
        println!("cargo:rustc-link-search=third-party/libspdm/build/lib/");
        #[cfg(feature = "libspdm_tests")]
        {
            println!("cargo:rustc-link-search=third-party/SPDM-Responder-Validator/build/lib/");
        }
    }

    builder = builder.clang_arg("-DLIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT=1");

    let bindings = builder
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .use_core()
        .blocklist_item("max_align_t")
        .blocklist_function("qfcvt_r")
        .blocklist_function("qfcvt")
        .blocklist_function("qecvt_r")
        .blocklist_function("qecvt")
        .blocklist_function("qgcvt")
        .blocklist_function("strtold")
        .blocklist_type("_Float64x")
        .wrap_unsafe_ops(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    println!("cargo:rustc-link-arg=-Wl,--end-group");

    run_setup_certs("certs/bank-ecc384");
    run_setup_certs("certs/bank-mldsa87");

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
                Err(e) => {
                    println!(
                        "\x1b[33mcargo:warning=Ruby script {script} not found : error {}\x1b[0m",
                        e
                    )
                }
            }
        }
        Err(e) => println!(
            "\x1b[33mcargo:warning=Ruby script {script} not found : error {}\nSkipping fresh manifest generation\x1b[0m",
            e
        ),
    }
}

/// Runs `setup_certs.sh` for the given bank directory if its responder bundle
/// is missing. Panics with the script's stdout/stderr if the script fails so
/// missing-cert problems surface at build time rather than as runtime panics.
fn run_setup_certs(bank_dir: &str) {
    let bundle = format!("{}/alias/slot0/bundle_responder.certchain.der", bank_dir);
    if Path::new(&bundle).is_file() {
        return;
    }

    let cwd = env::current_dir().unwrap().join(bank_dir);
    let out = Command::new("./setup_certs.sh")
        .current_dir(&cwd)
        .output()
        .unwrap_or_else(|e| panic!("Failed to spawn setup_certs.sh in {}: {}", bank_dir, e));

    if !out.status.success() {
        eprintln!(
            "Unable to generate certificates for {bank_dir}. That bank won't be supported at runtime.",
        );
        if bank_dir == "certs/bank-mldsa87" {
            eprintln!(
                "Unable to generate PQC certificates. This probably means you aren't using OpenSSL 3.5+",
            );
        }

        eprintln!(
            "setup_certs.sh failed for {bank_dir} (exit {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}
