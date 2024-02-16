// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (C) 2022, Western Digital Corporation or its affiliates.

extern crate bindgen;

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

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

    // Link SPDM Test Libraries
    let mut builder = if cfg!(libspdm_tests) {
        println!("cargo:rustc-link-arg=-lcommon_test_utility_lib");
        println!("cargo:rustc-link-arg=-lspdm_responder_conformance_test_lib");

        bindgen::Builder::default()
            .clang_arg("-DLIBSPDM_TESTS")
            .header("wrapper.h")
            .clang_arg("-Ithird-party/libspdm/include")
            .clang_arg("-Ithird-party/libspdm")
            .clang_arg("-Ithird-party/SPDM-Responder-Validator/include")
            .clang_arg("-Ithird-party/SPDM-Responder-Validator/common_test_framework/include/")
    } else {
        bindgen::Builder::default()
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
        #[cfg(libspdm_tests)]
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

    if !Path::new("certs/slot0/bundle_responder.certchain.der").is_file() {
        Command::new("./setup_certs.sh")
            .current_dir(env::current_dir().unwrap().join("certs"))
            .output()
            .expect("Failed to execute command");
    }

    // This script generates a `manifest.out.cbor` file that
    // is the serialised measurement manifest, to be used
    // by spdm-utils in response to a `get-measuremets`
    // SPDM request.
    if !Path::new("manifest/encode_cbor.py").is_file() {
        panic!("cbor encode script not found!");
    }

    let rc = Command::new("python3")
        .arg("encode_cbor.py")
        .current_dir(env::current_dir().unwrap().join("manifest"))
        .output()
        .expect("Failed to execute encode_cbor");

    if !rc.status.success() {
        panic!(
            "failed to generate serialized CBOR manifest: {:?}",
            rc.status
        )
    }
}
