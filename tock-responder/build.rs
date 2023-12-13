fn main() {
    libtock_build_scripts::auto_layout();

    let target = std::env::var("TARGET").unwrap();
    let compiler_list: Vec<&str> = target.split("-").collect();
    let arch = compiler_list.first().unwrap().clone();

    println!("cargo:rustc-link-arg=-lmemlib");
    println!("cargo:rustc-link-arg=-lmalloclib");
    println!("cargo:rustc-link-arg=-ldebuglib");
    println!("cargo:rustc-link-arg=-lplatform_lib");
    println!("cargo:rustc-link-arg=-lcryptlib_mbedtls");
    println!("cargo:rustc-link-arg=-lrnglib");

    println!("cargo:rustc-link-arg=-lmbedtls");
    println!("cargo:rustc-link-arg=-lmbedx509");
    println!("cargo:rustc-link-arg=-lmbedcrypto");

    println!("cargo:rustc-link-arg=-lspdm_common_lib");
    println!("cargo:rustc-link-arg=-lspdm_requester_lib");
    println!("cargo:rustc-link-arg=-lspdm_responder_lib");
    println!("cargo:rustc-link-arg=-lspdm_secured_message_lib");
    println!("cargo:rustc-link-arg=-lspdm_secured_message_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_lib");
    println!("cargo:rustc-link-arg=-lspdm_crypt_ext_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_pcidoe_lib");
    println!("cargo:rustc-link-arg=-lspdm_transport_mctp_lib");

    // As we are linking against a C application we need to provide newlib
    // Rust isn't currently able to do this.
    // See https://github.com/rust-embedded/book/issues/255 for more details
    if arch == "riscv32imac" {
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32imac/libc.a");
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32imac/libm.a");
    } else if arch == "riscv32im" {
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32im/libc.a");
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32im/libm.a");
    } else if arch == "riscv32imc" {
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32i/libc.a");
        println!("cargo:rustc-link-arg=libtock-c/newlib/rv32/rv32i/libm.a");
    } else if arch == "thumbv7em" {
        println!("cargo:rustc-link-arg=libtock-c/newlib/cortex-m/v7-m/libc.a");
        println!("cargo:rustc-link-arg=libtock-c/newlib/cortex-m/v7-m/libm.a");
    } else {
        unreachable!();
    }

    // As we are using newlib, we also need to provide implementations for
    // the newlib stubs. libtock-c does this already, so let's use that.
    if arch == "riscv32imac" {
        println!("cargo:rustc-link-arg=libtock-c/libtock/build/rv32imac/libtock.a");
    } else if arch == "riscv32imc" {
        println!("cargo:rustc-link-arg=libtock-c/libtock/build/rv32imc/libtock.a");
    } else if arch == "riscv32im" {
        println!("cargo:rustc-link-arg=libtock-c/libtock/build/rv32im/libtock.a");
    } else if arch == "riscv32i" {
        println!("cargo:rustc-link-arg=libtock-c/libtock/build/rv32i/libtock.a");
    } else if arch == "thumbv7em" {
        println!("cargo:rustc-link-arg=libtock-c/libtock/build/cortex-m4/libtock.a");
    }

    if arch == "riscv32imac" {
        println!("cargo:rustc-link-search=../third-party/libspdm/build_no_std_riscv/lib/");
    } else if arch == "riscv32im" {
        println!("cargo:rustc-link-search=../third-party/libspdm/build_no_std_riscv/lib/");
    } else if arch == "riscv32imc" {
        println!("cargo:rustc-link-search=../third-party/libspdm/build_no_std_riscv/lib/");
    } else if arch == "thumbv7em" {
        println!("cargo:rustc-link-search=../third-party/libspdm/build_no_std_arm/lib/");
    } else {
        unreachable!();
    }
}
