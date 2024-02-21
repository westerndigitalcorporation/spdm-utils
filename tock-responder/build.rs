fn main() {
    libtock_build_scripts::auto_layout();

    let target = std::env::var("TARGET").unwrap();
    let compiler_list: Vec<&str> = target.split("-").collect();
    let arch = *compiler_list.first().unwrap();

    println!("cargo:rustc-link-arg=-lmemlib");
    println!("cargo:rustc-link-arg=-lmalloclib");
    println!("cargo:rustc-link-arg=-ldebuglib");
    println!("cargo:rustc-link-arg=-lplatform_lib");
    println!("cargo:rustc-link-arg=-lcryptlib_mbedtls");

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
