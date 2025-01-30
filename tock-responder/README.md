# Tock Responder

This is an application that runs on the [Tock](https://github.com/tock/tock)
kernel that implements SPDM over and MCTP I2C/SMBus Bus.

The application is written in Rust and uses libspdm to implement a basic SPDM
responder. The application sends and received the SPDM data over MCTP, but
currently does not support other MCTP commands besides the DMTF vendor
commands.

This is a proof of concept implementation, designed to show how Tock can be
used as a SPDM responder.

This has been tested on a nRF52840 board, but should work with any board
running Tock that supports I2C master and slave mode.

## Building

### Building libspdm

As we use libspdm for the backend you will first need to build libspdm.

#### Warnings

Currently only `Release` mode for `libspdm` is supported. Building in `Debug`
mode requires additional functionality (`printf` support etc...), these are
currently not implemented by the tock-responder Rust implementation.

#### Build libspdm for no_std targets

You will only need to build libspdm for the architecture you want to use.
So if you are using an ARM board you can skip the RISC-V build.

##### Building for ARM:

Note, that the -DMARCH option must be specified with the respective ARM target architecture. This argument is passed directly to the compiler. See `man arm-none-eabi-gcc` for all supported options.

```shell
mkdir -p build_no_std_arm
cd build_no_std_arm

# Comment out `MBEDTLS_HAVE_TIME_DATE` as Tock doesn't have
# an accurate time.
find ../os_stub/mbedtlslib/include/mbedtls/libspdm_mbedtls_config.h -type f -exec sed -i 's|#define MBEDTLS_HAVE_TIME_DATE|// #define MBEDTLS_HAVE_TIME_DATE|g' {} +

cmake -DARCH=arm -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=Release -DCRYPTO=mbedtls -DDISABLE_TESTS=1 -DMARCH=armv7e-m -DDISABLE_LTO=1 -DCMAKE_C_FLAGS="-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=1 -DMBEDTLS_SKIP_TIME_CHECK -DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP=0 -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1 -DMBEDTLS_PLATFORM_MS_TIME_ALT" ..
make -j8
cd ../

popd
```

##### Building for RISC-V:

```shell
pushd ../third-party/libspdm/

mkdir -p build_no_std_riscv
cd build_no_std_riscv

# Comment out `MBEDTLS_HAVE_TIME_DATE` as Tock doesn't have
# an accurate time.
find ../os_stub/mbedtlslib/include/mbedtls/libspdm_mbedtls_config.h -type f -exec sed -i 's|#define MBEDTLS_HAVE_TIME_DATE|// #define MBEDTLS_HAVE_TIME_DATE|g' {} +

cmake -DARCH=riscv32 -DTOOLCHAIN=RISCV_NONE -DTARGET=Release -DCRYPTO=mbedtls -DDISABLE_TESTS=1 -DCMAKE_C_FLAGS="-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=1 -DMBEDTLS_SKIP_TIME_CHECK -DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP=0 -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1 -DMBEDTLS_PLATFORM_MS_TIME_ALT" ..
make -j8
cd ../
```


### Build the example

Once libspdm is built for your architecture you can build the application.

For example for OpenTitan

```shell
make opentitan_spdm_responder
```

Or for the nRF52840

```shell
make nrf52840_spdm_responder
```
