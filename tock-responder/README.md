# Build steps

## Build libtock-c

```shell
push libtock-c/examples/
RISCV=1 ./build_all.sh
cd ../../
```


## Building libspdm

### Warnings

Currently only `Release` mode for `libspdm` is supported. Building in `Debug` mode requires additional functionality (`printf` support etc...), these are currently not implemented by the tock-responder.

### Build libspdm for no_std targets

#### Building for RISC-V:

```shell
pushd ../third-party/libspdm/

mkdir -p build_no_std_riscv
cd build_no_std_riscv
cmake -DARCH=riscv32 -DTOOLCHAIN=RISCV_NONE -DTARGET=Release -DCRYPTO=mbedtls -DDISABLE_TESTS=1 CFLAGS="-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=1" ..
make -j8
cd ../
```

#### Building for ARM:

Note, that the -DMARCH option must be specified with the respective ARM target architecture. This argument is passed directly to the compiler. See `man arm-none-eabi-gcc` for all supported options.

```shell
mkdir -p build_no_std_arm
cd build_no_std_arm
cmake -DARCH=arm -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=Release -DCRYPTO=mbedtls -DDISABLE_TESTS=1 -DMARCH=armv7e-m -DDISABLE_LTO=1 CFLAGS="-DLIBSPDM_ENABLE_CAPABILITY_CHUNK_CAP=1" ..
make -j8
cd ../

popd
```

## Build the example

Then you can build SPDM for any machine, for example for OpenTitan

```shell
make opentitan_spdm_responder
```

Or for the nRFS

```shell
make nrf52840_spdm_responder
```
