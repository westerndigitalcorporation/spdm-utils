# Build steps

## Build libtock-c

```shell
push libtock-c/examples/
RISCV=1 ./build_all.sh
cd ../../
```

## Build libspdm for no_std targets

```shell
pushd ../third-party/libspdm/

mkdir -p build_no_std_riscv
cd build_no_std_riscv
cmake -DARCH=riscv32 -DTOOLCHAIN=RISCV_NONE -DTARGET=Debug -DCRYPTO=mbedtls -DDISABLE_TESTS=1 ..
make -j8
cd ../

mkdir -p build_no_std_arm
cd build_no_std_arm
cmake -DARCH=arm -DTOOLCHAIN=ARM_GNU_BARE_METAL -DTARGET=Debug -DCRYPTO=mbedtls -DDISABLE_TESTS=1 ..
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
