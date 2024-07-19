<div align="center">
    <h1>SPDM-Utils</h1>
</div>

SPDM-Utils is an open source Linux application designed to support, test and
develop SPDM requesters and responders. SPDM-Utils is written in Rust
and uses [libspdm](https://github.com/DMTF/libspdm) as the backend.

It can be used as a requester CLI to interface with SPDM devices.
It includes support for the PCIe Data Object Exchange (DOE) Capability
and MCTP transport layers.

SPDM-Utils can also be used as a responder. It can be an embedded MCTP responder
running on Tock. It can also be used as a responder running on Linux, and exposed
to QEMU or other applications via sockets.

SPDM-Utils can use Unix sockets as well. So you can test it all locally as a
requester and responder.

# Copyright

Copyright (c) 2022 Western Digital

SPDM-Utils source code is dual licensed under the Apache-2.0 license and MIT license. A copy of these licenses can be found either in the LICENSE-APACHE or LICENSE-MIT files. Versions are also available at http://www.apache.org/licenses/LICENSE-2.0 and http://opensource.org/licenses/MIT.

See LICENSE-APACHE, LICENSE-MIT, and COPYRIGHT for details.

# Table of Contents

- [Dependencies](#dependencies)
    - [Fedora](#fedora)
- [Building](#building)
    - [Build libspdm](#build-libspdm)
    - [Build the binary](#build-the-binary)
    - [Build the `no_std` library](#build-the-no_std-library)
    - [Generate mutable certificates](#Generate-mutable-certificates)
    - [Configuring the Logger](#configuring-the-logger)
- [Testing](#testing)
    - [Running libspdm tests](#running-libspdm-tests)
    - [Testing completely on the host](#testing-completely-on-the-host)
    - [Testing a real device](#testing-a-real-device)
    - [Setting the certificate](#setting-the-certificate)
    - [Getting a Certificate Signing Request](#getting-a-certificate-signing-request)
    - [Signing a Certificate Signing Request](#signing-a-certificate-signing-request)
- [QEMU SPDM Device Emulation](#qemu-spdm-device-emulation)

# Dependencies

First you need to install Rust, instructions for that are available at: https://rustup.rs/

You will also need a few host dependencies

## Fedora

```shell
sudo dnf install cmake clang-libs clang-devel pciutils-devel openssl openssl-devel python3-devel
```

## Ruby

`spdm-utils` uses the [cbor-diag](https://github.com/cabo/cbor-diag) ruby gem for
manifest encoding and decoding. Similar to the implementation of this [CBOR parsing](https://cbor.me/)
online tool.

You will first need to have `gem` installed, this is a the package manager for ruby.
For example, for Fedora you can install it with:

```shell
$ sudo dnf install gem
```

After which, you can install `cbor-diag`

```shell
$ gem install cbor-diag
```

The default binary path *should* be, `$HOME/bin/`, which you may need to add to
your `PATH`. You can test that the scripts are usable with

```shell
$ which cbor2diag.rb
home/<user>/bin/cbor2diag.rb
```

When building `spdm-utils` it will generate a `manifest.out.cbor` which contains
the serialised cbor manifest, and also a `manifest.pretty` which is the *pretty* format
of the manifest (user friendly).

# Building

Initialise all sub-modules

```shell
cd third-party/
git submodule init; git submodule update --recursive
```

## Build libspdm

To build libspdm in the third-party directory

```shell
cd libspdm/
mkdir build; cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl -DENABLE_BINARY_BUILD=1 -DCOMPILED_LIBCRYPTO_PATH=/usr/lib/ -DCOMPILED_LIBSSL_PATH=/usr/lib/ -DDISABLE_TESTS=1 -DCMAKE_C_FLAGS="-DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1" ..
make -j8
```

Note that we build `libspdm` with chunking enabled. Chunking allows us to keep the maximum data transferred
in a single burst down by chunking the SPDM message data into frames of digestible size(s).

For example, `usb_i2c` communication with the `tock-responder` requires it, so we enable it by default.

## Build the binary

Then you can build SPDM-Utils with

```shell
cargo build --bin spdm_utils
```

## Build the `no_std` library

This is currently a work in progress

```shell
cargo build --lib --features=no_std
```

## Configuring the Logger

SPDM-Utils supports logging. The following log levels are supported:

- trace
- debug
- info
- warn
- error

By default SPDM-Utils will build with `trace` log level, meaning that the log
outputs are very verbose containing all logs. To change this, set the `LOG_LEVEL`
environment variable to the desired level when building. The logger also takes a
`LOG_STYLE` parameter which may be used to set the character style. This
defaults to `always` but can be changed to one of (see
[here](https://docs.rs/env_logger/latest/env_logger/#disabling-colors) for more):

- always
- never
- auto

```shell
LOG_LEVEL=info LOG_STYLE=never cargo build
```

# Testing

All changes should go through the Cargo formatter and tests, which can be run with

```shell
cargo fmt; cargo clippy; cargo test
```

## Running libspdm tests

Setup and build `SPDM-Responder-Validator` in the third-party directory

```shell
cd third-party/
git submodule init; git submodule update --recursive
cd SPDM-Responder-Validator/
rm -rf libspdm/

# This assumes that `third-party/libspdm` is configured correctly as above
# The symlink here ensures that the tests are build against the same version of libspdm
ln -s ../libspdm/ libspdm
mkdir build; cd build

cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Debug -DCRYPTO=openssl ..
make -j8
```

We can now build SPDM-Utils with

```shell
RUSTFLAGS='--cfg libspdm_tests' cargo build
```

## Testing completely on the host

You can run SPDM-Utils completely on the host using unix sockets.
In this case you can run the server side with

```shell
cargo run -- --socket-server request get-digests
```

and the client side with

```shell
./target/debug/spdm_utils --socket-client response
```

Note that the server must be run first. You can also swap the server/client
specification between the request or response side as well.

You can also run the libspdm tests by running tests on the socket server with:

```shell
cargo run -- --socket-server tests
```

## Testing a real device

You can run SPDM-Utils on the host to interact with a real DOE device. To do
that you can run the following example to get digest information

```shell
./target/debug/spdm_utils --doe-pci-cfg request get-digests
```

## Setting the certificate

From a host you can set the certificate of the device. As SPDM-Utils uses
the Alias cert model you can only set the root certificate to the device
certificate with the `SET_CERTIFICATE` command (see section 117 on the
SPDM spec).

For example to set the certificate run:

```shell
spdm_utils --doe-pci-cfg request --cert-path ./certs/alias/slot0/immutable.der set-certificate
```

You can additionally specify `--cert-slot-id` to specify the target slot number, valid slot numbers range from
0-7.

## Getting a Certificate Signing Request

A requester can get the Certificate Signing Request (CSR) from the device
with a command similar to this:

```shell
spdm_utils --doe-pci-cfg request get-csr
```

Which will save the file to `csr_response.der`. You can then verify the CSR
with openssl

```shell
openssl req -text -noout -inform der -verify -in ./csr_response.der
```

## Signing a Certificate Signing Request

Once you have a `csr_response.der` from the responder, you first want to
convert it to a PEM format with

```shell
openssl req -inform der -in ./csr_response.der -out csr_response.req
```

You can now sign the CSR

```shell
openssl x509 -req -in csr_response.req -out csr_response.cert -CA ./certs/alias/slot0/inter.der -sha384 -days 3650 -set_serial 2 -extensions device_ca -extfile ./certs/alias/openssl.cnf
```

Then convert the certificate back to DER

```shell
openssl asn1parse -in csr_response.cert -out csr_response.cert.der
```

Combine all of the immutable certs

```shell
cat ./certs/alias/slot0/ca.cert.der ./certs/alias/slot0/inter.cert.der ./csr_response.cert.der > set-cert.der
```

Now you can set the certificate of a slot

```shell
spdm_utils --doe-pci-cfg request --cert-slot-id 1 --cert-path ./set-cert.der set-certificate
```

Then you request the certificate back

```shell
spdm_utils --doe-pci-cfg request --cert-slot-id 1 get-certificate
```

If you are running the socket/client mode you will have to simulate a
device reset and certificate re-gen. That can be done by running this

```shell
cd certs
./setup_certs.sh ../target/debug/spdm_utils
cd ../
```

# QEMU SPDM Device Emulation

SPDM-Utils supports binding to QEMU to implement an SPDM responder side to
an emulated device in QEMU. SPDM support for QEMU is not upstream yet, however,
[this fork](https://github.com/qemu/qemu/compare/master...twilfredo:qemu:wilfred/spdm-a)
has the necessary changes required to emulated an NVMe device with SPDM support
over DOE.

For example, this may be an emulated NVMe device
in QEMU that binds to SPDM-Utils for the SPDM responder implementation.

With the current SPDM implementation in QEMU, the only transport layer supported
is DOE. SPDM-Utils must be started before QEMU for this to work.

```shell
$ ./target/debug/spdm_utils --qemu-server response

[2023-08-29T06:21:47Z DEBUG SPDM-Utils] Logger initialisation [OK]
[2023-08-29T06:21:47Z DEBUG SPDM-Utils::qemu_server] Setting up a server on [port: 2323, ip: 127.0.0.1]
[2023-08-29T06:21:47Z INFO  SPDM-Utils::qemu_server] Server started, waiting for qemu on port: 2323
```

Note: You can provide `--qemu-port <QEMU_PORT>` to specify a port for the server
and also `--spdm-transport-protocol <TRANSPORT>` to specify the transport layer.

This will start SPDM-Utils responder server on port 2323 (default). QEMU can now be
started. Once QEMU starts, if the connection is successful, the following logs
should show (ensure that INFO log level is enabled in SPDM-Utils).

```shell
[2023-08-29T06:22:01Z INFO  SPDM-Utils::qemu_server] New connection: 127.0.0.1:40528
[2023-08-29T06:22:01Z INFO  SPDM-Utils::responder] Running in a response loop
```

Now QEMU is ready to use SPDM-Utils as an SPDM responder for an emulated device.
