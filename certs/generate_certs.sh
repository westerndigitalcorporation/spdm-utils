#!/bin/bash
set -e

### This script generates all of the immutable SPDM-Utils certificates ###
### It is unlikely you want to run this script ###

## Generate slot 0 certs ##
pushd slot0

# Generate root CA
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -extensions v3_ca -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/CN=Test CA"

# Generate Intermediate CA
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=Test Intermediate CA"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf

# Generate Device CA
openssl req -nodes -newkey ec:param.pem -keyout device.key -out device.req -sha384 -batch -subj "/CN=Test Device CA"
openssl x509 -req -in device.req -out device.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 2 -extensions v3_inter -extfile ../openssl.cnf

# Generate der files
openssl asn1parse -in ca.cert -out ca.cert.der

# Generate the inter public and private key
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in inter.key -out inter.key.der
cat inter.cert.der inter.key.der > inter.der

# Generate the device public and private key
openssl asn1parse -in device.cert -out device.cert.der
openssl asn1parse -in device.key -out device.key.der
cat device.cert.der device.key.der > device.der

# Save all of the immutable certificates
cat ca.cert.der inter.cert.der device.cert.der > immutable.der

rm device.cert

popd
