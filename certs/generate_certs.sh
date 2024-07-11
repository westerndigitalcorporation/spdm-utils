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
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions inter_ca -extfile ../openssl.cnf

# Generate der files
openssl asn1parse -in ca.cert -out ca.cert.der

# Generate the inter public and private key
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in inter.key -out inter.key.der
cat inter.cert.der inter.key.der > inter.der

# Generate Leaf CSRs
openssl req -nodes -newkey ec:param.pem \
       -keyout end_requester.key -out end_requester.req -sha384 -batch \
       -subj "/CN=Test Bootloader Requester"
openssl req -nodes -newkey ec:param.pem \
       -keyout end_responder.key -out end_responder.req -sha384 -batch \
       -subj "/CN=Test Bootloader Responder"

popd

mkdir -p alias/slot0
pushd alias/slot0

# Generate Device CA
openssl req -nodes -newkey ec:../../slot0/param.pem -keyout device.key -out device.req -sha384 -batch -subj "/CN=Test Device CA"
openssl x509 -req -in device.req -out device.cert -CA ../../slot0/inter.cert -CAkey ../../slot0/inter.key -sha384 -days 3650 -set_serial 2 -extensions device_ca -extfile ../openssl.cnf

# Generate the device public and private key
openssl asn1parse -in device.cert -out device.cert.der
openssl asn1parse -in device.key -out device.key.der
cat device.cert.der device.key.der > device.der

# Save all of the immutable certificates
cat ../../slot0/ca.cert.der ../../slot0/inter.cert.der device.cert.der > immutable.der

rm device.cert

popd

mkdir -p device/slot0
pushd device/slot0

# Copy in CSRs
cp ../../slot0/end* ./

# Sign the CSRs
openssl x509 -req -in end_requester.req -out end_requester.cert -CA ../../slot0/inter.cert -CAkey ../../slot0/inter.key -sha384 -days 3650 -set_serial 4 -extensions leaf -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA ../../slot0/inter.cert -CAkey ../../slot0/inter.key -sha384 -days 3650 -set_serial 5 -extensions leaf -extfile ../openssl.cnf

# Generate der files
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der

cp end_responder.key device.key
cp end_responder.cert.der device.cert.der

cat ../../slot0/ca.cert.der ../../slot0/inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ../../slot0/ca.cert.der ../../slot0/inter.cert.der end_responder.cert.der > bundle_responder.certchain.der

popd
