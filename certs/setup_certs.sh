#!/usr/bin/env bash
set -e

### This script updates and signs the mutable SPDM-Utils certificates ###
### You probably want to run this on boot ###

# Generate the slot0 leaf certificates
# As we don't support MULTI_KEY_CAP, we must have a
# "single public-private key pair per supported
# algorithm for its leaf certificates". So we generate one
# certificate for slot0 and use that for all other slots
pushd alias/slot0

# Generate Alias CA (DeviceID in RIoT)
openssl req -nodes -newkey ec:../../slot0/param.pem \
	-keyout alias.key -out alias.req -sha384 -batch \
	-subj "/CN=Test Bootloader CA"
openssl x509 -req -in alias.req -out alias.cert -CA device.der -sha384 -days 3650 -set_serial 3 -extensions alias_ca -extfile ../openssl.cnf

# Copy in CSRs
cp ../../slot0/end* ./

# Sign the CSRs
openssl x509 -req -in end_requester.req -out end_requester.cert -CA alias.cert -CAkey alias.key -sha384 -days 3650 -set_serial 4 -extensions leaf_requester -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA alias.cert -CAkey alias.key -sha384 -days 3650 -set_serial 5 -extensions leaf_responder -extfile ../openssl.cnf

# Generate der files
openssl asn1parse -in alias.cert -out alias.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der

cat immutable.der alias.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat immutable.der alias.cert.der end_responder.cert.der > bundle_responder.certchain.der

popd

pushd alias

for slot in "slot1" "slot2" "slot3" "slot4" "slot5" "slot6" "slot7"
do
	if [ ! -d "${slot}" ]; then
		# slots are expected to monotinically increase by one
		break
	fi
	echo "setting up certificates for $slot"

	pushd ${slot}

	if [ -e "immutable.der" ]; then
		# We want to use the last immutable certificate. For slot0 that is the
		# "Test Device CA" but for other slots it might be the signed CSR
		# from set certificate.

		while openssl x509; do echo "%"; done < immutable.der | awk '
    /-----BEGIN CERTIFICATE-----/ { f=1; rec="" }
    f { rec = rec $0 ORS }
    /-----END CERTIFICATE-----/ { f=0 }
    END { if (f=="0") printf "%s", rec }
' > custom_device.cert
		openssl x509 -req -in ../slot0/alias.req -out alias.cert -CA custom_device.cert -CAkey ../slot0/device.key -sha384 -days 3650 -set_serial 3 -extensions alias_ca -extfile ../openssl.cnf

		openssl x509 -req -in ../slot0/end_requester.req -out end_requester.cert -CA alias.cert -CAkey ../slot0/alias.key -sha384 -days 3650 -set_serial 4 -extensions leaf -extfile ../openssl.cnf
		openssl x509 -req -in ../slot0/end_responder.req -out end_responder.cert -CA alias.cert -CAkey ../slot0/alias.key -sha384 -days 3650 -set_serial 5 -extensions leaf -extfile ../openssl.cnf

		# Generate der files
		openssl asn1parse -in alias.cert -out alias.cert.der
		openssl asn1parse -in end_requester.cert -out end_requester.cert.der
		openssl asn1parse -in end_responder.cert -out end_responder.cert.der

		cat immutable.der alias.cert.der end_requester.cert.der > bundle_requester.certchain.der
		cat immutable.der alias.cert.der end_responder.cert.der > bundle_responder.certchain.der
	else
		echo "Error: This $slot does not have an immutable.der file"
	fi

	popd
done

popd
