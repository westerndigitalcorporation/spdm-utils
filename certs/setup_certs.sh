#!/bin/bash
set -e

### This script updates and signs the mutable SPDM-Utils certificates ###
### You probably want to run this on boot ###
### The first argument should be the file path to SPDM-Utils ###

FULL_HASH=$(sha384sum $1)
export MEASUREMENT_HASH=${FULL_HASH::16}

# Generate the slot0 leaf certificates
# As we don't support MULTI_KEY_CAP, we must have a
# "single public-private key pair per supported
# algorithm for its leaf certificates". So we generate one
# certificate for slot0 and use that for all other slots
pushd slot0

# Generate Alias CA (DeviceID in RIoT)
openssl req -nodes -newkey ec:param.pem \
	-keyout alias.key -out alias.req -sha384 -batch \
	-subj "/CN=Test Bootloader CA/measurement=${MEASUREMENT_HASH}" \
	-config <(cat /etc/ssl/openssl.cnf <(printf "\n[new_oids]\nmeasurement = 1.2.3.45\n[ dn ]\nmeasurement = empty"))
openssl x509 -req -in alias.req -out alias.cert -CA device.der -sha384 -days 3650 -set_serial 3 -extensions v3_inter -extfile ../openssl-alias.cnf

# Generate AliasCert (Alias key pair in RIoT)
openssl req -nodes -newkey ec:param.pem \
	-keyout end_requester.key -out end_requester.req -sha384 -batch \
	-subj "/CN=Test Bootloader AliasCert/measurement=${MEASUREMENT_HASH}" \
	-config <(cat /etc/ssl/openssl.cnf <(printf "\n[new_oids]\nmeasurement = 1.2.3.45\n[ dn ]\nmeasurement = empty"))
openssl req -nodes -newkey ec:param.pem \
	-keyout end_responder.key -out end_responder.req -sha384 -batch \
	-subj "/CN=Test Bootloader AliasCert/measurement=${MEASUREMENT_HASH}" \
	-config <(cat /etc/ssl/openssl.cnf <(printf "\n[new_oids]\nmeasurement = 1.2.3.45\n[ dn ]\nmeasurement = empty"))

openssl x509 -req -in end_requester.req -out end_requester.cert -CA alias.cert -CAkey alias.key -sha384 -days 3650 -set_serial 4 -extensions v3_end -extfile ../openssl-alias.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA alias.cert -CAkey alias.key -sha384 -days 3650 -set_serial 5 -extensions v3_end -extfile ../openssl-alias.cnf

# Generate der files
openssl asn1parse -in alias.cert -out alias.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der

popd

for slot in "slot0" "slot1" "slot2" "slot3" "slot4" "slot5" "slot6" "slot7"
do
	if [ ! -d "${slot}" ]; then
		# slots are expected to monotinically increase by one
		break
	fi
	echo "setting up certificates for $slot"

	pushd ${slot}

	if [ -e "immutable.der" ]; then
		cat immutable.der ../slot0/alias.cert.der ../slot0/end_requester.cert.der > bundle_requester.certchain.der
		cat immutable.der ../slot0/alias.cert.der ../slot0/end_responder.cert.der > bundle_responder.certchain.der
	else
		echo "Error: This $slot does not have an immutable.der file"
	fi

	popd
done
