#!/bin/bash

if [ $# != 1 ]; then
	echo "Usage: $0 <disk name (e.g. zbc0)"
	exit 1;
fi

dname="$1"

naa="naa.50014059cfa9ba75"

# Delete emulated disk
cat << EOF | targetcli

cd /loopback/${naa}/luns
delete 0
cd /loopback
delete ${naa}
cd /backstores/user:zbc
delete ${dname}
cd /
exit

EOF
