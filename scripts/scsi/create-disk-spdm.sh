#!/bin/bash

if [ $# != 5 ]; then
        echo "Usage: $0 <disk name> <cap (GB)> HM|HA <zone size (MB)> <conv zones num>"
        exit 1;
fi

dname="$1"
cap="$2"
model="$3"
zs="$4"
cnum="$5"

naa="naa.50014059cfa9ba75"

# Setup emulated disk
cat << EOF | targetcli

cd /backstores/user:zbc
create name=${dname} size=${cap}G cfgstring=model-${model}/zsize-${zs}/conv-${cnum}/spdm-2323@/var/local/${dname}.raw
cd /loopback
create ${naa}
cd ${naa}/luns
create /backstores/user:zbc/${dname} 0
cd /
exit

EOF

sleep 1
disk=`lsscsi | grep "TCMU ZBC device" | cut -d '/' -f3 | sed 's/ //g'`
echo "mq-deadline" > /sys/block/"${disk}"/queue/scheduler
