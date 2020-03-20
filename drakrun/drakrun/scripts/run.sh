#!/bin/bash

if [ "$1" = "" ]
then
    echo "Usage: ./run.sh <VM_ID>"
    exit 1
fi

VM_ID=$1

echo "[!] Spinning up VM $VM_ID"

cd $(dirname "$0")
VM_MAC=$(python3 $DRAK_MAIN_DIR/genmac.py "$VM_ID")

echo "[!] Destroying old domain..."
xl destroy "vm-$VM_ID" 2>/dev/null

if [ "$2" = "zfs" ]
then
    $DRAK_ETC_DIR/scripts/setup-zfs.sh "$1"
elif [ "$2" = "qcow2" ]
then
    $DRAK_ETC_DIR/scripts/setup-qcow2.sh "$1"
fi

echo "[!] Restoring xl domain..."
xl -vvv restore "$DRAK_ETC_DIR/configs/vm-$VM_ID.cfg" $DRAK_LIB_DIR/volumes/snapshot.sav

if [ $? != 0 ]
then
    echo "Failed to restore VM"
    cat "/var/log/xen/qemu-dm-vm-$VM_ID.log"
    exit 4
fi

echo -n "[!] Delete nic0 in VM... "
xl qemu-monitor-command "vm-$VM_ID" "device_del nic0"

if [ $? != 0 ] ; then echo "Failed to delete nic0" ; exit 5 ; fi

TRIES=0

while true
do
    xl qemu-monitor-command "vm-$VM_ID" "info network" | grep -q nic0

    if [ $? == 1 ]
    then
        break
    else
        sleep 0.25
	    TRIES=$((TRIES + 1))

        if [ "$TRIES" -ge 120 ]
        then
            echo "Failed to see nic0 deleted by qemu"
	    exit 7
        fi
    fi
done

echo -n "[!] Add nic1 in VM... "
xl qemu-monitor-command "vm-$VM_ID" "device_add e1000,id=nic1,netdev=net0,mac=$VM_MAC"

if [ $? != 0 ] ; then echo "Failed to add nic1" ; exit 6 ; fi

TRIES=0

while true
do
    xl qemu-monitor-command "vm-$VM_ID" "info network" | grep -q nic1

    if [ $? == 0 ]
    then
        break
    else
        sleep 0.25
	    TRIES=$((TRIES + 1))

        if [ "$TRIES" -ge 120 ]
        then
            echo "Failed to see nic1 added by qemu"
	    exit 7
        fi
    fi
done

CDROM="/tmp/drakrun/vm-$VM_ID/malwar.iso"
xl qemu-monitor-command "vm-$VM_ID" "change ide-5632 $CDROM"

echo "[!] All set!"

