#!/usr/bin/python3

import logging
import os
import subprocess
import time

from drakrun.genmac import gen_mac, print_mac

LIB_DIR = os.path.dirname(os.path.realpath(__file__))
ETC_DIR = os.path.dirname(os.path.realpath(__file__))


def run_vm(vm_id):
    try:
        subprocess.check_output(["xl", "destroy", "vm-{vm_id}".format(vm_id=vm_id)], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        pass

    try:
        os.unlink(os.path.join(LIB_DIR, "volumes/vm-{vm_id}.img".format(vm_id=vm_id)))
    except FileNotFoundError:
        pass

    subprocess.run(["qemu-img", "create",
                    "-f", "qcow2",
                    "-o", "backing_file=vm-0.img",
                    os.path.join(LIB_DIR, "volumes/vm-{vm_id}.img".format(vm_id=vm_id))], check=True)

    try:
        subprocess.run(["xl", "-vvv", "restore",
                        os.path.join(ETC_DIR, "configs/vm-{vm_id}.cfg".format(vm_id=vm_id)),
                        os.path.join(LIB_DIR, "volumes/snapshot.sav")], check=True)
    except subprocess.CalledProcessError:
        logging.exception("Failed to restore VM {vm_id}".format(vm_id=vm_id))

        with open("/var/log/xen/qemu-dm-vm-{vm_id}.log".format(vm_id=vm_id), "rb") as f:
            logging.error(f.read())

    subprocess.run(["xl", "qemu-monitor-command",
                    "vm-{vm_id}".format(vm_id=vm_id),
                    "device_del nic0"], check=True)

    for _ in range(120):
        output = subprocess.check_output(["xl", "qemu-monitor-command",
                                          "vm-{vm_id}".format(vm_id=vm_id),
                                          "info network"])

        if b"nic0" not in output:
            break

        time.sleep(0.25)
    else:
        raise RuntimeError("Failed to see nic0 deleted in vm-{vm_id}".format(vm_id=vm_id))

    vm_mac = print_mac(gen_mac(vm_id))
    subprocess.run(["xl", "qemu-monitor-command",
                    "vm-{vm_id}".format(vm_id=vm_id),
                    "device_add e1000,id=nic1,netdev=net0,mac={vm_mac}".format(vm_mac=vm_mac)], check=True)

    for _ in range(120):
        output = subprocess.check_output(["xl", "qemu-monitor-command",
                                          "vm-{vm_id}".format(vm_id=vm_id),
                                          "info network"])

        if b"nic1" in output:
            break

        time.sleep(0.25)
    else:
        raise RuntimeError("Failed to see nic1 created in vm-{vm_id}".format(vm_id=vm_id))

    subprocess.run(["xl", "qemu-monitor-command",
                    "vm-{vm_id}".format(vm_id=vm_id),
                    "change ide-5632 /tmp/drakrun/vm-{vm_id}/malwar.iso".format(vm_id=vm_id)], check=True)
