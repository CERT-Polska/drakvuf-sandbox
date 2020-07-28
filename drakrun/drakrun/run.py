#!/usr/bin/python3

import logging
import os
import subprocess
import time
import json

from drakrun.storage import get_storage_backend
from drakrun.config import ETC_DIR, LIB_DIR, InstallInfo


def run_vm(vm_id):
    install_info = InstallInfo.load()

    try:
        subprocess.check_output(["xl", "destroy", "vm-{vm_id}".format(vm_id=vm_id)], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        pass

    try:
        os.unlink(os.path.join(LIB_DIR, "volumes/vm-{vm_id}.img".format(vm_id=vm_id)))
    except FileNotFoundError:
        pass

    storage_backend = get_storage_backend(install_info)
    storage_backend.rollback_vm_storage(vm_id)

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
                    "change ide-5632 /tmp/drakrun/vm-{vm_id}/malwar.iso".format(vm_id=vm_id)], check=True)
