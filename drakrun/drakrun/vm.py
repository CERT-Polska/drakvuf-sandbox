import os
import re
import logging
import subprocess
from pathlib import Path

from drakrun.storage import get_storage_backend, StorageBackendBase
from drakrun.config import (
    VM_CONFIG_DIR,
    VOLUME_DIR,
    ETC_DIR,
    LIB_DIR,
    InstallInfo
)

log = logging.getLogger("drakrun")

FIRST_CDROM_DRIVE = "hdc"
SECOND_CDROM_DRIVE = "hdd"


def generate_vm_conf(install_info: InstallInfo, vm_id: int):
    with open(os.path.join(ETC_DIR, 'scripts', 'cfg.template'), 'r') as f:
        template = f.read()

    storage_backend = get_storage_backend(install_info)

    disks = []
    disks.append(storage_backend.get_vm_disk_path(vm_id))

    install_iso_path = os.path.abspath(install_info.iso_path)
    disks.append(f'file:{install_iso_path},{FIRST_CDROM_DRIVE}:cdrom,r')

    if install_info.enable_unattended:
        unattended_iso_path = os.path.join(LIB_DIR, 'volumes', 'unattended.iso')
        disks.append(f'file:{unattended_iso_path},{SECOND_CDROM_DRIVE}:cdrom,r')

    disks = ', '.join(['"{}"'.format(disk) for disk in disks])

    template = template.replace('{{ VM_ID }}', str(vm_id))
    template = template.replace('{{ DISKS }}', disks)
    template = template.replace('{{ VNC_PORT }}', str(6400 + vm_id))

    if vm_id == 0:
        template = re.sub('on_reboot[ ]*=(.*)', 'on_reboot = "restart"', template)

    with open(os.path.join(ETC_DIR, 'configs', f'vm-{vm_id}.cfg'), 'w') as f:
        f.write("# Autogenerated, don't edit this file directly!\n")
        f.write("# Instead please edit /etc/drakrun/scripts/cfg.template\n")
        f.write("# and restart drakrun@<vm_id> service.\n\n")
        f.write(template)

    log.info("Generated VM configuration for vm-{vm_id}".format(vm_id=vm_id))


class VirtualMachine:
    def __init__(self, backend: StorageBackendBase, vm_id: int) -> None:
        self.backend = backend
        self.vm_id = vm_id

    @property
    def vm_name(self) -> str:
        return f"vm-{self.vm_id}"

    @property
    def is_running(self) -> bool:
        res = subprocess.run(
            ["xl", "list", self.vm_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0

    def restore(self):
        if self.is_running:
            self.destroy()
        cfg_path = Path(VM_CONFIG_DIR) / f"{self.vm_name}.cfg"
        snapshot_path = Path(VOLUME_DIR) / "snapshot.sav"
        self.backend.rollback_vm_storage(self.vm_id)
        subprocess.run(["xl", "restore", cfg_path, snapshot_path], check=True)

    def destroy(self):
        if self.is_running:
            subprocess.run(["xl", "destroy", self.vm_name], check=True)
