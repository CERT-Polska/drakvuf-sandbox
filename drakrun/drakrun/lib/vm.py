import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import ETC_DIR, LIB_DIR, VM_CONFIG_DIR, VOLUME_DIR
from drakrun.lib.storage import StorageBackendBase, get_storage_backend
from drakrun.lib.util import safe_delete

from .bindings.xen import (
    xen_create_vm,
    xen_destroy_vm,
    xen_get_domid,
    xen_is_vm_running,
    xen_restore_vm,
    xen_save_vm,
    xen_unpause_vm,
)

log = logging.getLogger(__name__)

FIRST_CDROM_DRIVE = "hdc"
SECOND_CDROM_DRIVE = "hdd"


def generate_vm_conf(
    install_info: InstallInfo,
    vm_id: int,
    disks: Optional[List[str]] = None,
):
    with open(os.path.join(ETC_DIR, "scripts", "cfg.template"), "r") as f:
        template = f.read()

    storage_backend = get_storage_backend(install_info)

    if disks is None:
        disks = [storage_backend.get_vm_disk_path(vm_id)]

        install_iso_path = os.path.abspath(install_info.iso_path)
        disks.append(f"file:{install_iso_path},{FIRST_CDROM_DRIVE}:cdrom,r")

        if install_info.enable_unattended:
            unattended_iso_path = os.path.join(LIB_DIR, "volumes", "unattended.iso")
            disks.append(f"file:{unattended_iso_path},{SECOND_CDROM_DRIVE}:cdrom,r")

    disks = ", ".join(['"{}"'.format(disk) for disk in disks])

    template = template.replace("{{ VM_ID }}", str(vm_id))
    template = template.replace("{{ DISKS }}", disks)
    template = template.replace("{{ VNC_PORT }}", str(6400 + vm_id))
    template = template.replace("{{ VCPUS }}", str(install_info.vcpus))
    template = template.replace("{{ MEMORY }}", str(install_info.memory))

    if vm_id == 0:
        template = re.sub("on_reboot[ ]*=(.*)", 'on_reboot = "restart"', template)

    target_path = os.path.join(ETC_DIR, "configs", f"vm-{vm_id}.cfg")
    with open(target_path, "w") as f:
        f.write("# Autogenerated, don't edit this file directly!\n")
        f.write("# Instead please edit /etc/drakrun/scripts/cfg.template\n")
        f.write("# and restart drakrun@<vm_id> service.\n\n")
        f.write(template)

    log.info("Generated VM configuration for vm-{vm_id}".format(vm_id=vm_id))


def get_all_vm_conf() -> list:
    regex = re.compile(r"vm-(\d+)\.cfg")
    vm_ids = []

    for f in os.listdir(VM_CONFIG_DIR):
        reg = regex.search(f)

        if reg is not None:
            vm_ids.append(int(reg.group(1)))

    return vm_ids


def delete_vm_conf(vm_id: int) -> bool:
    return safe_delete(os.path.join(VM_CONFIG_DIR, f"vm-{vm_id}.cfg"))


class VirtualMachine:
    def __init__(
        self, backend: StorageBackendBase, vm_id: int, fmt: str = "vm-{}", cfg_path=None
    ) -> None:
        self.backend = backend
        self.vm_id = vm_id
        self._format = fmt
        self._cfg_path = cfg_path or Path(VM_CONFIG_DIR) / f"{self.vm_name}.cfg"

    @property
    def vm_name(self) -> str:
        return self._format.format(self.vm_id)

    @property
    def is_running(self) -> bool:
        return xen_is_vm_running(self.vm_name)

    def get_domid(self) -> int:
        return xen_get_domid(self.vm_name)

    def create(self, pause: bool = False, timeout: Optional[float] = None) -> None:
        log.info(f"Creating VM {self.vm_name}")
        xen_create_vm(self.vm_name, self._cfg_path, pause=pause, timeout=timeout)

    def unpause(self, timeout: Optional[float] = None) -> None:
        log.info(f"Unpausing VM {self.vm_name}")
        xen_unpause_vm(self.vm_name, timeout=timeout)

    def save(self, snapshot_path: str, pause: bool = False) -> None:
        log.info(f"Saving VM {self.vm_name}")
        xen_save_vm(self.vm_name, snapshot_path, pause=pause)

    def restore(self, snapshot_path: str = None, pause: bool = False) -> None:
        if snapshot_path is None:
            snapshot_path = Path(VOLUME_DIR) / "snapshot.sav"
        # Ensure VM is destroyed
        self.destroy()
        # No need to rollback vm-0. Since the state of vm-0
        # is correct by definition.
        if self.vm_id != 0 and self.backend is not None and self.vm_id is not None:
            self.backend.rollback_vm_storage(self.vm_id)

        log.info(f"Restoring VM {self.vm_name}")
        xen_restore_vm(self.vm_name, self._cfg_path, snapshot_path, pause=pause)

    def destroy(self) -> None:
        if self.is_running:
            log.info(f"Destroying {self.vm_name}")
            xen_destroy_vm(self.vm_name)

    def memory_dump(self, compressed_filepath):
        """Dump raw memory from running vm using vmi-dump-memory and compress it with gzip
        :raises: subprocess.CalledProcessError
        """

        with tempfile.NamedTemporaryFile() as raw_memdump, open(
            compressed_filepath, "wb"
        ) as compressed_file:

            log.info(f"Dumping raw memory from {self.vm_name} guest...")
            try:
                subprocess.run(
                    ["vmi-dump-memory", self.vm_name, raw_memdump.name], check=True
                )
            except subprocess.CalledProcessError as e:
                log.error(f"Dumping raw memory from {self.vm_name} failed.")
                raise e

            log.info(f"Compressing {self.vm_name} guest memory dump...")
            try:
                subprocess.run(
                    ["gzip", "-c", raw_memdump.name], check=True, stdout=compressed_file
                )
            except subprocess.CalledProcessError as e:
                log.error(f"Compressing raw memory from {self.vm_name} failed.")
                raise e
