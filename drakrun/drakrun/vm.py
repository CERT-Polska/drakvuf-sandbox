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
from drakrun.util import safe_delete, try_run

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
    template = template.replace('{{ VCPUS }}', str(install_info.vcpus))
    template = template.replace('{{ MEMORY }}', str(install_info.memory))

    if vm_id == 0:
        template = re.sub('on_reboot[ ]*=(.*)', 'on_reboot = "restart"', template)

    with open(os.path.join(ETC_DIR, 'configs', f'vm-{vm_id}.cfg'), 'w') as f:
        f.write("# Autogenerated, don't edit this file directly!\n")
        f.write("# Instead please edit /etc/drakrun/scripts/cfg.template\n")
        f.write("# and restart drakrun@<vm_id> service.\n\n")
        f.write(template)

    log.info("Generated VM configuration for vm-{vm_id}".format(vm_id=vm_id))


def get_all_vm_conf() -> list:
    regex = re.compile(r'vm-(\d+)\.cfg')
    vm_ids = []

    for f in os.listdir(VM_CONFIG_DIR):
        reg = regex.search(f)

        if reg is not None:
            vm_ids.append(int(reg.group(1)))

    return vm_ids


def delete_vm_conf(vm_id: int) -> bool:
    return safe_delete(os.path.join(VM_CONFIG_DIR, f"vm-{vm_id}.cfg"))


class VirtualMachine:
    def __init__(self, backend: StorageBackendBase, vm_id: int, fmt: str = "vm-{}", cfg_path=None) -> None:
        self.backend = backend
        self.vm_id = vm_id
        self._format = fmt
        self._cfg_path = Path(VM_CONFIG_DIR) / f"{self.vm_name}.cfg" if cfg_path is None else cfg_path

    @property
    def vm_name(self) -> str:
        return self._format.format(self.vm_id)

    @property
    def is_running(self) -> bool:
        res = subprocess.run(
            ["xl", "list", self.vm_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0

    def create(self, pause=False, **kwargs):
        args = ['xl', 'create']
        if pause:
            args += ['-p']
        args += [self._cfg_path]
        logging.info(f"Creating VM {self.vm_name}")
        try_run(args, f"Failed to launch VM {self.vm_name}", **kwargs)

    def pause(self, **kwargs):
        logging.info(f"Pausing VM {self.vm_name}")
        try_run(['xl', 'pause', self.vm_name], f"Failed to pause VM {self.vm_name}", **kwargs)

    def unpause(self, **kwargs):
        logging.info(f"Unpausing VM {self.vm_name}")
        try_run(['xl', 'unpause', self.vm_name], f"Failed to unpause VM {self.vm_name}", **kwargs)

    def save(self, filename, pause=False, cont=False, **kwargs):
        logging.info(f"Saving VM {self.vm_name}")
        args = ['xl', 'save']

        # no such args will shutdown the VM after saving
        if pause is True:
            args += ['-p']
        elif cont is True:
            args += ['-c']

        if kwargs.get('stderr') is None:
            kwargs['stderr'] = kwargs['stdout'] = subprocess.STDOUT

        args += [self.vm_name, filename]

        try_run(args, f"Failed to save VM {self.vm_name}", **kwargs)

    def restore(
        self,
        snapshot_path=None,
        pause=False,
        **kwargs
    ) -> None:
        """ Restore virtual machine from snapshot.
        :raises: subprocess.CalledProcessError
        """
        # if the vm is running
        # shouldn't we raise exceptions? and then handle it?
        if self.is_running:
            self.destroy()

        args = ['xl', 'restore']

        if snapshot_path is None:
            snapshot_path = Path(VOLUME_DIR) / "snapshot.sav"

        if pause is True:
            args += ['-p']

        if kwargs.get('stderr') is None:
            kwargs['stderr'] = kwargs['stdout'] = subprocess.STDOUT

        # No need to rollback vm-0. Since the state of vm-0
        # is correct by definition.
        if self.vm_id != 0 and self.backend is not None and self.vm_id is not None:
            self.backend.rollback_vm_storage(self.vm_id)

        args += [self._cfg_path, snapshot_path]
        logging.info(f"Restoring VM {self.vm_name}")
        try_run(args, msg=f"Failed to restore VM {self.vm_name}", **kwargs)

    def destroy(self, **kwargs):
        """ Destroy a running virtual machine.
        :raises: subprocess.CalledProcessError
        """
        if self.is_running:
            logging.info(f"Destroying {self.vm_name}")
            try_run(["xl", "destroy", self.vm_name], f"Failed to destroy VM {self.vm_name}", **kwargs)
