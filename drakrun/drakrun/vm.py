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
from drakrun.util import safe_delete
from multiprocessing import Process
from tqdm import tqdm
import time

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
    config_dir = os.path.join(ETC_DIR, 'configs')
    vm_ids = []

    for f in os.listdir(config_dir):
        reg = regex.search(f)

        if reg is not None:
            vm_ids.append(int(reg.group(1)))

    return vm_ids


def delete_vm_conf(vm_id: int) -> bool:
    config_dir = os.path.join(ETC_DIR, 'configs')
    return safe_delete(os.path.join(config_dir, f"vm-{vm_id}.cfg"))


def get_restore_percentage(vm_id: int) -> bool:
    install_info = InstallInfo.try_load()
    if install_info is None:
        return
    time.sleep(3)
    cur_mem = 0
    safe_zero_count = 0
    with tqdm(total=install_info.memory) as pbar:
        while cur_mem != install_info.memory:
            try:
                proc = subprocess.run(f"xl list vm-{vm_id} | tail -n 1 | tr -s ' ' | cut -f 3 -d ' '", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                break

            try:
                cur_mem = int(proc.stdout.decode())
                if safe_zero_count == 10:
                    break
                if cur_mem == pbar.n:
                    safe_zero_count += 1
                else:
                    pbar.update(cur_mem - pbar.n)
                    if cur_mem == install_info.memory:
                        break
            except ValueError:
                pass
            time.sleep(1)


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

    def restore(self) -> None:
        """ Restore virtual machine from snapshot.
        :raises: subprocess.CalledProcessError
        """
        if self.is_running:
            self.destroy()
        cfg_path = Path(VM_CONFIG_DIR) / f"{self.vm_name}.cfg"
        snapshot_path = Path(VOLUME_DIR) / "snapshot.sav"

        # No need to rollback vm-0. Since the state of vm-0
        # is correct by definition.
        if self.vm_id != 0:
            self.backend.rollback_vm_storage(self.vm_id)
        else:
            if not os.path.exists(os.path.join(VOLUME_DIR, "vm-0.img")):
                self.backend.initialize_vm0_volume(InstallInfo.try_load().disk_size)

        p = Process(target=get_restore_percentage, args=(self.vm_id,))
        p.start()
        subprocess.run(["xl", "restore", cfg_path, snapshot_path], check=True)

    def destroy(self):
        """ Destroy a running virtual machine.
        :raises: subprocess.CalledProcessError
        """
        if self.is_running:
            logging.info(f"Destroying {self.vm_name}")
            subprocess.run(["xl", "destroy", self.vm_name], check=True)
