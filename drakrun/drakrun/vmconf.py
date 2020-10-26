import os
import re
import logging

from drakrun.storage import get_storage_backend
from drakrun.config import ETC_DIR, LIB_DIR, InstallInfo


def generate_vm_conf(install_info: InstallInfo, vm_id: int):
    with open(os.path.join(ETC_DIR, 'scripts/cfg.template'), 'r') as f:
        template = f.read()

    storage_backend = get_storage_backend(install_info)

    disks = []
    disks.append(storage_backend.get_vm_disk_path(vm_id))

    disks.append('file:{iso},hdc:cdrom,r'.format(iso=os.path.abspath(install_info.iso_path)))

    if install_info.enable_unattended:
        disks.append('file:{main_dir}/volumes/unattended.iso,hdd:cdrom,r'.format(main_dir=LIB_DIR))

    disks = ', '.join(['"{}"'.format(disk) for disk in disks])

    template = template.replace('{{ VM_ID }}', str(vm_id))
    template = template.replace('{{ DISKS }}', disks)
    template = template.replace('{{ VNC_PORT }}', str(6400 + vm_id))

    if vm_id == 0:
        template = re.sub('on_reboot[ ]*=(.*)', 'on_reboot = "restart"', template)

    with open(os.path.join(ETC_DIR, 'configs/vm-{}.cfg'.format(vm_id)), 'w') as f:
        f.write("# Autogenerated, don't edit this file directly!\n")
        f.write("# Instead please edit /etc/drakrun/scripts/cfg.template\n")
        f.write("# and restart drakrun@<vm_id> service.\n\n")
        f.write(template)

    logging.info("Generated VM configuration for vm-{vm_id}".format(vm_id=vm_id))