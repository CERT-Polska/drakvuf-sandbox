import logging
import os

import click

from drakrun.config import InstallInfo
from drakrun.machinery.networking import delete_vm_network, stop_dnsmasq
from drakrun.machinery.service import stop_all_drakruns
from drakrun.machinery.storage import get_storage_backend
from drakrun.machinery.vm import VirtualMachine, delete_vm_conf, get_all_vm_conf
from drakrun.paths import APISCOUT_PROFILE_DIR, PROFILE_DIR, VOLUME_DIR
from drakrun.util import safe_delete

from ._config import config
from ._util import check_root


def cleanup_postinstall_files():
    for profile in os.listdir(PROFILE_DIR):
        safe_delete(os.path.join(PROFILE_DIR, profile))
    for profile_file in os.listdir(APISCOUT_PROFILE_DIR):
        safe_delete(os.path.join(APISCOUT_PROFILE_DIR, profile_file))


@click.command(help="Cleanup the changes made by draksetup")
def cleanup():
    if not check_root():
        return

    install_info = InstallInfo.try_load()

    if install_info is None:
        logging.error("The cleanup has been performed")
        return

    stop_all_drakruns()

    backend = get_storage_backend(install_info)
    vm_ids = get_all_vm_conf()

    net_enable = int(config["drakrun"].get("net_enable", "0"))
    out_interface = config["drakrun"].get("out_interface", "")
    dns_server = config["drakrun"].get("dns_server", "")

    for vm_id in vm_ids:
        vm = VirtualMachine(backend, vm_id)
        vm.destroy()

        delete_vm_network(
            vm_id=vm_id,
            net_enable=net_enable,
            out_interface=out_interface,
            dns_server=dns_server,
        )
        if net_enable:
            stop_dnsmasq(vm_id=vm_id)

        backend.delete_vm_volume(vm_id)

        delete_vm_conf(vm_id)

    safe_delete(os.path.join(VOLUME_DIR, "snapshot.sav"))
    cleanup_postinstall_files()

    InstallInfo.delete()
