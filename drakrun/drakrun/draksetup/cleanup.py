import logging
import os

import click

from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import (
    delete_all_vm_networks,
    delete_legacy_iptables,
    delete_vm_network,
    stop_dnsmasq,
)
from drakrun.lib.paths import VOLUME_DIR
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.util import safe_delete
from drakrun.lib.vm import VirtualMachine, delete_vm_conf, get_all_vm_conf

from .util.profile_builder import cleanup_profile_files
from .util.systemd import stop_all_drakruns

log = logging.getLogger(__name__)


@click.command(help="Cleanup the changes made by draksetup")
def cleanup():
    install_info = InstallInfo.try_load()

    if install_info is None:
        log.error("The cleanup has been performed")
        return

    stop_all_drakruns()

    backend = get_storage_backend(install_info)
    vm_ids = get_all_vm_conf()

    for vm_id in vm_ids:
        vm = VirtualMachine(backend, vm_id)
        vm.destroy()

        delete_vm_network(vm_id=vm_id)
        stop_dnsmasq(vm_id=vm_id)
        backend.delete_vm_volume(vm_id)
        delete_vm_conf(vm_id)

    delete_legacy_iptables()
    delete_all_vm_networks()

    safe_delete(os.path.join(VOLUME_DIR, "snapshot.sav"))
    cleanup_profile_files()

    InstallInfo.delete()
