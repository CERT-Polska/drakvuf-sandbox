import logging

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.vmi_profile import create_vmi_info, create_vmi_json_profile

log = logging.getLogger(__name__)


@click.command(help="Finalize VM installation")
def postinstall():
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm0 = VirtualMachine(0, install_info, config.network)

    if vm0.is_running is False:
        log.error("vm-0 is not running")
        raise click.Abort()

    vm0.eject_cd()
    vmi_info = create_vmi_info(vm0)
    vm0.save()
    vm0.storage.snapshot_vm0_volume()

    vm1 = VirtualMachine(1, install_info, config.network)
    vm1.restore()
    try:
        create_vmi_json_profile(vm1, vmi_info)
    finally:
        vm1.destroy()
    log.info("All right, VM setup is done.")
