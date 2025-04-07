import click

from drakrun.lib.install_info import InstallInfo
from drakrun.lib.network_info import NetworkConfiguration
from drakrun.lib.paths import INSTALL_INFO_PATH, NETWORK_CONF_PATH
from drakrun.lib.vm import VirtualMachine


@click.command(help="Start VM from snapshot")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
def vm_start(vm_id: int):
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    network_conf = NetworkConfiguration.load(NETWORK_CONF_PATH)
    vm = VirtualMachine(vm_id, install_info, network_conf)
    vm.restore()
