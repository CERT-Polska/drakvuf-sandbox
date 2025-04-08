import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH
from drakrun.lib.vm import VirtualMachine


@click.command(help="Stop VM and cleanup network")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
def vm_stop(vm_id: int):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(vm_id, install_info, config.network)
    vm.destroy()
