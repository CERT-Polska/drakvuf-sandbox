import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH
from drakrun.lib.vm import VirtualMachine

from .check_root import check_root


@click.command(help="Start VM from snapshot")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
@check_root
def vm_start(vm_id: int):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(vm_id, install_info, config.network)
    vm.restore()
