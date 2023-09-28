import logging

import click

from ..config import Configuration
from ..drakvuf.vm import DrakvufVM
from .util import check_root

log = logging.getLogger(__name__)


@click.command(help="Restore VM for modification or maintenance")
@click.argument("vm_id", type=int)
@click.option(
    "--config-name",
    "config_name",
    default=Configuration.DEFAULT_NAME,
    type=str,
    show_default=True,
    help="Configuration name",
)
@click.option(
    "--disable-net",
    "disable_net",
    is_flag=True,
    default=False,
    help="Disable network",
)
def vm_restore(vm_id, config_name, disable_net):
    if not check_root():
        return

    config = Configuration.load(config_name)
    vm = DrakvufVM(config, vm_id=vm_id)
    vm_name = vm.vm.vm_name
    if vm.vm.is_running:
        raise click.ClickException(f"Machine {vm_name} is already running")
    vm.restore(net_enable=not disable_net)
    click.echo(f"Machine {vm_name} restored")
