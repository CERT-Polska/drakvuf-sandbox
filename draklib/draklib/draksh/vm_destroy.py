import logging

import click

from ..config import Configuration
from ..drakvuf.vm import DrakvufVM
from .util import check_root

log = logging.getLogger(__name__)


@click.command(help="Destroy VM after modification or maintenance")
@click.argument("vm_id", type=int)
@click.option(
    "--config-name",
    "config_name",
    default=Configuration.DEFAULT_NAME,
    type=str,
    show_default=True,
    help="Configuration name",
)
def vm_destroy(vm_id, config_name):
    if not check_root():
        return

    config = Configuration.load(config_name)
    vm = DrakvufVM(config, vm_id=vm_id)
    vm_name = vm.vm.vm_name
    if not vm.vm.is_running:
        raise click.ClickException(f"Machine {vm_name} is not running")
    vm.destroy()
    click.echo(f"Machine {vm_name} destroyed")
