import logging

import click

from ..config import Configuration
from ..drakvuf.vm import DrakvufVM
from .util import check_root

log = logging.getLogger(__name__)


@click.command(help="Run sample in Drakvuf environment")
@click.argument("vm_id", type=int)
@click.argument("sample_path", type=click.Path(exists=True))
@click.argument("out_dir", type=click.Path(file_okay=False))
@click.option(
    "--config-name",
    "config_name",
    default=Configuration.DEFAULT_NAME,
    type=str,
    show_default=True,
    help="Configuration name",
)
@click.option(
    "--timeout",
    "timeout",
    default=60,
    type=int,
    show_default=True,
    help="Analysis timeout",
)
@click.option(
    "--disable-net",
    "disable_net",
    is_flag=True,
    default=False,
    help="Disable network for installation",
)
def run(vm_id, sample_path, out_dir, config_name, timeout, disable_net):
    if not check_root():
        return

    config = Configuration.load(config_name)
    vm = DrakvufVM(config, vm_id)
    vm.restore(net_enable=not disable_net)
    try:
        log.info("Running guest preparation script...")
        vm.run_prepare_script()
    finally:
        vm.destroy()
