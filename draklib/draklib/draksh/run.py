import logging

import click

from ..config import Configuration
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
def run(vm_id, sample_path, out_dir, config_name):
    if not check_root():
        return
