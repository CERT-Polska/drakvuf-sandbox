import click

from .check_root import check_root


@click.command(help="Start drakrun analysis worker")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for running analyses",
)
@check_root
def worker(vm_id: int):
    from drakrun.analyzer.worker import worker_main

    worker_main(vm_id)
