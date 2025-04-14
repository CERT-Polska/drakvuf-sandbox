import click

from drakrun.analyzer.worker import worker_main


@click.command(help="Start drakrun analysis worker")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for running analyses",
)
def worker(vm_id: int):
    worker_main(vm_id)
