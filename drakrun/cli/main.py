import logging

import click

from .analyze import analyze
from .drakshell import drakshell
from .drakvuf_cmdline import drakvuf_cmdline
from .injector import injector
from .install import install
from .make_profile import make_profile
from .modify_vm0 import modify_vm0
from .mount import mount
from .postinstall import postinstall
from .postprocess import postprocess
from .s3_storage import s3_storage
from .snapshot import snapshot
from .vm_start import vm_start
from .vm_stop import vm_stop
from .worker import worker


@click.group()
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )
    logging.getLogger("drakrun").setLevel(logging.DEBUG)


main.add_command(analyze)
main.add_command(postprocess)
main.add_command(install)
main.add_command(postinstall)
main.add_command(vm_start)
main.add_command(vm_stop)
main.add_command(worker)
main.add_command(modify_vm0)
main.add_command(injector)
main.add_command(drakshell)
main.add_command(drakvuf_cmdline)
main.add_command(mount)
main.add_command(make_profile)
main.add_command(s3_storage)
main.add_command(snapshot)
