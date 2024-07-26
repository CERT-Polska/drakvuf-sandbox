import logging
import os

import click

from .cleanup import cleanup
from .cleanup_network import cleanup_network
from .init import init
from .install import install
from .install_minio import install_minio
from .memdump import memdump
from .modify_vm0 import modify_vm0
from .mount import mount
from .postinstall import postinstall
from .scale import scale
from .snapshot import snapshot
from .test import test


@click.group()
def main():
    if os.geteuid() != 0:
        raise click.Abort("draksetup must be run as root")
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


main.add_command(test)
main.add_command(install)
main.add_command(postinstall)
main.add_command(mount)
main.add_command(scale)
main.add_command(snapshot)
main.add_command(memdump)
main.add_command(cleanup)
main.add_command(cleanup_network)
main.add_command(init)
main.add_command(install_minio)
main.add_command(modify_vm0)
