import logging
import os

import click

from .cleanup import cleanup
from .install import install
from .memdump import memdump
from .mount import mount
from .postinstall import postinstall
from .postupgrade import postupgrade
from .scale import scale
from .snapshot import snapshot
from .test import test


@click.group()
def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )
    if os.geteuid() != 0:
        logging.warning("Not running as root, draksetup may work improperly!")


main.add_command(test)
main.add_command(install)
main.add_command(postinstall)
main.add_command(postupgrade)
main.add_command(mount)
main.add_command(scale)
main.add_command(snapshot)
main.add_command(memdump)
main.add_command(cleanup)


if __name__ == "__main__":
    main()
