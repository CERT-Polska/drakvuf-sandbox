import logging
import os.path
import secrets
import string

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, initialize_config_files, make_dirs
from drakrun.lib.storage import REGISTERED_BACKEND_NAMES, get_storage_backend
from drakrun.lib.vm import VirtualMachine

from .sanity_check import sanity_check

log = logging.getLogger(__name__)


@click.command(help="Install guest Virtual Machine", no_args_is_help=True)
@click.argument("iso_path", type=click.Path(exists=True))
@click.option(
    "--vcpus",
    "vcpus",
    default=2,
    type=int,
    show_default=True,
    help="Number of vCPUs per single VM",
)
@click.option(
    "--memory",
    "memory",
    default=4096,
    type=int,
    show_default=True,
    help="Memory per single VM (in MB)",
)
@click.option(
    "--storage-backend",
    "storage_backend",
    type=click.Choice(REGISTERED_BACKEND_NAMES, case_sensitive=False),
    default="qcow2",
    show_default=True,
    help="Storage backend type",
    is_eager=True,
)
@click.option(
    "--disk-size", "disk_size", default="100G", show_default=True, help="Disk size"
)
@click.option(
    "--zfs-tank-name",
    "zfs_tank_name",
    help="Tank name (only for ZFS storage backend)",
)
@click.option(
    "--lvm-volume-group",
    "lvm_volume_group",
    help="Volume group (only for lvm storage backend)",
)
def install(
    vcpus,
    memory,
    storage_backend,
    disk_size,
    iso_path,
    zfs_tank_name,
    lvm_volume_group,
):
    if storage_backend == "lvm" and lvm_volume_group is None:
        logging.error("lvm storage backend requires --lvm-volume-group")
        raise click.Abort()
    if storage_backend == "zfs" and zfs_tank_name is None:
        logging.error("zfs storage backend requires --zfs-tank-name")
        raise click.Abort()

    sanity_check()
    make_dirs()
    initialize_config_files()

    config = load_config()

    log.info("Performing installation...")
    passwd_characters = string.ascii_letters + string.digits
    vnc_passwd = "".join(secrets.choice(passwd_characters) for _ in range(20))
    install_info = InstallInfo(
        vcpus=vcpus,
        memory=memory,
        storage_backend=storage_backend,
        disk_size=disk_size,
        vnc_passwd=vnc_passwd,
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
    )
    install_info.save(INSTALL_INFO_PATH)

    backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(
        vm_id=0, install_info=install_info, network_conf=config.network
    )
    # Ensure VM0 is destroyed
    vm0.destroy()

    backend.initialize_vm0_volume(disk_size)

    iso_path = os.path.abspath(iso_path)
    vm0.create(iso_path=iso_path)

    log.info("-" * 80)
    log.info("Initial VM setup is complete and the vm-0 was launched.")
    log.info(
        "Please now VNC to the port 5900 on this machine to perform Windows installation."
    )
    log.info(
        "After you have installed Windows and booted it to the desktop, please execute:"
    )
    log.info("# draksetup postinstall")

    log.info("Your configured VNC password is:")
    log.info(vnc_passwd)

    log.info(
        "Please note that on some machines, system installer may boot for up to 10 minutes"
    )
    log.info("and may look unresponsive during the process. Please be patient.")
    log.info("-" * 80)
