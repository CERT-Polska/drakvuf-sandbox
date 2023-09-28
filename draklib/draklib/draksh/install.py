import hashlib
import logging
import os
import re
from pathlib import Path

import click
from tqdm import tqdm

from ..config import Configuration, InstallInfo, Parameters, get_default_subnet_addr
from ..machinery.networking import (
    check_networking_prerequisites,
    find_default_interface,
)
from ..machinery.storage import REGISTERED_BACKEND_NAMES
from ..machinery.vm import VirtualMachine
from .util import check_root


def ensure_zfs(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "zfs":
        raise click.BadParameter("This parameter is valid only with ZFS backend")
    return value


def ensure_lvm(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "lvm":
        raise click.BadParameter("This parameter is valid only with LVM backend")
    return value


@click.command(
    help="Create new configuration and install guest Virtual Machine",
    no_args_is_help=True,
)
@click.argument("iso_path", type=click.Path(exists=True))
@click.option(
    "--config-name",
    "config_name",
    default=Configuration.DEFAULT_NAME,
    type=str,
    show_default=True,
    help="Configuration name",
)
@click.option(
    "--vcpus",
    "vcpus",
    default=InstallInfo.vcpus,
    type=int,
    show_default=True,
    help="Number of vCPUs per single VM",
)
@click.option(
    "--memory",
    "memory",
    default=InstallInfo.memory,
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
    help="Storage backend",
    is_eager=True,
)
@click.option(
    "--disk-size", "disk_size", default="100G", show_default=True, help="Disk size"
)
@click.option(
    "--zfs-tank-name",
    "zfs_tank_name",
    callback=ensure_zfs,
    help="Tank name (only for ZFS storage backend)",
)
@click.option(
    "--lvm-volume-group",
    "lvm_volume_group",
    callback=ensure_lvm,
    help="Volume Group (only for lvm storage backend)",
)
@click.option(
    "--unattended-xml",
    "unattended_xml",
    type=click.Path(exists=True),
    help="Path to autounattend.xml for automated Windows install",
)
@click.option(
    "--subnet-addr",
    "subnet_addr",
    default=lambda: get_default_subnet_addr(),
    help="Subnet address for VM bridge with N as vm id",
)
@click.option(
    "--out-interface",
    "out_interface",
    default=lambda: find_default_interface(),
    help="Default interface for VM networking",
)
@click.option(
    "--dns-server",
    "dns_server",
    default=Parameters.dns_server,
    help="DNS server for VM networking (or 'use-default-gateway' "
    "if you want to use default gateway of VM network as DNS)",
)
@click.option(
    "--disable-net",
    "disable_net",
    is_flag=True,
    default=False,
    help="Disable network for installation",
)
def install(
    config_name,
    vcpus,
    memory,
    storage_backend,
    disk_size,
    iso_path,
    zfs_tank_name,
    lvm_volume_group,
    unattended_xml,
    subnet_addr,
    out_interface,
    dns_server,
    disable_net,
):
    if not check_root():
        return

    if storage_backend == "lvm" and lvm_volume_group is None:
        raise click.ClickException("lvm storage backend requires --lvm-volume-group")
    if storage_backend == "zfs" and zfs_tank_name is None:
        raise click.ClickException("zfs storage backend requires --zfs-tank-name")

    # TODO
    # if not sanity_check():
    #    logging.error("Sanity check failed.")
    #    return

    if vcpus < 1:
        raise click.ClickException("Your VM must have at least 1 vCPU.")

    if memory < 512:
        raise click.ClickException("Your VM must have at least 512 MB RAM.")

    if memory < 1536:
        logging.warning(
            "Using less than 1.5 GB RAM per VM is not recommended "
            "for any supported system."
        )

    if unattended_xml:
        logging.info("Baking unattended.iso for automated installation")

    try:
        check_networking_prerequisites()
    except RuntimeError as e:
        raise click.ClickException(str(e))

    logging.info("Performing installation...")

    sha256_hash = hashlib.sha256()

    logging.info("Calculating hash of iso")
    iso_path = Path(iso_path).resolve()
    iso_file_size = os.stat(iso_path).st_size
    block_size = 128 * 1024
    with tqdm(total=iso_file_size, unit_scale=True) as pbar:
        with open(iso_path, "rb") as f:
            for byte_block in iter(lambda: f.read(block_size), b""):
                pbar.update(block_size)
                sha256_hash.update(byte_block)

            iso_sha256 = sha256_hash.hexdigest()

    install_info = InstallInfo(
        vcpus=vcpus,
        memory=memory,
        storage_backend=storage_backend,
        disk_size=disk_size,
        iso_path=str(iso_path),
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
        enable_unattended=unattended_xml is not None,
        iso_sha256=iso_sha256,
    )
    parameters = Parameters(
        subnet_addr=subnet_addr,
        out_interface=out_interface,
        dns_server=dns_server,
    )
    if Configuration.exists(config_name):
        click.confirm(
            f"'{config_name}' already exists. Do you want to overwrite it?", abort=True
        )
        Configuration.delete(config_name)
    config = Configuration.create(config_name, parameters, install_info)

    vm0 = VirtualMachine(config, 0)
    if vm0.is_running:
        vm0.destroy()

    vm0.storage.initialize_vm0_volume(disk_size)
    vm0.setup_network(out_interface, dns_server, net_enable=not disable_net)
    vm0.create(first_cd=iso_path)

    logging.info("-" * 80)
    logging.info("Initial VM setup is complete and the vm-0 was launched.")
    logging.info(
        "Please now VNC to the port 5900 on this machine "
        "to perform Windows installation."
    )
    logging.info(
        "After you have installed Windows and booted it "
        "to the desktop, please execute:"
    )
    logging.info("# draksh postinstall")

    data = vm0.vm_config_path.read_text()
    m = re.search(r"vncpasswd[ ]*=(.*)", data)
    if m:
        passwd = m.group(1).strip()
        if passwd[0] == '"' and passwd[-1] == '"':
            passwd = passwd[1:-1]

        logging.info("Your configured VNC password is:")
        logging.info(passwd)

    logging.info(
        "Please note that on some machines, system installer "
        "may boot for up to 10 minutes"
    )
    logging.info("and may look unresponsive during the process. Please be patient.")
    logging.info("-" * 80)
