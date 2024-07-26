import hashlib
import logging
import os
import re
import subprocess
import tempfile

import click
from tqdm import tqdm

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import setup_vm_network, start_dnsmasq
from drakrun.lib.paths import VM_CONFIG_DIR, VOLUME_DIR
from drakrun.lib.storage import REGISTERED_BACKEND_NAMES, get_storage_backend
from drakrun.lib.vm import VirtualMachine, generate_vm_conf

from .util.sanity_check import sanity_check
from .util.systemd import stop_all_drakruns

log = logging.getLogger(__name__)


def ensure_zfs(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "zfs":
        raise click.BadParameter("This parameter is valid only with ZFS backend")
    return value


def ensure_lvm(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "lvm":
        raise click.BadParameter("This parameter is valid only with LVM backend")
    return value


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
    default=3072,
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
def install(
    vcpus,
    memory,
    storage_backend,
    disk_size,
    iso_path,
    zfs_tank_name,
    lvm_volume_group,
    unattended_xml,
):
    if storage_backend == "lvm" and lvm_volume_group is None:
        raise Exception("lvm storage backend requires --lvm-volume-group")
    if storage_backend == "zfs" and zfs_tank_name is None:
        raise Exception("zfs storage backend requires --zfs-tank-name")

    if vcpus < 1:
        log.error("Your VM must have at least 1 vCPU.")
        return

    if memory < 512:
        log.error("Your VM must have at least 512 MB RAM.")
        return

    if memory < 1536:
        log.warning(
            "Using less than 1.5 GB RAM per VM is not recommended for any supported system."
        )

    if unattended_xml:
        log.info("Baking unattended.iso for automated installation")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_xml_path = os.path.join(tmpdir, "autounattend.xml")

            with open(tmp_xml_path, "wb") as fw:
                with open(unattended_xml, "rb") as fr:
                    fw.write(fr.read())

            try:
                subprocess.check_output(
                    [
                        "genisoimage",
                        "-o",
                        os.path.join(VOLUME_DIR, "unattended.iso"),
                        "-J",
                        "-r",
                        tmp_xml_path,
                    ],
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError:
                log.exception("Failed to generate unattended.iso.")

    drakconfig = load_config()

    if not sanity_check():
        log.error("Sanity check failed.")
        return

    stop_all_drakruns()

    log.info("Performing installation...")

    sha256_hash = hashlib.sha256()

    log.info("Calculating hash of iso")
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
        iso_path=os.path.abspath(iso_path),
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
        enable_unattended=unattended_xml is not None,
        iso_sha256=iso_sha256,
    )
    install_info.save()

    backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(backend, 0)
    vm0.destroy()

    generate_vm_conf(install_info, 0)

    backend.initialize_vm0_volume(disk_size)

    try:
        subprocess.check_output("brctl show", shell=True)
    except subprocess.CalledProcessError:
        log.exception(
            "Failed to execute brctl show. Make sure you have bridge-utils installed."
        )
        return

    net_enable = drakconfig.drakrun.net_enable
    out_interface = drakconfig.drakrun.out_interface
    dns_server = drakconfig.drakrun.dns_server

    setup_vm_network(
        vm_id=0,
        net_enable=net_enable,
        out_interface=out_interface,
        dns_server=dns_server,
    )

    if net_enable:
        start_dnsmasq(vm_id=0, dns_server=dns_server, background=True)

    cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")

    vm0.create()

    log.info("-" * 80)
    log.info("Initial VM setup is complete and the vm-0 was launched.")
    log.info(
        "Please now VNC to the port 5900 on this machine to perform Windows installation."
    )
    log.info(
        "After you have installed Windows and booted it to the desktop, please execute:"
    )
    log.info("# draksetup postinstall")

    with open(cfg_path, "r") as f:
        data = f.read()
        m = re.search(r"vncpasswd[ ]*=(.*)", data)
        if m:
            passwd = m.group(1).strip()
            if passwd[0] == '"' and passwd[-1] == '"':
                passwd = passwd[1:-1]

            log.info("Your configured VNC password is:")
            log.info(passwd)

    log.info(
        "Please note that on some machines, system installer may boot for up to 10 minutes"
    )
    log.info("and may look unresponsive during the process. Please be patient.")
    log.info("-" * 80)
