import logging

import click

from ..machinery.storage import REGISTERED_BACKEND_NAMES
from .util import check_root


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
    "--profile-name",
    "profile_name",
    default="default",
    type=str,
    show_default=True,
    help="Profile name",
)
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
    if not check_root():
        return

    if storage_backend == "lvm" and lvm_volume_group is None:
        raise Exception("lvm storage backend requires --lvm-volume-group")
    if storage_backend == "zfs" and zfs_tank_name is None:
        raise Exception("zfs storage backend requires --zfs-tank-name")

    # TODO
    # if not sanity_check():
    #    logging.error("Sanity check failed.")
    #    return

    # TODO
    # stop_all_drakruns()

    logging.info("Performing installation...")

    if vcpus < 1:
        logging.error("Your VM must have at least 1 vCPU.")
        return

    if memory < 512:
        logging.error("Your VM must have at least 512 MB RAM.")
        return

    if memory < 1536:
        logging.warning(
            "Using less than 1.5 GB RAM per VM is not recommended for any supported system."
        )

    if unattended_xml:
        logging.info("Baking unattended.iso for automated installation")

    sha256_hash = hashlib.sha256()

    logging.info("Calculating hash of iso")
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
        logging.exception(
            "Failed to execute brctl show. Make sure you have bridge-utils installed."
        )
        return

    net_enable = conf["drakrun"].getboolean("net_enable", fallback=False)
    out_interface = conf["drakrun"].get("out_interface", "")
    dns_server = conf["drakrun"].get("dns_server", "")

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

    logging.info("-" * 80)
    logging.info("Initial VM setup is complete and the vm-0 was launched.")
    logging.info(
        "Please now VNC to the port 5900 on this machine to perform Windows installation."
    )
    logging.info(
        "After you have installed Windows and booted it to the desktop, please execute:"
    )
    logging.info("# draksetup postinstall")

    with open(cfg_path, "r") as f:
        data = f.read()
        m = re.search(r"vncpasswd[ ]*=(.*)", data)
        if m:
            passwd = m.group(1).strip()
            if passwd[0] == '"' and passwd[-1] == '"':
                passwd = passwd[1:-1]

            logging.info("Your configured VNC password is:")
            logging.info(passwd)

    logging.info(
        "Please note that on some machines, system installer may boot for up to 10 minutes"
    )
    logging.info("and may look unresponsive during the process. Please be patient.")
    logging.info("-" * 80)
