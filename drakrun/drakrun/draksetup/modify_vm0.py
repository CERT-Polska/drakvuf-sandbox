import logging
import os
import pathlib
import re
import shutil

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import setup_vm_network, start_dnsmasq, stop_dnsmasq
from drakrun.lib.paths import VM_CONFIG_DIR, VOLUME_DIR
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.vm import VirtualMachine, generate_vm_conf

from .util.profile_builder import create_vm_profiles

log = logging.getLogger(__name__)


@click.group(name="modify-vm0", help="Modify base VM snapshot (vm-0)")
def modify_vm0():
    pass


@modify_vm0.command(name="begin", help="Safely restore vm-0 for modification")
def begin_modify_vm0():
    drakconfig = load_config()
    install_info = InstallInfo.load()
    backend = get_storage_backend(install_info)

    log.info("Creating vm-0 storage snapshot...")
    backend.initialize_vm0_modify_storage()

    log.info("Setting up vm-0...")
    generate_vm_conf(install_info, 0, disks=[backend.get_vm0_modify_disk_path()])
    vm0 = VirtualMachine(backend, 0)

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

    vm0.restore()

    log.info("-" * 80)
    log.info("Initial VM setup is complete and the vm-0 was launched.")
    log.info("Please now VNC to the port 5900 on this machine to perform modification.")
    log.info("After you have applied your changes, please execute:")
    log.info(
        "- 'draksetup modify-vm0 commit' to apply your modification to the base image"
    )
    log.info("- 'draksetup modify-vm0 rollback' to rollback your changes")

    cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")
    with open(cfg_path, "r") as f:
        data = f.read()
        m = re.search(r"vncpasswd[ ]*=(.*)", data)
        if m:
            passwd = m.group(1).strip()
            if passwd[0] == '"' and passwd[-1] == '"':
                passwd = passwd[1:-1]

            log.info("Your configured VNC password is:")
            log.info(passwd)

    log.info("-" * 80)


@modify_vm0.command(name="commit", help="Commit changes made during vm-0 modification")
@click.option(
    "--apivectors/--no-apivectors",
    "generate_apivectors_profile",
    default=True,
    show_default=True,
    help="Generate extra usermode profile for apivectors",
)
def commit_modify_vm0(generate_apivectors_profile):
    install_info = InstallInfo.load()
    backend = get_storage_backend(install_info)

    log.info("Saving VM snapshot...")

    vm0 = VirtualMachine(backend, 0)

    # Create vm-0 snapshot, and destroy it
    temporary_snapshot_path = pathlib.Path("/tmp/snapshot.sav")
    target_snapshot_path = pathlib.Path(VOLUME_DIR) / "snapshot.sav"
    try:
        vm0.save(temporary_snapshot_path.as_posix())
        log.info("Snapshot was saved succesfully.")

        # Memory state is frozen, we can't do any writes to persistent storage
        log.info("Committing persistent memory...")
        backend.commit_vm0_modify_storage()
        shutil.move(temporary_snapshot_path, target_snapshot_path)
    finally:
        temporary_snapshot_path.unlink(missing_ok=True)

    log.info("Ensuring dnsmasq is stopped...")
    stop_dnsmasq(vm_id=0)
    create_vm_profiles(generate_apivectors_profile)


@modify_vm0.command(
    name="rollback", help="Rollback changes made during vm-0 modification"
)
def rollback_modify_vm0():
    install_info = InstallInfo.load()
    backend = get_storage_backend(install_info)
    vm0 = VirtualMachine(backend, 0)
    vm0.destroy()

    log.info("Destroying vm-0 temporary snapshots...")
    backend.delete_vm0_modify_storage()

    log.info("Ensuring dnsmasq is stopped...")
    stop_dnsmasq(0)
