import logging
import os
import subprocess

import click

from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import VOLUME_DIR
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.vm import FIRST_CDROM_DRIVE, SECOND_CDROM_DRIVE, VirtualMachine

from .util.profile_builder import cleanup_profile_files, create_vm_profiles

log = logging.getLogger(__name__)


def eject_cd(domain, drive):
    subprocess.run(["xl", "cd-eject", domain, drive], check=True)


@click.command(help="Finalize sandbox installation")
@click.option(
    "--apivectors/--no-apivectors",
    "generate_apivectors_profile",
    default=True,
    show_default=True,
    help="Generate extra usermode profile for apivectors",
)
def postinstall(generate_apivectors_profile):
    install_info = InstallInfo.load()
    storage_backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(storage_backend, 0)

    if vm0.is_running is False:
        log.exception("vm-0 is not running")
        return

    log.info("Cleaning up leftovers(if any)")
    cleanup_profile_files()

    log.info("Ejecting installation CDs")
    eject_cd("vm-0", FIRST_CDROM_DRIVE)
    if install_info.enable_unattended:
        # If unattended install is enabled, we have an additional CD-ROM drive
        eject_cd("vm-0", SECOND_CDROM_DRIVE)

    log.info("Saving VM snapshot...")

    # Create vm-0 snapshot, and destroy it
    # WARNING: qcow2 snapshot method is a noop. fresh images are created on the fly
    # so we can't keep the vm-0 running
    vm0.save(os.path.join(VOLUME_DIR, "snapshot.sav"))
    log.info("Snapshot was saved succesfully.")

    # Memory state is frozen, we can't do any writes to persistent storage
    log.info("Snapshotting persistent memory...")
    storage_backend.snapshot_vm0_volume()

    create_vm_profiles(generate_apivectors_profile)

    log.info("All right, drakrun setup is done.")
    log.info("If you want to enable drakrun worker, execute:")
    log.info("  # draksetup scale 1")
    log.info("or provide a higher number if you want to have more parallel VMs")
