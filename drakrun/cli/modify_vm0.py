import logging
import pathlib
import shutil
import tempfile

import click

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH
from drakrun.lib.vm import VirtualMachine
from drakrun.lib.vmi_profile import create_vmi_info, create_vmi_json_profile

from .banner import banner
from .check_root import check_root

log = logging.getLogger(__name__)


@click.group(name="modify-vm0", help="Modify base VM snapshot (vm-0)")
@check_root
def modify_vm0():
    pass


@modify_vm0.command(name="begin", help="Safely restore vm-0 for modification")
@click.option(
    "--cold-boot",
    "cold_boot",
    is_flag=True,
    default=False,
    help="Cold-boot vm-0 instead of restoring from snapshot",
)
def begin_modify_vm0(cold_boot):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)

    vm0 = VirtualMachine(0, install_info, config.network)

    # Internally, it's expected that VM-0 will be restored from vm-modify snapshot
    vm0.restore(cold_boot=cold_boot)
    banner(f"""
        Initial VM setup is complete and the vm-0 was launched.
        Please now VNC to the port 5900 on this machine to perform Windows installation.
        After you have installed Windows and booted it to the desktop, please execute:
        - 'draksetup modify-vm0 commit' to apply your modification to the base image
        - 'draksetup modify-vm0 rollback' to rollback your changes
        Your configured VNC password is:
        {install_info.vnc_passwd}
    """)


@modify_vm0.command(name="commit", help="Commit changes made during vm-0 modification")
def commit_modify_vm0():
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)

    vm0 = VirtualMachine(0, install_info, config.network)
    tmp_path = pathlib.Path(tempfile.gettempdir())
    temporary_snapshot_path = tmp_path / "snapshot.sav"
    target_snapshot_path = pathlib.Path(install_info.snapshot_dir) / "snapshot.sav"
    try:
        vmi_info = create_vmi_info(vm0)
        vm0.save(temporary_snapshot_path.as_posix())
        log.info("Snapshot was saved succesfully.")

        # Memory state is frozen, we can't do any writes to persistent storage
        log.info("Committing persistent memory...")
        vm0.storage.commit_vm0_modify_storage()
        shutil.move(temporary_snapshot_path, target_snapshot_path)
    finally:
        temporary_snapshot_path.unlink(missing_ok=True)

    vm = VirtualMachine(1, install_info, config.network)
    vm.restore()
    try:
        create_vmi_json_profile(vm, vmi_info)
    finally:
        vm.destroy()
    log.info("Profile successfully created")


@modify_vm0.command(
    name="rollback", help="Rollback changes made during vm-0 modification"
)
def rollback_modify_vm0():
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)

    vm0 = VirtualMachine(0, install_info, config.network)
    vm0.destroy()
    vm0.storage.delete_vm0_modify_storage()
