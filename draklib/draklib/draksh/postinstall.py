import logging

import click

from ..config import Profile
from ..drakvuf.dlls import get_essential_dll_file_list, get_optional_dll_file_list
from ..drakvuf.vm import DrakvufVM
from ..machinery.vm import FIRST_CDROM_DRIVE, SECOND_CDROM_DRIVE
from ..util import ensure_delete
from .util import check_root

log = logging.getLogger(__name__)


@click.command(help="Finalize VM installation and generate profiles")
@click.option(
    "--profile-name",
    "profile_name",
    default="default",
    type=str,
    show_default=True,
    help="Profile name",
)
def postinstall(profile_name):
    if not check_root():
        return

    profile = Profile.load(profile_name)

    vm1 = DrakvufVM(profile, 1)
    vm0 = DrakvufVM(profile, 0)

    if vm1.vm.is_running is True:
        # If vm1 is running: probably we failed to make a DLL profile
        # Let's revert it and use already made snapshot
        vm1.vm.destroy()

    if not vm0.vm.snapshot_path.exists() or not click.confirm(
        "vm-0 snapshot exists. Do you want to use already made snapshot?"
    ):
        if vm0.vm.is_running is False:
            raise click.ClickException("vm-0 is not running")

        log.info("Cleaning up leftovers (if any)")
        for path in profile.vm_profile_dir.glob("*"):
            ensure_delete(path)

        log.info("Ejecting installation CDs")
        vm0.vm.eject_cd(FIRST_CDROM_DRIVE)
        if profile.install_info.enable_unattended:
            # If unattended installation is enabled, we have an additional CD-ROM drive
            # TODO
            vm0.vm.eject_cd(SECOND_CDROM_DRIVE)

        win_guid_info = vm0.get_win_guid()

        log.info(f"Determined Windows version: {win_guid_info.version}")
        log.info(f"Determined PDB GUID: {win_guid_info.guid}")
        log.info(f"Determined kernel filename: {win_guid_info.filename}")

        vm0.create_kernel_profile(win_guid_info)
        vm0.create_runtime_info()

        log.info("Saving VM snapshot...")
        # Create vm-0 snapshot, and destroy it
        # WARNING: qcow2 snapshot method is a noop. fresh images are created on the fly
        # so we can't keep the vm-0 running
        vm0.save(destroy_after=True)
        log.info("Snapshot was saved succesfully.")

        # Memory state is frozen, we can't do any writes to persistent storage
        log.info("Snapshotting persistent memory...")
        vm0.vm.storage.snapshot_vm0_volume()

    # Restore a VM and create DLL profiles
    vm1 = DrakvufVM(profile, 1)
    vm1.load_runtime_info()

    vm1.restore()
    win_guid_info = vm1.get_win_guid()

    essential_dlls = get_essential_dll_file_list(win_guid_info)
    for dllspec in essential_dlls:
        if (profile.vm_profile_dir / f"{dllspec.dest}.json").exists():
            log.info(f"DLL profile for {dllspec.dest} already exists.")
            continue
        vm1.make_dll_profile(dllspec)

    optional_dlls = get_optional_dll_file_list(win_guid_info)
    failed_dlls = []
    for dllspec in optional_dlls:
        if (profile.vm_profile_dir / f"{dllspec.dest}.json").exists():
            log.info(f"DLL profile for {dllspec.dest} already exists.")
            continue
        try:
            vm1.make_dll_profile(dllspec)
        except Exception:
            log.exception("Failed to profile optional DLL")
            failed_dlls.append(dllspec)

    vm1.destroy()
    if not failed_dlls:
        log.info("Profile created successfully!")
    else:
        log.info("Profile created although not all DLLs were profiled")
        for failed_dll in failed_dlls:
            log.info(f"- {failed_dll.path}")
