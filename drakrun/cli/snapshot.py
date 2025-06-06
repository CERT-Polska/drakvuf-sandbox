import gzip
import logging
import shutil
from pathlib import Path

import click

from drakrun.cli.banner import banner
from drakrun.cli.sanity_check import sanity_check
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import (
    INSTALL_INFO_PATH,
    SNAPSHOT_DIR,
    VMI_PROFILES_DIR,
    initialize_config_files,
    make_dirs,
)
from drakrun.lib.storage import REGISTERED_BACKEND_NAMES, get_storage_backend

log = logging.getLogger(__name__)


@click.group(name="snapshot", help="Snapshot management commands (import/export)")
def snapshot():
    pass


@snapshot.command(name="export", help="Export snapshot into local directory")
@click.argument(
    "output_dir",
    type=click.Path(exists=False),
)
def snapshot_export(output_dir):
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    output_dir = Path(output_dir)
    output_dir.mkdir()
    log.info("Exporting install.json...")
    shutil.copy(INSTALL_INFO_PATH, output_dir / "install.json")
    log.info("Exporting cfg.template...")
    shutil.copy(install_info.xl_cfg_template, output_dir / "cfg.template")

    log.info("Exporting VM disk (this may take a while)...")
    backend = get_storage_backend(install_info)
    backend.export_vm0(output_dir / "disk.img.gz")

    log.info("Exporting snapshot.sav...")
    snapshot_path = install_info.snapshot_dir / "snapshot.sav"
    exported_snapshot_path = output_dir / "snapshot.sav.gz"
    with snapshot_path.open("rb") as src:
        with gzip.open(exported_snapshot_path, "wb", compresslevel=6) as dst:
            shutil.copyfileobj(src, dst)

    log.info("Exporting profiles...")
    exported_profiles_path = output_dir / "profiles"
    exported_profiles_path.mkdir()
    for profile_path in VMI_PROFILES_DIR.glob("*.json"):
        shutil.copy(profile_path, exported_profiles_path / profile_path.name)

    log.info("Snapshot successfully exported to %s", output_dir.resolve().as_posix())


@snapshot.command(name="import", help="Import snapshot from local directory")
@click.argument(
    "input_dir",
    type=click.Path(exists=True),
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
    "--zfs-tank-name",
    "zfs_tank_name",
    help="Tank name (only for ZFS storage backend)",
)
@click.option(
    "--lvm-volume-group",
    "lvm_volume_group",
    help="Volume group (only for lvm storage backend)",
)
@click.option(
    "--force",
    "-y",
    "force",
    is_flag=True,
    default=False,
    help="Force overwrite of existing snapshot",
)
def snapshot_import(input_dir, storage_backend, zfs_tank_name, lvm_volume_group, force):
    if storage_backend == "lvm" and lvm_volume_group is None:
        log.error("lvm storage backend requires --lvm-volume-group")
        raise click.Abort()
    if storage_backend == "zfs" and zfs_tank_name is None:
        log.error("zfs storage backend requires --zfs-tank-name")
        raise click.Abort()

    if INSTALL_INFO_PATH.exists() and not force:
        click.confirm(
            "This action is irreversible and will OVERWRITE existing snapshot. "
            "Are you sure?",
            abort=True,
        )

    # Perform same initialization steps as for install
    sanity_check()

    if INSTALL_INFO_PATH.exists():
        log.info("Cleaning up old snapshot files...")
        INSTALL_INFO_PATH.unlink(missing_ok=True)
        if VMI_PROFILES_DIR.exists():
            shutil.rmtree(VMI_PROFILES_DIR)
        if SNAPSHOT_DIR.exists():
            shutil.rmtree(SNAPSHOT_DIR)

    make_dirs()
    initialize_config_files()

    input_dir = Path(input_dir)
    exported_install_info = InstallInfo.load(input_dir / "install.json")

    install_info = InstallInfo(
        vcpus=exported_install_info.vcpus,
        memory=exported_install_info.memory,
        storage_backend=storage_backend,
        disk_size=exported_install_info.disk_size,
        vnc_passwd=exported_install_info.vnc_passwd,
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
    )
    install_info.save(INSTALL_INFO_PATH)

    log.info("Importing cfg.template...")
    shutil.copy(input_dir / "cfg.template", install_info.xl_cfg_template)

    log.info("Importing VM disk (this may take a while)...")
    backend = get_storage_backend(install_info)
    backend.import_vm0(input_dir / "disk.img.gz")

    log.info("Importing snapshot.sav...")
    exported_snapshot_path = input_dir / "snapshot.sav.gz"
    snapshot_path = install_info.snapshot_dir / "snapshot.sav"
    with gzip.open(exported_snapshot_path, "rb") as src:
        with snapshot_path.open("wb") as dst:
            shutil.copyfileobj(src, dst)

    log.info("Importing profiles...")
    exported_profiles_path = input_dir / "profiles"
    for profile_path in exported_profiles_path.glob("*.json"):
        shutil.copy(profile_path, VMI_PROFILES_DIR / profile_path.name)

    banner(
        f"""
        Initial VM setup is complete.
        Please test your VM by running the following command:
        # drakrun vm-start
        Then go to VNC port 5901 and check if your machine is running.
        After that use drakrun vm-stop to stop the machine.
        If your VM fails to boot, your configuration may be different from
        the one you've used for exporting your snapshot. In that case, use
        # drakrun modify-vm0 begin --cold-boot
        and then proceed accordingly.
        Your configured VNC password is:
        {install_info.vnc_passwd}
    """
    )
