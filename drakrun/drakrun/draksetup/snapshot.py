import io
import json
import logging
import os
import subprocess
import tempfile

import click
from minio.error import NoSuchKey

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.minio import get_minio_client
from drakrun.lib.networking import setup_vm_network, start_dnsmasq
from drakrun.lib.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    PROFILE_DIR,
    VM_CONFIG_DIR,
    VOLUME_DIR,
)
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.vm import generate_vm_conf

from .util.ensure_dirs import ensure_dirs

log = logging.getLogger(__name__)


@click.group(help="Manage VM snapshots")
def snapshot():
    pass


@snapshot.command(
    name="export", help="Upload local snapshot to MinIO.", no_args_is_help=True
)
@click.option("--name", required=True, help="Name of the snapshot")
@click.option(
    "--bucket", default="drakrun-snapshots", help="MinIO bucket to store the snapshot"
)
@click.option(
    "--full", default=False, is_flag=True, help="Upload memory snapshot and profiles"
)
@click.option("--force", default=False, is_flag=True, help="Overwrite remote snapshot")
def snapshot_export(name, bucket, full, force):
    install_info = InstallInfo.try_load()
    if install_info is None:
        log.error("Missing installation info. Did you forget to set up the sandbox?")
        return

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    if len(list(mc.list_objects(bucket, f"{name}/"))) > 0 and not force:
        log.error(
            "There are objects in bucket %s at path %s. Aborting...", bucket, f"{name}/"
        )
        return

    log.info("Exporting snapshot as %s into %s", name, bucket)

    if full:
        log.warning(
            "Full snapshots may not work if hardware used for "
            "importing and exporting differs. You have been warned!"
        )
        do_export_full(mc, bucket, name)
    else:
        do_export_minimal(mc, bucket, name)

    log.info("Done. To use exported snapshot on other machine, execute:")
    log.info("# draksetup snapshot import --name %s --bucket %s", name, bucket)


@snapshot.command(
    name="import", help="Download and configure remote snapshot", no_args_is_help=True
)
@click.option("--name", required=True, help="Name of the exported snapshot")
@click.option(
    "--bucket", default="drakrun-snapshots", help="MinIO bucket to store the snapshot"
)
@click.option(
    "--full", default=False, is_flag=True, help="Download VM memory and profiles"
)
@click.option(
    "--zpool", help="Override zpool name stored in snapshot (only for ZFS snapshots)"
)
def snapshot_import(name, bucket, full, zpool):
    local_install = InstallInfo.try_load()
    if local_install is not None:
        click.confirm(
            "Detected local snapshot. It will be REMOVED. Continue?", abort=True
        )

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    ensure_dirs()

    try:
        if full:
            log.warning(
                "Importing full snapshot. This may not work if hardware is different"
            )
            do_import_full(mc, name, bucket, zpool)
        else:
            do_import_minimal(mc, name, bucket, zpool)

            # This could probably use some refactoring
            # We're duplicating quite a lot of code from install function
            install_info = InstallInfo.load()
            generate_vm_conf(install_info, 0)
            backend = get_storage_backend(install_info)
            backend.rollback_vm_storage(0)

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

            try:
                subprocess.run(["xl", "create", cfg_path], check=True)
            except subprocess.CalledProcessError:
                log.exception("Failed to launch VM vm-0")
                return

            log.info("Minimal snapshots require postinstall to work correctly")
            log.info("Please VNC to the port 5900 to ensure the OS booted correctly")
            log.info("After that, execute this command to finish the setup")
            log.info("# draksetup postinstall")
    except NoSuchKey:
        log.error("Import failed. Missing files in bucket.")


def do_export_minimal(mc, bucket, name):
    """Perform minimal snapshot export, symmetric to do_import_minimal"""
    log.info("Uploading installation info")
    install_info = InstallInfo.load()
    install_data = json.dumps(install_info.to_dict()).encode()
    mc.put_object(
        bucket, f"{name}/install.json", io.BytesIO(install_data), len(install_data)
    )

    log.info("Uploading VM template")
    mc.fput_object(
        bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template")
    )

    with tempfile.NamedTemporaryFile() as disk_image:
        log.info("Exporting VM hard drive")
        storage = get_storage_backend(install_info)
        storage.export_vm0(disk_image.name)

        log.info("Uploading disk.img")
        mc.fput_object(bucket, f"{name}/disk.img", disk_image.name)


def do_import_minimal(mc, name, bucket, zpool):
    """Perform minimal snapshot import, symmetric to do_export_minimal"""
    log.info("Downloading installation info")
    mc.fget_object(
        bucket,
        f"{name}/install.json",
        InstallInfo.INSTALL_FILE_PATH,
    )

    log.info("Downloading VM config")
    mc.fget_object(
        bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template")
    )

    # Now we have imported InstallInfo object
    install_info = InstallInfo.load()

    # Patch ZFS pool name
    if zpool is not None:
        install_info.zfs_tank_name = zpool
        # Save patched ZFS dataset name (storage backend has to know it)
        install_info.save()

    storage = get_storage_backend(install_info)

    with tempfile.NamedTemporaryFile() as disk_image:
        log.info("Downloading VM disk image")
        mc.fget_object(bucket, f"{name}/disk.img", disk_image.name)

        log.info("Importing VM disk")
        storage.import_vm0(disk_image.name)


def do_export_full(mc, bucket, name):
    """Perform full snapshot export, symmetric to do_import_full"""
    do_export_minimal(mc, bucket, name)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        # Compress snapshot
        log.info("Compressing snapshot.sav")
        subprocess.check_call(
            ["gzip", "-c", os.path.join(VOLUME_DIR, "snapshot.sav")],
            stdout=compressed_snapshot,
        )

        log.info("Uploading snapshot.sav.gz")
        mc.fput_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

    # Upload profiles
    for file in os.listdir(PROFILE_DIR):
        log.info("Uploading profile %s", file)
        mc.fput_object(
            bucket, f"{name}/profiles/{file}", os.path.join(PROFILE_DIR, file)
        )

    # Upload ApiScout profile
    for file in os.listdir(APISCOUT_PROFILE_DIR):
        log.info("Uploading file %s", file)
        mc.fput_object(
            bucket,
            f"{name}/apiscout_profile/{file}",
            os.path.join(APISCOUT_PROFILE_DIR, file),
        )


def do_import_full(mc, name, bucket, zpool):
    """Perform full snapshot import, symmetric to do_export_full"""
    do_import_minimal(mc, name, bucket, zpool)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        mc.fget_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

        log.info("Decompressing VM snapshot")
        with open(os.path.join(VOLUME_DIR, "snapshot.sav"), "wb") as snapshot:
            subprocess.run(
                ["zcat", compressed_snapshot.name], stdout=snapshot, check=True
            )

    profiles_prefix = f"{name}/profiles/"
    for object in mc.list_objects(bucket, prefix=profiles_prefix):
        # Strip profiles prefix
        profile_name = object.object_name[len(profiles_prefix) :]
        mc.fget_object(
            bucket, object.object_name, os.path.join(PROFILE_DIR, profile_name)
        )

    apiscout_profile_prefix = f"{name}/apiscout_profile/"
    for object in mc.list_objects(bucket, prefix=apiscout_profile_prefix):
        # Strip apiscout profile prefix
        filename = object.object_name[len(apiscout_profile_prefix) :]
        mc.fget_object(
            bucket, object.object_name, os.path.join(APISCOUT_PROFILE_DIR, filename)
        )
