import logging
import os
import subprocess
import tempfile

import click
from minio.error import NoSuchKey

from drakrun.lib.config import load_config
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.minio import get_minio_client
from drakrun.lib.paths import VOLUME_DIR
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.util import file_sha256
from drakrun.lib.vm import VirtualMachine

log = logging.getLogger(__name__)


@click.group(help="Manage VM raw memory pre-sample dumps")
def memdump():
    pass


@memdump.command(name="export", help="Upload pre-sample raw memory dump to MinIO.")
@click.option("--instance", required=True, type=int, help="Instance ID of restored VM")
@click.option(
    "--bucket",
    default="presample-memdumps",
    help="MinIO bucket to store the compressed raw image",
)
def memdump_export(bucket, instance):
    install_info = InstallInfo.try_load()
    if install_info is None:
        log.error("Missing installation info. Did you forget to set up the sandbox?")
        return

    backend = get_storage_backend(install_info)
    vm = VirtualMachine(backend, instance)
    if vm.is_running:
        log.exception(f"vm-{instance} is running")
        return

    log.info("Calculating snapshot hash...")
    snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))
    name = f"{snapshot_sha256}_pre_sample.raw_memdump.gz"

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    try:
        mc.stat_object(bucket, name)
        log.info("This file already exists in specified bucket")
        return
    except NoSuchKey:
        pass
    except Exception:
        log.exception("Failed to check if object exists on minio")

    log.info("Restoring VM and performing memory dump")

    try:
        vm.restore(pause=True)
    except subprocess.CalledProcessError:
        log.exception(f"Failed to restore VM {vm.vm_name}")
        with open(f"/var/log/xen/qemu-dm-{vm.vm_name}.log", "rb") as f:
            log.error(f.read())
    log.info("VM restored")

    with tempfile.NamedTemporaryFile() as compressed_memdump:
        vm.memory_dump(compressed_memdump.name)

        log.info(f"Uploading {name} to {bucket}")
        mc.fput_object(bucket, name, compressed_memdump.name)

    try:
        vm.destroy()
    except Exception:
        log.exception("Failed to destroy VM")

    log.info("Done")
