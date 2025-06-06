import gzip
import logging
import shutil
from pathlib import Path

import click

from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_PROFILES_DIR
from drakrun.lib.storage import get_storage_backend

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
def snapshot_import():
    pass
