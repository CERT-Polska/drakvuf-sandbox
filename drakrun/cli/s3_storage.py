import logging
import shutil

import click
from lib.s3_storage import is_analysis_on_s3

from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.lib.s3_storage import (
    LocalLockType,
    download_analysis,
    get_s3_client,
    has_analysis_lock,
    reset_analysis_lock,
    set_analysis_lock,
    upload_analysis,
)

log = logging.getLogger(__name__)


def _get_s3_client():
    s3_config = load_config().s3
    if not s3_config:
        click.echo("S3 storage is not configured", err=True)
        raise click.Abort()
    if not s3_config.enabled:
        click.echo("S3 storage is not enabled", err=True)
        raise click.Abort()
    return get_s3_client(s3_config), s3_config.bucket


@click.group(name="s3-storage", help="S3 storage utilities")
def s3_storage():
    pass


@s3_storage.command(name="export", help="Export local analysis to S3 storage")
@click.argument("analysis_id", type=click.UUID)
@click.option(
    "--analysis-dir",
    "analysis_dir",
    default=None,
    type=click.Path(exists=True),
    help=f"Alternative analysis storage path (default is {ANALYSES_DIR.as_posix()})",
)
@click.option(
    "--force",
    "force",
    is_flag=True,
    default=False,
    help="Ignore upload/download locks, don't check if already exported",
)
def s3_export(analysis_id, analysis_dir, force):
    if analysis_dir is None:
        analysis_dir = ANALYSES_DIR
    analysis_id = str(analysis_id)
    s3_client, s3_bucket = _get_s3_client()
    analysis_path = analysis_dir / analysis_id
    if not analysis_path.exists():
        click.echo(f"{analysis_path.as_posix()} doesn't exist", err=True)
        raise click.Abort()
    if not force:
        if has_analysis_lock(analysis_path):
            click.echo(
                f"{analysis_path.as_posix()} is locked for pending upload or download."
                " Use --force if you want to ignore the lock.",
                err=True,
            )
            raise click.Abort()
        if is_analysis_on_s3(analysis_id, s3_client, s3_bucket):
            click.echo(
                f"{analysis_id} is already uploaded to S3"
                " Use --force if you want to perform a reupload",
                err=True,
            )
            raise click.Abort()
    set_analysis_lock(analysis_path, LocalLockType.upload_lock)
    try:
        upload_analysis(analysis_id, analysis_path, s3_client, s3_bucket)
    finally:
        reset_analysis_lock(analysis_path, LocalLockType.upload_lock)


@s3_storage.command(
    name="import", help="Import analysis from S3 storage to local storage"
)
@click.argument("analysis_id", type=click.UUID)
@click.option(
    "--analysis-dir",
    "analysis_dir",
    default=None,
    type=click.Path(exists=True),
    help=f"Alternative analysis storage path (default is {ANALYSES_DIR.as_posix()})",
)
@click.option(
    "--force",
    "force",
    is_flag=True,
    default=False,
    help="Ignore upload/download locks",
)
def s3_import(analysis_id, analysis_dir, force):
    if analysis_dir is None:
        analysis_dir = ANALYSES_DIR
    analysis_id = str(analysis_id)
    s3_client, s3_bucket = _get_s3_client()
    analysis_path = analysis_dir / analysis_id
    if analysis_path.exists():
        if not force:
            click.echo(
                f"{analysis_path.as_posix()} already exists"
                " Use --force if you want to redownload it anyway",
                err=True,
            )
            raise click.Abort()
        else:
            shutil.rmtree(analysis_path)

    analysis_path.mkdir()
    set_analysis_lock(analysis_path, LocalLockType.download_lock)
    try:
        download_analysis(analysis_id, analysis_path, s3_client, s3_bucket)
    finally:
        reset_analysis_lock(analysis_path, LocalLockType.download_lock)
