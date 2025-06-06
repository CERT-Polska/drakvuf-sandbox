import logging

import click

from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.lib.s3_storage import download_analysis, get_s3_client, upload_analysis

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


@click.group(name="s3", help="S3 storage utilities")
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
def s3_export(analysis_id, analysis_dir):
    if analysis_dir is None:
        analysis_dir = ANALYSES_DIR
    analysis_id = str(analysis_id)
    analysis_path = analysis_dir / analysis_id
    if not analysis_path.exists():
        click.echo(f"Analysis {analysis_id} does not exist", err=True)
        raise click.Abort()
    s3_client, s3_bucket = _get_s3_client()
    upload_analysis(analysis_id, analysis_path, s3_client, s3_bucket)


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
def s3_import(analysis_id, analysis_dir):
    if analysis_dir is None:
        analysis_dir = ANALYSES_DIR
    analysis_id = str(analysis_id)
    analysis_path = analysis_dir / analysis_id
    if analysis_path.exists():
        click.echo(f"Analysis {analysis_id} already exists", err=True)
        raise click.Abort()
    analysis_path.mkdir()
    s3_client, s3_bucket = _get_s3_client()
    download_analysis(analysis_id, analysis_path, s3_client, s3_bucket)
