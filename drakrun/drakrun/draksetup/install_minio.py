import logging
import os
import secrets
import shutil
import tempfile
import textwrap
from pathlib import Path

import click
import requests
from tqdm import tqdm

from drakrun.lib.bindings.systemd import enable_service, start_service

log = logging.getLogger(__name__)

MINIO_DOWNLOAD_URL = "https://dl.min.io/server/minio/release/linux-amd64/minio"
MINIO_ENV_CONFIG_FILE = Path("/etc/default/minio")
SYSTEMD_SERVICE_PATH = Path("/etc/systemd/system")


def generate_minio_service_config():
    """
    Creates /etc/default/minio with generated credentials
    """
    access_key = secrets.token_urlsafe(30)
    secret_key = secrets.token_urlsafe(30)
    minio_env = textwrap.dedent(
        f"""\
        MINIO_ROOT_USER={access_key}
        MINIO_ROOT_PASSWORD={secret_key}
        MINIO_VOLUMES="/var/lib/minio"
        # MINIO_OPTS sets any additional commandline options to pass to the MinIO server.
        # For example, `--console-address :9001` sets the MinIO Console listen port
        MINIO_OPTS="--console-address :9001"
        """
    )
    MINIO_ENV_CONFIG_FILE.write_text(minio_env)
    log.info(f"Created {MINIO_ENV_CONFIG_FILE.as_posix()} with default configuration")


@click.command(help="Install MinIO (for testing purposes)")
def install_minio():
    data_dir = Path(__file__).parent / "data"
    if minio_path := shutil.which("minio"):
        log.info(f"MinIO already found in {minio_path}, no need to download")
    else:
        log.info("Downloading MinIO")
        response = requests.get(MINIO_DOWNLOAD_URL, stream=True)
        total_length = response.headers.get("content-length")
        with tqdm(
            total=total_length, unit_scale=True
        ) as pbar, tempfile.NamedTemporaryFile(delete=False) as f:
            try:
                for data in response.iter_content(chunk_size=4096):
                    f.write(data)
                    pbar.update(len(data))
                os.rename(f.name, "/usr/local/bin/minio")
            except BaseException:
                os.remove(f.name)
        os.chmod("/usr/local/bin/minio", 0o0755)

    if MINIO_ENV_CONFIG_FILE.exists():
        log.info(f"{MINIO_ENV_CONFIG_FILE.as_posix()} already exists, no need to setup")
    else:
        generate_minio_service_config()

    minio_service_path = SYSTEMD_SERVICE_PATH / "minio.service"
    if minio_service_path.exists():
        log.info(f"{minio_service_path} already exists, no need to setup")
    else:
        config_data = (data_dir / "minio.service").read_text()
        minio_service_path.write_text(config_data)
        log.info("Starting minio service")
        enable_service("minio")
        start_service("minio")
