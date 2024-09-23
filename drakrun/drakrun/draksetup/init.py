import configparser
import logging
import secrets
import string
import sysconfig
from pathlib import Path
from typing import List, Optional

import click

from drakrun.lib.bindings.systemd import (
    enable_service,
    start_service,
    systemctl_daemon_reload,
)
from drakrun.lib.config import DrakrunConfig, load_config, update_config
from drakrun.lib.minio import get_minio_client
from drakrun.lib.paths import ETC_DIR, PACKAGE_DIR

from .util.ensure_dirs import ensure_dirs

log = logging.getLogger(__name__)

MINIO_ENV_CONFIG_FILE = Path("/etc/default/minio")
SYSTEMD_SERVICE_PATH = Path("/etc/systemd/system")
PACKAGE_DATA_DIR = PACKAGE_DIR / "data"
ETC_SCRIPTS_DIR = Path(ETC_DIR) / "scripts"


def create_configuration_file(config_file_name, target_dir=None):
    target_dir = target_dir or Path(ETC_DIR)
    target_path = target_dir / config_file_name
    if target_path.exists():
        log.info(f"{target_path} already created.")
        return target_path

    config_data = (PACKAGE_DATA_DIR / config_file_name).read_text()
    target_path.write_text(config_data)
    log.info(f"Created {target_path}.")
    return target_path


def set_template_vnc_password(template_path):
    template_data = template_path.read_text()
    passwd_characters = string.ascii_letters + string.digits
    vnc_passwd = "".join(secrets.choice(passwd_characters) for _ in range(20))
    template_data = template_data.replace("{{ VNC_PASS }}", vnc_passwd)
    template_path.write_text(template_data)


def apply_local_minio_service_config(config: DrakrunConfig):
    parser = configparser.ConfigParser(strict=False, allow_no_value=True)
    minio_env = "[DEFAULT]\n" + MINIO_ENV_CONFIG_FILE.read_text()
    parser.read_string(minio_env)
    config.minio.access_key = parser.get("DEFAULT", "MINIO_ROOT_USER")
    config.minio.secret_key = parser.get("DEFAULT", "MINIO_ROOT_PASSWORD")
    return config


def get_scripts_bin_path():
    scripts_path = Path(sysconfig.get_path("scripts"))
    if scripts_path == Path("/usr/bin"):
        # pip installs global scripts in different path than
        # pointed by sysconfig
        return Path("/usr/local/bin")
    return scripts_path


def fix_exec_start(config_file_name):
    """
    This function fixes ExecStart entry to point at correct virtualenv bin directory

    ExecStart=/usr/local/bin/karton-system --config-file /etc/drakrun/config.ini
    """
    systemd_config_path = SYSTEMD_SERVICE_PATH / config_file_name
    systemd_config = systemd_config_path.read_text()
    current_exec_start = next(
        line for line in systemd_config.splitlines() if line.startswith("ExecStart=")
    )
    current_exec_path_str = current_exec_start.split("=")[1].split()[0]
    current_exec_path = Path(current_exec_path_str)
    new_exec_path = get_scripts_bin_path() / current_exec_path.name
    if current_exec_path != new_exec_path:
        systemd_config = systemd_config.replace(
            current_exec_path_str, new_exec_path.as_posix()
        )
        systemd_config_path.write_text(systemd_config)
        log.info(
            f"{systemd_config_path}: Replaced {current_exec_path} with {new_exec_path}"
        )
    return systemd_config_path


def apply_setting(
    message, current_value, option_value, hide_input=False, unattended=False
):
    if option_value is not None:
        # If option value is already provided: just return option_value
        return option_value
    if unattended:
        # If unattended and no option value: just leave current value
        return current_value
    default_value = current_value or None
    input_value = click.prompt(message, default=default_value, hide_input=hide_input)
    if input_value is None:
        # If input not provided and no reasonable default found: leave current value
        return current_value
    else:
        # Else: provide input value
        return input_value


@click.command(help="Pre-installation activities")
@click.option("--s3-address", default=None, help="S3 endpoint address")
@click.option("--s3-access-key", default=None, help="S3 access key")
@click.option("--s3-secret-key", default=None, help="S3 secret key")
@click.option(
    "--s3-secure", default=False, is_flag=True, help="S3 enable secure connection"
)
@click.option(
    "--s3-make-buckets",
    default=True,
    is_flag=True,
    help="Auto-create S3 buckets: karton, drakrun",
)
@click.option("--redis-host", default=None, help="Redis host")
@click.option("--redis-port", default=None, help="Redis port")
@click.option(
    "--only",
    type=click.Choice(["web", "system", "drakrun"]),
    multiple=True,
    help="Create configuration only for specific service for multi-node configuration",
)
@click.option(
    "--unattended",
    default=False,
    is_flag=True,
    help="Don't prompt for values, expect required parameters in arguments",
)
def init(
    s3_address: Optional[str],
    s3_access_key: Optional[str],
    s3_secret_key: Optional[str],
    s3_secure: bool,
    s3_make_buckets: bool,
    redis_host: Optional[str],
    redis_port: Optional[str],
    only: List[str],
    unattended: bool,
):
    # Simple activities handled by deb packages before
    # In the future, consider splitting this to remove hard dependency on systemd etc
    ensure_dirs()

    drakrun_config_path = create_configuration_file("config.ini")

    try:
        config = load_config()
    except Exception:
        import traceback

        traceback.print_exc()
        click.echo(
            "Failed to load currently installed configuration. "
            f"Fix {drakrun_config_path.as_posix()} or remove file to reconfigure it "
            f"from scratch and run 'draksetup init' again.",
            err=True,
        )
        raise click.Abort()

    config.redis.host = apply_setting(
        "Provide redis hostname", config.redis.host, redis_host, unattended=unattended
    )
    config.redis.port = apply_setting(
        "Provide redis port", config.redis.port, redis_port, unattended=unattended
    )
    config.minio.address = apply_setting(
        "Provide S3 (MinIO) address",
        config.minio.address,
        s3_address,
        unattended=unattended,
    )

    minio_env_applied = False
    if MINIO_ENV_CONFIG_FILE.exists():
        log.info(
            f"Found {MINIO_ENV_CONFIG_FILE.as_posix()} file with MinIO credentials"
        )
        if unattended or click.confirm(
            f"Do you want to import credentials from {MINIO_ENV_CONFIG_FILE.as_posix()} file?",
            default=True,
        ):
            apply_local_minio_service_config(config)
            minio_env_applied = True

    if not minio_env_applied:
        config.minio.access_key = apply_setting(
            "Provide S3 (MinIO) access key",
            config.minio.access_key,
            s3_access_key,
            unattended=unattended,
        )
        config.minio.secret_key = apply_setting(
            "Provide S3 (MinIO) secret key",
            config.minio.secret_key,
            s3_secret_key,
            unattended=unattended,
        )

    config.minio.secure = s3_secure
    update_config(config)
    log.info(f"Updated {drakrun_config_path.as_posix()}.")

    mc = get_minio_client(config)

    def check_s3_bucket(bucket_name):
        if not mc.bucket_exists(bucket_name):
            if s3_make_buckets:
                log.info(f"Bucket '{bucket_name}' doesn't exist, creating one...")
                mc.make_bucket(bucket_name)
            else:
                click.echo(
                    f"Bucket '{bucket_name}' doesn't exist. "
                    "Create proper S3 buckets to continue.",
                    err=True,
                )
                raise click.Abort()

    check_s3_bucket("drakrun")
    check_s3_bucket(config.minio.bucket)

    def is_component_to_init(component_name):
        return not only or component_name in only

    if is_component_to_init("drakrun"):
        create_configuration_file("hooks.txt")
        create_configuration_file("drakrun@.service", target_dir=SYSTEMD_SERVICE_PATH)
        fix_exec_start("drakrun@.service")
        template_path = create_configuration_file(
            "cfg.template", target_dir=ETC_SCRIPTS_DIR
        )
        set_template_vnc_password(template_path)
        create_configuration_file("vm-post-restore.ps1", target_dir=ETC_SCRIPTS_DIR)

    if is_component_to_init("system"):
        create_configuration_file(
            "drak-system.service", target_dir=SYSTEMD_SERVICE_PATH
        )
        fix_exec_start("drak-system.service")

    if is_component_to_init("web"):
        create_configuration_file("uwsgi.ini")
        create_configuration_file("drak-web.service", target_dir=SYSTEMD_SERVICE_PATH)
        fix_exec_start("drak-web.service")

    systemctl_daemon_reload()

    # drakrun is going to be enabled after complete install/postinstall setup
    if is_component_to_init("system"):
        log.info("Starting drak-system service")
        enable_service("drak-system")
        start_service("drak-system")
    if is_component_to_init("web"):
        log.info("Starting drak-web service")
        enable_service("drak-web")
        start_service("drak-web")
