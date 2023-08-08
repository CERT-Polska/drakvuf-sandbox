import logging
import os
import secrets
import string

import click

from drakrun.config import InstallInfo
from drakrun.machinery.networking import find_default_interface
from drakrun.machinery.service import start_enabled_drakruns, stop_all_drakruns
from drakrun.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    LIB_DIR,
    PROFILE_DIR,
    VM_CONFIG_DIR,
    VOLUME_DIR,
)

from ._config import config
from ._util import check_root
from .postinstall import create_missing_profiles


def setup_dirs():
    os.makedirs(ETC_DIR, exist_ok=True)
    os.makedirs(VM_CONFIG_DIR, exist_ok=True)

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    os.makedirs(APISCOUT_PROFILE_DIR, exist_ok=True)
    os.makedirs(VOLUME_DIR, exist_ok=True)


def detect_defaults():
    out_interface = config.get("drakrun", "out_interface")

    if not out_interface:
        default_if = find_default_interface()

        if default_if:
            logging.info(f"Detected default network interface: {default_if}")
            config["drakrun"]["out_interface"] = default_if
        else:
            logging.warning("Unable to detect default network interface.")


@click.command(help="Perform tasks after drakrun upgrade")
def postupgrade():
    if not check_root():
        return

    with open(os.path.join(ETC_DIR, "scripts", "cfg.template"), "r") as f:
        template = f.read()

    passwd_characters = string.ascii_letters + string.digits
    passwd = "".join(secrets.choice(passwd_characters) for _ in range(20))
    template = template.replace("{{ VNC_PASS }}", passwd)

    with open(os.path.join(ETC_DIR, "scripts", "cfg.template"), "w") as f:
        f.write(template)

    # todo: migrate [minio] to [s3]

    setup_dirs()
    detect_defaults()

    install_info = InstallInfo.try_load()
    if not install_info:
        logging.info("Postupgrade done. DRAKVUF Sandbox not installed.")
        return

    stop_all_drakruns()
    create_missing_profiles()
    start_enabled_drakruns()
