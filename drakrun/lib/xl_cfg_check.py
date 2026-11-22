import logging
import pathlib
import re
import subprocess
from typing import Optional, Tuple

from .install_info import InstallInfo
from .paths import INSTALL_INFO_PATH, XL_CFG_TEMPLATE_PATH

log = logging.getLogger(__name__)

# Xen 4.20 and newer ship qemu-xen based on QEMU 9.1, which refuses to start the HDA codec
# ("no default audio driver available") unless an explicit audio backend is configured.
# Xen 4.19 (QEMU 8.0) falls back to a default backend, so older templates still work there.
AUDIO_BACKEND_REQUIRED_SINCE_XEN = (4, 20)
AUDIO_BACKEND_ARGS = (
    '"-audiodev", "none,id=snd0", "-global", "hda-duplex.audiodev=snd0"'
)
AUDIO_BACKEND_LINE = f"device_model_args_hvm = [ {AUDIO_BACKEND_ARGS} ]"


def get_xen_version() -> Optional[Tuple[int, int]]:
    """Returns (major, minor) of the running Xen, or None if it can't be determined"""
    try:
        output = subprocess.run(
            ["xl", "info"], capture_output=True, text=True, check=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    fields = {}
    for line in output.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    try:
        return int(fields["xen_major"]), int(fields["xen_minor"])
    except (KeyError, ValueError):
        return None


def get_xl_cfg_template_path() -> pathlib.Path:
    try:
        return InstallInfo.load(INSTALL_INFO_PATH).xl_cfg_template
    except Exception:
        return XL_CFG_TEMPLATE_PATH


def check_xl_cfg_template(template_path: pathlib.Path) -> Optional[str]:
    """
    Returns a warning if the xl config template is known not to work
    with the running Xen version, None otherwise.
    """
    try:
        template = pathlib.Path(template_path).read_text()
    except OSError:
        return None
    if not re.search(r"^\s*soundhw\s*=", template, re.MULTILINE):
        return None
    if "audiodev" in template:
        return None
    xen_version = get_xen_version()
    if xen_version is None or xen_version < AUDIO_BACKEND_REQUIRED_SINCE_XEN:
        return None
    if re.search(r"^\s*device_model_args_hvm\s*=", template, re.MULTILINE):
        fix = f"add {AUDIO_BACKEND_ARGS} to the existing device_model_args_hvm list"
    else:
        fix = f"add this line: {AUDIO_BACKEND_LINE}"
    return (
        f"{template_path} enables audio (soundhw) without an explicit audio backend. "
        f"QEMU shipped with Xen {xen_version[0]}.{xen_version[1]} refuses to start "
        f"the audio device without one, so VMs fail to start or restore. "
        f"To fix it, {fix}"
    )


def warn_about_xl_cfg_template(template_path: Optional[pathlib.Path] = None) -> bool:
    """Logs a warning if the xl config template needs fixing. Returns True if it does."""
    if template_path is None:
        template_path = get_xl_cfg_template_path()
    message = check_xl_cfg_template(template_path)
    if message is None:
        return False
    log.warning(message)
    return True
