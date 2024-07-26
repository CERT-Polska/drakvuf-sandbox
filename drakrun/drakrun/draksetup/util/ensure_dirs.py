import os

from drakrun.lib.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    LIB_DIR,
    PROFILE_DIR,
    VM_CONFIG_DIR,
    VOLUME_DIR,
)


def ensure_dirs():
    os.makedirs(ETC_DIR, exist_ok=True)
    os.makedirs(VM_CONFIG_DIR, exist_ok=True)

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    os.makedirs(APISCOUT_PROFILE_DIR, exist_ok=True)
    os.makedirs(VOLUME_DIR, exist_ok=True)
