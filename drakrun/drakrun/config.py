import json
import os
from dataclasses import dataclass
from typing import Optional

from dataclasses_json import DataClassJsonMixin

from drakrun.util import safe_delete

ETC_DIR = os.getenv("DRAKRUN_ETC_DIR") or "/etc/drakrun"
VM_CONFIG_DIR = os.path.join(ETC_DIR, "configs")


LIB_DIR = os.getenv("DRAKRUN_LIB_DIR") or "/var/lib/drakrun"
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")
APISCOUT_PROFILE_DIR = os.path.join(LIB_DIR, "apiscout_profile")
VOLUME_DIR = os.path.join(LIB_DIR, "volumes")


@dataclass
class InstallInfo(DataClassJsonMixin):
    storage_backend: str
    disk_size: str
    iso_path: str
    enable_unattended: bool
    vcpus: int = 2
    memory: int = 3072
    zfs_tank_name: Optional[str] = None
    lvm_volume_group: Optional[str] = None
    iso_sha256: Optional[str] = None

    INSTALL_FILE_PATH = os.path.join(ETC_DIR, "install.json")

    @staticmethod
    def load() -> "InstallInfo":
        """Reads and parses install.json file"""
        with open(InstallInfo.INSTALL_FILE_PATH, "r") as f:
            return InstallInfo.from_json(f.read())

    @staticmethod
    def try_load() -> Optional["InstallInfo"]:
        """Tries to load install.json of fails with None"""
        try:
            return InstallInfo.load()
        except FileNotFoundError:
            return None

    @staticmethod
    def delete():
        if not safe_delete(InstallInfo.INSTALL_FILE_PATH):
            raise Exception("install.json not deleted")

    def save(self):
        """Serializes self and writes to install.json"""
        with open(InstallInfo.INSTALL_FILE_PATH, "w") as f:
            f.write(json.dumps(self.to_dict(), indent=4))


def is_installed() -> bool:
    """Returns true when install.json is present"""
    return InstallInfo.try_load() is not None
