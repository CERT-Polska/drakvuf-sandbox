import os
import json

from dataclasses import dataclass
from typing import Optional
from dataclasses_json import DataClassJsonMixin

ETC_DIR = os.getenv("DRAKRUN_ETC_DIR") or "/etc/drakrun"
LIB_DIR = os.getenv("DRAKRUN_LIB_DIR") or "/var/lib/drakrun"


@dataclass
class InstallInfo(DataClassJsonMixin):
    storage_backend: str
    disk_size: str
    iso_path: str
    max_vms: int
    enable_unattended: bool
    zfs_tank_name: Optional[str] = None
    iso_sha256: Optional[str] = None

    _INSTALL_FILENAME = "install.json"

    @staticmethod
    def load() -> 'InstallInfo':
        """ Reads and parses install.json file """
        with open(os.path.join(ETC_DIR, InstallInfo._INSTALL_FILENAME), "r") as f:
            return InstallInfo.from_json(f.read())

    @staticmethod
    def try_load() -> Optional['InstallInfo']:
        """ Tries to load install.json of fails with None """
        try:
            return InstallInfo.load()
        except FileNotFoundError:
            return None

    def save(self):
        """ Serializes self and writes to install.json """
        with open(os.path.join(ETC_DIR, InstallInfo._INSTALL_FILENAME), "w") as f:
            f.write(json.dumps(self.to_dict(), indent=4))


def is_installed() -> bool:
    """ Returns true when install.json is present """
    return InstallInfo.try_load() is not None
