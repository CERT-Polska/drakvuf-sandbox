import json
import pathlib
from dataclasses import dataclass
from typing import Optional

from dataclasses_json import DataClassJsonMixin

from .paths import SNAPSHOT_DIR, XL_CFG_TEMPLATE_PATH


@dataclass
class InstallInfo(DataClassJsonMixin):
    """
    This object is main configuration of the VM, initialized during installation process.

    Values are mapped to the xl domain configuration file template.
    """

    storage_backend: str
    disk_size: str
    vnc_passwd: str
    vcpus: int
    memory: int
    reboot_vm0_action: str = "restart"
    reboot_vmn_action: str = "destroy"
    xl_cfg_template: str = XL_CFG_TEMPLATE_PATH.as_posix()
    snapshot_dir: str = SNAPSHOT_DIR.as_posix()

    lvm_snapshot_size: str = "1G"
    zfs_tank_name: Optional[str] = None
    lvm_volume_group: Optional[str] = None

    @staticmethod
    def load(path: pathlib.Path) -> "InstallInfo":
        """Parses InstallInfo file at the provided path"""
        with path.open("r") as f:
            return InstallInfo.from_json(f.read())

    def save(self, path: pathlib.Path) -> None:
        """Serializes self and writes to the provided path"""
        with path.open("w") as f:
            f.write(json.dumps(self.to_dict(), indent=4))
