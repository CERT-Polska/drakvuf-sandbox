import json
import os
import re

from dataclasses import dataclass, field
from typing import Optional

from dataclasses_json import config, dataclass_json, DataClassJsonMixin

from .util import safe_delete

hexstring = config(
    encoder=lambda v: hex(v),
    decoder=lambda v: int(v, 16),
)

ETC_DIR = os.getenv("DRAKRUN_ETC_DIR") or "/etc/drakrun"
VM_CONFIG_DIR = os.path.join(ETC_DIR, "configs")


LIB_DIR = os.getenv("DRAKRUN_LIB_DIR") or "/var/lib/drakrun"
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")
APISCOUT_PROFILE_DIR = os.path.join(LIB_DIR, "apiscout_profile")
VOLUME_DIR = os.path.join(LIB_DIR, "volumes")

DEFAULT_DRAKVUF_PLUGINS = [
    "apimon",
    "bsodmon",
    "clipboardmon",
    "cpuidmon",
    "crashmon",
    "debugmon",
    "delaymon",
    "exmon",
    "filedelete",
    "filetracer",
    "librarymon",
    "memdump",
    "procdump",
    "procmon",
    "regmon",
    "rpcmon",
    "ssdtmon",
    "syscalls",
    "tlsmon",
    "windowmon",
    "wmimon",
]

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

    _FILENAME = "install.json"
    _FILE_PATH = os.path.join(ETC_DIR, _FILENAME)

    @staticmethod
    def load() -> "InstallInfo":
        """Reads and parses install.json file"""
        with open(InstallInfo._FILE_PATH, "r") as f:
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
        if not safe_delete(InstallInfo._FILE_PATH):
            raise Exception("install.json not deleted")

    def save(self):
        """Serializes self and writes to install.json"""
        with open(InstallInfo._FILE_PATH, "w") as f:
            f.write(json.dumps(self.to_dict(), indent=4))


@dataclass_json
@dataclass
class VmiOffsets:
    # Fields correspond to output defined in
    # https://github.com/libvmi/libvmi/blob/master/examples/win-offsets.c

    win_ntoskrnl: int = field(metadata=hexstring)
    win_ntoskrnl_va: int = field(metadata=hexstring)

    win_tasks: int = field(metadata=hexstring)
    win_pdbase: int = field(metadata=hexstring)
    win_pid: int = field(metadata=hexstring)
    win_pname: int = field(metadata=hexstring)
    win_kdvb: int = field(metadata=hexstring)
    win_sysproc: int = field(metadata=hexstring)
    win_kpcr: int = field(metadata=hexstring)
    win_kdbg: int = field(metadata=hexstring)

    kpgd: int = field(metadata=hexstring)

    @staticmethod
    def from_tool_output(output: str) -> "VmiOffsets":
        """
        Parse vmi-win-offsets tool output and return VmiOffsets.
        If any of the fields is missing, throw TypeError
        """
        offsets = re.findall(r"^([a-z_]+):(0x[0-9a-f]+)$", output, re.MULTILINE)
        vals = {k: int(v, 16) for k, v in offsets}
        return VmiOffsets(**vals)


@dataclass
class RuntimeInfo(DataClassJsonMixin):
    vmi_offsets: VmiOffsets
    inject_pid: int

    _FILENAME = "runtime.json"
    _FILE_PATH = os.path.join(PROFILE_DIR, _FILENAME)

    @staticmethod
    def load() -> "RuntimeInfo":
        with open(RuntimeInfo._FILE_PATH, "r") as f:
            return RuntimeInfo.from_json(f.read())


def is_installed() -> bool:
    """Returns true when install.json is present"""
    return InstallInfo.try_load() is not None
