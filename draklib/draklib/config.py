import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .util import DataClassConfigMixin

ETC_DIR = Path(os.getenv("DRAKLIB_ETC_DIR") or "/etc/draklib")
LIB_DIR = Path(os.getenv("DRAKLIB_LIB_DIR") or "/var/lib/draklib")
TEMPLATE_DIR = Path(__file__).parent / "templates"


@dataclass
class InstallInfo(DataClassConfigMixin):
    storage_backend: str
    disk_size: str
    iso_path: str
    enable_unattended: bool
    out_interface: str
    dns_server: str = "8.8.8.8"
    vcpus: int = 2
    memory: int = 3072
    # This is not strictly a default
    # For next profile, next range is allocated
    subnet_addr: str = "10.13.N.0"
    zfs_tank_name: Optional[str] = None
    lvm_volume_group: Optional[str] = None
    iso_sha256: Optional[str] = None

    _FILENAME = "install.json"

    @staticmethod
    def get_default_subnet_addr():
        """
        This method is required to find defaults that does not
        collide with already created profiles
        """
        default_subnet_addr = InstallInfo.subnet_addr.split(".")
        default_next_subnet = int(default_subnet_addr[1])

        for profile in Profile.load_all():
            subnet_addr = profile.install_info.subnet_addr.split(".")
            if subnet_addr[0] != default_subnet_addr[0]:
                # Not 10.x.x.x on profile
                continue
            if int(subnet_addr[1]) >= default_next_subnet:
                default_next_subnet = int(subnet_addr[1]) + 1

        return ".".join(
            [
                default_subnet_addr[0],
                str(default_next_subnet),
                default_subnet_addr[2],
                default_subnet_addr[3],
            ]
        )


class Profile:
    """
    Profiles are different VM setups for easier targeting different Windows
    versions e.g. Win7x86, Win7x64, Win10-15063 etc.

    For simple environments it's enough to have just the "default" profile,
    which is the default one.
    """

    DEFAULT_PROFILE_NAME = "default"

    def __init__(self, profile_name: str, install_info: InstallInfo):
        self.profile_name = profile_name
        self.install_info = install_info

    @property
    def etc_dir(self) -> Path:
        return ETC_DIR / self.profile_name

    @property
    def lib_dir(self) -> Path:
        return LIB_DIR / self.profile_name

    @property
    def volumes_dir(self) -> Path:
        return self.lib_dir / "volumes"

    @property
    def vm_profile_dir(self) -> Path:
        return self.lib_dir / "profiles"

    @property
    def vm_template_path(self) -> Path:
        return self.etc_dir / "vm.cfg.template"

    @property
    def vm_config_dir(self) -> Path:
        return self.lib_dir / "configs"

    def get_vm_name(self, vm_id: int) -> str:
        if self.profile_name == self.DEFAULT_PROFILE_NAME:
            return f"vm-{vm_id}"
        else:
            return f"{self.profile_name}-vm-{vm_id}"

    def ip_from_vm_id(self, vm_id: int, host_id: int):
        subnet_ip = self.install_info.subnet_addr.replace("N", str(vm_id))
        return ".".join(subnet_ip.split(".")[:3] + [str(host_id)])

    @staticmethod
    def resolve_profile_name(profile_name: Optional[str]) -> str:
        """
        Finds an actual name of default profile if empty profile name provided.
        """
        if not profile_name:
            lib_dir = LIB_DIR / Profile.DEFAULT_PROFILE_NAME
            if lib_dir.is_symlink():
                return lib_dir.readlink().name
            else:
                return Profile.DEFAULT_PROFILE_NAME
        return profile_name

    @staticmethod
    def load(profile_name: Optional[str]) -> "Profile":
        profile_name = Profile.resolve_profile_name(profile_name)
        lib_dir = LIB_DIR / profile_name
        if not lib_dir.exists():
            raise RuntimeError(f"Profile '{profile_name}' doesn't exist")

        install_info = InstallInfo.load(lib_dir)
        return Profile(profile_name, install_info)

    def _initialize(self):
        self.etc_dir.mkdir(parents=True)
        self.volumes_dir.mkdir()
        self.vm_profile_dir.mkdir()
        self.vm_config_dir.mkdir()
        shutil.copy(TEMPLATE_DIR / "vm.cfg.template", self.vm_template_path)

    @staticmethod
    def create(profile_name: Optional[str], install_info: InstallInfo) -> "Profile":
        profile_name = profile_name or Profile.DEFAULT_PROFILE_NAME
        lib_dir = LIB_DIR / profile_name
        if lib_dir.exists():
            raise RuntimeError(f"Profile '{profile_name}' already exists")
        lib_dir.mkdir(parents=True)
        install_info.save(lib_dir)
        profile = Profile(profile_name, install_info)
        profile._initialize()
        return profile

    @staticmethod
    def load_all() -> List["Profile"]:
        profiles = []
        for install_path in LIB_DIR.glob("*/install.json"):
            profile_path = install_path.parent
            if profile_path.is_symlink():
                continue
            profiles.append(Profile.load(profile_path.name))
        return profiles
