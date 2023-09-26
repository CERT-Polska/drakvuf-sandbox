import os
import secrets
import shutil
import string
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .util import DataClassConfigMixin

ETC_DIR = Path(os.getenv("DRAKLIB_ETC_DIR") or "/etc/draklib")
LIB_DIR = Path(os.getenv("DRAKLIB_LIB_DIR") or "/var/lib/draklib")
STATIC_DIR = Path(__file__).parent / "static"


@dataclass
class Parameters(DataClassConfigMixin):
    out_interface: str
    dns_server: str = "8.8.8.8"
    # This is not only partially a default
    # For next profile, next range is allocated
    subnet_addr: str = "10.13.N.0"

    _FILENAME = "config.json"

    @staticmethod
    def get_default_subnet_addr():
        """
        This method is required to find defaults that does not
        collide with already created profiles
        """
        default_subnet_addr = Parameters.subnet_addr.split(".")
        default_next_subnet = int(default_subnet_addr[1])

        for config in Configuration.load_all():
            subnet_addr = config.parameters.subnet_addr.split(".")
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


@dataclass
class InstallInfo(DataClassConfigMixin):
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


class Configuration:
    """
    Configurations are different VM setups for easier targeting different
    Windows versions e.g. Win7x86, Win7x64, Win10-15063 etc.

    For simple environments it's enough to have just the "default" profile,
    which is the default one.

    This object gives access to basic persistent files and configurations
    """

    DEFAULT_NAME = "default"

    def __init__(self, name: str, parameters: Parameters, install_info: InstallInfo):
        self.name = name
        self.parameters = parameters
        self.install_info = install_info

    @property
    def etc_dir(self) -> Path:
        return ETC_DIR / self.name

    @property
    def lib_dir(self) -> Path:
        return LIB_DIR / self.name

    @property
    def volumes_dir(self) -> Path:
        return self.lib_dir / "volumes"

    @property
    def snapshot_path(self) -> Path:
        return self.volumes_dir / "snapshot.sav"

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
        if self.name == self.DEFAULT_NAME:
            return f"vm-{vm_id}"
        else:
            return f"{self.name}-vm-{vm_id}"

    def ip_from_vm_id(self, vm_id: int, host_id: int):
        subnet_ip = self.parameters.subnet_addr.replace("N", str(vm_id))
        return ".".join(subnet_ip.split(".")[:3] + [str(host_id)])

    @staticmethod
    def resolve_name(name: Optional[str]) -> str:
        """
        Finds an actual name of default profile if empty profile name provided.
        """
        if not name:
            lib_dir = LIB_DIR / Configuration.DEFAULT_NAME
            if lib_dir.is_symlink():
                return lib_dir.readlink().name
            else:
                return Configuration.DEFAULT_NAME
        return name

    @staticmethod
    def exists(name: Optional[str] = None) -> bool:
        name = Configuration.resolve_name(name)
        lib_dir = LIB_DIR / name
        return lib_dir.exists()

    @staticmethod
    def load(name: Optional[str] = None) -> "Configuration":
        name = Configuration.resolve_name(name)
        etc_dir = ETC_DIR / name
        lib_dir = LIB_DIR / name
        if not lib_dir.exists():
            raise RuntimeError(f"Configuration '{name}' doesn't exist")

        parameters = Parameters.load(etc_dir)
        install_info = InstallInfo.load(lib_dir)
        return Configuration(name, install_info, parameters)

    def _initialize(self) -> None:
        self.volumes_dir.mkdir()
        self.vm_profile_dir.mkdir()
        self.vm_config_dir.mkdir()

        template = (STATIC_DIR / "vm.cfg.template").read_text()
        passwd_characters = string.ascii_letters + string.digits
        passwd = "".join(secrets.choice(passwd_characters) for _ in range(20))
        template = template.replace("{{ VNC_PASS }}", passwd)
        self.vm_template_path.write_text(template)

        shutil.copyfile(STATIC_DIR / "hooks.txt", self.etc_dir / "hooks.txt")

    @staticmethod
    def create(
        name: Optional[str], parameters: Parameters, install_info: InstallInfo
    ) -> "Configuration":
        name = name or Configuration.DEFAULT_NAME
        etc_dir = ETC_DIR / name
        lib_dir = LIB_DIR / name
        if lib_dir.exists():
            raise RuntimeError(f"Configuration '{name}' already exists")
        etc_dir.mkdir(parents=True)
        lib_dir.mkdir(parents=True)
        parameters.save(etc_dir)
        install_info.save(lib_dir)

        config = Configuration(name, parameters, install_info)
        config._initialize()
        return config

    @staticmethod
    def load_all() -> List["Configuration"]:
        configs = []
        for install_path in LIB_DIR.glob("*/install.json"):
            config_path = install_path.parent
            if config_path.is_symlink():
                continue
            configs.append(Configuration.load(config_path.name))
        return configs

    @staticmethod
    def delete(name: Optional[str]) -> None:
        name = Configuration.resolve_name(name)
        lib_dir = LIB_DIR / name
        shutil.rmtree(lib_dir)
        etc_dir = ETC_DIR / name
        shutil.rmtree(etc_dir)
