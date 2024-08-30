import configparser
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from configupdater import ConfigUpdater
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator
from typing_extensions import Annotated

from .paths import CONFIG_PATH, PACKAGE_DIR

CommaSeparatedStrList = Annotated[
    List[str],
    BeforeValidator(lambda v: [el.strip() for el in v.split(",") if el.strip()]),
]

DEFAULT_PLUGINS = [
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


class RedisConfigSection(BaseModel):
    host: str
    port: int


class MinioConfigSection(BaseModel):
    address: str
    bucket: Optional[str] = Field(default=None)
    secure: bool
    access_key: str
    secret_key: str


class CapaConfigSection(BaseModel):
    rules_directory: Path = PACKAGE_DIR / "data" / "capa-rules"
    analyze_drakmon_log: bool
    analyze_memdumps: bool
    analyze_only_malware_pids: bool
    worker_pool_processes: int = 4


class DrakrunConfigSection(BaseModel):
    model_config = ConfigDict(extra="ignore")

    raw_memory_dump: bool = Field(default=False)
    net_enable: bool = Field(default=False)
    out_interface: Optional[str] = Field(default=None)
    dns_server: str = Field(default="8.8.8.8")
    syscall_filter: Optional[str] = Field(default=None)
    enable_ipt: bool = Field(default=False)
    analysis_timeout: int = Field(default=10 * 60)
    analysis_low_timeout: Optional[int] = Field(default=None)
    use_root_uid: bool = Field(default=False)
    anti_hammering_threshold: int = Field(default=0)
    attach_profiles: bool = Field(default=False)
    attach_apiscout_profile: bool = Field(default=False)
    xen_cmdline_check: str = Field(default="fail")

    @field_validator("xen_cmdline_check", mode="after")
    @classmethod
    def xen_cmdline_check_validator(cls, v: str):
        allowed_choices = ["fail", "ignore", "no"]
        if v not in allowed_choices:
            raise ValueError(f"must be one of: {allowed_choices}")
        return v


class DrakvufPluginsConfigSection(BaseModel):
    all: CommaSeparatedStrList = Field(
        validation_alias="_all_", default_factory=lambda: list(DEFAULT_PLUGINS)
    )
    low: Optional[CommaSeparatedStrList] = Field(default=None)
    high: Optional[CommaSeparatedStrList] = Field(default=None)

    @field_validator("all", mode="after")
    @classmethod
    def validate_plugin_list(cls, plugin_list: List[str]) -> List[str]:
        if not plugin_list:
            raise ValueError("_all_ plugin list must not be empty")
        return plugin_list

    def get_plugin_list(self, quality: str = "high") -> List[str]:
        if quality not in ["all", "low", "high"]:
            raise ValueError(f"'{quality}' is not a valid feed quality level")
        priority_plugin_list = getattr(self, quality)
        if priority_plugin_list:
            plugin_list = list(priority_plugin_list)
        else:
            plugin_list = list(self.all)
        if "ipt" in plugin_list and "codemon" not in plugin_list:
            # Using ipt plugin implies using codemon
            plugin_list.append("codemon")
        return plugin_list


class DrakrunConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    redis: RedisConfigSection
    minio: MinioConfigSection
    drakrun: DrakrunConfigSection
    drakvuf_plugins: DrakvufPluginsConfigSection
    capa: CapaConfigSection

    @staticmethod
    def _file_to_dict(filename: str) -> Dict[str, Dict[str, str]]:
        config = configparser.ConfigParser()
        config.read(filename)
        return {section: {**config[section]} for section in config.sections()}

    @staticmethod
    def _env_to_dict() -> Dict[str, Dict[str, str]]:
        config_dict = defaultdict(dict)
        for name, value in os.environ.items():
            # Load env variables named DRAKRUN_[section]_[key]
            # to match ConfigParser structure
            result = re.fullmatch(r"DRAKRUN_([A-Z0-9-]+)_([A-Z0-9_]+)", name)

            if not result:
                continue

            section, key = result.groups()
            section = section.lower()
            key = key.lower()

            config_dict[section][key] = value
        return dict(config_dict)

    @staticmethod
    def load(filename: str) -> "DrakrunConfig":
        dict_from_file = DrakrunConfig._file_to_dict(filename)
        dict_from_env = DrakrunConfig._env_to_dict()
        return DrakrunConfig(**{**dict_from_file, **dict_from_env})

    def update(self, filename: str) -> None:
        """
        Writes back some changes into main config file
        """
        updater = ConfigUpdater()
        updater.read(filename)
        updater["redis"]["host"] = self.redis.host
        updater["redis"]["port"] = str(self.redis.port)
        updater["minio"]["address"] = self.minio.address
        updater["minio"]["access_key"] = self.minio.access_key
        updater["minio"]["secret_key"] = self.minio.secret_key
        updater["minio"]["secure"] = "1" if self.minio.secure else "0"
        updater["minio"]["bucket"] = self.minio.bucket
        updater.update_file()


def load_config() -> DrakrunConfig:
    return DrakrunConfig.load(CONFIG_PATH)


def update_config(config: DrakrunConfig):
    config.update(CONFIG_PATH)
