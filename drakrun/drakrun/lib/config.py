import configparser
from typing import List, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator
from typing_extensions import Annotated

from .paths import CONFIG_PATH

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
    bucket: str
    secure: bool
    access_key: str
    secret_key: str


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


class DrakvufPluginsConfigSection(BaseModel):
    all: CommaSeparatedStrList = Field(
        validation_alias="_all_", default_factory=lambda: list(DEFAULT_PLUGINS)
    )
    low: CommaSeparatedStrList
    high: CommaSeparatedStrList

    @field_validator("all", mode="after")
    @classmethod
    def validate_plugin_list(cls, plugin_list: List[str]) -> List[str]:
        if not plugin_list:
            raise ValueError("_all_ plugin list must not be empty")
        return plugin_list

    def get_plugin_list(self, quality: str = "high") -> List[str]:
        if quality not in self.model_fields_set:
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

    @staticmethod
    def load_from_file(filename: str) -> "DrakrunConfig":
        config = configparser.ConfigParser()
        config.read(filename)
        return DrakrunConfig(
            **{section: {**config[section]} for section in config.sections()}
        )


def load_config() -> DrakrunConfig:
    return DrakrunConfig.load_from_file(CONFIG_PATH)
