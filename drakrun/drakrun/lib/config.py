import configparser
from typing import Optional, List, Dict, Any

from pydantic import BaseModel, ConfigDict, Field, BeforeValidator, model_validator
from typing_extensions import Annotated
from .paths import CONFIG_PATH

CommaSeparatedStrList = Annotated[
    List[str],
    BeforeValidator(lambda v: [el.strip() for el in v.split(",") if el.strip()])
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
    model_config = ConfigDict(extra='ignore')

    raw_memory_dump: bool = Field(default=False)
    net_enable: bool = Field(default=False)
    out_interface: Optional[str] = Field(default=None)
    dns_server: str = Field(default="8.8.8.8")
    syscall_filter: Optional[str] = Field(default=None)
    enable_ipt: bool = Field(default=False)
    analysis_timeout: int = Field(default=10*60)
    analysis_low_timeout: int = Field(default=10*60)
    use_root_uid: bool = Field(default=False)
    anti_hammering_threshold: int = Field(default=0)
    attach_profiles: bool = Field(default=False)
    attach_apiscout_profile: bool = Field(default=False)

    @model_validator(mode="before")
    @classmethod
    def default_low_timeout(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        # If analysis_low_timeout defined separately: leave it as is
        if "analysis_low_timeout" in data and data["analysis_low_timeout"]:
            return data
        # If not defined but analysis_timeout defined: map timeout to low_timeout
        if "analysis_timeout" in data:
            return {"analysis_low_timeout": data["analysis_timeout"], **data}
        # If also not defined: use defaults
        return data


class DrakvufPluginsConfigSection(BaseModel):
    model_config = ConfigDict(extra='ignore')

    # TODO: provide default list of plugins
    # TODO: validate things like "codemon" must appear with "ipt"
    # TODO: let's disallow 'no plugins', it's useless and it's not easy to turn off all plugins
    # TODO: finally, let's make a method that allows to get a list to be used for given priority
    all: CommaSeparatedStrList
    low: CommaSeparatedStrList
    normal: CommaSeparatedStrList
    high: CommaSeparatedStrList


class DrakrunConfig(BaseModel):
    model_config = ConfigDict(extra='ignore')

    redis: RedisConfigSection
    minio: MinioConfigSection
    drakrun: DrakrunConfigSection
    drakvuf_plugins: DrakvufPluginsConfigSection

    @staticmethod
    def load_from_file(filename: str) -> "DrakrunConfig":
        config = configparser.ConfigParser()
        config.read(filename)
        return DrakrunConfig(**{section: {**config[section]} for section in config.sections()})


def load_config() -> DrakrunConfig:
    return DrakrunConfig.load_from_file(CONFIG_PATH)
