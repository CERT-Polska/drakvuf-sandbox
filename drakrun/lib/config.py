import configparser
import pathlib
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, ConfigDict

from drakrun.lib.paths import CONFIG_PATH

DNS_USE_GATEWAY_ADDRESS = "use-gateway-address"
OUT_INTERFACE_DEFAULT = "default"

class NetworkConfigSection(BaseModel):
    dns_server: str
    out_interface: str
    net_enable: bool

class DrakrunConfigSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    plugins: List[str] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None

class DrakrunConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    network: NetworkConfigSection
    drakrun: DrakrunConfigSection

    @staticmethod
    def _file_to_dict(filename: str) -> Dict[str, Dict[str, str]]:
        config = configparser.ConfigParser()
        config.read(filename)
        return {section: {**config[section]} for section in config.sections()}

    @staticmethod
    def load(filename: str) -> "DrakrunConfig":
        dict_from_file = DrakrunConfig._file_to_dict(filename)
        return DrakrunConfig(**dict_from_file)


def load_config() -> DrakrunConfig:
    return DrakrunConfig.load(CONFIG_PATH)
