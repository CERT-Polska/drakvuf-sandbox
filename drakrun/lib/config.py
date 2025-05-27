import pathlib
from typing import Any, Dict, List, Optional

import tomli
from pydantic import BaseModel, ConfigDict

from drakrun.lib.paths import CONFIG_PATH, PACKAGE_DIR

DNS_USE_GATEWAY_ADDRESS = "use-gateway-address"
OUT_INTERFACE_DEFAULT = "default"


class RedisConfigSection(BaseModel):
    host: str = "localhost"
    port: int = 6379
    username: Optional[str] = None
    password: Optional[str] = None

    def make_url(self):
        if self.username is not None and self.password is not None:
            return f"redis://{self.username}:{self.password}@{self.host}:{self.port}"
        else:
            return f"redis://{self.host}:{self.port}"


class NetworkConfigSection(BaseModel):
    dns_server: str
    out_interface: str
    net_enable: bool


class DrakrunConfigSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    plugins: List[str]
    default_timeout: int
    job_timeout_leeway: int = 300
    """Give extra 5 minutes as a timeout for whole analysis process
    including VM restore, post-restore, drakvuf hard timeout and
    postprocessing."""
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None


class CapaConfigSection(BaseModel):
    rules_directory: pathlib.Path = PACKAGE_DIR / "data" / "capa-rules"
    analyze_drakmon_log: bool = True
    analyze_memdumps: bool = False
    analyze_only_malware_pids: bool = False
    worker_pool_processes: int = 4


class DrakrunConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    redis: RedisConfigSection
    network: NetworkConfigSection
    drakrun: DrakrunConfigSection
    capa: CapaConfigSection = CapaConfigSection()

    @staticmethod
    def load(filename: str) -> "DrakrunConfig":
        with open(filename, "rb") as f:
            config = tomli.load(f)
        return DrakrunConfig.model_validate(config)


def load_config() -> DrakrunConfig:
    return DrakrunConfig.load(CONFIG_PATH)
