import pathlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

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
    job_timeout_leeway: int = 600
    net_enable: Optional[bool] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None
    no_post_restore: bool = False
    no_screenshotter: bool = False
    result_ttl: int = -1
    gzip_syscalls: bool = False
    use_7zip: bool = False
    path_to_7zip: str = "C:/Program Files/7-Zip/7z.exe"
    # Override hostname used in worker names on this host.
    # It gets automatically detected if not set.
    worker_hostname: Optional[str] = None
    # Don't pick 'shellexec' method even if supported by Drakvuf
    no_shellexec: bool = False


class DrakrunDefaultsPresetSection(BaseModel):
    plugins: Optional[List[str]] = None
    default_timeout: Optional[int] = None
    job_timeout_leeway: Optional[int] = None
    net_enable: Optional[bool] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    extra_output_subdirs: Optional[List[str]] = None
    no_post_restore: Optional[bool] = None
    no_screenshotter: Optional[bool] = None
    gzip_syscalls: Optional[bool] = None


class CapaConfigSection(BaseModel):
    rules_directory: pathlib.Path = PACKAGE_DIR / "data" / "capa-rules"
    analyze_drakmon_log: bool = True
    analyze_memdumps: bool = False
    analyze_only_malware_pids: bool = False
    worker_pool_processes: int = 4


class MemdumpConfigSection(BaseModel):
    # Maximum total size of collected, uncompressed dumps
    max_total_dumps_size: int = 500 * 1024 * 1024
    # Minimal accepted size of a single memory dump
    min_single_dump_size: int = 512
    # Maximal accepted size of a single memory dump
    max_single_dump_size: int = 32 * 1024 * 1024
    # Drop dumps from System process
    filter_out_system_pid: bool = True


class S3StorageConfigSection(BaseModel):
    enabled: bool = True
    bucket: str = "drakrun"
    address: str
    access_key: str
    secret_key: Optional[str]
    iam_auth: bool = False
    remove_local_after_upload: bool = True


class KartonConfigSection(BaseModel):
    enabled: bool = False
    config_path: Optional[pathlib.Path] = None
    # redis expire timeout for karton results
    redis_ttl: int = 3600
    # How often KartonState is polled to check if analysis is done
    poll_interval: int = 10


class DrakrunConfig(BaseSettings):
    model_config = SettingsConfigDict(
        extra="allow",
        toml_file=CONFIG_PATH,
        env_prefix="drakrun__",
        nested_model_default_partial_update=True,
        env_nested_delimiter="__",
    )
    redis: RedisConfigSection
    network: NetworkConfigSection
    drakrun: DrakrunConfigSection
    capa: CapaConfigSection = CapaConfigSection()
    memdump: MemdumpConfigSection = MemdumpConfigSection()
    karton: KartonConfigSection = KartonConfigSection()
    s3: Optional[S3StorageConfigSection] = None
    preset: Dict[str, DrakrunDefaultsPresetSection] = Field(default_factory=dict)

    def get_drakrun_defaults(
        self, preset_name: Optional[str] = None
    ) -> DrakrunDefaultsPresetSection:
        if preset_name is None:
            preset = dict(DrakrunDefaultsPresetSection())
        elif preset_name not in self.preset:
            raise RuntimeError(f"Preset {preset_name} is not defined in configuration")
        else:
            preset = dict(self.preset[preset_name])
        global_defaults = dict(self.drakrun)
        return DrakrunDefaultsPresetSection(
            **{
                key: (preset[key] if preset[key] is not None else global_defaults[key])
                for key in preset.keys()
            }
        )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            env_settings,
            TomlConfigSettingsSource(settings_cls),
        )


def load_config() -> DrakrunConfig:
    return DrakrunConfig()
