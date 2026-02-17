import pathlib
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from drakrun.lib.config import DrakrunConfig


class AnalysisOptions(BaseModel):
    # Host sample path (local filesystem or None when using S3)
    host_sample_path: Optional[pathlib.Path] = None
    # Filename of the uploaded sample (archive name for archives, executable for normal files)
    sample_filename: Optional[str] = None
    # Guest VM: entry path inside archive (e.g., "setup/setup.exe")
    guest_archive_entry_path: Optional[str] = None
    # Target directory on guest VM (where files will be placed)
    guest_target_directory: pathlib.PureWindowsPath = pathlib.PureWindowsPath(
        "%USERPROFILE%\\Desktop\\"
    )
    # Start command to run on the VM
    start_command: Optional[Union[List[str], str]] = None
    # Preset of defaults to be used for analysis
    preset: Optional[str] = None
    # Plugins to enable
    plugins: List[str]
    # Alternative hooks list for apimon
    apimon_hooks_path: Optional[pathlib.Path] = None
    # Alternative syscall list for apimon
    syscall_hooks_path: Optional[pathlib.Path] = None
    # Analysis timeout
    timeout: Optional[int] = None
    # Job timeout leeway for worker
    job_timeout_leeway: Optional[int] = None
    # networking: Enable Internet access
    net_enable: bool
    # extra arguments for Drakvuf command line
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    # extra directories to create in output dir
    extra_output_subdirs: Optional[List[str]] = None
    # Don't restore/destroy the VM
    no_vm_restore: Optional[bool] = None
    # Don't run a post-restore script
    no_post_restore: Optional[bool] = None
    # Don't make screenshots during analysis
    no_screenshotter: Optional[bool] = None
    # If .zip archive is passed, extract it before analysis
    extract_archive: Optional[bool] = None
    # Archive password for 'extract_archive' function
    archive_password: Optional[str] = None

    @staticmethod
    def _apply_defaults(
        config: DrakrunConfig, options: Dict[str, Any]
    ) -> Dict[str, Any]:
        defaults = config.get_drakrun_defaults(options.get("preset"))
        if not config.network.net_enable:
            # If network access is globally disabled, enforce net_enable=False
            net_enable = False
        else:
            # If network access is globally enabled, use value from options
            net_enable = options.get("net_enable", defaults.net_enable)
            # If unset, set True
            if net_enable is None:
                net_enable = True
        defaults_dict = dict(defaults)
        return {
            **options,
            **{
                key: (
                    options.get(key)
                    if options.get(key) is not None
                    else defaults_dict[key]
                )
                for key in defaults_dict.keys()
            },
            **dict(net_enable=net_enable),
        }

    @classmethod
    def with_config_defaults(cls, config: DrakrunConfig, **kwargs):
        return cls(
            **cls._apply_defaults(config, kwargs),
        )

    def to_dict(self, exclude_none=True):
        return self.model_dump(
            mode="json",
            exclude={"vm_id", "output_dir"},
            exclude_none=exclude_none,
        )
