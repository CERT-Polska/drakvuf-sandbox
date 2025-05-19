import pathlib
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from drakrun.lib.config import DrakrunConfig


class AnalysisOptions(BaseModel):
    # Host sample path
    sample_path: Optional[pathlib.Path] = None
    # Target file name on guest VM
    target_filename: Optional[str] = None
    # Start command to run on the VM
    start_command: Optional[Union[List[str], str]] = None
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

    def __init__(self, config: DrakrunConfig, **kwargs):
        net_enable = kwargs.get("net_enable")
        if net_enable is None:
            net_enable = config.network.net_enable

        super().__init__(
            **{
                **kwargs,
                **dict(
                    plugins=kwargs.get("plugins") or config.drakrun.plugins,
                    apimon_hooks_path=kwargs.get("apimon_hooks_path")
                    or config.drakrun.apimon_hooks_path,
                    syscall_hooks_path=kwargs.get("syscall_hooks_path")
                    or config.drakrun.syscall_hooks_path,
                    net_enable=net_enable,
                ),
            },
        )

    def to_dict(self, exclude_none=True):
        return self.model_dump(
            mode="json",
            exclude={"vm_id", "output_dir"},
            exclude_none=exclude_none,
        )
