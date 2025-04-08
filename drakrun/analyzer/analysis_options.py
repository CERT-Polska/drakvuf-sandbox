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
    plugins: Optional[List[str]] = None
    # Alternative hooks list for apimon
    apimon_hooks_path: Optional[pathlib.Path] = None
    # Alternative syscall list for apimon
    syscall_hooks_path: Optional[pathlib.Path] = None
    # Analysis timeout
    timeout: Optional[int] = None
    # networking: Enable Internet access
    net_enable: Optional[bool] = None
    # extra arguments for Drakvuf command line
    extra_drakvuf_args: Optional[Dict[str, Any]] = None
    # extra directories to create in output dir
    extra_output_subdirs: Optional[List[str]] = None
    # Don't restore/destroy the VM
    no_vm_restore: Optional[bool] = None
    # Don't run a post-restore script
    no_post_restore: Optional[bool] = None

    def apply_config_defaults(self, config: DrakrunConfig):
        if self.plugins is None:
            self.plugins = config.drakrun.plugins
        if self.apimon_hooks_path is None:
            self.apimon_hooks_path = config.drakrun.apimon_hooks_path
        if self.syscall_hooks_path is None:
            self.syscall_hooks_path = config.drakrun.syscall_hooks_path
        if self.extra_drakvuf_args is None:
            self.extra_drakvuf_args = config.drakrun.extra_drakvuf_args
        if self.extra_output_subdirs is None:
            self.extra_output_subdirs = config.drakrun.extra_output_subdirs
        if self.net_enable is None:
            self.net_enable = config.network.net_enable

    def to_dict(self, exclude_none=True):
        return self.model_dump(
            mode="json",
            exclude={"vm_id", "output_dir"},
            exclude_none=exclude_none,
        )
