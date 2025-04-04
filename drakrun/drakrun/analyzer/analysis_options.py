import json
import pathlib
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

DEFAULT_PLUGINS = [
    "apimon",
    "exmon",
    "memdump",
    "procmon",
    "regmon",
    "socketmon",
    "tlsmon",
]


class AnalysisOptions(BaseModel):
    # VM id to use for analysis
    vm_id: int
    # Output directory for analysis artifacts
    output_dir: pathlib.Path
    # Host sample path
    sample_path: Optional[pathlib.Path] = None
    # Target file name on guest VM
    target_filename: Optional[str] = None
    # Start command to run on the VM
    start_command: Optional[Union[List[str], str]] = None
    # Plugins to enable
    plugins: List[str] = DEFAULT_PLUGINS
    # Alternative hooks list for apimon
    apimon_hooks_path: Optional[pathlib.Path] = None
    # Alternative syscall list for apimon
    syscall_hooks_path: Optional[pathlib.Path] = None
    # Analysis timeout
    timeout: Optional[int] = None
    # networking: DNS server
    dns_server: Optional[str] = None
    # networking: Output interface
    out_interface: Optional[str] = None
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

    def load(self, path: pathlib.Path) -> "AnalysisOptions":
        """Loads additional AnalysisOptions from file"""
        obj = self.model_dump()
        with path.open("r") as f:
            obj.update(json.loads(f.read()))
        return AnalysisOptions.model_validate(obj)

    def to_dict(self, exclude_none=True):
        return self.model_dump(
            mode="json",
            exclude={"vm_id", "output_dir"},
            exclude_none=exclude_none,
        )

    def save(self, path: pathlib.Path) -> None:
        """Serializes self and writes to the provided path"""
        with path.open("w") as f:
            f.write(json.dumps(self.to_dict()))
