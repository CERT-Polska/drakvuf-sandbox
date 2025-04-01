import pathlib
from dataclasses import dataclass
from typing import List, Optional, Union


@dataclass
class AnalysisOptions:
    vm_id: int
    output_dir: pathlib.Path
    sample_path: Optional[pathlib.Path] = None
    target_filename: Optional[str] = None
    plugins: Optional[List[str]] = None
    apimon_hooks_path: Optional[pathlib.Path] = None
    syscall_hooks_path: Optional[pathlib.Path] = None
    timeout: int = 600
    start_command: Optional[Union[List[str], str]] = None
    extension: Optional[str] = None
    dns_server: Optional[str] = None
    out_interface: Optional[str] = None
    net_enable: Optional[bool] = None
    extra_drakvuf_args: Optional[List[str]] = None
