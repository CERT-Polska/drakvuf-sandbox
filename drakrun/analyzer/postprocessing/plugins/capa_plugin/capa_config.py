from pathlib import Path

from pydantic import BaseModel

from drakrun.lib.paths import PACKAGE_DIR


class CapaConfigSection(BaseModel):
    rules_directory: Path = PACKAGE_DIR / "data" / "capa-rules"
    analyze_drakmon_log: bool = True
    analyze_memdumps: bool = False
    analyze_only_malware_pids: bool = False
    worker_pool_processes: int = 4
