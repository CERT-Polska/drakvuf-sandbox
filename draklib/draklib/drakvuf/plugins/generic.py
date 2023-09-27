import shutil
from pathlib import Path
from typing import List, Optional

from ...config import Configuration


class DrakvufPlugin:
    plugin_name = ""

    def __init__(self, plugin_name: Optional[str] = None):
        if plugin_name is not None:
            self.plugin_name = plugin_name

    def init_analysis(self, config: Configuration, analysis_dir: Path):
        return

    def get_plugin_cmdline(self) -> List[str]:
        return ["-a", self.plugin_name]

    def finish_analysis(self):
        return


class ApimonDrakvufPlugin(DrakvufPlugin):
    plugin_name = "apimon"

    def __init__(self, plugin_name: Optional[str] = None):
        super().__init__(plugin_name)
        self.dll_hooks_list = None

    def init_analysis(self, config: Configuration, analysis_dir: Path):
        self.dll_hooks_list = analysis_dir / "hooks.txt"
        if not self.dll_hooks_list.exists():
            shutil.copyfile(config.etc_dir / "hooks.txt", self.dll_hooks_list)

    def get_plugin_cmdline(self) -> List[str]:
        return super().get_plugin_cmdline() + [
            "--dll-hooks-list",
            str(self.dll_hooks_list),
        ]


class BsodmonDrakvufPlugin(DrakvufPlugin):
    plugin_name = "bsodmon"

    def __init__(self, plugin_name: Optional[str] = None):
        super().__init__(plugin_name)
        self.crashdump_dir = None

    def init_analysis(self, config: Configuration, analysis_dir: Path):
        self.crashdump_dir = analysis_dir / "bsods"
        self.crashdump_dir.mkdir(exist_ok=True)

    def get_plugin_cmdline(self) -> List[str]:
        return super().get_plugin_cmdline() + [
            "--crashdump-dir",
            str(self.crashdump_dir),
        ]

    def finish_analysis(self):
        # todo: remove directory if empty
        return
