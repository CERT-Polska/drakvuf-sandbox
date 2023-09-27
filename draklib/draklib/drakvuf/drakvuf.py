from typing import List

from ..config import Configuration
from .dlls import all_dll_file_list
from .profile import RuntimeInfo


class Drakvuf:
    def __init__(
        self,
        config: Configuration,
        vm_id: int,
        runtime_info: RuntimeInfo,
        kernel_profile_path: str,
    ):
        self.config = config
        self.vm_id = vm_id
        self.vm_name = config.get_vm_name(vm_id)
        self.runtime_info = runtime_info
        self.kernel_profile_path = kernel_profile_path

    def get_dll_profile_args(self) -> List[str]:
        args = []
        for dllspec in all_dll_file_list:
            if not dllspec.arg:
                continue
            dll_profile_path = self.config.vm_profile_dir / f"{dllspec.dest}.json"
            if dll_profile_path.exists():
                args.extend([dllspec.arg, str(dll_profile_path)])
        return args

    def get_base_drakvuf_cmdline(
        self, timeout, full_cmd, cwd, debug=False
    ) -> List[str]:
        drakvuf_cmd = [
            "drakvuf",
            "-o",
            "json",
            # be aware of https://github.com/tklengyel/drakvuf/pull/951
            "-F",  # enable fast singlestep
            "-j",
            "60",  # injection timeout = 60
            "-t",
            str(timeout),
            "-i",
            str(self.runtime_info.inject_pid),
            "-k",
            hex(self.runtime_info.vmi_offsets.kpgd),
            "-d",
            self.vm_name,
            "-e",
            full_cmd,
            "-r",
            self.kernel_profile_path,
            "-c",
            cwd,
        ] + self.get_dll_profile_args()
        if debug:
            drakvuf_cmd.extend(["-v"])
        return drakvuf_cmd
