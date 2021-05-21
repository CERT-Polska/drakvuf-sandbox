import subprocess
from typing import List
from drakrun.util import RuntimeInfo


class Injector:
    """ Helper class, simplifying usage of DRAKVUF Injector """

    def __init__(self, vm_name: str, runtime_info: RuntimeInfo, kernel_profile: str):
        self.vm_name = vm_name
        self.kernel_profile = kernel_profile
        self.runtime_info = runtime_info

    def _get_cmdline_generic(self, method: str) -> List[str]:
        """ Build base command line for all injection methods """
        return [
            "injector",
            "-o",
            "json",
            "-d",
            self.vm_name,
            "-r",
            self.kernel_profile,
            "-i",
            str(self.runtime_info.inject_pid),
            "-k",
            hex(self.runtime_info.vmi_offsets.kpgd),
            "-m",
            method,
        ]

    def _get_cmdline_writefile(self, local: str, remote: str) -> List[str]:
        cmd = self._get_cmdline_generic("writefile")
        cmd.extend(["-e", remote])
        cmd.extend(["-B", local])
        return cmd

    def _get_cmdline_readfile(self, remote: str, local: str) -> List[str]:
        cmd = self._get_cmdline_generic("readfile")
        cmd.extend(["-e", remote])
        cmd.extend(["-B", local])
        return cmd

    def _get_cmdline_createproc(self, exec_cmd: str, wait: bool = False) -> List[str]:
        cmd = self._get_cmdline_generic("createproc")
        cmd.extend(["-e", exec_cmd])
        if wait:
            cmd.append("-w")
        return cmd

    def write_file(
        self, local_path: str, remote_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """ Copy local file to the VM """
        injector_cmd = self._get_cmdline_writefile(local_path, remote_path)
        return subprocess.run(
            injector_cmd, stdout=subprocess.PIPE, timeout=timeout, check=True
        )

    def read_file(
        self, remote_path: str, local_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """ Copy VM file to local """
        injector_cmd = self._get_cmdline_readfile(remote_path, local_path)
        return subprocess.run(injector_cmd, timeout=timeout, capture_output=True)

    def create_process(
        self, cmdline: str, wait: bool = False, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        injector_cmd = self._get_cmdline_createproc(cmdline, wait=wait)
        """ Create a process inside the VM with given command line """
        return subprocess.run(injector_cmd, check=True)
