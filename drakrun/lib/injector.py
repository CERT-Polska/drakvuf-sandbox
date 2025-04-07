import subprocess
from typing import List

from .drakvuf_cmdline import get_base_injector_cmdline
from .libvmi import VmiInfo


class Injector:
    """Helper class, simplifying usage of DRAKVUF Injector"""

    def __init__(self, vm_name: str, vmi_info: VmiInfo, kernel_profile_path: str):
        self.vm_name = vm_name
        self.kernel_profile_path = kernel_profile_path
        self.vmi_info = vmi_info

    def _run_with_timeout(
        self,
        args: List[str],
        timeout: int,
        check: bool = False,
        capture_output: bool = False,
    ):
        """
        subprocess.run(timeout=...) kills process instead of sending SIGTERM after
        reaching timeout. In our case, we want to let injector do a clean termination.
        """
        kwargs = {}
        if capture_output:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.PIPE
        with subprocess.Popen(args, **kwargs) as proc:
            try:
                outs, errs = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout)
                raise
            finally:
                if proc.poll() is None:
                    proc.kill()
            retcode = proc.poll()
            if check and retcode:
                raise subprocess.CalledProcessError(
                    retcode, proc.args, output=outs, stderr=errs
                )
            return subprocess.CompletedProcess(proc.args, retcode, outs, errs)

    def get_cmdline_generic(self, method: str, args: List[str]) -> List[str]:
        """Build base command line for all injection methods"""
        return get_base_injector_cmdline(
            self.vm_name, self.kernel_profile_path, self.vmi_info, method, args
        )

    def get_cmdline_writefile(self, local: str, remote: str) -> List[str]:
        return self.get_cmdline_generic("writefile", ["-e", remote, "-B", local])

    def get_cmdline_readfile(self, remote: str, local: str) -> List[str]:
        return self.get_cmdline_generic("readfile", ["-e", remote, "-B", local])

    def get_cmdline_createproc(self, exec_cmd: str, wait: bool = False) -> List[str]:
        return self.get_cmdline_generic(
            "createproc", ["-e", exec_cmd, *(["-w"] if wait else [])]
        )

    def get_cmdline_shellcode(self, shellcode_path: str) -> List[str]:
        return self.get_cmdline_generic("shellcode", ["-e", shellcode_path])

    def write_file(
        self, local_path: str, remote_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Copy local file to the VM
        """
        injector_cmd = self.get_cmdline_writefile(local_path, remote_path)
        return self._run_with_timeout(
            injector_cmd, timeout=timeout, check=True, capture_output=True
        )

    def read_file(
        self, remote_path: str, local_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Copy VM file to local
        """
        injector_cmd = self.get_cmdline_readfile(remote_path, local_path)
        return self._run_with_timeout(
            injector_cmd, timeout=timeout, capture_output=True
        )

    def create_process(
        self, cmdline: str, wait: bool = False, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Create a process inside the VM with given command line
        """
        injector_cmd = self.get_cmdline_createproc(cmdline, wait=wait)
        return self._run_with_timeout(injector_cmd, timeout=timeout, check=True)

    def inject_shellcode(self, shellcode_path: str, timeout: int = 60):
        injector_cmd = self.get_cmdline_shellcode(shellcode_path)
        return self._run_with_timeout(injector_cmd, timeout=timeout, check=True)
