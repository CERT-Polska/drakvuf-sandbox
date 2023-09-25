import json
import subprocess
from typing import List

from .profile import RuntimeInfo


class Injector:
    """Helper class, simplifying usage of DRAKVUF Injector"""

    def __init__(
        self, vm_name: str, runtime_info: RuntimeInfo, kernel_profile_path: str
    ):
        self.vm_name = vm_name
        self.kernel_profile_path = kernel_profile_path
        self.runtime_info = runtime_info

    def _raise_error(self, output: str):
        parsed_error = json.loads(output)
        if parsed_error.get("Status") == "Error":
            if parsed_error.get("ErrorCode") == 2:
                raise InjectorFileNotFound("File was not found", output)
        elif parsed_error.get("Status") == "Timeout":
            raise InjectorTimeout("Injection timeout", output)
        else:
            details_fields = ["Status", "Error", "ErrorCode"]
            details = ", ".join(
                [
                    f"{detail}={parsed_error[detail]}"
                    for detail in details_fields
                    if detail in parsed_error
                ]
            )
            raise InjectorError(f"Injector error has occurred ({details})", output)

    def execute(self, method: str, args: List[str], timeout: int):
        cmd_args = [
            "injector",
            "-o",
            "json",
            "-d",
            self.vm_name,
            "-r",
            self.kernel_profile_path,
            "-i",
            str(self.runtime_info.inject_pid),
            "-k",
            hex(self.runtime_info.vmi_offsets.kpgd),
            "-m",
            method,
            "--timeout",
            str(timeout),
        ] + args
        try:
            result = subprocess.check_output(cmd_args, text=True)
            return json.loads(result)
        except subprocess.CalledProcessError as e:
            self._raise_error(e.stdout)

    def write_file(
        self, local_path: str, remote_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Copy local file to the VM
        """
        return self.execute(
            "writefile", ["-e", remote_path, "-B", local_path], timeout=timeout
        )

    def read_file(
        self, remote_path: str, local_path: str, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        return self.execute(
            "readfile", ["-e", remote_path, "-B", local_path], timeout=timeout
        )

    def create_process(
        self, cmdline: str, wait: bool = False, timeout: int = 60
    ) -> subprocess.CompletedProcess:
        """
        Create a process inside the VM with given command line
        we pass (timeout-5) to drakvuf to give it 5 seconds to finish it's loop
        """
        args = ["-e", cmdline]
        if wait:
            args += ["-w"]
        return self.execute("createproc", args, timeout=timeout)


class InjectorError(Exception):
    def __init__(self, message, output):
        super().__init__(message)
        self.output = output


class InjectorTimeout(InjectorError):
    pass


class InjectorFileNotFound(InjectorError):
    pass
