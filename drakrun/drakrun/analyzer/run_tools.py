import contextlib
import pathlib
import subprocess
from typing import List, Optional

from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.network_info import NetworkConfiguration
from drakrun.lib.networking import start_tcpdump_collector
from drakrun.lib.vm import VirtualMachine


@contextlib.contextmanager
def process_graceful_exit(proc: subprocess.Popen, termination_timeout: int = 5):
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(termination_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(termination_timeout)


def run_tcpdump(vm: VirtualMachine, output_file: pathlib.Path):
    return process_graceful_exit(start_tcpdump_collector(vm.get_domid(), output_file))


@contextlib.contextmanager
def run_drakvuf(
    vm_name: str,
    vmi_info: VmiInfo,
    kernel_profile_path: str,
    output_file: pathlib.Path,
    drakvuf_args: List[str],
    drakvuf_timeout: Optional[int] = None,
):
    drakvuf_cmdline = get_base_drakvuf_cmdline(
        vm_name,
        kernel_profile_path,
        vmi_info,
        timeout=drakvuf_timeout,
        extra_args=drakvuf_args,
    )

    with output_file.open("wb") as output:
        drakvuf = subprocess.Popen(drakvuf_cmdline, stdout=output)
        with process_graceful_exit(drakvuf):
            yield drakvuf


@contextlib.contextmanager
def run_vm(vm_id: int, install_info: InstallInfo, network_conf: NetworkConfiguration):
    vm = VirtualMachine(vm_id, install_info, network_conf)
    vm.restore()
    try:
        yield vm
    finally:
        vm.destroy()
