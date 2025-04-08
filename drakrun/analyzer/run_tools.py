import contextlib
import pathlib
import subprocess
from typing import List

from drakrun.lib.config import NetworkConfigSection
from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.network_info import NetworkInfo
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


def run_tcpdump(network_info: NetworkInfo, output_file: pathlib.Path):
    return process_graceful_exit(
        start_tcpdump_collector(network_info.bridge_name, output_file)
    )


@contextlib.contextmanager
def run_drakvuf(
    vm_name: str,
    vmi_info: VmiInfo,
    kernel_profile_path: str,
    output_file: pathlib.Path,
    drakvuf_args: List[str],
):
    drakvuf_cmdline = get_base_drakvuf_cmdline(
        vm_name,
        kernel_profile_path,
        vmi_info,
        extra_args=drakvuf_args,
    )

    with output_file.open("wb") as output:
        drakvuf = subprocess.Popen(drakvuf_cmdline, stdout=output)
        with process_graceful_exit(drakvuf):
            yield drakvuf


@contextlib.contextmanager
def run_vm(
    vm_id: int,
    install_info: InstallInfo,
    network_conf: NetworkConfigSection,
    no_restore: bool = False,
):
    vm = VirtualMachine(vm_id, install_info, network_conf)
    if no_restore:
        if not vm.is_running:
            raise RuntimeError(f"Virtual machine {vm.vm_name} is not running")
        yield vm
    else:
        vm.restore()
        try:
            yield vm
        finally:
            vm.destroy()
