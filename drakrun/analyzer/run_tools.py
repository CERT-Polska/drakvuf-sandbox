import contextlib
import logging
import pathlib
import subprocess
import threading
import time
from typing import List, Optional

from drakrun.analyzer.screenshotter import Screenshotter
from drakrun.lib.config import NetworkConfigSection
from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.network_info import NetworkInfo
from drakrun.lib.networking import start_tcpdump_collector
from drakrun.lib.vm import VirtualMachine

logger = logging.getLogger(__name__)


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


def log_activity_watchdog(
    output_file: pathlib.Path,
    stop_event: threading.Event,
    inactivity_threshold: int = 30,
):
    last_size = 0
    last_activity_time = time.time()

    while not stop_event.is_set():
        time.sleep(5)

        try:
            current_size = output_file.stat().st_size

            if current_size > last_size:
                last_activity_time = time.time()
                last_size = current_size
            else:
                inactive_duration = time.time() - last_activity_time

                if inactive_duration > inactivity_threshold:
                    logger.warning(
                        f"DRAKVUF output inactive for {inactive_duration} - possible VM crash"
                    )
                    last_activity_time = time.time()
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.debug(f"Watchdog error: {e}")


@contextlib.contextmanager
def run_drakvuf(
    vm_name: str,
    vmi_info: VmiInfo,
    kernel_profile_path: str,
    output_file: pathlib.Path,
    drakvuf_args: List[str],
    exec_cmd: Optional[str] = None,
    cwd: Optional[pathlib.Path] = None,
):
    drakvuf_cmdline = get_base_drakvuf_cmdline(
        vm_name,
        kernel_profile_path,
        vmi_info,
        exec_cmd=exec_cmd,
        extra_args=drakvuf_args,
    )

    stop_watchdog = threading.Event()
    watchdog_thread = threading.Thread(
        target=log_activity_watchdog,
        args=(output_file, stop_watchdog),
        daemon=True,
        name="drakvuf-watchdog",
    )
    watchdog_thread.start()

    try:
        with output_file.open("wb") as output:
            drakvuf = subprocess.Popen(
                drakvuf_cmdline, stdout=output, cwd=cwd
            )
            with process_graceful_exit(drakvuf):
                yield drakvuf
    finally:
        stop_watchdog.set()
        watchdog_thread.join(timeout=1)


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


@contextlib.contextmanager
def run_screenshotter(
    vm_id: int,
    install_info: InstallInfo,
    output_dir: pathlib.Path,
    enabled: bool = True,
):
    if not enabled:
        yield
        return
    screenshotter = Screenshotter(
        output_dir=output_dir,
        vnc_host="localhost",
        vnc_port=5900 + vm_id,
        vnc_password=install_info.vnc_passwd,
    )
    try:
        screenshotter.start()
        yield
    finally:
        screenshotter.stop()
