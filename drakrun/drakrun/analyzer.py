import json
import logging
import os
import ntpath
import subprocess
from pathlib import Path
from typing import List, Optional
from .lib.injector import Injector
from .lib.drakpdb import dll_file_list
from .lib.config import InstallInfo, RUNTIME_FILE, PROFILE_DIR, ETC_DIR
from .lib.networking import (
    setup_vm_network,
    start_dnsmasq,
    start_tcpdump_collector,
)
from .lib.storage import get_storage_backend
from .lib.util import RuntimeInfo
from .lib.vm import VirtualMachine

log = logging.getLogger(__name__)

DEFAULT_ANALYSIS_TIMEOUT = 10 * 60
SUPPORTED_PLUGINS = [
    "apimon",
    "bsodmon",
    "clipboardmon",
    "cpuidmon",
    "crashmon",
    "debugmon",
    "delaymon",
    "exmon",
    "filedelete",
    "filetracer",
    "librarymon",
    "memdump",
    "procdump",
    "procmon",
    "regmon",
    "rpcmon",
    "ssdtmon",
    "syscalls",
    "tlsmon",
    "windowmon",
    "wmimon",
]


class DrakvufVM:
    def __init__(self, vm_id: int):
        self.vm_id = vm_id
        self.install_info = InstallInfo.load()
        self.storage_backend = get_storage_backend(self.install_info)
        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)
        self.kernel_profile_path = os.path.join(PROFILE_DIR, "kernel.json")
        self.vm = VirtualMachine(self.storage_backend, vm_id)
        self.injector = Injector(
            self.vm.vm_name, self.runtime_info, self.kernel_profile_path
        )


def build_drakvuf_cmdline(
    drakvm: DrakvufVM,
    drakvuf_plugins: List[str],
    timeout: int,
    cwd: str,
    full_cmd: str,
    dump_dir: str,
    ipt_dir: str,
    hooks_path: str,
    anti_hammering_threshold: Optional[int] = None,
    syscall_filter: Optional[str] = None,
) -> List[str]:
    kernel_profile_path = os.path.join(PROFILE_DIR, "kernel.json")
    plugins_opts = sum((["-a", plugin] for plugin in sorted(drakvuf_plugins)), [])
    profile_files = os.listdir(PROFILE_DIR)
    profile_opts = []
    for profile in dll_file_list:
        if profile.arg is None:
            continue
        if f"{profile.dest}.json" in profile_files:
            profile_opts.extend(
                [profile.arg, os.path.join(PROFILE_DIR, f"{profile.dest}.json")]
            )
    drakvuf_cmd = [
        "drakvuf",
        *plugins_opts,
        *profile_opts,
        *["-o", "json"],
        # be aware of https://github.com/tklengyel/drakvuf/pull/951
        "-F",  # enable fast singlestep
        *["-j", "60"],
        *["-t", str(timeout)],
        *["-i", str(drakvm.runtime_info.inject_pid)],
        *["-k", hex(drakvm.runtime_info.vmi_offsets.kpgd)],
        *["-d", drakvm.vm.vm_name],
        *["--dll-hooks-list", hooks_path],
        *["--memdump-dir", dump_dir],
        *["--ipt-dir", ipt_dir],
        "--ipt-trace-user",
        *["--codemon-dump-dir", ipt_dir],
        "--codemon-log-everything",
        "--codemon-analyse-system-dll-vad",
        *["-r", kernel_profile_path],
        *["-e", full_cmd],
        *["-c", cwd],
        *(
            ["--traps-ttl", str(anti_hammering_threshold)]
            if anti_hammering_threshold is not None
            else []
        ),
        *(
            ["--traps-ttl", str(anti_hammering_threshold)]
            if anti_hammering_threshold is not None
            else []
        ),
        *(["-S", syscall_filter] if syscall_filter is not None else []),
    ]
    return drakvuf_cmd


def analyze_file(
    vm_id: int,
    sample_path: str,
    output_directory: Path,
    sample_type: Optional[str] = None,
    sample_entrypoints: List[str] = None,
    net_enable: bool = False,
    net_out_interface: Optional[str] = None,
    net_dns_server: str = "8.8.8.8",
    timeout: int = 10 * 60,
    drakvuf_plugins: Optional[List[str]] = None,
):
    dump_dir = output_directory / "dumps"
    ipt_dir = output_directory / "ipt"
    hooks_path = os.path.join(ETC_DIR, "hooks.txt")
    dump_dir.mkdir(parents=True)
    ipt_dir.mkdir()

    setup_vm_network(vm_id, net_enable, net_out_interface, net_dns_server)

    drakvm = DrakvufVM(vm_id)
    drakvm.vm.restore()
    try:
        target_path = f"%USERPROFILE%\\Desktop\\{os.path.basename(sample_path)}"
        result = drakvm.injector.write_file(sample_path, target_path)
        if result.returncode != 0:
            raise RuntimeError("Failed to copy sample to the VM")

        target_path = json.loads(result.stdout)["ProcessName"]
        sample_cmdline = "cmd /C start " + target_path
        drakvuf_cmdline = build_drakvuf_cmdline(
            drakvm,
            drakvuf_plugins,
            timeout,
            cwd=ntpath.dirname(target_path),
            full_cmd=sample_cmdline,
            dump_dir=str(dump_dir),
            ipt_dir=str(ipt_dir),
            hooks_path=str(hooks_path),
        )
        if net_enable:
            network_setup_attempts = 3
            for i in range(network_setup_attempts):
                try:
                    log.info(
                        f"Trying to setup network "
                        f"(attempt {i + 1}/{network_setup_attempts})"
                    )
                    drakvm.injector.create_process(
                        "cmd /C ipconfig /release >nul", wait=True, timeout=120
                    )
                    drakvm.injector.create_process(
                        "cmd /C ipconfig /renew >nul", wait=True, timeout=120
                    )
                    break
                except Exception:
                    log.exception("Analysis attempt failed. Retrying...")
            else:
                raise RuntimeError(
                    f"Failed to setup VM network after {network_setup_attempts} attempts"
                )
        dnsmasq = start_dnsmasq(vm_id, net_dns_server)
        try:
            tcpdump = start_tcpdump_collector(
                drakvm.vm.get_domid(), str(output_directory)
            )
            try:
                with (output_directory / "drakmon.log").open("wb") as f:
                    subprocess.run(
                        drakvuf_cmdline, check=True, stdout=f, timeout=timeout + 60
                    )
            finally:
                tcpdump.terminate()
        finally:
            dnsmasq.terminate()
    finally:
        drakvm.vm.destroy()
