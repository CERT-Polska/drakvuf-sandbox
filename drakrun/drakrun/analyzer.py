import argparse
import contextlib
import dataclasses
import itertools
import json
import logging
import ntpath
import os
import pathlib
import random
import shutil
import string
import subprocess
import time
import unicodedata
from typing import List, Optional, Tuple

import magic
from pathvalidate import Platform, is_valid_filename

from .lib.config import load_config
from .lib.drakpdb import dll_file_list
from .lib.injector import Injector
from .lib.install_info import InstallInfo
from .lib.networking import (
    delete_vm_network,
    setup_vm_network,
    start_dnsmasq,
    start_tcpdump_collector,
)
from .lib.paths import ETC_DIR, PROFILE_DIR, RUNTIME_FILE
from .lib.sample_startup import get_sample_entrypoints, get_sample_startup_command
from .lib.storage import get_storage_backend
from .lib.util import RuntimeInfo, graceful_exit
from .lib.vm import VirtualMachine
from .postprocess import postprocess_analysis

log = logging.getLogger(__name__)


class UnretryableAnalysisError(Exception):
    """
    Analysis error that is not intermittent and should not lead to the retry of the analysis
    """


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


def prepare_output_dir(output_dir: pathlib.Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise RuntimeError("Output directory is not empty")
    (output_dir / "dumps").mkdir()
    (output_dir / "ipt").mkdir()


@dataclasses.dataclass
class AnalysisOptions:
    sample_path: pathlib.Path
    vm_id: int
    output_dir: pathlib.Path
    plugins: List[str]
    sample_filename: str
    hooks_path: pathlib.Path = pathlib.Path(ETC_DIR) / "hooks.txt"
    timeout: int = 600
    start_command: Optional[str] = None
    extension: Optional[str] = None
    dns_server: Optional[str] = None
    out_interface: Optional[str] = None
    net_enable: bool = True
    anti_hammering_threshold: int = 0
    syscall_filter: Optional[str] = None
    raw_memory_dump: bool = False
    postprocess: bool = True


def random_filename() -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(10))


def filename_for_task(options: AnalysisOptions) -> Tuple[str, str]:
    """
    Return a tuple of (filename, extension) for a given task.
    This depends on the content magic, "extension" and "file_name" options.
    """
    extension = options.extension
    if not extension:
        magic_output = magic.from_file(options.sample_path)
        if "(DLL)" in magic_output:
            extension = "dll"
        else:
            extension = "exe"
    # Make sure the extension is lowercase
    extension = extension.lower()
    # Validate filename provided by user and append proper extension if necessary
    file_name = options.sample_filename
    # Normalize/remove Unicode characters as current version of Drakvuf
    # isn't really good at handling them in logs
    file_name = (
        unicodedata.normalize("NFKD", file_name)
        .encode("ascii", "ignore")
        .decode("ascii")
    )
    if file_name and is_valid_filename(file_name, platform=Platform.UNIVERSAL):
        if "." not in file_name or file_name.split(".")[-1].lower() != extension:
            file_name += f".{extension}"
    else:
        # Use random filename if name is invalid
        file_name = random_filename() + f".{extension}"
    return file_name, extension


@contextlib.contextmanager
def run_vm(vm: DrakvufVM, options: AnalysisOptions):
    setup_vm_network(
        vm.vm_id,
        options.net_enable,
        options.out_interface,
        options.dns_server,
    )
    try:
        with graceful_exit(start_dnsmasq(vm.vm_id, options.dns_server)):
            try:
                vm.vm.restore()
            except subprocess.CalledProcessError as e:
                with open(f"/var/log/xen/qemu-dm-{vm.vm.vm_name}.log", "rb") as f:
                    qemu_error = f.read()
                raise UnretryableAnalysisError(
                    f"Failed to restore VM {vm.vm.vm_name}: {qemu_error}"
                ) from e
            try:
                yield vm
            finally:
                vm.vm.destroy()
    finally:
        delete_vm_network(vm.vm_id)


def run_tcpdump(vm: DrakvufVM, options: AnalysisOptions):
    # todo: start_tcpdump_collector should accept pathlib.Path
    return graceful_exit(
        start_tcpdump_collector(vm.vm.get_domid(), str(options.output_dir))
    )


def drop_sample_to_vm(
    vm: DrakvufVM, sample_path: pathlib.Path, target_filename: str
) -> str:
    """
    Writes sample to the VM and returns expanded target path
    """
    target_path = f"%USERPROFILE%\\Desktop\\{target_filename}"
    result = vm.injector.write_file(str(sample_path), target_path)
    try:
        return json.loads(result.stdout)["ProcessName"]
    except ValueError as e:
        log.error(
            "JSON decode error occurred when tried to parse injector's logs. "
            f"Raw log line: {result.stdout}"
        )
        raise e


def run_post_restore_vm_commands(vm: DrakvufVM, options: AnalysisOptions):
    log.info("Running post-restore VM commands...")
    if options.net_enable:
        max_attempts = 3
        for i in range(max_attempts):
            try:
                log.info(f"Trying to setup network (attempt {i + 1}/{max_attempts})")
                vm.injector.create_process(
                    "cmd /C ipconfig /release >nul", wait=True, timeout=120
                )
                vm.injector.create_process(
                    "cmd /C ipconfig /renew >nul", wait=True, timeout=120
                )
                break
            except Exception:
                log.exception("Analysis attempt failed. Retrying...")
        else:
            log.warning(f"Giving up after {max_attempts} failures...")
            raise RuntimeError("Failed to setup VM network after 3 attempts")


def get_profile_args_list() -> List[str]:
    files = os.listdir(PROFILE_DIR)

    out = []

    for profile in dll_file_list:
        if profile.arg is None:
            continue
        if f"{profile.dest}.json" in files:
            out.extend([profile.arg, os.path.join(PROFILE_DIR, f"{profile.dest}.json")])

    return out


def build_drakvuf_cmdline(
    vm: DrakvufVM,
    cwd: str,
    full_cmd: str,
    plugins: List[str],
    options: AnalysisOptions,
) -> List[str]:
    plugin_args = list(
        itertools.chain.from_iterable(["-a", plugin] for plugin in sorted(plugins))
    )
    memdumps_dir = options.output_dir / "dumps"
    ipt_dir = options.output_dir / "ipt"
    drakvuf_cmd = (
        ["drakvuf"]
        + plugin_args
        + [
            "-o",
            "json",
            # be aware of https://github.com/tklengyel/drakvuf/pull/951
            "-F",  # enable fast singlestep
            "-j",
            "60",
            "-t",
            str(options.timeout),
            "-i",
            str(vm.runtime_info.inject_pid),
            "-k",
            hex(vm.runtime_info.vmi_offsets.kpgd),
            "-d",
            vm.vm.vm_name,
            "--dll-hooks-list",
            options.hooks_path,
            "--memdump-dir",
            str(memdumps_dir),
            "--ipt-dir",
            str(ipt_dir),
            "--ipt-trace-user",
            "--codemon-dump-dir",
            str(ipt_dir),
            "--codemon-log-everything",
            "--codemon-analyse-system-dll-vad",
            "-r",
            str(vm.kernel_profile_path),
            "-e",
            full_cmd,
            "-c",
            cwd,
        ]
    )

    if options.anti_hammering_threshold:
        drakvuf_cmd.extend(["--traps-ttl", str(options.anti_hammering_threshold)])

    drakvuf_cmd.extend(get_profile_args_list())

    if options.syscall_filter:
        drakvuf_cmd.extend(["-S", options.syscall_filter])

    return drakvuf_cmd


def make_injection_error(drakmon_log_path: pathlib.Path):
    injection_error = "<unknown error>"
    with drakmon_log_path.open("r") as drakvuf_log:
        # There should be only one line
        for line in drakvuf_log:
            entry = json.loads(line)
            if entry["Plugin"] == "inject":
                injection_error = entry["Error"]
                break
    return UnretryableAnalysisError(
        f"Injection succeeded but sample startup failed "
        f"with error: {injection_error}"
    )


def analyze_sample(options: AnalysisOptions):
    output_dir = options.output_dir
    prepare_output_dir(output_dir)
    vm = DrakvufVM(options.vm_id)

    file_name, extension = filename_for_task(options)
    log.info("Using file name %s", file_name)

    user_start_command = options.start_command
    # TODO: Read directly from file
    sample_content = options.sample_path.read_bytes()
    sample_entrypoints = get_sample_entrypoints(extension, sample_content)

    time_started = time.time()
    with run_vm(vm, options) as vm:
        log.info("Copying sample to VM...")
        target_path = drop_sample_to_vm(vm, options.sample_path, file_name)

        if user_start_command:
            start_command = user_start_command.replace("%f", target_path)
        else:
            start_command = get_sample_startup_command(
                target_path, extension, sample_entrypoints
            )
        log.info("Using command: %s", start_command)

        run_post_restore_vm_commands(vm, options)

        cwd = ntpath.dirname(target_path)
        drakvuf_cmd = build_drakvuf_cmdline(
            vm, cwd, start_command, plugins=options.plugins, options=options
        )

        drakmon_log_path = output_dir / "drakmon.log"
        with run_tcpdump(vm, options), drakmon_log_path.open("wb") as drakmon_log:
            try:
                subprocess.run(
                    drakvuf_cmd,
                    stdout=drakmon_log,
                    check=True,
                    timeout=options.timeout + 60,
                )
            except subprocess.CalledProcessError as e:
                # see DRAKVUF src/exitcodes.h for more details
                INJECTION_UNSUCCESSFUL = 4

                if e.returncode == INJECTION_UNSUCCESSFUL:
                    raise make_injection_error(drakmon_log_path) from e
                else:
                    # Something bad happened
                    raise e
            except subprocess.TimeoutExpired as e:
                raise UnretryableAnalysisError(
                    "DRAKVUF process timeout expired (hang?)"
                ) from e

        if options.raw_memory_dump:
            vm.vm.memory_dump(str(output_dir / "post_sample.raw_memdump.gz"))

    log.info("Analysis done. Postprocessing artifacts...")

    extra_metadata = postprocess_analysis(output_dir)

    time_finished = time.time()
    return {
        "time_started": time_started,
        "time_finished": time_finished,
        "start_command": start_command,
        **extra_metadata,
    }


class PluginsArgAction(argparse.Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not allowed")
        super().__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        if option_string is None:
            raise ValueError("Value is required for --plugins option")
        setattr(namespace, self.dest, option_string.split(","))


def confirm(prompt):
    while True:
        answer = input(prompt).lower()
        if answer == "y":
            return True
        elif answer == "n":
            return False


def main():
    logging.basicConfig(level=logging.INFO)
    drakconfig = load_config()
    parser = argparse.ArgumentParser(
        description="Analyze a file in Drakvuf",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("sample_path", help="Path to the sample")
    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Don't ask if output directory can be deleted",
    )
    parser.add_argument(
        "--vm-id",
        help="ID of the Virtual machine to use for analysis",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--output-dir",
        help="Path where analysis results will be written",
        required=True,
    )
    parser.add_argument(
        "--plugins",
        help="Comma separated DRAKVUF plugins to use",
        default=drakconfig.drakvuf_plugins.get_plugin_list(),
        action=PluginsArgAction,
    )
    parser.add_argument(
        "--timeout",
        default=drakconfig.drakrun.analysis_timeout,
        type=int,
        help="Analysis timeout, in seconds",
    )
    parser.add_argument(
        "--hooks-path", help="Path to the custom hook list", required=False
    )
    parser.add_argument(
        "--start-command", help="Override the default startup command", required=False
    )
    parser.add_argument(
        "--extension",
        help="Alternative extension indicating sample format",
        required=False,
    )
    parser.add_argument(
        "--sample-filename", help="Sample filename to use in the VM", required=False
    )
    parser.add_argument(
        "--dns-server",
        help="DNS server to use for analysis",
        default=drakconfig.drakrun.dns_server,
        required=False,
    )
    parser.add_argument(
        "--out-interface",
        help="Interface to be used by VM for Internet communication",
        default=drakconfig.drakrun.out_interface,
        required=False,
    )
    parser.add_argument(
        "--net-enable",
        help="If enabled, VM will be able to connect to the Internet via out-interface",
        default=drakconfig.drakrun.net_enable,
        action=argparse.BooleanOptionalAction,
    )
    parser.add_argument(
        "--anti-hammering-threshold",
        help="Threshold for API hammering detection (or 0 to disable)",
        default=drakconfig.drakrun.anti_hammering_threshold,
        type=int,
    )
    parser.add_argument(
        "--syscall-filter",
        help="Syscall filter for syscalls plugin",
        default=drakconfig.drakrun.syscall_filter,
        type=str,
    )
    parser.add_argument(
        "--raw-memory-dump",
        help="Make full memory dump of VM after analysis",
        default=drakconfig.drakrun.raw_memory_dump,
        action=argparse.BooleanOptionalAction,
    )
    parser.add_argument(
        "--postprocess",
        help="Postprocess artifacts",
        default=AnalysisOptions.postprocess,
        action=argparse.BooleanOptionalAction,
    )

    args = parser.parse_args()

    sample_path = pathlib.Path(args.sample_path)
    if not sample_path.exists():
        raise RuntimeError(f"Provided file '{str(args.sample_path)}' does not exist")

    output_dir = pathlib.Path(args.output_dir)
    if output_dir.exists():
        if args.force or confirm("Output directory already exists. Overwrite? (y/n)"):
            shutil.rmtree(output_dir)
    output_dir.mkdir()

    hooks_path = (
        pathlib.Path(args.hooks_path) if args.hooks_path else AnalysisOptions.hooks_path
    )

    analysis_options = AnalysisOptions(
        sample_path=sample_path,
        vm_id=args.vm_id,
        output_dir=output_dir,
        plugins=args.plugins,
        timeout=args.timeout,
        hooks_path=hooks_path,
        start_command=args.start_command,
        extension=args.extension,
        sample_filename=args.sample_filename or sample_path.name,
        dns_server=args.dns_server,
        out_interface=args.out_interface,
        net_enable=args.net_enable,
        anti_hammering_threshold=args.anti_hammering_threshold,
        syscall_filter=args.syscall_filter,
        raw_memory_dump=args.raw_memory_dump,
        postprocess=args.postprocess,
    )
    analyze_sample(analysis_options)
