import enum
import json
import logging
import pathlib
import subprocess
from typing import Any, Dict, List, Optional, Protocol

from drakrun.lib.config import NetworkConfigSection, load_config
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.paths import (
    ETC_DIR,
    INSTALL_INFO_PATH,
    PACKAGE_DATA_PATH,
    VMI_INFO_PATH,
    VMI_KERNEL_PROFILE_PATH,
)

from .analysis_options import AnalysisOptions
from .post_restore import get_post_restore_command
from .postprocessing import postprocess_output_dir
from .run_tools import run_drakvuf, run_tcpdump, run_vm
from .startup_command import get_startup_argv, get_target_filename_from_sample_path

log = logging.getLogger(__name__)


class AnalysisSubstatus(enum.Enum):
    starting_vm = "starting_vm"
    preparing_vm = "preparing_vm"
    analyzing = "analyzing"
    postprocessing = "postprocessing"
    done = "done"


class AnalysisSubstatusCallback(Protocol):
    def __call__(
        self,
        substatus: AnalysisSubstatus,
        updated_options: Optional[AnalysisOptions] = None,
    ) -> None:
        ...


def prepare_output_dir(output_dir: pathlib.Path, options: AnalysisOptions) -> None:
    if "memdump" in options.plugins:
        (output_dir / "memdumps").mkdir()

    if options.extra_output_subdirs is not None:
        for dirname in options.extra_output_subdirs:
            subdir = output_dir.joinpath(dirname).resolve()
            if subdir.relative_to(output_dir.resolve()):
                raise RuntimeError(
                    f"Incorrect directory name {dirname} in extra_output_subdirs option"
                )
            subdir.mkdir()


def args_dict_to_list(args: Dict[str, Any]) -> List[str]:
    args_list = []
    for argname, argvalue in args.items():
        if argvalue in [None, False]:
            continue
        elif argvalue is True:
            args_list.append(argname)
        elif type(argvalue) in [list, tuple]:
            for item in argvalue:
                args_list.extend([argname, item])
        else:
            args_list.extend([argname, str(argvalue)])
    return args_list


def prepare_drakvuf_args(
    output_dir: pathlib.Path, options: AnalysisOptions
) -> List[str]:
    base_args = {
        "-a": [plugin_name for plugin_name in options.plugins],
        "-t": options.timeout,
    }
    if "memdump" in options.plugins:
        base_args["--memdump-dir"] = (output_dir / "memdumps").resolve().as_posix()
    if "apimon" in options.plugins or "memdump" in options.plugins:
        if options.apimon_hooks_path is not None:
            dll_hooks_path = options.apimon_hooks_path.resolve()
        elif (ETC_DIR / "hooks.txt").exists():
            dll_hooks_path = (ETC_DIR / "hooks.txt").resolve()
        else:
            dll_hooks_path = (PACKAGE_DATA_PATH / "hooks.txt").resolve()
        base_args["--dll-hooks-list"] = dll_hooks_path.as_posix()
    if "syscalls" in options.plugins:
        if options.syscall_hooks_path is not None:
            syscall_hooks_path = options.syscall_hooks_path.resolve()
        elif (ETC_DIR / "syscalls.txt").exists():
            syscall_hooks_path = (ETC_DIR / "syscalls.txt").resolve()
        else:
            syscall_hooks_path = (PACKAGE_DATA_PATH / "syscalls.txt").resolve()
        base_args["--syscall-hooks-list"] = syscall_hooks_path.as_posix()
    if options.extra_drakvuf_args is not None:
        base_args.update(options.extra_drakvuf_args)
    return args_dict_to_list(base_args)


def drop_sample_to_vm(injector: Injector, sample_path: pathlib.Path, target_path: str):
    result = injector.write_file(str(sample_path), target_path)
    try:
        return json.loads(result.stdout)["ProcessName"]
    except ValueError as e:
        log.error(
            "JSON decode error occurred when tried to parse injector's logs. "
            f"Raw log line: {result.stdout}"
        )
        raise e


def analyze_file(
    vm_id: int,
    output_dir: pathlib.Path,
    options: AnalysisOptions,
    substatus_callback: Optional[AnalysisSubstatusCallback] = None,
):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    kernel_profile_path = VMI_KERNEL_PROFILE_PATH.as_posix()

    prepare_output_dir(output_dir, options)

    network_conf = NetworkConfigSection(
        out_interface=config.network.out_interface,
        dns_server=config.network.dns_server,
        net_enable=options.net_enable,
    )

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.starting_vm)

    with run_vm(
        vm_id, install_info, network_conf, no_restore=options.no_vm_restore
    ) as vm:
        network_info = vm.get_network_info()
        injector = Injector(vm.vm_name, vmi_info, kernel_profile_path)

        if substatus_callback is not None:
            substatus_callback(AnalysisSubstatus.preparing_vm)

        log.info("Connecting to drakshell...")
        drakshell = Drakshell(vm.vm_name)
        drakshell.connect(timeout=10)
        info = drakshell.get_info()
        log.info(f"Drakshell active on: {str(info)}")

        if not options.no_post_restore:
            log.info("Running post-restore command...")
            post_restore_cmd = get_post_restore_command(network_conf.net_enable)
            drakshell.check_call(post_restore_cmd)

        if options.sample_path is not None:
            if options.target_filename is None:
                options.target_filename = get_target_filename_from_sample_path(
                    options.sample_path
                )
            lower_target_name = options.target_filename.lower()
            if not lower_target_name.startswith(
                "c:"
            ) and not lower_target_name.startswith("%"):
                options.target_filename = (
                    "%USERPROFILE%\\Desktop\\" + options.target_filename
                )
            log.info(
                f"Copying sample to the VM ({options.sample_path.as_posix()} -> {options.target_filename})..."
            )
            guest_path = drop_sample_to_vm(
                injector, options.sample_path, options.target_filename
            )

            if options.start_command is None:
                options.start_command = get_startup_argv(guest_path)

        tcpdump_file = output_dir / "dump.pcap"
        drakmon_file = output_dir / "drakmon.log"
        drakvuf_args = prepare_drakvuf_args(output_dir, options)

        try:
            if substatus_callback is not None:
                substatus_callback(AnalysisSubstatus.analyzing, updated_options=options)

            with run_tcpdump(network_info, tcpdump_file), run_drakvuf(
                vm.vm_name, vmi_info, kernel_profile_path, drakmon_file, drakvuf_args
            ) as drakvuf:
                if options.start_command is not None:
                    log.info(f"Running command: {guest_path}.")
                    drakshell.run([guest_path], terminate_drakshell=True)
                else:
                    drakshell.finish()
                log.info("Analysis started...")
                try:
                    # -t should be respected, but let's give 30 more secs
                    if options.timeout is not None:
                        drakvuf.wait(options.timeout + 30)
                    else:
                        drakvuf.wait()
                except subprocess.TimeoutExpired:
                    log.info("Drakvuf hard timed out - hang?")
                    drakvuf.terminate()
                    drakvuf.wait(10)
        except KeyboardInterrupt:
            log.info("Interrupted with CTRL-C, analysis finished.")

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.postprocessing)

    postprocess_output_dir(output_dir)

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.done)
