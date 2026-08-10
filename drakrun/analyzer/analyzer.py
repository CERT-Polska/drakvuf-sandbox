import contextlib
import enum
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
    DUMPS_DIR,
    ETC_DIR,
    INSTALL_INFO_PATH,
    PACKAGE_DATA_PATH,
    VMI_INFO_PATH,
    VMI_KERNEL_PROFILE_PATH,
)
from drakrun.lib.version_detection import get_drakvuf_version

from .analysis_metadata import AnalysisMetadata
from .analysis_options import AnalysisOptions, StartMethod
from .file_handlers import (
    PreparedSampleInfo,
    get_handler_for_file,
)
from .post_restore import get_post_restore_command
from .postprocessing import postprocess_analysis_dir
from .run_tools import run_drakvuf, run_screenshotter, run_tcpdump, run_vm
from .startup_command import (
    get_startup_method_and_argv,
    make_exec_parameters,
)

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
        updated_options: bool = False,
    ) -> None: ...


def prepare_output_dir(output_dir: pathlib.Path, options: AnalysisOptions) -> None:
    if "memdump" in options.plugins:
        (output_dir / DUMPS_DIR).mkdir()

    if options.extra_output_subdirs is not None:
        for dirname in options.extra_output_subdirs:
            subdir = output_dir.joinpath(dirname).resolve()
            if not subdir.relative_to(output_dir.resolve()):
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
        base_args["--memdump-dir"] = (output_dir / DUMPS_DIR).resolve().as_posix()
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


def analyze_file(
    vm_id: int,
    output_dir: pathlib.Path,
    metadata: AnalysisMetadata,
    substatus_callback: Optional[AnalysisSubstatusCallback] = None,
):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    kernel_profile_path = VMI_KERNEL_PROFILE_PATH.as_posix()
    options = metadata.options

    drakvuf_version_info = get_drakvuf_version()
    shellexec_supported = drakvuf_version_info.supports_shellexec_verb
    # ShellExecute is able to auto-elevate binary in case of ERROR_ELEVATION_REQUIRED
    # so if Drakvuf implements the improved shellexec injection: it should be
    # our first choice for binaries
    preferred_start_method: StartMethod = (
        "shellexec"
        if shellexec_supported and not config.drakrun.no_shellexec
        else "createproc"
    )

    if options.start_method == "runas" and not shellexec_supported:
        raise RuntimeError(
            "Installed DRAKVUF version doesn't support custom ShellExecute verbs "
            "required for executing samples with elevated privileges."
        )

    prepare_output_dir(output_dir, options)

    network_conf = NetworkConfigSection(
        out_interface=config.network.out_interface,
        dns_server=config.network.dns_server,
        net_enable=options.net_enable,
    )

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.starting_vm)

    if options.extract_archive:
        log.info(
            f"Archive mode: extract_archive=True, guest_archive_entry_path={options.guest_archive_entry_path}, "
            f"start_command={options.start_command}"
        )

    tcpdump_file = output_dir / "dump.pcap"
    drakmon_file = output_dir / "drakmon.log"
    drakvuf_err_file = output_dir / "drakvuf_stderr.log"
    drakvuf_args = prepare_drakvuf_args(output_dir, options)

    with contextlib.ExitStack() as stack:
        vm = stack.enter_context(
            run_vm(vm_id, install_info, network_conf, no_restore=options.no_vm_restore)
        )
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

        # Prepare sample using file handlers.
        # This can involve transfering to vm, mounting disk image/unpacking archive
        # and automatically selecting file to execute if not specified
        sample_info: Optional[PreparedSampleInfo] = None
        if options.host_sample_path is not None:
            handler = get_handler_for_file(options)
            if handler is None:
                raise ValueError(
                    f"No handler found for file: {options.host_sample_path}"
                )

            log.info(f"Using handler: {handler.__class__.__name__}")
            sample_info = handler.prepare(config, drakshell, injector, options)

            # Determine start command if not provided
            if options.start_command is None and sample_info.guest_executable_path:
                log.info(
                    f"Setting start_command from: {sample_info.guest_executable_path}"
                )
                start_method, options.start_command = get_startup_method_and_argv(
                    sample_info.guest_executable_path, preferred_start_method
                )
                # If user provides their own method, we will stick to that one
                if options.start_method is None:
                    options.start_method = start_method

        try:
            if options.start_command is not None:
                # If user provided the start command but not the start method
                # fallback to the preferred_start_method
                start_method = options.start_method or preferred_start_method
                # At this point:
                # - createproc always use CreateProcess method
                # - shellexec uses CreateProcess combined with "cmd /c start"
                #   in case of old Drakvuf version or ShellExecuteEx
                # - runas requires Drakvuf version that implements ShellExecuteEx
                #   and verbs
                exec_parameters = make_exec_parameters(
                    options.start_command,
                    start_method,
                    str(
                        sample_info.guest_working_directory
                        if sample_info
                        else options.guest_working_directory
                    ),
                    shellexec_supported,
                )
                # At this point options object is used only to visualize
                # the started command in metadata. Actual execution parameters are
                # contained in exec_parameters
                options.start_command = exec_parameters.full_command
                options.start_method = exec_parameters.start_method
            else:
                exec_parameters = None

            if substatus_callback is not None:
                substatus_callback(AnalysisSubstatus.analyzing, updated_options=True)

            if exec_parameters is None:
                # If we don't inject the command to run:
                # evacuate the drakshell before running anything
                drakshell.finish()

            log.info(
                f"Starting analysis with drakvuf args: {drakvuf_args}, start command: "
                f"{options.start_command}, exec method: {options.start_method}"
            )

            stack.enter_context(run_tcpdump(network_info, tcpdump_file))
            stack.enter_context(
                run_screenshotter(
                    vm_id,
                    install_info,
                    output_dir,
                    enabled=(not options.no_screenshotter),
                )
            )
            drakvuf = stack.enter_context(
                run_drakvuf(
                    vm_name=vm.vm_name,
                    vmi_info=vmi_info,
                    kernel_profile_path=kernel_profile_path,
                    output_file=drakmon_file,
                    output_err_file=drakvuf_err_file,
                    drakvuf_args=drakvuf_args,
                    drakvuf_version_info=drakvuf_version_info,
                    exec_parameters=exec_parameters,
                    drakvuf_cwd=output_dir,
                )
            )

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

    extra_metadata = postprocess_analysis_dir(output_dir, config, metadata)

    if substatus_callback is not None:
        substatus_callback(AnalysisSubstatus.done)
    return extra_metadata
