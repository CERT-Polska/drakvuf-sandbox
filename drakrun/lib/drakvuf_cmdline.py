from typing import List, Optional

from .libvmi import VmiInfo, get_dll_cmdline_args


def get_base_drakvuf_cmdline(
    vm_name: str,
    kernel_profile_path: str,
    vmi_info: VmiInfo,
    exec_cmd: Optional[str] = None,
    shellexec_args: Optional[str] = None,
    start_method: Optional[str] = None,
    working_dir: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> List[str]:
    args = [
        "drakvuf",
        "-o",
        "json",
        # be aware of https://github.com/tklengyel/drakvuf/pull/951
        "-F",  # enable fast singlestep
        "-k",
        hex(vmi_info.vmi_offsets.kpgd),
        "-r",
        kernel_profile_path,
        "-d",
        vm_name,
    ]
    args.extend(get_dll_cmdline_args())
    if exec_cmd is not None:
        if start_method == "createproc":
            exec_args = ["-m", "createproc", "-e", exec_cmd]
        elif start_method == "shellexec":
            exec_args = ["-m", "shellexec", "-e", exec_cmd]
            if shellexec_args:
                exec_args.extend(["-f", shellexec_args])
        elif start_method == "runas":
            exec_args = ["-m", "shellexec", "-V", "runas", "-e", exec_cmd]
            if shellexec_args:
                exec_args.extend(["-f", shellexec_args])
        else:
            raise ValueError(f"Unsupported start method: {start_method}")
        if working_dir is not None:
            exec_args.extend(["-c", working_dir])
        args.extend(
            [
                "-j",
                "60",
                "-i",
                str(vmi_info.inject_pid),
                *exec_args,
                *(
                    ["-I", str(vmi_info.inject_tid), "--exit-injection-thread"]
                    if vmi_info.inject_tid is not None
                    else []
                ),
            ]
        )
    if extra_args:
        args.extend(extra_args)
    return args


def get_base_injector_cmdline(
    vm_name: str,
    kernel_profile_path: str,
    vmi_info: VmiInfo,
    method: str,
    args: Optional[List[str]] = None,
) -> List[str]:
    args = args or []
    return [
        "injector",
        "-o",
        "json",
        "-d",
        vm_name,
        "-r",
        kernel_profile_path,
        "-i",
        str(vmi_info.inject_pid),
        "-k",
        hex(vmi_info.vmi_offsets.kpgd),
        "-m",
        method,
        *(["-I", str(vmi_info.inject_tid)] if vmi_info.inject_tid is not None else []),
        *args,
    ]
