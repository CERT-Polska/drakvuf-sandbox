from typing import List, Optional

from .libvmi import VmiInfo, get_dll_cmdline_args


def get_base_drakvuf_cmdline(
    vm_name: str,
    kernel_profile_path: str,
    vmi_info: VmiInfo,
    exec_cmd: Optional[str] = None,
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
        args.extend(
            [
                "-j",
                "60",
                "-i",
                str(vmi_info.inject_pid),
                "-e",
                exec_cmd,
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
