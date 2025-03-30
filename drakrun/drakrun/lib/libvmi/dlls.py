from typing import NamedTuple, Optional

from ..paths import VMI_PROFILES_DIR

DLL = NamedTuple("DLL", [("path", str), ("dest", str), ("arg", Optional[str])])

# profile file list, without 'C:\' and with '/' instead of '\'
# Profiles required by Drakvuf core
required_dll_file_list = [
    DLL("Windows/System32/ntdll.dll", "native_ntdll_profile", "--json-ntdll"),
    DLL("Windows/SysWOW64/ntdll.dll", "wow64_ntdll_profile", "--json-wow"),
    DLL("Windows/System32/win32k.sys", "native_win32k_profile", "--json-win32k"),
    DLL("Windows/System32/kernel32.dll", "native_kernel32_profile", "--json-kernel32"),
    DLL(
        "Windows/SysWOW64/kernel32.dll",
        "wow64_kernel32_profile",
        "--json-wow-kernel32",
    ),
]

# Profiles required by some Drakvuf plugins
optional_dll_file_list = [
    DLL("Windows/System32/drivers/tcpip.sys", "native_tcpip_profile", "--json-tcpip"),
    DLL("Windows/System32/sspicli.dll", "native_sspicli_profile", "--json-sspicli"),
    DLL(
        "Windows/System32/KernelBase.dll",
        "native_kernelbase_profile",
        "--json-kernelbase",
    ),
    DLL("Windows/System32/IPHLPAPI.DLL", "native_iphlpapi_profile", "--json-iphlpapi"),
    DLL("Windows/System32/mpr.dll", "native_mpr_profile", "--json-mpr"),
    # .NET DLLs aren't present in winsxs and are 32-bit, use x86_prefix
    DLL(
        "Windows/Microsoft.NET/Framework/v4.0.30319/clr.dll",
        "native_clr_profile",
        "--json-clr",
    ),
    DLL(
        "Windows/Microsoft.NET/Framework/v2.0.50727/mscorwks.dll",
        "native_mscorwks_profile",
        "--json-mscorwks",
    ),
]

dll_file_list = required_dll_file_list + optional_dll_file_list


def get_dll_cmdline_args():
    args = []
    for dll in dll_file_list:
        dll_profile_path = VMI_PROFILES_DIR / f"{dll.dest}.json"
        if dll_profile_path.exists():
            args.extend([dll.arg, dll_profile_path.as_posix()])
    return args
