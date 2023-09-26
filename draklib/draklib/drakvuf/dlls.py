from typing import List, NamedTuple, Optional

from .profile import VmiGuidInfo

DLL = NamedTuple("DLL", [("path", str), ("dest", str), ("arg", Optional[str])])


# profile file list, without 'C:\' and with '/' instead of '\'
# something is wrong if these DLLs fail
essential_native_dll_file_list = [
    DLL("Windows/System32/ntdll.dll", "native_ntdll_profile", "--json-ntdll"),
    DLL("Windows/System32/win32k.sys", "native_win32k_profile", "--json-win32k"),
    DLL("Windows/System32/kernel32.dll", "native_kernel32_profile", "--json-kernel32"),
]

essential_wow64_dll_file_list = [
    DLL("Windows/SysWOW64/ntdll.dll", "wow64_ntdll_profile", "--json-wow"),
    DLL(
        "Windows/SysWOW64/kernel32.dll",
        "wow64_kernel32_profile",
        "--json-wow-kernel32",
    ),
]

# profile file list, without 'C:\' and with '/' instead of '\'
optional_native_dll_file_list = [
    DLL("Windows/System32/drivers/tcpip.sys", "native_tcpip_profile", "--json-tcpip"),
    DLL("Windows/System32/sspicli.dll", "native_sspicli_profile", "--json-sspicli"),
    DLL(
        "Windows/System32/KernelBase.dll",
        "native_kernelbase_profile",
        "--json-kernelbase",
    ),
    DLL("Windows/System32/IPHLPAPI.DLL", "native_iphlpapi_profile", "--json-iphlpapi"),
    DLL("Windows/System32/mpr.dll", "native_mpr_profile", "--json-mpr"),
    DLL("Windows/System32/ole32.dll", "native_ole32_profile", None),
    # wasn't able to find this file in our snapshot - should be investigated
    # at some point
    DLL("Windows/System32/combase.dll", "native_combase_profile", None),
    # .NET DLLs aren't present in winsxs and are 32-bit, use x86_prefix
    DLL(
        "Windows/Microsoft.NET/Framework/v4.0.30319/clr.dll",
        "x86_clr_profile",
        "--json-clr",
    ),
    DLL(
        "Windows/Microsoft.NET/Framework/v2.0.50727/mscorwks.dll",
        "x86_mscorwks_profile",
        "--json-mscorwks",
    ),
    DLL(
        "Windows/winsxs/amd64_microsoft.windows.gdiplus_"
        "6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a/GdiPlus.dll",
        "native_gdiplus_profile",
        None,
    ),
    DLL(
        "Windows/winsxs/x86_microsoft.windows.gdiplus_"
        "6595b64144ccf1df_1.1.7601.17514_none_72d18a4386696c80/GdiPlus.dll",
        "x86_gdiplus_profile",
        None,
    ),
    DLL("Windows/System32/Wldap32.dll", "native_Wldap32_profile", None),
    DLL("Windows/System32/advapi32.dll", "native_advapi32_profile", None),
    DLL("Windows/System32/comctl32.dll", "native_comctl32_profile", None),
    DLL("Windows/System32/crypt32.dll", "native_crypt32_profile", None),
    DLL("Windows/System32/dnsapi.dll", "native_dnsapi_profile", None),
    DLL("Windows/System32/gdi32.dll", "native_gdi32_profile", None),
    DLL("Windows/System32/imagehlp.dll", "native_imagehlp_profile", None),
    DLL("Windows/System32/imm32.dll", "native_imm32_profile", None),
    DLL("Windows/System32/msacm32.dll", "native_msacm32_profile", None),
    DLL("Windows/System32/msvcrt.dll", "native_msvcrt_profile", None),
    DLL("Windows/System32/netapi32.dll", "native_netapi32_profile", None),
    DLL("Windows/System32/oleaut32.dll", "native_oleaut32_profile", None),
    DLL("Windows/System32/powrprof.dll", "native_powrprof_profile", None),
    DLL("Windows/System32/psapi.dll", "native_psapi_profile", None),
    DLL("Windows/System32/rpcrt4.dll", "native_rpcrt4_profile", None),
    DLL("Windows/System32/secur32.dll", "native_secur32_profile", None),
    DLL("Windows/System32/SensApi.dll", "native_SensApi_profile", None),
    DLL("Windows/System32/shell32.dll", "native_shell32_profile", None),
    DLL("Windows/System32/shlwapi.dll", "native_shlwapi_profile", None),
    DLL("Windows/System32/urlmon.dll", "native_urlmon_profile", None),
    DLL("Windows/System32/user32.dll", "native_user32_profile", None),
    DLL("Windows/System32/userenv.dll", "native_userenv_profile", None),
    DLL("Windows/System32/version.dll", "native_version_profile", None),
    DLL("Windows/System32/winhttp.dll", "native_winhttp_profile", None),
    DLL("Windows/System32/wininet.dll", "native_wininet_profile", None),
    DLL("Windows/System32/winmm.dll", "native_winmm_profile", None),
    DLL("Windows/System32/winspool.drv", "native_winspool_profile", None),
    DLL("Windows/System32/ws2_32.dll", "native_ws2_32_profile", None),
    DLL("Windows/System32/wsock32.dll", "native_wsock32_profile", None),
    DLL("Windows/System32/wtsapi32.dll", "native_wtsapi32_profile", None),
]

optional_wow64_dll_file_list = [
    DLL("Windows/SysWOW64/IPHLPAPI.DLL", "wow64_iphlpapi_profile", None),
    DLL("Windows/SysWOW64/mpr.dll", "wow64_mpr_profile", None),
    DLL("Windows/SysWOW64/ole32.dll", "wow64_ole32_profile", None),
    DLL("Windows/SysWOW64/Wldap32.dll", "wow64_Wldap32_profile", None),
    DLL("Windows/SysWOW64/advapi32.dll", "wow64_advapi32_profile", None),
    DLL("Windows/SysWOW64/comctl32.dll", "wow64_comctl32_profile", None),
    DLL("Windows/SysWOW64/crypt32.dll", "wow64_crypt32_profile", None),
    DLL("Windows/SysWOW64/dnsapi.dll", "wow64_dnsapi_profile", None),
    DLL("Windows/SysWOW64/gdi32.dll", "wow64_gdi32_profile", None),
    DLL("Windows/SysWOW64/imagehlp.dll", "wow64_imagehlp_profile", None),
    DLL("Windows/SysWOW64/imm32.dll", "wow64_imm32_profile", None),
    DLL("Windows/SysWOW64/msacm32.dll", "wow64_msacm32_profile", None),
    DLL("Windows/SysWOW64/msvcrt.dll", "wow64_msvcrt_profile", None),
    DLL("Windows/SysWOW64/netapi32.dll", "wow64_netapi32_profile", None),
    DLL("Windows/SysWOW64/oleaut32.dll", "wow64_oleaut32_profile", None),
    DLL("Windows/SysWOW64/powrprof.dll", "wow64_powrprof_profile", None),
    DLL("Windows/SysWOW64/psapi.dll", "wow64_psapi_profile", None),
    DLL("Windows/SysWOW64/rpcrt4.dll", "wow64_rpcrt4_profile", None),
    DLL("Windows/SysWOW64/secur32.dll", "wow64_secur32_profile", None),
    DLL("Windows/SysWOW64/SensApi.dll", "wow64_SensApi_profile", None),
    DLL("Windows/SysWOW64/shell32.dll", "wow64_shell32_profile", None),
    DLL("Windows/SysWOW64/shlwapi.dll", "wow64_shlwapi_profile", None),
    DLL("Windows/SysWOW64/urlmon.dll", "wow64_urlmon_profile", None),
    DLL("Windows/SysWOW64/user32.dll", "wow64_user32_profile", None),
    DLL("Windows/SysWOW64/userenv.dll", "wow64_userenv_profile", None),
    DLL("Windows/SysWOW64/version.dll", "wow64_version_profile", None),
    DLL("Windows/SysWOW64/winhttp.dll", "wow64_winhttp_profile", None),
    DLL("Windows/SysWOW64/wininet.dll", "wow64_wininet_profile", None),
    DLL("Windows/SysWOW64/winmm.dll", "wow64_winmm_profile", None),
    DLL("Windows/SysWOW64/winspool.drv", "wow64_winspool_profile", None),
    DLL("Windows/SysWOW64/ws2_32.dll", "wow64_ws2_32_profile", None),
    DLL("Windows/SysWOW64/wsock32.dll", "wow64_wsock32_profile", None),
    DLL("Windows/SysWOW64/wtsapi32.dll", "wow64_wtsapi32_profile", None),
]

all_dll_file_list = (
    essential_native_dll_file_list
    + essential_wow64_dll_file_list
    + optional_native_dll_file_list
    + optional_wow64_dll_file_list
)


def get_essential_dll_file_list(vmi_guid_info: VmiGuidInfo) -> List[DLL]:
    dlls = list(essential_native_dll_file_list)
    if vmi_guid_info.version.startswith("64-bit"):
        dlls += essential_wow64_dll_file_list
    return dlls


def get_optional_dll_file_list(vmi_guid_info: VmiGuidInfo) -> List[DLL]:
    dlls = list(optional_native_dll_file_list)
    if vmi_guid_info.version.startswith("64-bit"):
        dlls += optional_wow64_dll_file_list
    return dlls
