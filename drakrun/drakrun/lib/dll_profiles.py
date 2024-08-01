from typing import NamedTuple, Optional

DLL = NamedTuple("DLL", [("path", str), ("dest", str), ("arg", Optional[str])])


# profile file list, without 'C:\' and with '/' instead of '\'
# Profiles required by Drakvuf core
required_dll_file_list = [
    DLL("Windows/System32/ntdll.dll", "amd64_ntdll_profile", "--json-ntdll"),
    DLL("Windows/SysWOW64/ntdll.dll", "wow64_ntdll_profile", "--json-wow"),
    DLL("Windows/System32/win32k.sys", "amd64_win32k_profile", "--json-win32k"),
    DLL("Windows/System32/kernel32.dll", "amd64_kernel32_profile", "--json-kernel32"),
    DLL(
        "Windows/SysWOW64/kernel32.dll",
        "wow64_kernel32_profile",
        "--json-wow-kernel32",
    ),
]

# Profiles required by some Drakvuf plugins
optional_dll_file_list = [
    DLL("Windows/System32/drivers/tcpip.sys", "amd64_tcpip_profile", "--json-tcpip"),
    DLL("Windows/System32/sspicli.dll", "amd64_sspicli_profile", "--json-sspicli"),
    DLL(
        "Windows/System32/KernelBase.dll",
        "amd64_kernelbase_profile",
        "--json-kernelbase",
    ),
    DLL("Windows/System32/IPHLPAPI.DLL", "amd64_iphlpapi_profile", "--json-iphlpapi"),
    DLL("Windows/System32/mpr.dll", "amd64_mpr_profile", "--json-mpr"),
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
]

# Profiles used by Apivectors
apivectors_dll_file_list = [
    DLL("Windows/SysWOW64/IPHLPAPI.DLL", "x86_iphlpapi_profile", None),
    DLL("Windows/SysWOW64/mpr.dll", "x86_mpr_profile", None),
    DLL("Windows/System32/ole32.dll", "amd64_ole32_profile", None),
    DLL("Windows/SysWOW64/ole32.dll", "x86_ole32_profile", None),
    DLL("Windows/System32/combase.dll", "amd64_combase_profile", None),
    DLL(
        "Windows/winsxs/amd64_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_2b24536c71ed437a/GdiPlus.dll",
        "amd64_gdiplus_profile",
        None,
    ),
    DLL(
        "Windows/winsxs/x86_microsoft.windows.gdiplus_6595b64144ccf1df_1.1.7601.17514_none_72d18a4386696c80/GdiPlus.dll",
        "x86_gdiplus_profile",
        None,
    ),
    DLL("Windows/System32/Wldap32.dll", "amd64_Wldap32_profile", None),
    DLL("Windows/SysWOW64/Wldap32.dll", "x86_Wldap32_profile", None),
    DLL("Windows/System32/advapi32.dll", "amd64_advapi32_profile", None),
    DLL("Windows/SysWOW64/advapi32.dll", "x86_advapi32_profile", None),
    DLL("Windows/System32/comctl32.dll", "amd64_comctl32_profile", None),
    DLL("Windows/SysWOW64/comctl32.dll", "x86_comctl32_profile", None),
    DLL("Windows/System32/crypt32.dll", "amd64_crypt32_profile", None),
    DLL("Windows/SysWOW64/crypt32.dll", "x86_crypt32_profile", None),
    DLL("Windows/System32/dnsapi.dll", "amd64_dnsapi_profile", None),
    DLL("Windows/SysWOW64/dnsapi.dll", "wow64_dnsapi_profile", None),
    DLL("Windows/System32/gdi32.dll", "amd64_gdi32_profile", None),
    DLL("Windows/SysWOW64/gdi32.dll", "wow64_gdi32_profile", None),
    DLL("Windows/System32/imagehlp.dll", "amd64_imagehlp_profile", None),
    DLL("Windows/SysWOW64/imagehlp.dll", "wow64_imagehlp_profile", None),
    DLL("Windows/System32/imm32.dll", "amd64_imm32_profile", None),
    DLL("Windows/SysWOW64/imm32.dll", "wow64_imm32_profile", None),
    DLL("Windows/System32/msacm32.dll", "amd64_msacm32_profile", None),
    DLL("Windows/SysWOW64/msacm32.dll", "x86_msacm32_profile", None),
    DLL("Windows/System32/msvcrt.dll", "amd64_msvcrt_profile", None),
    DLL("Windows/SysWOW64/msvcrt.dll", "x86_msvcrt_profile", None),
    DLL("Windows/System32/netapi32.dll", "amd64_netapi32_profile", None),
    DLL("Windows/SysWOW64/netapi32.dll", "x86_netapi32_profile", None),
    DLL("Windows/System32/oleaut32.dll", "amd64_oleaut32_profile", None),
    DLL("Windows/SysWOW64/oleaut32.dll", "wow64_oleaut32_profile", None),
    DLL("Windows/System32/powrprof.dll", "amd64_powrprof_profile", None),
    DLL("Windows/SysWOW64/powrprof.dll", "x86_powrprof_profile", None),
    DLL("Windows/System32/psapi.dll", "amd64_psapi_profile", None),
    DLL("Windows/SysWOW64/psapi.dll", "x86_psapi_profile", None),
    DLL("Windows/System32/rpcrt4.dll", "amd64_rpcrt4_profile", None),
    DLL("Windows/SysWOW64/rpcrt4.dll", "wow64_rpcrt4_profile", None),
    DLL("Windows/System32/secur32.dll", "amd64_secur32_profile", None),
    DLL("Windows/SysWOW64/secur32.dll", "wow64_secur32_profile", None),
    DLL("Windows/System32/SensApi.dll", "amd64_SensApi_profile", None),
    DLL("Windows/SysWOW64/SensApi.dll", "x86_SensApi_profile", None),
    DLL("Windows/System32/shell32.dll", "amd64_shell32_profile", None),
    DLL("Windows/SysWOW64/shell32.dll", "wow64_shell32_profile", None),
    DLL("Windows/System32/shlwapi.dll", "amd64_shlwapi_profile", None),
    DLL("Windows/SysWOW64/shlwapi.dll", "x86_shlwapi_profile", None),
    DLL("Windows/System32/urlmon.dll", "amd64_urlmon_profile", None),
    DLL("Windows/SysWOW64/urlmon.dll", "x86_urlmon_profile", None),
    DLL("Windows/System32/user32.dll", "amd64_user32_profile", None),
    DLL("Windows/SysWOW64/user32.dll", "wow64_user32_profile", None),
    DLL("Windows/System32/userenv.dll", "amd64_userenv_profile", None),
    DLL("Windows/SysWOW64/userenv.dll", "x86_userenv_profile", None),
    DLL("Windows/System32/version.dll", "amd64_version_profile", None),
    DLL("Windows/SysWOW64/version.dll", "x86_version_profile", None),
    DLL("Windows/System32/winhttp.dll", "amd64_winhttp_profile", None),
    DLL("Windows/SysWOW64/winhttp.dll", "wow64_winhttp_profile", None),
    DLL("Windows/System32/wininet.dll", "amd64_wininet_profile", None),
    DLL("Windows/SysWOW64/wininet.dll", "x86_wininet_profile", None),
    DLL("Windows/System32/winmm.dll", "amd64_winmm_profile", None),
    DLL("Windows/SysWOW64/winmm.dll", "x86_winmm_profile", None),
    DLL("Windows/System32/winspool.drv", "amd64_winspool_profile", None),
    DLL("Windows/SysWOW64/winspool.drv", "x86_winspool_profile", None),
    DLL("Windows/System32/ws2_32.dll", "amd64_ws2_32_profile", None),
    DLL("Windows/SysWOW64/ws2_32.dll", "x86_ws2_32_profile", None),
    DLL("Windows/System32/wsock32.dll", "amd64_wsock32_profile", None),
    DLL("Windows/SysWOW64/wsock32.dll", "x86_wsock32_profile", None),
    DLL("Windows/System32/wtsapi32.dll", "amd64_wtsapi32_profile", None),
    DLL("Windows/SysWOW64/wtsapi32.dll", "x86_wtsapi32_profile", None),
]


dll_file_list = (
    required_dll_file_list + optional_dll_file_list + apivectors_dll_file_list
)
