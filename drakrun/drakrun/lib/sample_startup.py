import logging
from typing import List

import mslex
import pefile
from oletools.olevba import VBA_Parser

from drakrun.lib.vba_graph import get_outer_nodes_from_vba_file

log = logging.getLogger(__name__)


def get_sample_startup_command(
    target_path: str, extension: str, entrypoints: List[str]
) -> str:
    """Gets a startup command suitable for running the files with the provided
    extension. Sometimes content is also parsed to determine the command.
    Extension should be provided without dot, so `dll` instead of `.dll`.
    """
    argv = get_startup_argv(target_path, extension, entrypoints)
    return mslex.join(argv, for_cmd=False)


def get_startup_argv(
    target_path: str, extension: str, entrypoints: List[str]
) -> List[str]:
    if extension == "dll":
        # If entrypoint is DllRegisterServer: let's use regsvr32
        if entrypoints == ["DllRegisterServer"]:
            return ["regsvr32", "/s", target_path]
        # If there is no entrypoint, or it's explicitly DllMain,
        # we're going to use rundll32 without extra entrypoints
        elif not entrypoints or entrypoints == ["DllMain"]:
            return ["rundll32", target_path]
        # If entrypoint is defined and doesn't look standard,
        # let's try the custom entrypoint
        else:
            return ["rundll32", target_path + "," + entrypoints[0]]
    elif extension in ["exe", "bat"]:
        return [target_path]
    elif extension == "ps1":
        return ["powershell.exe", "-executionpolicy", "bypass", "-File", target_path]
    elif is_office_file(extension):
        argv = []
        if is_office_word_file(extension):
            argv.append("winword.exe")
        elif is_office_excel_file(extension):
            argv.append("excel.exe")
        elif is_office_powerpoint_file(extension):
            argv.append("powerpnt.exe")
        else:
            raise RuntimeError(f"Unknown office file extension {extension}.")
        argv.extend(["/t", target_path])
        if entrypoints:
            for entrypoint in entrypoints:
                argv.append("/m" + entrypoint)
        return ["cmd.exe", "/C", mslex.join(["start", *argv])]
    elif extension in ["js", "jse", "vbs", "vbe"]:
        return ["wscript.exe", target_path]
    elif extension in ["hta", "html", "htm"]:
        return ["mshta.exe", target_path]
    elif extension in ["msi"]:
        return ["msiexec.exe", "/I", target_path, "/qb", "ACCEPTEULA=1", "LicenseAccepted=1"]
    elif extension in ["cpl"]:
        return ["control.exe", target_path]
    elif extension in ["mht"]:
        return ["iexplore.exe", target_path]
    elif extension in ["lnk"]:
        return ["cmd.exe", "/C", "start", "/wait", "\"\"", target_path]
    elif extension in ["sct"]:
        return ["regsvr32.exe", "/u", "/n", f"/i:{target_path}", "scrobj.dll"]
    elif extension in ["hta"]:
        return ["mshta.exe", target_path]
    elif extension in ["chm"]:
        return ["hh.exe", target_path]
    else:
        return ["cmd.exe", "/C", mslex.join(["start", target_path])]


def get_sample_entrypoints(extension: str, content: bytes) -> List[str]:
    if is_office_file(extension):
        return get_office_file_entrypoints(extension, content)
    elif extension == "dll":
        return [get_dll_entrypoint(content)]
    else:
        return []


def get_office_file_entrypoints(extension: str, content: bytes) -> List[str]:
    entrypoints = []
    if file_type_allows_macros(extension):
        vbaparser = VBA_Parser(f"malware.{extension}", data=content)
        if vbaparser.detect_vba_macros():
            outer_macros = get_outer_nodes_from_vba_file(vbaparser)
            if not outer_macros:
                outer_macros = []
            for outer_macro in outer_macros:
                entrypoints.append(outer_macro)
    return entrypoints


def get_dll_entrypoint(content: bytes) -> str:
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe = pefile.PE(data=content, fast_load=True)
    pe.parse_data_directories(directories=d)

    try:
        exports = [
            (e.ordinal, e.name.decode("utf-8", "ignore"))
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
        ]
    except AttributeError:
        return "DllMain"

    for export in exports:
        if export[1] == "DllRegisterServer":
            return "DllRegisterServer"

        if "DllMain" in export[1]:
            return export[1]

    if exports:
        export = exports[0]
        if exports[0][1]:
            entrypoint = export[1].split("@")[0]
            return entrypoint
        elif exports[0][0]:
            entrypoint = "#" + str(export[0])
            return entrypoint

    return "DllMain"


def file_type_allows_macros(extension: str) -> bool:
    return extension in ["docm", "dotm", "xls", "xlsm", "xltm", "pptx"]


def is_office_word_file(extension: str) -> bool:
    return extension in ["doc", "docm", "docx", "dotm", "rtf"]


def is_office_excel_file(extension: str) -> bool:
    return extension in ["xls", "xlsx", "xlsm", "xltx", "xltm"]


def is_office_powerpoint_file(extension: str) -> bool:
    return extension in ["ppt", "pptx"]


def is_office_file(extension: str) -> bool:
    return (
        is_office_word_file(extension)
        or is_office_excel_file(extension)
        or is_office_powerpoint_file(extension)
    )
