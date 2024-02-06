import logging
import subprocess

import pefile
from oletools.olevba import VBA_Parser

from drakrun.lib.vba_graph import get_outer_nodes_from_vba_file

log = logging.getLogger(__name__)


def get_sample_startup_command(extension: str, content: bytes) -> str:
    if extension == "dll":
        return get_dll_startup_command(content)
    if extension in ["exe", "bat"]:
        return "%f"
    if extension == "ps1":
        return "powershell.exe -executionpolicy bypass -File %f"
    if is_office_file(extension):
        return get_office_file_startup_command(extension, content)
    if extension in ["js", "jse", "vbs", "vbe"]:
        return "wscript.exe %f"
    if extension in ["hta", "html", "htm"]:
        return "mshta.exe %f"
    return "cmd.exe /C start %f"


def get_office_file_startup_command(extension: str, content: bytes) -> str:
    start_command = ["cmd.exe", "/C", "start"]
    if is_office_word_file(extension):
        start_command.append("winword.exe")
    elif is_office_excel_file(extension):
        start_command.append("excel.exe")
    elif is_office_powerpoint_file(extension):
        start_command.append("powerpnt.exe")
    else:
        raise RuntimeError(f"Unknown office file extension {extension}.")
    start_command.extend(["/t", "%f"])

    if file_type_allows_macros(extension):
        vbaparser = VBA_Parser(f"malware.{extension}", data=content)
        if vbaparser.detect_vba_macros():
            outer_macros = get_outer_nodes_from_vba_file(vbaparser)
            if not outer_macros:
                outer_macros = []
            for outer_macro in outer_macros:
                start_command.append(f"/m{outer_macro}")

    return subprocess.list2cmdline(start_command)


def get_dll_startup_command(pe_data: bytes) -> str:
    d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
    pe = pefile.PE(data=pe_data, fast_load=True)
    pe.parse_data_directories(directories=d)

    try:
        exports = [
            (e.ordinal, e.name.decode("utf-8", "ignore"))
            for e in pe.DIRECTORY_ENTRY_EXPORT.symbols
        ]
    except AttributeError:
        return "regsvr32 /s %f"

    for export in exports:
        if export[1] == "DllRegisterServer":
            return "regsvr32 /s %f"

        if "DllMain" in export[1]:
            return "rundll32 %f,{}".format(export[1])

    if exports:
        export = exports[0]
        if exports[0][1]:
            return "rundll32 %f,{}".format(export[1].split("@")[0])
        elif exports[0][0]:
            return "rundll32 %f,#{}".format(export[0])

    return "regsvr32 /s %f"


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
