import logging

import pefile
import subprocess
from oletools.olevba import VBA_Parser

from drakrun.vba_graph import get_outer_nodes_from_vba_file


log = logging.getLogger("drakrun")


class SampleStartupRouter:
    @staticmethod
    def get_sample_startup_command(extension, sample, file_path):
        start_command = None

        if extension == "dll":
            start_command = SampleStartupRouter.get_dll_startup_command(sample.content)
        elif extension in ["exe", "bat", "vbs"]:
            start_command = "%f"
        elif extension == "ps1":
            start_command = "powershell.exe -executionpolicy bypass -File %f"
        elif SampleStartupRouter.is_office_file(extension):
            start_command = SampleStartupRouter.get_office_file_startup_command(
                extension, file_path
            )
        elif extension in ["js", "jse"]:
            start_command = "wscript.exe %f"
        elif extension in ["hta", "html", "htm"]:
            start_command = "mshta.exe %f"
        else:
            log.warning(f"Unknown file extension {extension}.")
            # It's OK to fail on unknown extension
            return None
        return start_command

    @staticmethod
    def get_office_file_startup_command(extension, file_path):
        start_command = ["cmd.exe", "/C", "start"]
        if SampleStartupRouter.is_office_word_file(extension):
            start_command.append("winword.exe")
        elif SampleStartupRouter.is_office_excel_file(extension):
            start_command.append("excel.exe")
        elif SampleStartupRouter.is_office_powerpoint_file(extension):
            start_command.append("powerpnt.exe")
        else:
            log.warning(f"Unknown office file extension {extension}.")
            return None
        start_command.extend(["/t", "%f"])

        vbaparser = VBA_Parser(file_path)
        if vbaparser.detect_vba_macros():
            outer_macros = get_outer_nodes_from_vba_file(file_path)
            if not outer_macros:
                outer_macros = []
            for outer_macro in outer_macros:
                start_command.append(f"/m{outer_macro}")

        return subprocess.list2cmdline(start_command)

    @staticmethod
    def get_dll_startup_command(pe_data):
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
            if exports[0][1]:
                return "rundll32 %f,{}".format(export[1].split("@")[0])
            elif exports[0][0]:
                return "rundll32 %f,#{}".format(export[0])

        return "regsvr32 /s %f"

    @staticmethod
    def is_office_word_file(extension):
        return extension in ["doc", "docm", "docx", "dotm", "rtf"]

    @staticmethod
    def is_office_excel_file(extension):
        return extension in ["xls", "xlsx", "xlsm", "xltx", "xltm"]

    @staticmethod
    def is_office_powerpoint_file(extension):
        return extension in ["ppt", "pttx"]

    @staticmethod
    def is_office_file(extension):
        return (
            SampleStartupRouter.is_office_word_file(extension)
            or SampleStartupRouter.is_office_excel_file(extension)
            or SampleStartupRouter.is_office_powerpoint_file(extension)
        )
