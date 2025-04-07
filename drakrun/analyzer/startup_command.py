import logging
import pathlib
import random
import string
import unicodedata
from typing import List

import mslex
from pathvalidate import Platform, is_valid_filename

log = logging.getLogger(__name__)


def random_filename() -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(10))


def get_target_filename_from_sample_path(sample_path: pathlib.Path) -> str:
    name, extension = sample_path.name, sample_path.suffix
    if extension is None:
        raise ValueError(
            "Sample path must have extension if target filename is not provided"
        )
    extension = extension[1:].lower()
    # Normalize/remove Unicode characters as current version of Drakvuf
    # isn't really good at handling them in logs
    file_name = (
        unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    )
    if file_name and is_valid_filename(file_name, platform=Platform.UNIVERSAL):
        return file_name
    else:
        # Use random filename if name is invalid
        return random_filename() + f".{extension}"


def get_startup_argv(
    target_path: str,
) -> List[str]:
    extension = target_path.rsplit(".", 1)[-1].lower()
    if extension == "dll":
        return ["rundll32", target_path]
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
        return ["cmd.exe", "/C", mslex.join(["start", *argv])]
    elif extension in ["js", "jse", "vbs", "vbe"]:
        return ["wscript.exe", target_path]
    elif extension in ["hta", "html", "htm"]:
        return ["mshta.exe", target_path]
    else:
        return ["cmd.exe", "/C", mslex.join(["start", target_path])]


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
