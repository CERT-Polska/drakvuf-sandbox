import logging
import pathlib
import random
import string
import unicodedata
from typing import NamedTuple, Optional

import mslex
from pathvalidate import Platform, is_valid_filename

from .analysis_options import StartMethod

log = logging.getLogger(__name__)


def random_filename() -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(10))


def get_sample_filename_from_host_path(host_path: pathlib.Path) -> str:
    name, extension = host_path.name, host_path.suffix
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


def get_startup_method_and_argv(
    target_path: str,
) -> tuple[StartMethod, list[str]]:
    extension = target_path.rsplit(".", 1)[-1].lower()
    if extension == "dll":
        return "createproc", ["rundll32", target_path]
    elif extension in ["exe", "bat"]:
        return "createproc", [target_path]
    elif extension == "ps1":
        return "createproc", [
            "powershell.exe",
            "-executionpolicy",
            "bypass",
            "-File",
            target_path,
        ]
    elif extension in ["js", "jse", "vbs", "vbe"]:
        return "createproc", ["wscript.exe", target_path]
    elif extension in ["hta", "html", "htm"]:
        return "createproc", ["mshta.exe", target_path]
    else:
        return "shellexec", ["cmd.exe", "/C", "start", target_path]


class ExecParameters(NamedTuple):
    start_method: StartMethod
    command: str
    shellexec_args: Optional[str]
    full_command: str


def make_exec_parameters(
    start_command: list[str] | str,
    start_method: StartMethod,
    shellexec_supported: bool,
) -> ExecParameters:
    shellexec_args = None
    if start_method in ["shellexec", "runas"]:
        # If start_command is not None: it's str or list[str]
        if type(start_command) is str:
            splitted_cmd = mslex.split(start_command, like_cmd=False)
        else:
            splitted_cmd = start_command

        if shellexec_supported:
            exec_cmd = splitted_cmd[0]
            shellexec_args = mslex.join(splitted_cmd[1:], for_cmd=False)
            full_command = mslex.join(splitted_cmd, for_cmd=False)
        else:
            # If shellexec is not supported, we fallback to
            # cmd.exe /C start "" <cmd>
            start_method: StartMethod = "createproc"
            exec_cmd = 'cmd.exe /C start "" ' + mslex.join(splitted_cmd, for_cmd=False)
            full_command = exec_cmd

    elif start_method == "createproc":
        if type(start_command) is str:
            full_command = exec_cmd = start_command
        else:
            full_command = exec_cmd = mslex.join(start_command, for_cmd=False)
    else:
        raise ValueError(f"Unsupported start_method: {start_method}")

    return ExecParameters(
        start_method=start_method,
        command=exec_cmd,
        shellexec_args=shellexec_args,
        full_command=full_command,
    )
