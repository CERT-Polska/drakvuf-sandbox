import re
import subprocess
from dataclasses import dataclass, field
from typing import IO, AnyStr

from dataclasses_json import DataClassJsonMixin, config

from .structs import VmiGuidInfo


def vmi_win_guid(vm_name: str) -> VmiGuidInfo:
    result = subprocess.run(
        ["vmi-win-guid", "name", vm_name],
        timeout=30,
        capture_output=True,
    )

    output = result.stdout.decode()

    version = re.search(r"Version: (.*)", output)
    pdb_guid = re.search(r"PDB GUID: ([0-9a-f]+)", output)
    kernel_filename = re.search(r"Kernel filename: ([a-z]+\.[a-z]+)", output)

    if version is None or pdb_guid is None or kernel_filename is None:
        raise RuntimeError("Invalid vmi-win-guid output")

    return VmiGuidInfo(version.group(1), pdb_guid.group(1), kernel_filename.group(1))


hexstring = config(
    encoder=lambda v: hex(v),
    decoder=lambda v: int(v, 16),
)


@dataclass
class VmiOffsets(DataClassJsonMixin):
    # Fields correspond to output defined in
    # https://github.com/libvmi/libvmi/blob/master/examples/win-offsets.c

    win_ntoskrnl: int = field(metadata=hexstring)
    win_ntoskrnl_va: int = field(metadata=hexstring)

    win_tasks: int = field(metadata=hexstring)
    win_pdbase: int = field(metadata=hexstring)
    win_pid: int = field(metadata=hexstring)
    win_pname: int = field(metadata=hexstring)
    win_kdvb: int = field(metadata=hexstring)
    win_sysproc: int = field(metadata=hexstring)
    win_kpcr: int = field(metadata=hexstring)
    win_kdbg: int = field(metadata=hexstring)

    kpgd: int = field(metadata=hexstring)

    @staticmethod
    def from_tool_output(output: str) -> "VmiOffsets":
        """
        Parse vmi-win-offsets tool output and return VmiOffsets.
        If any of the fields is missing, throw TypeError
        """
        offsets = re.findall(r"^([a-z_]+):(0x[0-9a-f]+)$", output, re.MULTILINE)
        vals = {k: int(v, 16) for k, v in offsets}
        return VmiOffsets(**vals)


def extract_vmi_offsets(
    domain: str, kernel_profile: str, timeout: int = 30
) -> VmiOffsets:
    """Call vmi-win-offsets helper and obtain VmiOffsets values"""
    try:
        output = subprocess.check_output(
            ["vmi-win-offsets", "--name", domain, "--json-kernel", kernel_profile],
            timeout=timeout,
            text=True,
        )
        return VmiOffsets.from_tool_output(output)
    except TypeError:
        raise RuntimeError("Invalid output of vmi-win-offsets")
    except subprocess.CalledProcessError:
        raise RuntimeError("vmi-win-offsets exited with an error")
    except subprocess.TimeoutExpired:
        raise RuntimeError("vmi-win-offsets timed out")


def extract_explorer_pid(domain: str, kernel_profile: str, timeout: int = 30) -> int:
    """Call get-explorer-pid helper and get its PID"""
    try:
        output = subprocess.check_output(
            ["vmi-process-list", "--name", domain, "--json", kernel_profile],
            timeout=timeout,
            text=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError("vmi-process-list exited with an error")
    except subprocess.TimeoutExpired:
        raise RuntimeError("vmi-process-list timed out")

    m = re.search(r"\[ +(\d+)] explorer.exe", output)
    if m is not None:
        return int(m.group(1))
    else:
        raise RuntimeError("explorer.exe PID not found")


@dataclass
class RuntimeInfo(DataClassJsonMixin):
    vmi_offsets: VmiOffsets
    inject_pid: int

    @staticmethod
    def load(file_obj: IO[AnyStr]) -> "RuntimeInfo":
        return RuntimeInfo.from_json(file_obj.read())
