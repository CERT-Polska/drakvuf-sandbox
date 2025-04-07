import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from dataclasses_json import DataClassJsonMixin, config

log = logging.getLogger(__name__)

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


@dataclass
class VmiInfo(DataClassJsonMixin):
    vmi_offsets: VmiOffsets
    inject_pid: int
    inject_tid: Optional[int] = None

    @staticmethod
    def load(file_path: str) -> "VmiInfo":
        with open(file_path) as file_obj:
            return VmiInfo.from_json(file_obj.read())


@dataclass
class VmiGuidInfo:
    version: str
    guid: str
    filename: str
