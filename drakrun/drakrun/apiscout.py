import json
import logging
from operator import attrgetter
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List

import pefile

log = logging.getLogger(__name__)


def get_bitness(pe: pefile.PE) -> int:
    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
        return 64
    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
        return 32
    else:
        log.error(
            f"Unsupported machine_type: {pe.FILE_HEADER.Machine} -> {pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]}"
        )
        return None


def get_product_version(pe: pefile.PE) -> str:
    """
    Based on https://stackoverflow.com/a/16076661/12452744
    """

    def LOWORD(dword):
        return dword & 0x0000FFFF

    def HIWORD(dword):
        return dword >> 16

    if len(pe.VS_FIXEDFILEINFO) != 1:
        log.error("Unsupported case: len(pe.VS_FIXEDFILEINFO) != 1")
        return None
    try:
        ms = pe.VS_FIXEDFILEINFO[0].ProductVersionMS
        ls = pe.VS_FIXEDFILEINFO[0].ProductVersionLS
        return "{}.{}.{}.{}".format(HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls))
    except AttributeError:
        log.exception("")
        return None


def make_static_apiscout_profile_for_dll(filepath: str) -> Dict[str, Any]:
    """
    Based on https://github.com/danielplohmann/apiscout/blob/0fca2eefa5b557b05eb77ab7a3246825f7aa71c3/apiscout/db_builder/DatabaseBuilder.py#L99-L127
    """
    pe = pefile.PE(filepath, fast_load=True)
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ]
    )

    dll_entry = {}
    dll_entry["base_address"] = pe.OPTIONAL_HEADER.ImageBase
    dll_entry["bitness"] = get_bitness(pe)
    dll_entry["version"] = get_product_version(pe) or "0.0.0.0"
    dll_entry["filepath"] = filepath
    dll_entry["aslr_offset"] = 0
    dll_entry["exports"] = []
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        if pe.is_driver():
            return dll_entry
        raise RuntimeError(f"DIRECTORY_ENTRY_EXPORT not found in '{filepath}'")
    for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=attrgetter("address")):
        export_info = {}

        export_info["address"] = exp.address
        if exp.name is None:
            export_info["name"] = "None"
        else:
            export_info["name"] = exp.name.decode()
        export_info["ordinal"] = exp.ordinal
        dll_entry["exports"].append(export_info)

    return dll_entry


def build_apiscout_dll_key(dll_info: Dict[str, Any]) -> str:
    """
    From https://github.com/danielplohmann/apiscout/blob/0fca2eefa5b557b05eb77ab7a3246825f7aa71c3/apiscout/db_builder/DatabaseBuilder.py#L129-L131
    """
    filename = PureWindowsPath(dll_info["filepath"]).name
    return "{}_{}_{}_0x{:x}".format(
        dll_info["bitness"], dll_info["version"], filename, dll_info["base_address"]
    )


def build_static_apiscout_profile(
    apiscout_profile_dir: str, dll_basename_list: List[str]
) -> Dict[str, Any]:
    dlls_profiles = {}

    for dll_basename in dll_basename_list:
        filepath = Path(apiscout_profile_dir) / f"{dll_basename}.json"
        if not filepath.is_file():
            log.warning(
                f"'{filepath}' not found. Is there a problem with profiles generation?"
            )
            continue
        with open(filepath) as f:
            dll_profile = json.load(f)
        dlls_profiles[build_apiscout_dll_key(dll_profile)] = dll_profile

    with open(Path(apiscout_profile_dir) / "OS_INFO.json", "r") as f:
        os_info = json.load(f)

    static_apiscout_profile = {
        "aslr_offsets": False,
        "dlls": dlls_profiles,
        "filtered": False,
        "num_apis": sum(
            len(dll_profile["exports"]) for dll_profile in dlls_profiles.values()
        ),
        "num_dlls": len(dlls_profiles),
        "os_name": os_info["os_name"],
        # For recovering accurate version (e.g. "6.1.7601") ...
        "os_version": os_info["os_timestamp"],
    }

    return static_apiscout_profile
