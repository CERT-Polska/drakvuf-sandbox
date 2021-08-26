import json
from operator import attrgetter
import os
from pathlib import Path
import pefile
from typing import List, Dict, Any


def get_product_version(pe):
    """
    Based on https://stackoverflow.com/a/16076661/12452744
    """

    def LOWORD(dword):
        return dword & 0x0000FFFF

    def HIWORD(dword):
        return dword >> 16

    assert len(pe.VS_FIXEDFILEINFO) == 1
    try:
        ms = pe.VS_FIXEDFILEINFO[0].ProductVersionMS
        ls = pe.VS_FIXEDFILEINFO[0].ProductVersionLS
        return "{}.{}.{}.{}".format(HIWORD(ms), LOWORD(ms), HIWORD(ls), LOWORD(ls))
    except AttributeError:
        return "0.0.0.0"


def make_static_apiscout_profile_for_dll(filepath):
    """
    Based on https://github.com/danielplohmann/apiscout/blob/0fca2eefa5b557b05eb77ab7a3246825f7aa71c3/apiscout/db_builder/DatabaseBuilder.py#L99-L127
    """
    pe = pefile.PE(filepath)
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        raise Exception(f"DIRECTORY_ENTRY_EXPORT not found in '{filepath}'")

    dll_entry = {}
    dll_entry["base_address"] = pe.OPTIONAL_HEADER.ImageBase
    dll_entry["bitness"] = 32 if pe.FILE_HEADER.Machine == 0x14C else 64
    dll_entry["version"] = get_product_version(pe)
    dll_entry["filepath"] = filepath
    dll_entry["aslr_offset"] = 0
    dll_entry["exports"] = []
    for exp in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=attrgetter("address")):
        export_info = {}

        export_info["address"] = exp.address
        if exp.name is None:
            export_info["name"] = "None"
        else:
            export_info["name"] = exp.name.decode("utf-8")
        export_info["ordinal"] = exp.ordinal
        dll_entry["exports"].append(export_info)

    return dll_entry


def build_apiscout_dll_key(dll_info):
    """
    From https://github.com/danielplohmann/apiscout/blob/0fca2eefa5b557b05eb77ab7a3246825f7aa71c3/apiscout/db_builder/DatabaseBuilder.py#L129-L131
    """
    filename = os.path.basename(dll_info["filepath"])
    return "{}_{}_{}_0x{:x}".format(
        dll_info["bitness"], dll_info["version"], filename, dll_info["base_address"]
    )


def build_static_apiscout_profile(
    apiscout_profile_dir: str, dll_basename_list: List[str]
) -> Dict[str, Any]:
    dlls_profiles = {}

    for dll_basename in dll_basename_list:
        filepath = Path(apiscout_profile_dir) / f"{dll_basename}.json"
        with open(filepath) as f:
            dll_profile = json.load(f)
        dlls_profiles[build_apiscout_dll_key(dll_profile)] = dll_profile

    with open(os.path.join(apiscout_profile_dir, "OS_INFO.json"), "r") as f:
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
        "os_version": os_info[
            "os_timestamp"
        ],  # Accurate value (e.g. "6.1.7601") can be got with it...
    }

    return static_apiscout_profile
