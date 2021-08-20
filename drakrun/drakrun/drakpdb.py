import argparse
import os
import re

import pdbparse
import json

import requests
from construct import Struct, Const, Bytes, Int32ul, Int16ul, CString, EnumIntegerString
from construct.lib.containers import Container
from pefile import PE, DEBUG_TYPE
from requests import HTTPError
from tqdm import tqdm
from typing import NamedTuple, Optional, Union

DLL = NamedTuple("DLL", [("path", str), ("dest", str), ("arg", Optional[str])])


# something is wrong if these DLLs fail
compulsory_dll_file_list = [
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

# profile file list, without 'C:\' and with '/' instead of '\'
dll_file_list = [
    DLL("Windows/System32/drivers/tcpip.sys", "amd64_tcpip_profile", "--json-tcpip"),
    DLL("Windows/System32/sspicli.dll", "amd64_sspicli_profile", "--json-sspicli"),
    DLL(
        "Windows/System32/KernelBase.dll",
        "amd64_kernelbase_profile",
        "--json-kernelbase",
    ),
    DLL("Windows/System32/IPHLPAPI.DLL", "amd64_iphlpapi_profile", "--json-iphlpapi"),
    DLL("Windows/SysWOW64/IPHLPAPI.DLL", "x86_iphlpapi_profile", None),
    DLL("Windows/System32/mpr.dll", "amd64_mpr_profile", "--json-mpr"),
    DLL("Windows/SysWOW64/mpr.dll", "x86_mpr_profile", None),
    DLL("Windows/System32/ole32.dll", "amd64_ole32_profile", None),
    DLL("Windows/SysWOW64/ole32.dll", "x86_ole32_profile", None),
    # wasn't able to find this file in our snapshot - should be investigated
    # at some point
    DLL("Windows/System32/combase.dll", "amd64_combase_profile", None),
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


CV_RSDS_HEADER = "CV_RSDS" / Struct(
    "Signature" / Const(b"RSDS", Bytes(4)),
    "GUID"
    / Struct(
        "Data1" / Int32ul,
        "Data2" / Int16ul,
        "Data3" / Int16ul,
        "Data4" / Bytes(8),
    ),
    "Age" / Int32ul,
    "Filename" / CString(encoding="utf8"),
)


# Derived from rekall
TYPE_ENUM_TO_VTYPE = {
    "T_32PINT4": ["Pointer", dict(target="long")],
    "T_32PLONG": ["Pointer", dict(target="long")],
    "T_32PQUAD": ["Pointer", dict(target="long long")],
    "T_32PRCHAR": ["Pointer", dict(target="unsigned char")],
    "T_32PREAL32": ["Pointer", dict(target="Void")],
    "T_32PREAL64": ["Pointer", dict(target="Void")],
    "T_32PSHORT": ["Pointer", dict(target="short")],
    "T_32PUCHAR": ["Pointer", dict(target="unsigned char")],
    "T_32PUINT4": ["Pointer", dict(target="unsigned int")],
    "T_32PULONG": ["Pointer", dict(target="unsigned long")],
    "T_32PUQUAD": ["Pointer", dict(target="unsigned long long")],
    "T_32PUSHORT": ["Pointer", dict(target="unsigned short")],
    "T_32PVOID": ["Pointer", dict(target="Void")],
    "T_32PWCHAR": ["Pointer", dict(target="UnicodeString")],
    "T_32PHRESULT": ["Pointer", dict(target="long")],
    "T_64PINT4": ["Pointer", dict(target="long")],
    "T_64PLONG": ["Pointer", dict(target="long")],
    "T_64PQUAD": ["Pointer", dict(target="long long")],
    "T_64PSHORT": ["Pointer", dict(target="short")],
    "T_64PRCHAR": ["Pointer", dict(target="unsigned char")],
    "T_64PUCHAR": ["Pointer", dict(target="unsigned char")],
    "T_64PWCHAR": ["Pointer", dict(target="String")],
    "T_64PULONG": ["Pointer", dict(target="unsigned long")],
    "T_64PUQUAD": ["Pointer", dict(target="unsigned long long")],
    "T_64PUSHORT": ["Pointer", dict(target="unsigned short")],
    "T_64PVOID": ["Pointer", dict(target="Void")],
    "T_64PREAL32": ["Pointer", dict(target="float")],
    "T_64PREAL64": ["Pointer", dict(target="double")],
    "T_64PUINT4": ["Pointer", dict(target="unsigned int")],
    "T_64PHRESULT": ["Pointer", dict(target="long")],
    "T_BOOL08": ["unsigned char", {}],
    "T_CHAR": ["char", {}],
    "T_INT4": ["long", {}],
    "T_INT8": ["long long", {}],
    "T_LONG": ["long", {}],
    "T_QUAD": ["long long", {}],
    "T_RCHAR": ["unsigned char", {}],
    "T_REAL32": ["float", {}],
    "T_REAL64": ["double", {}],
    "T_REAL80": ["long double", {}],
    "T_SHORT": ["short", {}],
    "T_UCHAR": ["unsigned char", {}],
    "T_UINT4": ["unsigned long", {}],
    "T_UINT8": ["unsigned long long", {}],
    "T_ULONG": ["unsigned long", {}],
    "T_UQUAD": ["unsigned long long", {}],
    "T_USHORT": ["unsigned short", {}],
    "T_VOID": ["Void", {}],
    "T_WCHAR": ["UnicodeString", {}],
    "T_HRESULT": ["long", {}],
}


class Demangler(object):
    """A utility class to demangle VC++ names.

    This is not a complete or accurate demangler, it simply extract the name and
    strips out args etc.

    Ref:
    http://www.kegel.com/mangle.html
    """

    STRING_MANGLE_MAP = {
        r"?0": ",",
        r"?1": "/",
        r"?2": r"\\",
        r"?4": ".",
        r"?3": ":",
        r"?5": "_",  # Really space.
        r"?6": ".",  # Really \n.
        r"?7": '"',
        r"?8": "'",
        r"?9": "-",
        r"?$AA": "",
        r"?$AN": "",  # Really \r.
        r"?$CF": "%",
        r"?$EA": "@",
        r"?$CD": "#",
        r"?$CG": "&",
        r"?$HO": "~",
        r"?$CI": "(",
        r"?$CJ": ")",
        r"?$DM1": "</",
        r"?$DMO": ">",
        r"?$DN": "=",
        r"?$CK": "*",
        r"?$CB": "!",
    }

    STRING_MANGLE_RE = re.compile(
        "("
        + "|".join(
            [x.replace("?", "\\?").replace("$", "\\$") for x in STRING_MANGLE_MAP]
        )
        + ")"
    )

    def _UnpackMangledString(self, string):
        string = string.split("@")[3]
        result = "str:" + self.STRING_MANGLE_RE.sub(
            lambda m: self.STRING_MANGLE_MAP[m.group(0)], string
        )
        return result

    SIMPLE_X86_CALL = re.compile(r"[_@]([A-Za-z0-9_]+)@(\d{1,3})$")
    FUNCTION_NAME_RE = re.compile(r"\?([A-Za-z0-9_]+)@")

    def DemangleName(self, mangled_name):
        """Returns the de-mangled name.

        At this stage we don't really do proper demangling since we usually dont
        care about the prototype, nor c++ exports. In the future we should
        though.
        """
        m = self.SIMPLE_X86_CALL.match(mangled_name)
        if m:
            # If we see x86 name mangling (_cdecl, __stdcall) with stack sizes
            # of 4 bytes, this is definitely a 32 bit pdb. Sometimes we dont
            # know the architecture of the pdb file for example if we do not
            # have the original binary, but only the GUID as extracted by
            # version_scan.
            # TODO set arch to i386
            return m.group(1)

        m = self.FUNCTION_NAME_RE.match(mangled_name)
        if m:
            return m.group(1)

        # Strip the first _ from the name. I386 mangled constants have a
        # leading _ but their AMD64 counterparts do not.
        if mangled_name and mangled_name[0] in "_.":
            mangled_name = mangled_name[1:]

        elif mangled_name.startswith("??_C@"):
            return self._UnpackMangledString(mangled_name)

        return mangled_name


class DummyOmap(object):
    def remap(self, addr):
        return addr


def get_field_type_info(field):
    if isinstance(field.index, EnumIntegerString):
        return TYPE_ENUM_TO_VTYPE[str(field.index)]

    try:
        return [field.index.name, {}]
    except AttributeError:
        return ["<unknown>", {}]


def traverse_tree(ss, visited=None):
    if visited is None:
        visited = set()

    for info in ss:
        if not info.name or info.name in visited:
            continue

        yield info.name, process_struct(info)
        visited.add(info.name)

        try:
            for struct in info.fieldlist.substructs:
                try:
                    yield from traverse_tree([struct.element_type], visited=visited)
                except AttributeError:
                    pass

                try:
                    yield from traverse_tree([struct.index], visited=visited)
                except AttributeError:
                    pass

                try:
                    yield from traverse_tree([struct.index.utype], visited=visited)
                except AttributeError:
                    pass
        except AttributeError:
            pass


def process_struct(struct_info):
    ss = {}

    try:
        for struct in struct_info.fieldlist.substructs:
            # try to access struct.offset and trigger
            # an AttributeError if it's missing
            _ = struct.offset
            ss[struct.name] = struct
    except AttributeError:
        pass

    field_info = {}
    for name, field in ss.items():
        typ = get_field_type_info(field)
        field_info[name] = (field.offset, typ)

    return [struct_info.size, field_info]


def make_symstore_hash(
    codeview_struct: Union[Container, pdbparse.PDBInfoStream]
) -> str:
    """
    If `codeview_struct` is an instance of Container, it should be returned from `CV_RSDS_HEADER.parse()`.
    """
    guid = codeview_struct.GUID
    guid_str = "%08x%04x%04x%s" % (
        guid.Data1,
        guid.Data2,
        guid.Data3,
        guid.Data4.hex(),
    )
    return "%s%x" % (guid_str, codeview_struct.Age)


def make_pdb_profile(
    filepath, dll_origin_path=None, dll_path=None, dll_symstore_hash=None
):
    pdb = pdbparse.parse(filepath)

    try:
        sects = pdb.STREAM_SECT_HDR_ORIG.sections
        omap = pdb.STREAM_OMAP_FROM_SRC
    except AttributeError:
        # In this case there is no OMAP, so we use the given section
        # headers and use the identity function for omap.remap
        sects = pdb.STREAM_SECT_HDR.sections
        omap = DummyOmap()

    gsyms = pdb.STREAM_GSYM
    profile = {"$FUNCTIONS": {}, "$CONSTANTS": {}, "$STRUCTS": {}}
    struct_specs = {
        name: info for name, info in traverse_tree(pdb.STREAM_TPI.structures.values())
    }

    for structName, structFields in struct_specs.items():
        if structFields != [0, {}]:
            profile["$STRUCTS"][structName] = structFields

    mapped_syms = {"$CONSTANTS": {}, "$FUNCTIONS": {}}

    for sym in gsyms.globals:
        try:
            off = sym.offset
            sym_name = sym.name
            virt_base = sects[sym.segment - 1].VirtualAddress
            mapped = omap.remap(off + virt_base)
            if (sym.symtype & 2) == 2:
                target_key = "$FUNCTIONS"
            else:
                target_key = "$CONSTANTS"
        except IndexError:
            # skip symbol because segment was not found
            continue
        except AttributeError:
            # missing offset in symbol?
            continue

        sym_name = Demangler().DemangleName(sym_name)

        if sym_name not in mapped_syms[target_key]:
            mapped_syms[target_key][sym_name] = list()

        mapped_syms[target_key][sym_name].append(mapped)

    for target_key, sym_dict in mapped_syms.items():
        for sym_name, value_set in sym_dict.items():
            ndx = 0

            for mapped in sorted(value_set):
                if ndx == 0:
                    next_sym_name = sym_name
                else:
                    next_sym_name = "{}_{}".format(sym_name, ndx)

                ndx += 1
                profile[target_key][next_sym_name] = mapped

    del mapped_syms
    pdb_symstore_hash = make_symstore_hash(pdb.STREAM_PDB)
    base_filename = os.path.splitext(os.path.basename(filepath))[0]

    profile["$METADATA"] = {
        "DLL_GUID_AGE": dll_symstore_hash,
        "GUID_AGE": pdb_symstore_hash,
        "PDBFile": os.path.basename(filepath),
        "ProfileClass": base_filename[0].upper() + base_filename[1:].lower(),
        "Timestamp": pdb.STREAM_PDB.TimeDateStamp.replace(tzinfo=None).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        ),
        "Type": "Profile",
        "Version": pdb.STREAM_PDB.Version,
    }

    # Additional metadata requested by the ApiVectors developers
    profile["$EXTRAS"] = {}
    if dll_origin_path:
        profile["$EXTRAS"]["DLLPath"] = str(dll_origin_path)

    if dll_path:
        try:
            pe = PE(dll_path, fast_load=True)
            profile["$EXTRAS"]["ImageBase"] = hex(pe.OPTIONAL_HEADER.ImageBase)
        except AttributeError:
            # I think that DLLs have some sanity and the optional header is
            # always present. Ignore this error if it happens
            pass

    return json.dumps(profile, indent=4, sort_keys=True)


def fetch_pdb(pdbname, guidage, destdir="."):
    url = "https://msdl.microsoft.com/download/symbols/{}/{}/{}".format(
        pdbname, guidage.lower(), pdbname
    )

    try:
        with requests.get(url, stream=True) as res:
            res.raise_for_status()
            total_size = int(res.headers.get("content-length", 0))
            dest = os.path.join(destdir, os.path.basename(pdbname))

            with tqdm(total=total_size, unit="iB", unit_scale=True) as pbar:
                with open(dest, "wb") as f:
                    for chunk in res.iter_content(chunk_size=1024 * 8):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))

        return dest
    except HTTPError as e:
        print("Failed to download from: {}, reason: {}".format(url, str(e)))

    raise RuntimeError("Failed to fetch PDB")


def pe_codeview_data(file):
    pe = PE(file, fast_load=True)
    pe.parse_data_directories()
    try:
        codeview = next(
            filter(
                lambda x: x.struct.Type == DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"],
                pe.DIRECTORY_ENTRY_DEBUG,
            )
        )
    except StopIteration:
        print("Failed to find CodeView in pdb")
        raise RuntimeError("Failed to find GUID age")

    offset = codeview.struct.PointerToRawData
    size = codeview.struct.SizeOfData
    codeview_struct = CV_RSDS_HEADER.parse(pe.__data__[offset : offset + size])
    return {
        "filename": codeview_struct.Filename,
        "symstore_hash": make_symstore_hash(codeview_struct),
    }


def main():
    parser = argparse.ArgumentParser(description="drakpdb")
    parser.add_argument(
        "action",
        type=str,
        help="one of: fetch_pdb (requires --pdb-name and --guid_age), parse_pdb (requires --pdb-name), pe_codeview_data (requires --file)",
    )
    parser.add_argument(
        "--pdb_name",
        type=str,
        help="name of pdb file with extension, e.g. ntkrnlmp.pdb",
    )
    parser.add_argument("--guid_age", type=str, help="guid/age of the pdb file")
    parser.add_argument(
        "--file", type=str, help="file to get symstore_hash (GUID + Age) from"
    )

    args = parser.parse_args()

    if args.action == "parse_pdb":
        print(make_pdb_profile(args.pdb_name))
    elif args.action == "fetch_pdb":
        fetch_pdb(args.pdb_name, args.guid_age)
    elif args.action == "pe_codeview_data":
        print(pe_codeview_data(args.file))
    else:
        raise RuntimeError("Unknown action")


if __name__ == "__main__":
    main()
