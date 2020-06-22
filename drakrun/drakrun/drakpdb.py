import argparse
import os
import re

import pdbparse
import json

import requests
from construct import EnumIntegerString
from requests import HTTPError
from tqdm import tqdm
from typing import NamedTuple


DLL = NamedTuple("DLL", [("path", str), ("dest", str)])

# profile file list, without 'C:\' and with '/' instead of '\'
dll_file_list = [
    DLL("Windows/System32/drivers/tcpip.sys", "tcpip_profile"),
    DLL("Windows/System32/win32k.sys", "win32k_profile"),
    DLL("Windows/System32/sspicli.dll", "sspicli_profile"),
    DLL("Windows/System32/kernel32.dll", "kernel32_profile"),
    DLL("Windows/System32/KernelBase.dll", "kernelbase_profile"),
    DLL("Windows/SysWOW64/kernel32.dll", "wow_kernel32_profile"),
    DLL("Windows/System32/IPHLPAPI.DLL", "iphlpapi_profile"),
    DLL("Windows/System32/mpr.dll", "mpr_profile"),
    DLL("Windows/System32/ntdll.dll", "ntdll_profile"),
    DLL("Windows/System32/ole32.dll", "ole32_profile"),
    DLL("Windows/SysWOW64/ole32.dll", "wow_ole32_profile"),
    DLL("Windows/System32/combase.dll", "combase_profile"),
    DLL("Windows/Microsoft.NET/Framework/v4.0.30319/clr.dll", "clr_profile"),
    DLL("Windows/Microsoft.NET/Framework/v2.0.50727/mscorwks.dll", "mscorwks_profile")
]


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
    "T_64PLONG": ["Pointer", dict(target="long")],
    "T_64PQUAD": ["Pointer", dict(target="long long")],
    "T_64PRCHAR": ["Pointer", dict(target="unsigned char")],
    "T_64PUCHAR": ["Pointer", dict(target="unsigned char")],
    "T_64PWCHAR": ["Pointer", dict(target="String")],
    "T_64PULONG": ["Pointer", dict(target="unsigned long")],
    "T_64PUQUAD": ["Pointer", dict(target="unsigned long long")],
    "T_64PUSHORT": ["Pointer", dict(target="unsigned short")],
    "T_64PVOID": ["Pointer", dict(target="Void")],
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
    "T_ULONG": ["unsigned long", {}],
    "T_UQUAD": ["unsigned long long", {}],
    "T_USHORT": ["unsigned short", {}],
    "T_VOID": ["Void", {}],
    "T_WCHAR": ["UnicodeString", {}],
    "T_HRESULT": ["long", {}]
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

    STRING_MANGLE_RE = re.compile("(" + "|".join(
        [x.replace("?", "\\?").replace("$", "\\$")
         for x in STRING_MANGLE_MAP]) + ")")

    def _UnpackMangledString(self, string):
        string = string.split("@")[3]
        result = "str:" + self.STRING_MANGLE_RE.sub(
            lambda m: self.STRING_MANGLE_MAP[m.group(0)], string)
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
            ss[struct.name] = struct
    except AttributeError:
        pass

    fields = [struct.name for struct in ss.values()]
    field_info = {ss[field].name: [ss[field].offset, get_field_type_info(ss[field])] for field in fields}
    return [struct_info.size, field_info]


def make_pdb_profile(filepath):
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
    struct_specs = {name: info for name, info in traverse_tree(pdb.STREAM_TPI.structures.values())}

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
                    next_sym_name = '{}_{}'.format(sym_name, ndx)

                ndx += 1
                profile[target_key][next_sym_name] = mapped

    del mapped_syms
    guid = pdb.STREAM_PDB.GUID
    guid_str = "%.8X%.4X%.4X%s" % (guid.Data1, guid.Data2, guid.Data3, guid.Data4.hex().upper())
    symstore_hash = "%s%s" % (guid_str, pdb.STREAM_PDB.Age)
    base_fn = os.path.splitext(os.path.basename(filepath))[0]

    profile["$METADATA"] = {
        "GUID_AGE": symstore_hash,
        "PDBFile": os.path.basename(filepath),
        "ProfileClass": base_fn[0].upper() + base_fn[1:].lower(),
        "Timestamp": pdb.STREAM_PDB.TimeDateStamp.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%SZ"),
        "Type": "Profile",
        "Version": pdb.STREAM_PDB.Version
    }
    return json.dumps(profile, indent=4, sort_keys=True)


def fetch_pdb(pdbname, guidage, destdir='.'):
    url = "https://msdl.microsoft.com/download/symbols/{}/{}/{}".format(pdbname, guidage.lower(), pdbname)

    try:
        with requests.get(url, stream=True) as res:
            res.raise_for_status()
            total_size = int(res.headers.get('content-length', 0))
            dest = os.path.join(destdir, os.path.basename(pdbname))

            with tqdm(total=total_size, unit='iB', unit_scale=True) as pbar:
                with open(dest, "wb") as f:
                    for chunk in res.iter_content(chunk_size=1024 * 8):
                        if chunk:
                            f.write(chunk)
                            pbar.update(len(chunk))

        return dest
    except HTTPError as e:
        print("Failed to download from: {}, reason: {}".format(url, str(e)))

    raise RuntimeError("Failed to fetch PDB")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='drakpdb')
    parser.add_argument('action', type=str, help='one of: fetch_pdb, parse_pdb')
    parser.add_argument('pdb_name', type=str, help='name of pdb file without extension, e.g. ntkrnlmp')
    parser.add_argument('guid_age', nargs='?', help='guid/age of the pdb file')

    args = parser.parse_args()

    if args.action == "parse_pdb":
        print(make_pdb_profile(args.pdb_name))
    elif args.action == "fetch_pdb":
        fetch_pdb(args.pdb_name, args.guid_age)
    else:
        raise RuntimeError('Unknown action')
