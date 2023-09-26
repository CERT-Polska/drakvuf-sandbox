import argparse
import json
import os
import re
from typing import Union

import pdbparse
import pefile
import requests
from construct import Bytes, Const, CString, EnumIntegerString, Int16ul, Int32ul, Struct
from construct.lib.containers import Container
from requests import HTTPError
from tqdm import tqdm

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
    "T_64PCHAR": ["Pointer", dict(target="char")],
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
    If `codeview_struct` is an instance of Container,
    it should be returned from `CV_RSDS_HEADER.parse()`.
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
            pe = pefile.PE(dll_path, fast_load=True)
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


def pe_codeview_data(filepath):
    pe = pefile.PE(filepath, fast_load=True)
    pe.parse_data_directories()
    try:
        codeview = next(
            filter(
                lambda x: x.struct.Type
                == pefile.DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"],
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
        help="one of: fetch_pdb (requires --pdb-name and --guid_age), "
        "parse_pdb (requires --pdb-name), pe_codeview_data (requires --file)",
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
