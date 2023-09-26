import pefile
from construct import Bytes, Const, CString, Int16ul, Int32ul, Struct
from construct.lib.containers import Container
from volatility3.framework.contexts import Context
from volatility3.framework.symbols.windows.pdbconv import PdbReader, PdbRetreiver


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


def make_symstore_hash(
    codeview_struct: Container
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


def fetch_pdb(pdbname, guid):
    return PdbRetreiver().retreive_pdb(
        guid=guid, file_name=pdbname
    )


def make_pdb_profile(fileurlpath, pdbname):
    ctx = Context()
    return PdbReader(ctx, fileurlpath, database_name=pdbname).get_json()
