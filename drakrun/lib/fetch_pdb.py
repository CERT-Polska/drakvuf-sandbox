import logging
import pathlib
import shutil

from drakpdb import fetch_pdb

from drakrun.lib.paths import PDB_CACHE_DIR

log = logging.getLogger(__name__)


def get_cache_pdb_name(pdbname: str, guidage: str) -> str:
    pdb_basename, pdb_ext = pdbname.rsplit(".", 1)
    return f"{pdb_basename}-{guidage}.{pdb_ext}"


def vmi_fetch_pdb(pdbname: str, guidage: str) -> pathlib.Path:
    cache_pdbname = get_cache_pdb_name(pdbname, guidage)
    destpath = (PDB_CACHE_DIR / cache_pdbname).resolve()
    if destpath.exists():
        log.info("PDB %s already fetched", cache_pdbname)
        return destpath
    pdb_filepath = fetch_pdb(pdbname, guidage, PDB_CACHE_DIR.as_posix())
    shutil.move(pdb_filepath, destpath)
    return destpath
