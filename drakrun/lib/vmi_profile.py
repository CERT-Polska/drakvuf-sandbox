import json
import logging
import pathlib
import tempfile
import time

from drakpdb import make_pdb_profile, pe_codeview_data

from drakrun.lib.drakshell import get_drakshell
from drakrun.lib.fetch_pdb import vmi_fetch_pdb
from drakrun.lib.injector import Injector
from drakrun.lib.libvmi.dlls import DLL, optional_dll_file_list, required_dll_file_list
from drakrun.lib.libvmi.vmi_info import VmiInfo
from drakrun.lib.paths import VMI_INFO_PATH, VMI_KERNEL_PROFILE_PATH, VMI_PROFILES_DIR
from drakrun.lib.vm import VirtualMachine

from .libvmi import extract_explorer_pid, extract_vmi_offsets, get_vmi_kernel_guid

log = logging.getLogger(__name__)


def extract_dll_profile(injector: Injector, dll: DLL):
    tempdir = pathlib.Path(tempfile.gettempdir())
    local_dll_path = (tempdir / dll.dest).as_posix()
    guest_dll_path = str(pathlib.PureWindowsPath("C:/", dll.path))

    proc = injector.read_file(guest_dll_path, local_dll_path)
    out = json.loads(proc.stdout.decode())
    if out["Status"] == "Error" and out["Error"] in [
        "ERROR_FILE_NOT_FOUND",
        "ERROR_PATH_NOT_FOUND",
    ]:
        raise FileNotFoundError
    if out["Status"] != "Success":
        raise RuntimeError(f"Injector failed with {proc.stderr}")

    codeview_data = pe_codeview_data(local_dll_path)
    pdb_filepath = vmi_fetch_pdb(
        codeview_data["filename"], codeview_data["symstore_hash"]
    )
    profile = make_pdb_profile(
        pdb_filepath,
        dll_origin_path=guest_dll_path,
        dll_path=local_dll_path,
        dll_symstore_hash=codeview_data["symstore_hash"],
    )
    profile_path = VMI_PROFILES_DIR / f"{dll.dest}.json"
    profile_path.write_text(json.dumps(profile, indent=4))


def create_vmi_info(vm: VirtualMachine, with_drakshell: bool = True) -> VmiInfo:
    if not vm.is_running:
        raise RuntimeError("VM is not running")
    kernel_info = get_vmi_kernel_guid(vm.vm_name)
    log.info(f"Determined PDB GUID: {kernel_info.guid}")
    log.info(f"Determined kernel filename: {kernel_info.filename}")

    pdb_file = vmi_fetch_pdb(kernel_info.filename, kernel_info.guid)
    kernel_profile = make_pdb_profile(pdb_file.as_posix())
    VMI_KERNEL_PROFILE_PATH.write_text(json.dumps(kernel_profile, indent=4))

    vmi_offsets = extract_vmi_offsets(vm.vm_name, VMI_KERNEL_PROFILE_PATH)
    explorer_pid = extract_explorer_pid(
        vm.vm_name, VMI_KERNEL_PROFILE_PATH, vmi_offsets
    )
    vmi_info = VmiInfo(vmi_offsets, inject_pid=explorer_pid)
    if with_drakshell:
        injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH.as_posix())
        for try_no in range(5):
            try:
                _, drakshell_info = get_drakshell(vm, injector)
                vmi_info.inject_pid = drakshell_info["pid"]
                vmi_info.inject_tid = drakshell_info["tid"]
                break
            except Exception as e:
                log.warning("Failed to install drakshell on the VM", exc_info=e)
                if try_no < 4:
                    log.warning(
                        f"Another try ({try_no+2}/5) in 5 seconds... You can try connecting to the VM using VNC and moving "
                        f"mouse over the desktop while we're trying to setup the drakshell."
                    )
                    time.sleep(5)
                else:
                    log.warning(
                        "I surrender, drakshell will be inactive. I hope you won't have problems with profile generation."
                    )

    VMI_INFO_PATH.write_text(vmi_info.to_json(indent=4))
    return vmi_info


def create_vmi_json_profile(vm: VirtualMachine, vmi_info: VmiInfo):
    if not vm.is_running:
        raise RuntimeError("VM is not running")

    injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH.as_posix())
    for dll in required_dll_file_list:
        extract_dll_profile(injector, dll)

    for dll in optional_dll_file_list:
        try:
            extract_dll_profile(injector, dll)
        except Exception:
            logging.exception(f"Failed to get profile for {dll.path}")
