"""
High-level VM interface using Drakvuf and LibVMI for introspection operations
"""
import logging
from pathlib import Path, PureWindowsPath

from ..config import Configuration
from ..machinery.vm import VirtualMachine
from ..util import ensure_delete
from .dlls import DLL
from .drakpdb import fetch_pdb, make_pdb_profile, pe_codeview_data
from .drakpdbvol import make_pdb_profile as vol_make_pdb_profile
from .injector import Injector, InjectorTimeout
from .profile import (
    RuntimeInfo,
    VmiGuidInfo,
    extract_explorer_pid,
    extract_vmi_offsets,
    vmi_win_guid,
)

log = logging.getLogger(__name__)


class DrakvufVM:
    def __init__(self, config: Configuration, vm_id: int):
        self.profile = config
        self.vm_id = vm_id
        self.vm = VirtualMachine(config, vm_id)
        self.runtime_info = None

    @property
    def kernel_profile_path(self) -> Path:
        return self.profile.vm_profile_dir / "kernel.json"

    @property
    def runtime_profile_path(self) -> Path:
        return self.profile.vm_profile_dir / "runtime.json"

    def _get_win_guid(self) -> VmiGuidInfo:
        return vmi_win_guid(vm_name=self.vm.vm_name)

    def _create_kernel_profile(self, win_guid: VmiGuidInfo):
        logging.info("Fetching PDB file...")
        kernel_pdb_file = fetch_pdb(
            win_guid.filename, win_guid.guid, destdir=str(self.profile.vm_profile_dir)
        )
        log.info("Generating profile out of PDB file...")
        kernel_profile = vol_make_pdb_profile(kernel_pdb_file, win_guid.filename)

        log.info("Saving profile...")
        self.kernel_profile_path.write_text(kernel_profile)
        return kernel_profile

    def create_runtime_info(self):
        win_guid = self._get_win_guid()
        log.info(f"Determined Windows version: {win_guid.version}")
        log.info(f"Determined PDB GUID: {win_guid.guid}")
        log.info(f"Determined kernel filename: {win_guid.filename}")
        self._create_kernel_profile(win_guid=win_guid)
        log.info("Extracting VMI offsets...")
        vmi_offsets = extract_vmi_offsets(
            self.vm.vm_name, str(self.kernel_profile_path)
        )
        log.info("Extracting explorer.exe PID...")
        explorer_pid = extract_explorer_pid(
            self.vm.vm_name, str(self.kernel_profile_path)
        )
        self.runtime_info = RuntimeInfo(
            win_guid=win_guid, vmi_offsets=vmi_offsets, inject_pid=explorer_pid
        )
        log.info("Saving runtime profile...")
        self.runtime_profile_path.write_text(self.runtime_info.to_json(indent=4))

    def load_runtime_info(self) -> RuntimeInfo:
        runtime_info_json = self.runtime_profile_path.read_text()
        self.runtime_info = RuntimeInfo.from_json(runtime_info_json)
        return self.runtime_info

    @property
    def injector(self) -> Injector:
        if self.runtime_info is None:
            raise RuntimeError("Runtime info required. Call load_runtime_info first.")
        return Injector(
            self.vm.vm_name, self.runtime_info, str(self.kernel_profile_path)
        )

    def restore(self, net_enable: bool = True):
        out_interface = self.profile.parameters.out_interface
        dns_server = self.profile.parameters.dns_server
        self.vm.setup_network(out_interface, dns_server, net_enable=net_enable)
        self.vm.restore()

    def destroy(self):
        self.vm.destroy()
        self.vm.clean_network()

    def save(self, destroy_after: bool = False):
        return self.vm.save(destroy_after=destroy_after)

    def make_dll_profile(self, dllspec: DLL, tries: int = 3):
        log.info(f"Fetching {dllspec.path} from VM")

        local_dll_path = self.profile.vm_profile_dir / dllspec.dest
        guest_dll_path = str(PureWindowsPath("C:/", dllspec.path))

        while tries > 0:
            try:
                self.injector.read_file(guest_dll_path, str(local_dll_path), timeout=30)
                break
            except InjectorTimeout:
                tries -= 1
                if tries == 0:
                    raise

        # TODO: apiscout
        codeview_data = pe_codeview_data(local_dll_path)
        pdb_tmp_filepath = fetch_pdb(
            codeview_data["filename"],
            codeview_data["symstore_hash"],
            str(self.profile.vm_profile_dir),
        )

        logging.debug("Parsing PDB into JSON profile...")
        try:
            profile = vol_make_pdb_profile(pdb_tmp_filepath, codeview_data["filename"])
        except Exception:
            log.exception("vol_make_pdb_profile failed")
            log.warning("Falling back to lenient drakpdb.make_pdb_profile")
            profile = make_pdb_profile(
                pdb_tmp_filepath,
                dll_origin_path=guest_dll_path,
                dll_path=str(local_dll_path),
                dll_symstore_hash=codeview_data["symstore_hash"],
            )
        dll_profile_path = self.profile.vm_profile_dir / f"{dllspec.dest}.json"
        dll_profile_path.write_text(profile)
        ensure_delete(local_dll_path)
        return dll_profile_path

    def run_prepare_script(self, tries: int = 3):
        local_path = self.profile.etc_dir / "prepare.bat"
        guest_path = PureWindowsPath("C:/Users/Public/prepare.bat")
        while tries > 0:
            try:
                self.injector.write_file(str(local_path), str(guest_path), timeout=30)
                self.injector.create_process(
                    f"cmd /C start {str(guest_path)}", wait=True, timeout=120
                )
                break
            except InjectorTimeout:
                tries -= 1
                if tries == 0:
                    raise
