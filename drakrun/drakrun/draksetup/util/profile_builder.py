import json
import logging
import os
import re
import subprocess
import traceback
from pathlib import Path, PureWindowsPath

from drakrun.lib.apiscout import (
    build_static_apiscout_profile,
    make_static_apiscout_profile_for_dll,
)
from drakrun.lib.config import load_config
from drakrun.lib.drakpdb import (
    DLL,
    apivectors_dll_file_list,
    dll_file_list,
    fetch_pdb,
    make_pdb_profile,
    optional_dll_file_list,
    pe_codeview_data,
    required_dll_file_list,
)
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import delete_vm_network, setup_vm_network
from drakrun.lib.paths import APISCOUT_PROFILE_DIR, PACKAGE_DIR, PROFILE_DIR
from drakrun.lib.storage import StorageBackendBase, get_storage_backend
from drakrun.lib.util import (
    RuntimeInfo,
    VmiGuidInfo,
    VmiOffsets,
    safe_delete,
    vmi_win_guid,
)
from drakrun.lib.vm import VirtualMachine, generate_vm_conf

log = logging.getLogger(__name__)


def profiles_exist(profile_name: str) -> bool:
    return (Path(PROFILE_DIR) / f"{profile_name}.json").is_file() and (
        Path(APISCOUT_PROFILE_DIR) / f"{profile_name}.json"
    ).is_file()


def cleanup_profile_files():
    for profile in os.listdir(PROFILE_DIR):
        safe_delete(os.path.join(PROFILE_DIR, profile))
    for profile_file in os.listdir(APISCOUT_PROFILE_DIR):
        safe_delete(os.path.join(APISCOUT_PROFILE_DIR, profile_file))


def on_create_rekall_profile_failure(
    msg: str,
    should_raise: bool,
    exception: Exception = None,
):
    """
    An exception handler for create_rekall_profile

        Parameters:
            msg (str): Message to raise
            should_raise (bool): Should it raise an exception or log a warning
            exception (Exception): Exception object which is used for tracebacks

        Returns:
            None
    """
    if should_raise:
        raise Exception(f"[REQUIRED DLL] {msg}") from exception
    else:
        log.warning(f"[SKIPPING DLL] {msg}")
        log.debug(traceback.format_exc())


def create_rekall_profile(injector: Injector, file: DLL, raise_on_error=False):
    pdb_tmp_filepath = None
    cmd = None
    out = None
    try:
        log.info(f"Fetching rekall profile for {file.path}")

        local_dll_path = os.path.join(PROFILE_DIR, file.dest)
        guest_dll_path = str(PureWindowsPath("C:/", file.path))

        cmd = injector.read_file(guest_dll_path, local_dll_path)
        out = json.loads(cmd.stdout.decode())
        if out["Status"] == "Error" and out["Error"] in [
            "ERROR_FILE_NOT_FOUND",
            "ERROR_PATH_NOT_FOUND",
        ]:
            raise FileNotFoundError
        if out["Status"] != "Success":
            log.debug("stderr: " + cmd.stderr.decode())
            log.debug(out)
            # Take care if the error message is changed
            raise Exception("Some error occurred in injector")

        static_apiscout_dll_profile = make_static_apiscout_profile_for_dll(
            local_dll_path
        )
        with open(os.path.join(APISCOUT_PROFILE_DIR, f"{file.dest}.json"), "w") as f:
            f.write(json.dumps(static_apiscout_dll_profile, indent=4, sort_keys=True))

        codeview_data = pe_codeview_data(local_dll_path)
        pdb_tmp_filepath = fetch_pdb(
            codeview_data["filename"], codeview_data["symstore_hash"], PROFILE_DIR
        )

        log.debug("Parsing PDB into JSON profile...")
        profile = make_pdb_profile(
            pdb_tmp_filepath,
            dll_origin_path=guest_dll_path,
            dll_path=local_dll_path,
            dll_symstore_hash=codeview_data["symstore_hash"],
        )
        with open(os.path.join(PROFILE_DIR, f"{file.dest}.json"), "w") as f:
            f.write(profile)
    except json.JSONDecodeError:
        log.debug(f"stdout: {cmd.stdout}")
        log.debug(f"stderr: {cmd.stderr}")
        log.debug(traceback.format_exc())
        raise Exception(f"Failed to parse json response on {file.path}")
    except FileNotFoundError as e:
        on_create_rekall_profile_failure(
            f"Failed to copy file {file.path}", raise_on_error, e
        )
    except RuntimeError as e:
        on_create_rekall_profile_failure(
            f"Failed to fetch profile for {file.path}", raise_on_error, e
        )
    except subprocess.TimeoutExpired as e:
        on_create_rekall_profile_failure(
            f"Injector timed out for {file.path}", raise_on_error, e
        )
    except Exception as e:
        # Take care if the error message is changed
        if str(e) == "Some error occurred in injector":
            raise
        else:
            # Can help in debugging
            if cmd:
                log.debug("stdout: " + cmd.stdout.decode())
                log.debug("stderr: " + cmd.stderr.decode())
                log.debug("rc: " + str(cmd.returncode))
            log.debug(traceback.format_exc())
            on_create_rekall_profile_failure(
                f"Unexpected exception while creating rekall profile for {file.path}",
                raise_on_error,
                e,
            )
    finally:
        safe_delete(local_dll_path)
        # was crashing here if the first file reached some exception
        if pdb_tmp_filepath is not None:
            safe_delete(os.path.join(PROFILE_DIR, pdb_tmp_filepath))


def extract_explorer_pid(
    domain: str, kernel_profile: str, offsets: VmiOffsets, timeout: int = 30
) -> int:
    """Call get-explorer-pid helper and get its PID"""
    pid_tool = (PACKAGE_DIR / "tools/get-explorer-pid").as_posix()
    try:
        explorer_pid_s = subprocess.check_output(
            [pid_tool, domain, kernel_profile, hex(offsets.kpgd)], timeout=timeout
        ).decode("utf-8", "ignore")

        m = re.search(r"explorer\.exe:([0-9]+)", explorer_pid_s)
        if m is not None:
            return int(m.group(1))

    except subprocess.CalledProcessError:
        log.exception("get-explorer-pid exited with an error")
    except subprocess.TimeoutExpired:
        log.exception("get-explorer-pid timed out")

    raise RuntimeError("Extracting explorer PID failed")


def extract_vmi_offsets(
    domain: str, kernel_profile: str, timeout: int = 30
) -> VmiOffsets:
    """Call vmi-win-offsets helper and obtain VmiOffsets values"""
    try:
        output = subprocess.check_output(
            ["vmi-win-offsets", "--name", domain, "--json-kernel", kernel_profile],
            timeout=timeout,
        ).decode("utf-8", "ignore")

        return VmiOffsets.from_tool_output(output)
    except TypeError:
        log.exception("Invalid output of vmi-win-offsets")
    except subprocess.CalledProcessError:
        log.exception("vmi-win-offsets exited with an error")
    except subprocess.TimeoutExpired:
        log.exception("vmi-win-offsets timed out")

    raise RuntimeError("Extracting VMI offsets failed")


def build_os_info(
    apiscout_profile_dir: str,
    kernel_info: VmiGuidInfo,
    storage_backend: StorageBackendBase,
):
    os_info = {
        "os_name": kernel_info.version,
        "os_timestamp": storage_backend.get_vm0_snapshot_time(),
    }

    with open(os.path.join(apiscout_profile_dir, "OS_INFO.json"), "w") as f:
        f.write(json.dumps(os_info, indent=4, sort_keys=True))


def create_vm_profiles(generate_apivectors_profile: bool):
    """
    Creates VM profile by restoring vm-1 and extracting the required information
    """
    # restore vm-1
    drakconfig = load_config()
    out_interface = drakconfig.drakrun.out_interface
    dns_server = drakconfig.drakrun.dns_server
    install_info = InstallInfo.load()
    backend = get_storage_backend(install_info)

    generate_vm_conf(install_info, 1)
    setup_vm_network(
        vm_id=1, net_enable=False, out_interface=out_interface, dns_server=dns_server
    )
    vm = VirtualMachine(backend, 1)
    vm.restore()

    kernel_info = vmi_win_guid("vm-1")

    log.info(f"Determined PDB GUID: {kernel_info.guid}")
    log.info(f"Determined kernel filename: {kernel_info.filename}")

    log.info("Fetching PDB file...")
    pdb_file = fetch_pdb(kernel_info.filename, kernel_info.guid, destdir=PROFILE_DIR)

    log.info("Generating profile out of PDB file...")
    profile = make_pdb_profile(pdb_file)

    log.info("Saving profile...")
    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    with open(kernel_profile, "w") as f:
        f.write(profile)

    safe_delete(pdb_file)

    vmi_offsets = extract_vmi_offsets("vm-1", kernel_profile)
    explorer_pid = extract_explorer_pid("vm-1", kernel_profile, vmi_offsets)
    runtime_info = RuntimeInfo(vmi_offsets=vmi_offsets, inject_pid=explorer_pid)

    log.info("Saving runtime profile...")
    with open(os.path.join(PROFILE_DIR, "runtime.json"), "w") as f:
        f.write(runtime_info.to_json(indent=4))

    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    injector = Injector("vm-1", runtime_info, kernel_profile)

    # Ensure that all declared usermode profiles exist
    # This is important when upgrade defines new entries in required_dll_file_list
    for profile in required_dll_file_list:
        create_rekall_profile(injector, profile, True)

    for profile in optional_dll_file_list:
        try:
            create_rekall_profile(injector, profile)
        except Exception:
            log.exception("Unexpected exception from create_rekall_profile!")

    if generate_apivectors_profile:
        for profile in apivectors_dll_file_list:
            try:
                create_rekall_profile(injector, profile)
            except Exception:
                log.exception("Unexpected exception from create_rekall_profile!")

        build_os_info(APISCOUT_PROFILE_DIR, vmi_win_guid(vm.vm_name), backend)

        dll_basename_list = [dll.dest for dll in dll_file_list]
        static_apiscout_profile = build_static_apiscout_profile(
            APISCOUT_PROFILE_DIR, dll_basename_list
        )
        with open(
            Path(APISCOUT_PROFILE_DIR) / "static_apiscout_profile.json", "w"
        ) as f:
            json.dump(static_apiscout_profile, f)

    vm.destroy()
    delete_vm_network(vm_id=1)
