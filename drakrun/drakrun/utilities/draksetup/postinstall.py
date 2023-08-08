import json
import logging
import os
import re
import subprocess
import traceback
from pathlib import Path, PureWindowsPath

import click
import requests

from drakrun.config import InstallInfo, RuntimeInfo, VmiOffsets
from drakrun.machinery.injector import Injector
from drakrun.machinery.networking import delete_vm_network, setup_vm_network
from drakrun.machinery.storage import StorageBackendBase, get_storage_backend
from drakrun.machinery.vm import (
    FIRST_CDROM_DRIVE,
    SECOND_CDROM_DRIVE,
    VirtualMachine,
    VmiGuidInfo,
    eject_cd,
    generate_vm_conf,
    vmi_win_guid,
)
from drakrun.paths import APISCOUT_PROFILE_DIR, ETC_DIR, PROFILE_DIR, VOLUME_DIR
from drakrun.profile.apiscout import (
    build_static_apiscout_profile,
    make_static_apiscout_profile_for_dll,
)
from drakrun.profile.drakpdb import (
    DLL,
    dll_file_list,
    fetch_pdb,
    make_pdb_profile,
    pe_codeview_data,
    required_dll_file_list,
    unrequired_dll_file_list,
)
from drakrun.util import safe_delete

from ._config import config
from ._util import check_root
from .cleanup import cleanup_postinstall_files


def extract_explorer_pid(
    domain: str, kernel_profile: str, offsets: VmiOffsets, timeout: int = 30
) -> int:
    """Call get-explorer-pid helper and get its PID"""
    module_dir = os.path.dirname(os.path.realpath(__file__))
    pid_tool = os.path.join(module_dir, "draksetup/tools", "get-explorer-pid")
    try:
        explorer_pid_s = subprocess.check_output(
            [pid_tool, domain, kernel_profile, hex(offsets.kpgd)], timeout=timeout
        ).decode("utf-8", "ignore")

        m = re.search(r"explorer\.exe:([0-9]+)", explorer_pid_s)
        if m is not None:
            return int(m.group(1))

    except subprocess.CalledProcessError:
        logging.exception("get-explorer-pid exited with an error")
    except subprocess.TimeoutExpired:
        logging.exception("get-explorer-pid timed out")

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
        logging.exception("Invalid output of vmi-win-offsets")
    except subprocess.CalledProcessError:
        logging.exception("vmi-win-offsets exited with an error")
    except subprocess.TimeoutExpired:
        logging.exception("vmi-win-offsets timed out")

    raise RuntimeError("Extracting VMI offsets failed")


def profiles_exist(profile_name: str) -> bool:
    return (Path(PROFILE_DIR) / f"{profile_name}.json").is_file() and (
        Path(APISCOUT_PROFILE_DIR) / f"{profile_name}.json"
    ).is_file()


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
        logging.warning(f"[SKIPPING DLL] {msg}")
        logging.debug(traceback.format_exc())


def create_rekall_profile(injector: Injector, file: DLL, raise_on_error=False):
    pdb_tmp_filepath = None
    logging.info(f"Fetching rekall profile for {file.path}")

    local_dll_path = os.path.join(PROFILE_DIR, file.dest)
    guest_dll_path = str(PureWindowsPath("C:/", file.path))

    cmd = injector.read_file(guest_dll_path, local_dll_path)
    try:
        out = json.loads(cmd.stdout.decode())
        if out["Status"] == "Error" and out["Error"] in [
            "ERROR_FILE_NOT_FOUND",
            "ERROR_PATH_NOT_FOUND",
        ]:
            raise FileNotFoundError
        if out["Status"] != "Success":
            logging.debug("stderr: " + cmd.stderr.decode())
            logging.debug(out)
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

        logging.debug("Parsing PDB into JSON profile...")
        profile = make_pdb_profile(
            pdb_tmp_filepath,
            dll_origin_path=guest_dll_path,
            dll_path=local_dll_path,
            dll_symstore_hash=codeview_data["symstore_hash"],
        )
        with open(os.path.join(PROFILE_DIR, f"{file.dest}.json"), "w") as f:
            f.write(profile)
    except json.JSONDecodeError:
        logging.debug(f"stdout: {cmd.stdout}")
        logging.debug(f"stderr: {cmd.stderr}")
        logging.debug(traceback.format_exc())
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
                logging.debug("stdout: " + cmd.stdout.decode())
                logging.debug("stderr: " + cmd.stderr.decode())
                logging.debug("rc: " + str(cmd.returncode))
            logging.debug(traceback.format_exc())
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


def create_missing_profiles():
    """
    Creates usermode profiles by restoring vm-1 and extracting the DLLs.
    Assumes that injector is configured properly, i.e. kernel and runtime
    profiles exist and that vm-1 is free to use.
    """

    # Prepare injector
    runtime_info = RuntimeInfo.load()
    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    injector = Injector("vm-1", runtime_info, kernel_profile)

    # restore vm-1
    out_interface = config["drakrun"].get("out_interface", "")
    dns_server = config["drakrun"].get("dns_server", "")
    install_info = InstallInfo.load()
    backend = get_storage_backend(install_info)

    generate_vm_conf(install_info, 1)
    setup_vm_network(
        vm_id=1, net_enable=False, out_interface=out_interface, dns_server=dns_server
    )
    vm = VirtualMachine(backend, 1)
    vm.restore()

    # Ensure that all declared usermode profiles exist
    # This is important when upgrade defines new entries
    # in required_dll_file_list and unrequired_dll_file_list
    for profile in required_dll_file_list:
        if not profiles_exist(profile.dest):
            create_rekall_profile(injector, profile, True)

    for profile in unrequired_dll_file_list:
        if not profiles_exist(profile.dest):
            try:
                create_rekall_profile(injector, profile)
            except Exception:
                logging.exception("Unexpected exception from create_rekall_profile!")

    build_os_info(APISCOUT_PROFILE_DIR, vmi_win_guid(vm.vm_name), backend)

    dll_basename_list = [dll.dest for dll in dll_file_list]
    static_apiscout_profile = build_static_apiscout_profile(
        APISCOUT_PROFILE_DIR, dll_basename_list
    )
    with open(Path(APISCOUT_PROFILE_DIR) / "static_apiscout_profile.json", "w") as f:
        json.dump(static_apiscout_profile, f)

    vm.destroy()
    delete_vm_network(
        vm_id=1, net_enable=False, out_interface=out_interface, dns_server=dns_server
    )


def send_usage_report(report):
    try:
        res = requests.post(
            "https://drakvuf.cert.pl/usage/draksetup", json=report, timeout=5
        )
        res.raise_for_status()
    except requests.RequestException:
        logging.exception("Failed to send usage report. This is not a serious problem.")


@click.command(help="Finalize sandbox installation")
@click.option(
    "--report/--no-report",
    "report",
    default=True,
    show_default=True,
    help="Send anonymous usage report",
)
@click.option(
    "--usermode/--no-usermode",
    "generate_usermode",
    default=True,
    show_default=True,
    help="Generate user mode profiles",
)
def postinstall(report, generate_usermode):
    if not check_root():
        return

    if os.path.exists(os.path.join(ETC_DIR, "no_usage_reports")):
        report = False

    install_info = InstallInfo.load()
    storage_backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(storage_backend, 0)

    if vm0.is_running is False:
        logging.exception("vm-0 is not running")
        return

    logging.info("Cleaning up leftovers(if any)")
    cleanup_postinstall_files()

    logging.info("Ejecting installation CDs")
    eject_cd("vm-0", FIRST_CDROM_DRIVE)
    if install_info.enable_unattended:
        # If unattended install is enabled, we have an additional CD-ROM drive
        eject_cd("vm-0", SECOND_CDROM_DRIVE)

    kernel_info = vmi_win_guid("vm-0")

    logging.info(f"Determined PDB GUID: {kernel_info.guid}")
    logging.info(f"Determined kernel filename: {kernel_info.filename}")

    logging.info("Fetching PDB file...")
    dest = fetch_pdb(kernel_info.filename, kernel_info.guid, destdir=PROFILE_DIR)

    logging.info("Generating profile out of PDB file...")
    profile = make_pdb_profile(dest)

    logging.info("Saving profile...")
    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    with open(kernel_profile, "w") as f:
        f.write(profile)

    safe_delete(dest)

    vmi_offsets = extract_vmi_offsets("vm-0", kernel_profile)
    explorer_pid = extract_explorer_pid("vm-0", kernel_profile, vmi_offsets)
    runtime_info = RuntimeInfo(vmi_offsets=vmi_offsets, inject_pid=explorer_pid)

    logging.info("Saving runtime profile...")
    with open(os.path.join(PROFILE_DIR, "runtime.json"), "w") as f:
        f.write(runtime_info.to_json(indent=4))

    logging.info("Saving VM snapshot...")

    # Create vm-0 snapshot, and destroy it
    # WARNING: qcow2 snapshot method is a noop. fresh images are created on the fly
    # so we can't keep the vm-0 running
    vm0.save(os.path.join(VOLUME_DIR, "snapshot.sav"))
    logging.info("Snapshot was saved succesfully.")

    # Memory state is frozen, we can't do any writes to persistent storage
    logging.info("Snapshotting persistent memory...")
    storage_backend.snapshot_vm0_volume()

    if report:
        send_usage_report(
            {
                "kernel": {
                    "guid": kernel_info.guid,
                    "filename": kernel_info.filename,
                    "version": kernel_info.version,
                },
                "install_iso": {"sha256": install_info.iso_sha256},
            }
        )

    if generate_usermode:
        # Restore a VM and create usermode profiles
        create_missing_profiles()

    logging.info("All right, drakrun setup is done.")
    logging.info("First instance of drakrun will be enabled automatically...")
    subprocess.check_output("systemctl enable drakrun@1", shell=True)
    subprocess.check_output("systemctl start drakrun@1", shell=True)

    logging.info("If you want to have more parallel instances, execute:")
    logging.info("  # draksetup scale <number of instances>")
