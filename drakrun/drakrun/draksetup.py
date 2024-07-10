import configparser
import hashlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import sysconfig
import tempfile
import textwrap
import time
import traceback
from pathlib import Path, PureWindowsPath
from typing import List, Optional

import click
import requests
from minio.error import NoSuchKey
from tqdm import tqdm

from drakrun.lib.apiscout import (
    build_static_apiscout_profile,
    make_static_apiscout_profile_for_dll,
)
from drakrun.lib.bindings.systemd import (
    enable_service,
    start_service,
    systemctl_daemon_reload,
)
from drakrun.lib.config import DrakrunConfig, load_config, update_config
from drakrun.lib.drakpdb import (
    DLL,
    dll_file_list,
    fetch_pdb,
    make_pdb_profile,
    pe_codeview_data,
    required_dll_file_list,
    unrequired_dll_file_list,
)
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.minio import get_minio_client
from drakrun.lib.networking import (
    delete_all_vm_networks,
    delete_legacy_iptables,
    delete_vm_network,
    setup_vm_network,
    start_dnsmasq,
    stop_dnsmasq,
)
from drakrun.lib.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    LIB_DIR,
    PROFILE_DIR,
    RUNTIME_FILE,
    VM_CONFIG_DIR,
    VOLUME_DIR,
)
from drakrun.lib.storage import (
    REGISTERED_BACKEND_NAMES,
    StorageBackendBase,
    get_storage_backend,
)
from drakrun.lib.util import (
    RuntimeInfo,
    VmiGuidInfo,
    VmiOffsets,
    file_sha256,
    safe_delete,
    vmi_win_guid,
)
from drakrun.lib.vm import (
    FIRST_CDROM_DRIVE,
    SECOND_CDROM_DRIVE,
    VirtualMachine,
    delete_vm_conf,
    generate_vm_conf,
    get_all_vm_conf,
)

log = logging.getLogger(__name__)


def ensure_dirs():
    os.makedirs(ETC_DIR, exist_ok=True)
    os.makedirs(VM_CONFIG_DIR, exist_ok=True)

    os.makedirs(LIB_DIR, exist_ok=True)
    os.makedirs(PROFILE_DIR, exist_ok=True)
    os.makedirs(APISCOUT_PROFILE_DIR, exist_ok=True)
    os.makedirs(VOLUME_DIR, exist_ok=True)


def ensure_zfs(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "zfs":
        raise click.BadParameter("This parameter is valid only with ZFS backend")
    return value


def ensure_lvm(ctx, param, value):
    if value is not None and ctx.params["storage_backend"] != "lvm":
        raise click.BadParameter("This parameter is valid only with LVM backend")
    return value


def check_root():
    if os.getuid() != 0:
        log.error("Please run the command as root")
        return False
    else:
        return True


def stop_all_drakruns():
    log.info("Ensuring that drakrun@* services are stopped...")
    try:
        subprocess.check_output(
            "systemctl stop 'drakrun@*'", shell=True, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        raise Exception("Drakrun services not stopped")


def start_enabled_drakruns():
    log.info("Starting previously stopped drakruns")
    enabled_services = set(list(get_enabled_drakruns()))
    wait_processes(
        "start services",
        [
            subprocess.Popen(
                ["systemctl", "start", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enabled_services
        ],
    )


def cleanup_postinstall_files():
    for profile in os.listdir(PROFILE_DIR):
        safe_delete(os.path.join(PROFILE_DIR, profile))
    for profile_file in os.listdir(APISCOUT_PROFILE_DIR):
        safe_delete(os.path.join(APISCOUT_PROFILE_DIR, profile_file))


@click.command(help="Cleanup the changes made by draksetup")
def cleanup():
    if not check_root():
        return

    install_info = InstallInfo.try_load()

    if install_info is None:
        log.error("The cleanup has been performed")
        return

    stop_all_drakruns()

    backend = get_storage_backend(install_info)
    vm_ids = get_all_vm_conf()

    for vm_id in vm_ids:
        vm = VirtualMachine(backend, vm_id)
        vm.destroy()

        delete_vm_network(vm_id=vm_id)
        stop_dnsmasq(vm_id=vm_id)
        backend.delete_vm_volume(vm_id)
        delete_vm_conf(vm_id)

    delete_legacy_iptables()
    delete_all_vm_networks()

    safe_delete(os.path.join(VOLUME_DIR, "snapshot.sav"))
    cleanup_postinstall_files()

    InstallInfo.delete()


@click.command(help="Cleanup changes in iptables and bridges")
def cleanup_network():
    if not check_root():
        return
    delete_legacy_iptables()
    delete_all_vm_networks()


def sanity_check():
    if not check_root():
        return False

    log.info("Checking xen-detect...")
    proc = subprocess.run("xen-detect -N", shell=True)

    if proc.returncode != 1:
        log.error(
            "It looks like the system is not running on Xen. Please reboot your machine into Xen hypervisor."
        )
        return False

    log.info("Testing if xl tool is sane...")

    try:
        subprocess.run(
            "xl info",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError:
        log.exception(
            "Failed to test xl info command. There might be some dependency problem (please execute 'xl info' manually to find out)."
        )
        return False

    try:
        subprocess.run(
            "xl list",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
    except subprocess.SubprocessError:
        log.exception(
            "Failed to test xl list command. There might be a problem with xen services (check 'systemctl status xenstored', 'systemctl status xenconsoled')."
        )
        return False

    if not perform_xtf():
        log.error("Your Xen installation doesn't pass the necessary tests.")
        return False

    return True


def perform_xtf():
    log.info("Testing your Xen installation...")
    module_dir = os.path.dirname(os.path.realpath(__file__))
    cfg_path = os.path.join(module_dir, "tools", "test-hvm64-example.cfg")
    firmware_path = os.path.join(module_dir, "tools", "test-hvm64-example")

    with open(cfg_path, "r") as f:
        test_cfg = (
            f.read().replace("{{ FIRMWARE_PATH }}", firmware_path).encode("utf-8")
        )

    with tempfile.NamedTemporaryFile() as tmpf:
        tmpf.write(test_cfg)
        tmpf.flush()

        test_hvm64 = VirtualMachine(None, None, "test-hvm64-example", tmpf.name)
        log.info("Checking if the test domain already exists...")
        test_hvm64.destroy()

        log.info("Creating new test domain...")
        test_hvm64.create(pause=True, timeout=30)

        module_dir = os.path.dirname(os.path.realpath(__file__))
        test_altp2m_tool = os.path.join(module_dir, "tools", "test-altp2m")

        log.info("Testing altp2m feature...")
        try:
            subprocess.run(
                [test_altp2m_tool, "test-hvm64-example"],
                stderr=subprocess.STDOUT,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", "replace")
            log.error(
                f"Failed to enable altp2m on domain. Your hardware might not support Extended Page Tables. Logs:\n{output}"
            )
            test_hvm64.destroy()
            return False

        log.info("Performing simple XTF test...")
        p = subprocess.Popen(
            ["xl", "console", "test-hvm64-example"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        test_hvm64.unpause(timeout=30)
        stdout_b, _ = p.communicate(timeout=10)

        stdout_text = stdout_b.decode("utf-8")
        stdout = [line.strip() for line in stdout_text.split("\n")]

        for line in stdout:
            if line == "Test result: SUCCESS":
                log.info(
                    "All tests passed. Your Xen installation seems to work properly."
                )
                return True

    log.error(
        f"Preflight check with Xen Test Framework doesn't pass. Your hardware might not support VT-x. Logs: \n{stdout_text}"
    )
    return False


@click.command(help="Perform self-test to check Xen installation")
def test():
    if not sanity_check():
        sys.exit(1)


@click.command(help="Install guest Virtual Machine", no_args_is_help=True)
@click.argument("iso_path", type=click.Path(exists=True))
@click.option(
    "--vcpus",
    "vcpus",
    default=2,
    type=int,
    show_default=True,
    help="Number of vCPUs per single VM",
)
@click.option(
    "--memory",
    "memory",
    default=3072,
    type=int,
    show_default=True,
    help="Memory per single VM (in MB)",
)
@click.option(
    "--storage-backend",
    "storage_backend",
    type=click.Choice(REGISTERED_BACKEND_NAMES, case_sensitive=False),
    default="qcow2",
    show_default=True,
    help="Storage backend",
    is_eager=True,
)
@click.option(
    "--disk-size", "disk_size", default="100G", show_default=True, help="Disk size"
)
@click.option(
    "--zfs-tank-name",
    "zfs_tank_name",
    callback=ensure_zfs,
    help="Tank name (only for ZFS storage backend)",
)
@click.option(
    "--lvm-volume-group",
    "lvm_volume_group",
    callback=ensure_lvm,
    help="Volume Group (only for lvm storage backend)",
)
@click.option(
    "--unattended-xml",
    "unattended_xml",
    type=click.Path(exists=True),
    help="Path to autounattend.xml for automated Windows install",
)
def install(
    vcpus,
    memory,
    storage_backend,
    disk_size,
    iso_path,
    zfs_tank_name,
    lvm_volume_group,
    unattended_xml,
):
    if not check_root():
        return

    if storage_backend == "lvm" and lvm_volume_group is None:
        raise Exception("lvm storage backend requires --lvm-volume-group")
    if storage_backend == "zfs" and zfs_tank_name is None:
        raise Exception("zfs storage backend requires --zfs-tank-name")

    if vcpus < 1:
        log.error("Your VM must have at least 1 vCPU.")
        return

    if memory < 512:
        log.error("Your VM must have at least 512 MB RAM.")
        return

    if memory < 1536:
        log.warning(
            "Using less than 1.5 GB RAM per VM is not recommended for any supported system."
        )

    if unattended_xml:
        log.info("Baking unattended.iso for automated installation")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_xml_path = os.path.join(tmpdir, "autounattend.xml")

            with open(tmp_xml_path, "wb") as fw:
                with open(unattended_xml, "rb") as fr:
                    fw.write(fr.read())

            try:
                subprocess.check_output(
                    [
                        "genisoimage",
                        "-o",
                        os.path.join(VOLUME_DIR, "unattended.iso"),
                        "-J",
                        "-r",
                        tmp_xml_path,
                    ],
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError:
                log.exception("Failed to generate unattended.iso.")

    drakconfig = load_config()

    if not sanity_check():
        log.error("Sanity check failed.")
        return

    stop_all_drakruns()

    log.info("Performing installation...")

    sha256_hash = hashlib.sha256()

    log.info("Calculating hash of iso")
    iso_file_size = os.stat(iso_path).st_size
    block_size = 128 * 1024
    with tqdm(total=iso_file_size, unit_scale=True) as pbar:
        with open(iso_path, "rb") as f:
            for byte_block in iter(lambda: f.read(block_size), b""):
                pbar.update(block_size)
                sha256_hash.update(byte_block)

            iso_sha256 = sha256_hash.hexdigest()

    install_info = InstallInfo(
        vcpus=vcpus,
        memory=memory,
        storage_backend=storage_backend,
        disk_size=disk_size,
        iso_path=os.path.abspath(iso_path),
        zfs_tank_name=zfs_tank_name,
        lvm_volume_group=lvm_volume_group,
        enable_unattended=unattended_xml is not None,
        iso_sha256=iso_sha256,
    )
    install_info.save()

    backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(backend, 0)
    vm0.destroy()

    generate_vm_conf(install_info, 0)

    backend.initialize_vm0_volume(disk_size)

    try:
        subprocess.check_output("brctl show", shell=True)
    except subprocess.CalledProcessError:
        log.exception(
            "Failed to execute brctl show. Make sure you have bridge-utils installed."
        )
        return

    net_enable = drakconfig.drakrun.net_enable
    out_interface = drakconfig.drakrun.out_interface
    dns_server = drakconfig.drakrun.dns_server

    setup_vm_network(
        vm_id=0,
        net_enable=net_enable,
        out_interface=out_interface,
        dns_server=dns_server,
    )

    if net_enable:
        start_dnsmasq(vm_id=0, dns_server=dns_server, background=True)

    cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")

    vm0.create()

    log.info("-" * 80)
    log.info("Initial VM setup is complete and the vm-0 was launched.")
    log.info(
        "Please now VNC to the port 5900 on this machine to perform Windows installation."
    )
    log.info(
        "After you have installed Windows and booted it to the desktop, please execute:"
    )
    log.info("# draksetup postinstall")

    with open(cfg_path, "r") as f:
        data = f.read()
        m = re.search(r"vncpasswd[ ]*=(.*)", data)
        if m:
            passwd = m.group(1).strip()
            if passwd[0] == '"' and passwd[-1] == '"':
                passwd = passwd[1:-1]

            log.info("Your configured VNC password is:")
            log.info(passwd)

    log.info(
        "Please note that on some machines, system installer may boot for up to 10 minutes"
    )
    log.info("and may look unresponsive during the process. Please be patient.")
    log.info("-" * 80)


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
    module_dir = os.path.dirname(os.path.realpath(__file__))
    pid_tool = os.path.join(module_dir, "tools", "get-explorer-pid")
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


def eject_cd(domain, drive):
    subprocess.run(["xl", "cd-eject", domain, drive], check=True)


def insert_cd(domain, drive, iso):
    subprocess.run(["xl", "cd-insert", domain, drive, iso], check=True)


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


@click.command(help="Finalize sandbox installation")
@click.option(
    "--usermode/--no-usermode",
    "generate_usermode",
    default=True,
    show_default=True,
    help="Generate user mode profiles",
)
def postinstall(generate_usermode):
    if not check_root():
        return

    install_info = InstallInfo.load()
    storage_backend = get_storage_backend(install_info)

    vm0 = VirtualMachine(storage_backend, 0)

    if vm0.is_running is False:
        log.exception("vm-0 is not running")
        return

    log.info("Cleaning up leftovers(if any)")
    cleanup_postinstall_files()

    log.info("Ejecting installation CDs")
    eject_cd("vm-0", FIRST_CDROM_DRIVE)
    if install_info.enable_unattended:
        # If unattended install is enabled, we have an additional CD-ROM drive
        eject_cd("vm-0", SECOND_CDROM_DRIVE)

    kernel_info = vmi_win_guid("vm-0")

    log.info(f"Determined PDB GUID: {kernel_info.guid}")
    log.info(f"Determined kernel filename: {kernel_info.filename}")

    log.info("Fetching PDB file...")
    dest = fetch_pdb(kernel_info.filename, kernel_info.guid, destdir=PROFILE_DIR)

    log.info("Generating profile out of PDB file...")
    profile = make_pdb_profile(dest)

    log.info("Saving profile...")
    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    with open(kernel_profile, "w") as f:
        f.write(profile)

    safe_delete(dest)

    vmi_offsets = extract_vmi_offsets("vm-0", kernel_profile)
    explorer_pid = extract_explorer_pid("vm-0", kernel_profile, vmi_offsets)
    runtime_info = RuntimeInfo(vmi_offsets=vmi_offsets, inject_pid=explorer_pid)

    log.info("Saving runtime profile...")
    with open(os.path.join(PROFILE_DIR, "runtime.json"), "w") as f:
        f.write(runtime_info.to_json(indent=4))

    log.info("Saving VM snapshot...")

    # Create vm-0 snapshot, and destroy it
    # WARNING: qcow2 snapshot method is a noop. fresh images are created on the fly
    # so we can't keep the vm-0 running
    vm0.save(os.path.join(VOLUME_DIR, "snapshot.sav"))
    log.info("Snapshot was saved succesfully.")

    # Memory state is frozen, we can't do any writes to persistent storage
    log.info("Snapshotting persistent memory...")
    storage_backend.snapshot_vm0_volume()

    if generate_usermode:
        # Restore a VM and create usermode profiles
        create_missing_profiles()

    log.info("All right, drakrun setup is done.")
    log.info("First instance of drakrun will be enabled automatically...")
    subprocess.check_output("systemctl enable drakrun@1", shell=True)
    subprocess.check_output("systemctl start drakrun@1", shell=True)

    log.info("If you want to have more parallel instances, execute:")
    log.info("  # draksetup scale <number of instances>")


def profiles_exist(profile_name: str) -> bool:
    return (Path(PROFILE_DIR) / f"{profile_name}.json").is_file() and (
        Path(APISCOUT_PROFILE_DIR) / f"{profile_name}.json"
    ).is_file()


def create_missing_profiles():
    """
    Creates usermode profiles by restoring vm-1 and extracting the DLLs.
    Assumes that injector is configured properly, i.e. kernel and runtime
    profiles exist and that vm-1 is free to use.
    """

    # Prepare injector
    runtime_info = RuntimeInfo.load(RUNTIME_FILE)
    kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
    injector = Injector("vm-1", runtime_info, kernel_profile)

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

    # Ensure that all declared usermode profiles exist
    # This is important when upgrade defines new entries in required_dll_file_list and unrequired_dll_file_list
    for profile in required_dll_file_list:
        if not profiles_exist(profile.dest):
            create_rekall_profile(injector, profile, True)

    for profile in unrequired_dll_file_list:
        if not profiles_exist(profile.dest):
            try:
                create_rekall_profile(injector, profile)
            except Exception:
                log.exception("Unexpected exception from create_rekall_profile!")

    build_os_info(APISCOUT_PROFILE_DIR, vmi_win_guid(vm.vm_name), backend)

    dll_basename_list = [dll.dest for dll in dll_file_list]
    static_apiscout_profile = build_static_apiscout_profile(
        APISCOUT_PROFILE_DIR, dll_basename_list
    )
    with open(Path(APISCOUT_PROFILE_DIR) / "static_apiscout_profile.json", "w") as f:
        json.dump(static_apiscout_profile, f)

    vm.destroy()
    delete_vm_network(vm_id=1)


@click.command(help="Perform tasks after drakrun upgrade")
def postupgrade():
    if not check_root():
        return

    with open(os.path.join(ETC_DIR, "scripts/cfg.template"), "r") as f:
        template = f.read()

    passwd_characters = string.ascii_letters + string.digits
    passwd = "".join(secrets.choice(passwd_characters) for _ in range(20))
    template = template.replace("{{ VNC_PASS }}", passwd)

    with open(os.path.join(ETC_DIR, "scripts", "cfg.template"), "w") as f:
        f.write(template)

    ensure_dirs()

    install_info = InstallInfo.try_load()
    if not install_info:
        log.info("Postupgrade done. DRAKVUF Sandbox not installed.")
        return

    stop_all_drakruns()
    create_missing_profiles()
    start_enabled_drakruns()


def get_enabled_drakruns():
    service_path = "/etc/systemd/system/default.target.wants"
    if not os.path.isdir(service_path):
        return []

    for fn in os.listdir(service_path):
        if re.fullmatch("drakrun@[0-9]+\\.service", fn):
            yield fn


def wait_processes(descr, popens):
    total = len(popens)

    if total == 0:
        return True

    exit_codes = []

    with tqdm(total=total, unit_scale=True) as pbar:
        pbar.set_description(descr)
        while True:
            time.sleep(0.25)
            for popen in popens:
                exit_code = popen.poll()
                if exit_code is not None:
                    exit_codes.append(exit_code)
                    popens.remove(popen)
                    pbar.update(1)

            if len(popens) == 0:
                return all([exit_code == 0 for exit_code in exit_codes])


@click.command(help="Scale drakrun services", no_args_is_help=True)
@click.argument("scale_count", type=int)
def scale(scale_count):
    """Enable or disable additional parallel instances of drakrun service.."""
    if scale_count < 1:
        raise RuntimeError("Invalid value of scale parameter. Must be at least 1.")

    cur_services = set(list(get_enabled_drakruns()))
    new_services = set([f"drakrun@{i}.service" for i in range(1, scale_count + 1)])

    disable_services = cur_services - new_services
    enable_services = new_services

    wait_processes(
        "disable services",
        [
            subprocess.Popen(
                ["systemctl", "disable", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in disable_services
        ],
    )
    wait_processes(
        "enable services",
        [
            subprocess.Popen(
                ["systemctl", "enable", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enable_services
        ],
    )
    wait_processes(
        "start services",
        [
            subprocess.Popen(
                ["systemctl", "start", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enable_services
        ],
    )
    wait_processes(
        "stop services",
        [
            subprocess.Popen(
                ["systemctl", "stop", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in disable_services
        ],
    )


@click.command(help="Mount ISO into guest", no_args_is_help=True)
@click.argument("iso_path", type=click.Path(exists=True))
@click.option(
    "--domain",
    "domain_name",
    type=str,
    default="vm-0",
    show_default=True,
    help="Domain name (i.e. Virtual Machine name)",
)
def mount(iso_path, domain_name):
    """Inject ISO file into specified guest vm.
    Domain can be retrieved by running "xl list" command on the host.
    """
    iso_path_full = os.path.abspath(iso_path)
    insert_cd(domain_name, FIRST_CDROM_DRIVE, iso_path_full)


@click.group(help="Manage VM raw memory pre-sample dumps")
def memdump():
    pass


@memdump.command(name="export", help="Upload pre-sample raw memory dump to MinIO.")
@click.option("--instance", required=True, type=int, help="Instance ID of restored VM")
@click.option(
    "--bucket",
    default="presample-memdumps",
    help="MinIO bucket to store the compressed raw image",
)
def memdump_export(bucket, instance):
    install_info = InstallInfo.try_load()
    if install_info is None:
        log.error("Missing installation info. Did you forget to set up the sandbox?")
        return

    backend = get_storage_backend(install_info)
    vm = VirtualMachine(backend, instance)
    if vm.is_running:
        log.exception(f"vm-{instance} is running")
        return

    log.info("Calculating snapshot hash...")
    snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))
    name = f"{snapshot_sha256}_pre_sample.raw_memdump.gz"

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    try:
        mc.stat_object(bucket, name)
        log.info("This file already exists in specified bucket")
        return
    except NoSuchKey:
        pass
    except Exception:
        log.exception("Failed to check if object exists on minio")

    log.info("Restoring VM and performing memory dump")

    try:
        vm.restore(pause=True)
    except subprocess.CalledProcessError:
        log.exception(f"Failed to restore VM {vm.vm_name}")
        with open(f"/var/log/xen/qemu-dm-{vm.vm_name}.log", "rb") as f:
            log.error(f.read())
    log.info("VM restored")

    with tempfile.NamedTemporaryFile() as compressed_memdump:
        vm.memory_dump(compressed_memdump.name)

        log.info(f"Uploading {name} to {bucket}")
        mc.fput_object(bucket, name, compressed_memdump.name)

    try:
        vm.destroy()
    except Exception:
        log.exception("Failed to destroy VM")

    log.info("Done")


@click.group(help="Manage VM snapshots")
def snapshot():
    pass


@snapshot.command(
    name="export", help="Upload local snapshot to MinIO.", no_args_is_help=True
)
@click.option("--name", required=True, help="Name of the snapshot")
@click.option(
    "--bucket", default="drakrun-snapshots", help="MinIO bucket to store the snapshot"
)
@click.option(
    "--full", default=False, is_flag=True, help="Upload memory snapshot and profiles"
)
@click.option("--force", default=False, is_flag=True, help="Overwrite remote snapshot")
def snapshot_export(name, bucket, full, force):
    install_info = InstallInfo.try_load()
    if install_info is None:
        log.error("Missing installation info. Did you forget to set up the sandbox?")
        return

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    if len(list(mc.list_objects(bucket, f"{name}/"))) > 0 and not force:
        log.error(
            "There are objects in bucket %s at path %s. Aborting...", bucket, f"{name}/"
        )
        return

    log.info("Exporting snapshot as %s into %s", name, bucket)

    if full:
        log.warning(
            "Full snapshots may not work if hardware used for "
            "importing and exporting differs. You have been warned!"
        )
        do_export_full(mc, bucket, name)
    else:
        do_export_minimal(mc, bucket, name)

    log.info("Done. To use exported snapshot on other machine, execute:")
    log.info("# draksetup snapshot import --name %s --bucket %s", name, bucket)


@snapshot.command(
    name="import", help="Download and configure remote snapshot", no_args_is_help=True
)
@click.option("--name", required=True, help="Name of the exported snapshot")
@click.option(
    "--bucket", default="drakrun-snapshots", help="MinIO bucket to store the snapshot"
)
@click.option(
    "--full", default=False, is_flag=True, help="Download VM memory and profiles"
)
@click.option(
    "--zpool", help="Override zpool name stored in snapshot (only for ZFS snapshots)"
)
def snapshot_import(name, bucket, full, zpool):
    local_install = InstallInfo.try_load()
    if local_install is not None:
        click.confirm(
            "Detected local snapshot. It will be REMOVED. Continue?", abort=True
        )

    drakconfig = load_config()
    mc = get_minio_client(drakconfig)

    if not mc.bucket_exists(bucket):
        log.error("Bucket %s doesn't exist", bucket)
        return

    ensure_dirs()

    try:
        if full:
            log.warning(
                "Importing full snapshot. This may not work if hardware is different"
            )
            do_import_full(mc, name, bucket, zpool)
        else:
            do_import_minimal(mc, name, bucket, zpool)

            # This could probably use some refactoring
            # We're duplicating quite a lot of code from install function
            install_info = InstallInfo.load()
            generate_vm_conf(install_info, 0)
            backend = get_storage_backend(install_info)
            backend.rollback_vm_storage(0)

            net_enable = drakconfig.drakrun.net_enable
            out_interface = drakconfig.drakrun.out_interface
            dns_server = drakconfig.drakrun.dns_server
            setup_vm_network(
                vm_id=0,
                net_enable=net_enable,
                out_interface=out_interface,
                dns_server=dns_server,
            )

            if net_enable:
                start_dnsmasq(vm_id=0, dns_server=dns_server, background=True)

            cfg_path = os.path.join(VM_CONFIG_DIR, "vm-0.cfg")

            try:
                subprocess.run(["xl", "create", cfg_path], check=True)
            except subprocess.CalledProcessError:
                log.exception("Failed to launch VM vm-0")
                return

            log.info("Minimal snapshots require postinstall to work correctly")
            log.info("Please VNC to the port 5900 to ensure the OS booted correctly")
            log.info("After that, execute this command to finish the setup")
            log.info("# draksetup postinstall")
    except NoSuchKey:
        log.error("Import failed. Missing files in bucket.")


def do_export_minimal(mc, bucket, name):
    """Perform minimal snapshot export, symmetric to do_import_minimal"""
    log.info("Uploading installation info")
    install_info = InstallInfo.load()
    install_data = json.dumps(install_info.to_dict()).encode()
    mc.put_object(
        bucket, f"{name}/install.json", io.BytesIO(install_data), len(install_data)
    )

    log.info("Uploading VM template")
    mc.fput_object(
        bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template")
    )

    with tempfile.NamedTemporaryFile() as disk_image:
        log.info("Exporting VM hard drive")
        storage = get_storage_backend(install_info)
        storage.export_vm0(disk_image.name)

        log.info("Uploading disk.img")
        mc.fput_object(bucket, f"{name}/disk.img", disk_image.name)


def do_import_minimal(mc, name, bucket, zpool):
    """Perform minimal snapshot import, symmetric to do_export_minimal"""
    log.info("Downloading installation info")
    mc.fget_object(
        bucket,
        f"{name}/install.json",
        InstallInfo.INSTALL_FILE_PATH,
    )

    log.info("Downloading VM config")
    mc.fget_object(
        bucket, f"{name}/cfg.template", os.path.join(ETC_DIR, "scripts", "cfg.template")
    )

    # Now we have imported InstallInfo object
    install_info = InstallInfo.load()

    # Patch ZFS pool name
    if zpool is not None:
        install_info.zfs_tank_name = zpool
        # Save patched ZFS dataset name (storage backend has to know it)
        install_info.save()

    storage = get_storage_backend(install_info)

    with tempfile.NamedTemporaryFile() as disk_image:
        log.info("Downloading VM disk image")
        mc.fget_object(bucket, f"{name}/disk.img", disk_image.name)

        log.info("Importing VM disk")
        storage.import_vm0(disk_image.name)


def do_export_full(mc, bucket, name):
    """Perform full snapshot export, symmetric to do_import_full"""
    do_export_minimal(mc, bucket, name)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        # Compress snapshot
        log.info("Compressing snapshot.sav")
        subprocess.check_call(
            ["gzip", "-c", os.path.join(VOLUME_DIR, "snapshot.sav")],
            stdout=compressed_snapshot,
        )

        log.info("Uploading snapshot.sav.gz")
        mc.fput_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

    # Upload profiles
    for file in os.listdir(PROFILE_DIR):
        log.info("Uploading profile %s", file)
        mc.fput_object(
            bucket, f"{name}/profiles/{file}", os.path.join(PROFILE_DIR, file)
        )

    # Upload ApiScout profile
    for file in os.listdir(APISCOUT_PROFILE_DIR):
        log.info("Uploading file %s", file)
        mc.fput_object(
            bucket,
            f"{name}/apiscout_profile/{file}",
            os.path.join(APISCOUT_PROFILE_DIR, file),
        )


def do_import_full(mc, name, bucket, zpool):
    """Perform full snapshot import, symmetric to do_export_full"""
    do_import_minimal(mc, name, bucket, zpool)

    with tempfile.NamedTemporaryFile() as compressed_snapshot:
        mc.fget_object(bucket, f"{name}/snapshot.sav.gz", compressed_snapshot.name)

        log.info("Decompressing VM snapshot")
        with open(os.path.join(VOLUME_DIR, "snapshot.sav"), "wb") as snapshot:
            subprocess.run(
                ["zcat", compressed_snapshot.name], stdout=snapshot, check=True
            )

    profiles_prefix = f"{name}/profiles/"
    for object in mc.list_objects(bucket, prefix=profiles_prefix):
        # Strip profiles prefix
        profile_name = object.object_name[len(profiles_prefix) :]
        mc.fget_object(
            bucket, object.object_name, os.path.join(PROFILE_DIR, profile_name)
        )

    apiscout_profile_prefix = f"{name}/apiscout_profile/"
    for object in mc.list_objects(bucket, prefix=apiscout_profile_prefix):
        # Strip apiscout profile prefix
        filename = object.object_name[len(apiscout_profile_prefix) :]
        mc.fget_object(
            bucket, object.object_name, os.path.join(APISCOUT_PROFILE_DIR, filename)
        )


MINIO_DOWNLOAD_URL = "https://dl.min.io/server/minio/release/linux-amd64/minio"
MINIO_ENV_CONFIG_FILE = Path("/etc/default/minio")
SYSTEMD_SERVICE_PATH = Path("/etc/systemd/system")


def generate_minio_service_config():
    """
    Creates /etc/default/minio with generated credentials
    """
    access_key = secrets.token_urlsafe(30)
    secret_key = secrets.token_urlsafe(30)
    minio_env = textwrap.dedent(
        f"""\
        MINIO_ROOT_USER={access_key}
        MINIO_ROOT_PASSWORD={secret_key}
        MINIO_VOLUMES="/var/lib/minio"
        # MINIO_OPTS sets any additional commandline options to pass to the MinIO server.
        # For example, `--console-address :9001` sets the MinIO Console listen port
        MINIO_OPTS="--console-address :9001"
        """
    )
    MINIO_ENV_CONFIG_FILE.write_text(minio_env)
    log.info(f"Created {MINIO_ENV_CONFIG_FILE.as_posix()} with default configuration")


def apply_local_minio_service_config(config: DrakrunConfig):
    parser = configparser.ConfigParser(strict=False, allow_no_value=True)
    minio_env = "[DEFAULT]\n" + MINIO_ENV_CONFIG_FILE.read_text()
    parser.read_string(minio_env)
    config.minio.access_key = parser.get("DEFAULT", "MINIO_ROOT_USER")
    config.minio.secret_key = parser.get("DEFAULT", "MINIO_ROOT_PASSWORD")
    return config


@click.command(help="Install MinIO (for testing purposes)")
def install_minio():
    data_dir = Path(__file__).parent / "data"
    if minio_path := shutil.which("minio"):
        log.info(f"MinIO already found in {minio_path}, no need to download")
    else:
        log.info("Downloading MinIO")
        response = requests.get(MINIO_DOWNLOAD_URL, stream=True)
        total_length = response.headers.get("content-length")
        with tqdm(
            total=total_length, unit_scale=True
        ) as pbar, tempfile.NamedTemporaryFile(delete=False) as f:
            try:
                for data in response.iter_content(chunk_size=4096):
                    f.write(data)
                    pbar.update(len(data))
                os.rename(f.name, "/usr/local/bin/minio")
            except BaseException:
                os.remove(f.name)
        os.chmod("/usr/local/bin/minio", 0o0755)

    if MINIO_ENV_CONFIG_FILE.exists():
        log.info(f"{MINIO_ENV_CONFIG_FILE.as_posix()} already exists, no need to setup")
    else:
        generate_minio_service_config()

    minio_service_path = SYSTEMD_SERVICE_PATH / "minio.service"
    if minio_service_path.exists():
        log.info(f"{minio_service_path} already exists, no need to setup")
    else:
        config_data = (data_dir / "minio.service").read_text()
        minio_service_path.write_text(config_data)
        log.info("Starting minio service")
        enable_service("minio")
        start_service("minio")


@click.command(help="Pre-installation activities")
@click.option("--s3-address", default=None, help="S3 endpoint address")
@click.option("--s3-access-key", default=None, help="S3 access key")
@click.option("--s3-secret-key", default=None, help="S3 secret key")
@click.option(
    "--s3-secure", default=False, is_flag=True, help="S3 enable secure connection"
)
@click.option(
    "--s3-make-buckets",
    default=True,
    is_flag=True,
    help="Auto-create S3 buckets: karton, drakrun",
)
@click.option("--redis-host", default=None, help="Redis host")
@click.option("--redis-port", default=None, help="Redis port")
@click.option(
    "--only",
    type=click.Choice(["web", "system", "drakrun"]),
    multiple=True,
    help="Create configuration only for specific service for multi-node configuration",
)
@click.option(
    "--unattended",
    default=False,
    is_flag=True,
    help="Don't prompt for values, expect required parameters in arguments",
)
def init(
    s3_address: Optional[str],
    s3_access_key: Optional[str],
    s3_secret_key: Optional[str],
    s3_secure: bool,
    s3_make_buckets: bool,
    redis_host: Optional[str],
    redis_port: Optional[str],
    only: List[str],
    unattended: bool,
):
    # Simple activities handled by deb packages before
    # In the future, consider splitting this to remove hard dependency on systemd etc
    drakrun_dir = Path(ETC_DIR)
    scripts_dir = drakrun_dir / "scripts"
    data_dir = Path(__file__).parent / "data"

    drakrun_dir.mkdir(exist_ok=True)
    scripts_dir.mkdir(exist_ok=True)

    def create_configuration_file(config_file_name, target_dir=drakrun_dir):
        target_path = target_dir / config_file_name
        if target_path.exists():
            log.info(f"{target_path} already created.")
            return target_path

        config_data = (data_dir / config_file_name).read_text()
        target_path.write_text(config_data)
        log.info(f"Created {target_path}.")
        return target_path

    drakrun_config_path = create_configuration_file("config.ini")

    try:
        config = load_config()
    except Exception:
        import traceback

        traceback.print_exc()
        click.echo(
            "Failed to load currently installed configuration. "
            f"Fix {drakrun_config_path.as_posix()} or remove file to reconfigure it "
            f"from scratch and run 'draksetup init' again.",
            err=True,
        )
        raise click.Abort()

    def apply_setting(message, current_value, option_value, hide_input=False):
        if option_value is not None:
            # If option value is already provided: just return option_value
            return option_value
        if unattended:
            # If unattended and no option value: just leave current value
            return current_value
        default_value = current_value or None
        input_value = click.prompt(
            message, default=default_value, hide_input=hide_input
        )
        if input_value is None:
            # If input not provided and no reasonable default found: leave current value
            return current_value
        else:
            # Else: provide input value
            return input_value

    config.redis.host = apply_setting(
        "Provide redis hostname", config.redis.host, redis_host
    )
    config.redis.port = apply_setting(
        "Provide redis port", config.redis.port, redis_port
    )
    config.minio.address = apply_setting(
        "Provide S3 (MinIO) address", config.minio.address, s3_address
    )

    minio_env_applied = False
    if MINIO_ENV_CONFIG_FILE.exists():
        log.info(
            f"Found {MINIO_ENV_CONFIG_FILE.as_posix()} file with MinIO credentials"
        )
        if unattended or click.confirm(
            f"Do you want to import credentials from {MINIO_ENV_CONFIG_FILE.as_posix()} file?",
            default=True,
        ):
            apply_local_minio_service_config(config)
            minio_env_applied = True

    if not minio_env_applied:
        config.minio.access_key = apply_setting(
            "Provide S3 (MinIO) access key", config.minio.access_key, s3_access_key
        )
        config.minio.secret_key = apply_setting(
            "Provide S3 (MinIO) secret key", config.minio.secret_key, s3_secret_key
        )

    config.minio.secure = s3_secure
    update_config(config)
    log.info(f"Updated {drakrun_config_path.as_posix()}.")

    mc = get_minio_client(config)

    def check_s3_bucket(bucket_name):
        if not mc.bucket_exists(bucket_name):
            if s3_make_buckets:
                log.info(f"Bucket '{bucket_name}' doesn't exist, creating one...")
                mc.make_bucket(bucket_name)
            else:
                click.echo(
                    f"Bucket '{bucket_name}' doesn't exist. "
                    "Create proper S3 buckets to continue.",
                    err=True,
                )
                raise click.Abort()

    check_s3_bucket("drakrun")
    check_s3_bucket(config.minio.bucket)

    def is_component_to_init(component_name):
        return not only or component_name in only

    def get_scripts_bin_path():
        scripts_path = Path(sysconfig.get_path("scripts"))
        if scripts_path == Path("/usr/bin"):
            # pip installs global scripts in different path than
            # pointed by sysconfig
            return Path("/usr/local/bin")
        return scripts_path

    def fix_exec_start(config_file_name):
        """
        This function fixes ExecStart entry to point at correct virtualenv bin directory

        ExecStart=/usr/local/bin/karton-system --config-file /etc/drakrun/config.ini
        """
        systemd_config_path = SYSTEMD_SERVICE_PATH / config_file_name
        systemd_config = systemd_config_path.read_text()
        current_exec_start = next(
            line
            for line in systemd_config.splitlines()
            if line.startswith("ExecStart=")
        )
        current_exec_path_str = current_exec_start.split("=")[1].split()[0]
        current_exec_path = Path(current_exec_path_str)
        new_exec_path = get_scripts_bin_path() / current_exec_path.name
        if current_exec_path != new_exec_path:
            systemd_config = systemd_config.replace(
                current_exec_path_str, new_exec_path.as_posix()
            )
            systemd_config_path.write_text(systemd_config)
            log.info(
                f"{systemd_config_path}: Replaced {current_exec_path} with {new_exec_path}"
            )
        return systemd_config_path

    if is_component_to_init("drakrun"):
        create_configuration_file("hooks.txt")
        create_configuration_file("drakrun@.service", target_dir=SYSTEMD_SERVICE_PATH)
        fix_exec_start("drakrun@.service")
        create_configuration_file("cfg.template", target_dir=(drakrun_dir / "scripts"))

    if is_component_to_init("system"):
        create_configuration_file(
            "drak-system.service", target_dir=SYSTEMD_SERVICE_PATH
        )
        fix_exec_start("drak-system.service")

    if is_component_to_init("web"):
        create_configuration_file("uwsgi.ini")
        create_configuration_file("drak-web.service", target_dir=SYSTEMD_SERVICE_PATH)
        fix_exec_start("drak-web.service")

    systemctl_daemon_reload()

    # drakrun is going to be enabled after complete install/postinstall setup
    if is_component_to_init("system"):
        log.info("Starting drak-system service")
        enable_service("drak-system")
        start_service("drak-system")
    if is_component_to_init("web"):
        log.info("Starting drak-web service")
        enable_service("drak-web")
        start_service("drak-web")


@click.group()
def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )


main.add_command(test)
main.add_command(install)
main.add_command(postinstall)
main.add_command(postupgrade)
main.add_command(mount)
main.add_command(scale)
main.add_command(snapshot)
main.add_command(memdump)
main.add_command(cleanup)
main.add_command(cleanup_network)
main.add_command(init)
main.add_command(install_minio)


if __name__ == "__main__":
    if os.geteuid() != 0:
        logging.warning("Not running as root, draksetup may work improperly!")
    main()
