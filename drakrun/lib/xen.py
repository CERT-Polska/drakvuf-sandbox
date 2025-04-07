import logging
import subprocess
from typing import Dict, Optional

log = logging.getLogger(__name__)


def xen_is_vm_running(vm_name: str) -> bool:
    result = subprocess.run(["xl", "list", vm_name], capture_output=True)
    if result.returncode == 0:
        return True
    elif b"is an invalid domain identifier" in result.stderr:
        return False
    else:
        raise RuntimeError(f"Unexpected xl list output: {result.stderr}")


def xen_create_vm(
    vm_name: str,
    config_path: str,
    pause: bool = False,
    timeout: Optional[float] = None,
) -> None:
    try:
        subprocess.run(
            ["xl", "create", *(["-p"] if pause else []), config_path],
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to launch VM {vm_name}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Failed to launch VM {vm_name} within {timeout} seconds")


def xen_unpause_vm(vm_name: str, timeout: Optional[float] = None) -> None:
    try:
        subprocess.run(["xl", "unpause", vm_name], check=True, timeout=timeout)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to unpause VM {vm_name}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Failed to unpause VM {vm_name} within {timeout} seconds")


def xen_restore_vm(
    vm_name: str,
    config_path: str,
    snapshot_path: str,
    pause: bool = False,
) -> None:
    try:
        subprocess.run(
            ["xl", "restore", *(["-p"] if pause else []), config_path, snapshot_path],
            check=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to restore VM {vm_name}")


def xen_save_vm(
    vm_name: str,
    snapshot_path: str,
    pause: bool = False,
) -> None:
    try:
        subprocess.run(
            ["xl", "save", *(["-p"] if pause else []), vm_name, snapshot_path],
            check=True,
        )
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to save VM {vm_name}")


def xen_destroy_vm(vm_name: str) -> None:
    try:
        subprocess.run(["xl", "destroy", vm_name], check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(f"Failed to pause VM {vm_name}")


def xen_get_domid(vm_name: str) -> int:
    output = subprocess.check_output(["xl", "domid", vm_name], text=True)
    return int(output.strip())


def parse_xen_commandline(xen_commandline: str) -> Dict[str, str]:
    opts = xen_commandline.split(" ")
    elements = {}
    for opt in opts:
        if not opt.strip():
            continue

        if "=" not in opt:
            elements[opt] = "1"
        else:
            k, v = opt.split("=", 1)
            elements[k] = v

    return elements


def get_xen_info() -> Dict[str, str]:
    xl_info_out = subprocess.check_output(["xl", "info"], text=True)
    xl_info_lines = xl_info_out.strip().split("\n")

    elements = {}
    for line in xl_info_lines:
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        elements[k] = v
    return elements


def xen_insert_cd(domain, drive, iso):
    subprocess.run(["xl", "cd-insert", domain, drive, iso], check=True)


def xen_eject_cd(domain, drive):
    subprocess.run(["xl", "cd-eject", domain, drive], check=True)
