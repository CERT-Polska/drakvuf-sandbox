import logging
import pathlib
import re
import subprocess

from drakrun.lib.paths import PACKAGE_TOOLS_PATH

from .vmi_info import VmiGuidInfo, VmiOffsets

log = logging.getLogger(__name__)


def get_vmi_kernel_guid(vm_name: str) -> VmiGuidInfo:
    result = subprocess.run(
        ["vmi-win-guid", "name", vm_name],
        timeout=30,
        capture_output=True,
    )

    output = result.stdout.decode()

    version = re.search(r"Version: (.*)", output)
    pdb_guid = re.search(r"PDB GUID: ([0-9a-f]+)", output)
    kernel_filename = re.search(r"Kernel filename: ([a-z]+\.[a-z]+)", output)

    if version is None or pdb_guid is None or kernel_filename is None:
        raise RuntimeError("Invalid vmi-win-guid output")

    return VmiGuidInfo(version.group(1), pdb_guid.group(1), kernel_filename.group(1))


def extract_vmi_offsets(
    domain: str, kernel_profile_path: pathlib.Path, timeout: int = 30
) -> VmiOffsets:
    """Call vmi-win-offsets helper and obtain VmiOffsets values"""
    try:
        output = subprocess.check_output(
            [
                "vmi-win-offsets",
                "--name",
                domain,
                "--json-kernel",
                kernel_profile_path.as_posix(),
            ],
            timeout=timeout,
        ).decode("utf-8", "ignore")
    except TypeError:
        raise RuntimeError("Invalid output of vmi-win-offsets")
    except subprocess.CalledProcessError:
        raise RuntimeError("vmi-win-offsets exited with an error")
    except subprocess.TimeoutExpired:
        raise RuntimeError("vmi-win-offsets timed out")
    except Exception:
        raise RuntimeError("Extracting VMI offsets failed")

    return VmiOffsets.from_tool_output(output)


def extract_explorer_pid(
    domain: str,
    kernel_profile_path: pathlib.Path,
    vmi_offsets: VmiOffsets,
    timeout: int = 30,
):
    pid_tool = PACKAGE_TOOLS_PATH / "get-explorer-pid"
    if not pid_tool.exists():
        raise RuntimeError(
            "get-explorer-pid not found, draktools package is not built with tools"
        )
    try:
        explorer_pid_s = subprocess.check_output(
            [
                pid_tool.as_posix(),
                domain,
                kernel_profile_path.as_posix(),
                hex(vmi_offsets.kpgd),
            ],
            timeout=timeout,
        ).decode("utf-8", "ignore")
    except subprocess.CalledProcessError:
        raise RuntimeError("get-explorer-pid exited with an error")
    except subprocess.TimeoutExpired:
        raise RuntimeError("get-explorer-pid timed out")
    except Exception:
        raise RuntimeError("Extracting explorer PID failed")

    m = re.search(r"explorer\.exe:([0-9]+)", explorer_pid_s)
    if m is None:
        raise RuntimeError("Explorer PID not found in output")

    return int(m.group(1))
