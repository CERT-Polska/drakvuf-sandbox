import contextlib
import hashlib
import logging
import os
import re
import subprocess
import traceback
from dataclasses import dataclass, field

from dataclasses_json import config, dataclass_json

log = logging.getLogger(__name__)

hexstring = config(
    encoder=lambda v: hex(v),
    decoder=lambda v: int(v, 16),
)


@dataclass_json
@dataclass
class VmiOffsets:
    # Fields correspond to output defined in
    # https://github.com/libvmi/libvmi/blob/master/examples/win-offsets.c

    win_ntoskrnl: int = field(metadata=hexstring)
    win_ntoskrnl_va: int = field(metadata=hexstring)

    win_tasks: int = field(metadata=hexstring)
    win_pdbase: int = field(metadata=hexstring)
    win_pid: int = field(metadata=hexstring)
    win_pname: int = field(metadata=hexstring)
    win_kdvb: int = field(metadata=hexstring)
    win_sysproc: int = field(metadata=hexstring)
    win_kpcr: int = field(metadata=hexstring)
    win_kdbg: int = field(metadata=hexstring)

    kpgd: int = field(metadata=hexstring)

    @staticmethod
    def from_tool_output(output: str) -> "VmiOffsets":
        """
        Parse vmi-win-offsets tool output and return VmiOffsets.
        If any of the fields is missing, throw TypeError
        """
        offsets = re.findall(r"^([a-z_]+):(0x[0-9a-f]+)$", output, re.MULTILINE)
        vals = {k: int(v, 16) for k, v in offsets}
        return VmiOffsets(**vals)


@dataclass_json
@dataclass
class RuntimeInfo:
    vmi_offsets: VmiOffsets
    inject_pid: int

    @staticmethod
    def load(file_path: str) -> "RuntimeInfo":
        with open(file_path) as file_obj:
            return RuntimeInfo.from_json(file_obj.read())


def get_domid_from_instance_id(instance_id: int) -> int:
    output = subprocess.check_output(["xl", "domid", f"vm-{instance_id}"])
    return int(output.decode("utf-8").strip())


def get_xl_info():
    xl_info_out = subprocess.check_output(["xl", "info"]).decode("utf-8", "replace")
    xl_info_lines = xl_info_out.strip().split("\n")

    cfg = {}

    for line in xl_info_lines:
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        cfg[k] = v

    return cfg


def get_xen_commandline(parsed_xl_info):
    opts = parsed_xl_info["xen_commandline"].split(" ")

    cfg = {}

    for opt in opts:
        if not opt.strip():
            continue

        if "=" not in opt:
            cfg[opt] = "1"
        else:
            k, v = opt.split("=", 1)
            cfg[k] = v

    return cfg


def safe_delete(file_path) -> bool:
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            log.info(f"Deleted {file_path}")
        else:
            log.info(f"Already deleted {file_path}")
        return True
    except OSError as e:
        log.warning(f"{e.filename}: {e.strerror}")
        return False


def try_run(
    list_args: list, msg: str, reraise=True, **kwargs
) -> subprocess.CompletedProcess:
    """
    Runs subprocess.run in a try except with some default arguments ( which can be overriden by supplying kwargs )

            Parameters:
                    list_args (list): Subprocess list which will be passed to subprocess.run
                    msg (str): A meaningful error message to be raised during non-zero exit code
                    reraise (bool):
                        True: will raise an Exception with traceback on error
                        False: will log a warning on error
                    **kwargs: additional parameters to be passed to subprocess.run

            Defaults:
                    subprocess.run is called with the following arguments by default
                    stderr = subprocess.PIPE
                    stdout = subprocess.PIPE # to print to console, pass kwargs ( stdout = None )
                    check = True

            Returns:
                    sub (subprocess.CompletedProcess): Object with the completed process
                        or
                    None: if the subprocess failed and reraise=False
    """

    try:
        kwargs["stdout"]
    except KeyError:
        kwargs["stdout"] = subprocess.PIPE

    if kwargs.get("stderr") is None:
        kwargs["stderr"] = subprocess.PIPE
    if kwargs.get("check") is None:
        kwargs["check"] = True

    try:
        sub = subprocess.run(list_args, **kwargs)
    except (FileNotFoundError, TypeError) as e:
        log.debug("arguments to subprocess")
        log.debug(list_args)
        log.debug(msg)
        log.debug(kwargs)
        raise Exception("Command not found") from e
    except subprocess.CalledProcessError as e:
        if e.stdout is not None:
            log.debug("stdout: \n{}".format(e.stdout.decode()))
        if e.stderr is not None:
            log.debug("stderr: \n{}".format(e.stderr.decode()))
        log.debug("returncode: {}".format(e.returncode))
        if reraise:
            raise Exception(msg) from e
        else:
            log.warning(msg)
            log.debug(traceback.format_exc())
            return None
    return sub


@contextlib.contextmanager
def graceful_exit(proc: subprocess.Popen):
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired as err:
            log.error("Process %s doesn't exit after timeout.", err.cmd)
            proc.kill()
            proc.wait()
            log.error("Process was forceully killed")


def file_sha256(filename, blocksize=65536) -> str:
    file_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            file_hash.update(block)
    return file_hash.hexdigest()


@dataclass
class VmiGuidInfo:
    version: str
    guid: str
    filename: str


def vmi_win_guid(vm_name: str) -> VmiGuidInfo:
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
