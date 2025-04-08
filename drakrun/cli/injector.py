import logging
import pathlib
import re
from subprocess import CalledProcessError

import click
import mslex

from drakrun.lib.config import load_config
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_INFO_PATH, VMI_KERNEL_PROFILE_PATH
from drakrun.lib.vm import VirtualMachine

log = logging.getLogger(__name__)


@click.group(
    name="injector", help="Copy files and execute commands on VM using injector"
)
def injector():
    pass


def parse_copy_file_arg(path_arg):
    if match := re.match(r"vm-(\d)+:", path_arg):
        vm_id = match.group(1)
        _, path = path_arg.split(":", 1)
        windows_path = pathlib.PureWindowsPath(path)
        return vm_id, windows_path
    else:
        return None, pathlib.Path(path_arg)


@injector.command(name="copy", help="Copy files between VM and host")
@click.argument("src")
@click.argument("dst")
def copy_file(src, dst):
    """Copy files between VM and host

    src - source file (vm-n:<path> for VM and <path> for host)
    dst - destination file (vm-n:<path> for VM and <path> for host)
    """
    src_target, src_path = parse_copy_file_arg(src)
    dst_target, dst_path = parse_copy_file_arg(dst)
    if (src_target is None) == (dst_target is None):
        click.echo(
            "Incorrect target, files can be copied between VM and host only", err=True
        )
        raise click.Abort()

    vm_id = dst_target if dst_target is not None else src_target

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(vm_id, install_info, config.network)
    if not vm.is_running:
        click.echo("VM is not running", err=True)
        raise click.Abort()

    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH)

    # Resolve dir paths
    if src_target is None:
        # Check if source on host exists
        src_path = src_path.resolve()
        if not src_path.is_file():
            click.echo(f"{src_path} is not a file or doesn't exist", err=True)
            raise click.Abort()
        # If VM dst looks like dir, append source file name
        if any(dst.endswith(c) for c in ["/", "\\", "%", "."]):
            dst_path = dst_path / src_path.name
    else:
        # If dest path is dir, append source file name
        dst_path = dst_path.resolve()
        if dst_path.is_dir():
            dst_path = dst_path / src_path.name

    try:
        if src_target is None:
            # Writing file to the VM
            proc = injector.write_file(str(src_path), str(dst_path))
        else:
            # Reading file from the VM
            proc = injector.read_file(str(src_path), str(dst_path))
    except CalledProcessError as e:
        click.echo(f"Injector stopped with error code {e.returncode}", err=True)
        click.echo(e.stdout.decode(errors="ignore"), err=True)
        click.echo(e.stderr.decode(errors="ignore"), err=True)
        raise click.Abort()

    click.echo(proc.stdout.decode(errors="ignore"))


@injector.command(
    name="exec",
    help="Execute commands on VM using injector (non-interactive)",
    no_args_is_help=True,
)
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
@click.option(
    "-w",
    "--wait",
    is_flag=True,
    default=False,
    show_default=True,
    help="Wait for process to finish",
)
@click.option(
    "-t",
    "--timeout",
    "timeout",
    type=int,
    default=60,
    show_default=True,
    help="Injection timeout (in seconds, includes waiting for result if -w was used)",
)
@click.option(
    "-c",
    "--shell-cmd",
    is_flag=True,
    default=False,
    show_default=True,
    help="Provide a cmd.exe shell command instead of CreateProcess one",
)
@click.argument("cmd", nargs=-1, type=str)
def exec_cmd(vm_id, wait, timeout, shell_cmd, cmd):
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(vm_id, install_info, config.network)
    if not vm.is_running:
        click.echo("VM is not running", err=True)
        raise click.Abort()

    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH)
    if shell_cmd:
        command = mslex.join(["cmd.exe", "/c", cmd], for_cmd=False)
    else:
        command = mslex.join(cmd, for_cmd=False)

    try:
        injector.create_process(command, wait, timeout)
    except CalledProcessError as e:
        click.echo(f"Injector stopped with error code {e.returncode}", err=True)
        raise click.Abort()
