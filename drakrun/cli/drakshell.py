import logging
import sys
import time

import click

from drakrun.lib.config import load_config
from drakrun.lib.drakshell import Drakshell
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.paths import (
    INSTALL_INFO_PATH,
    PACKAGE_TOOLS_PATH,
    VMI_INFO_PATH,
    VMI_KERNEL_PROFILE_PATH,
)
from drakrun.lib.vm import VirtualMachine

log = logging.getLogger(__name__)


@click.command("drakshell")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
@click.argument("cmd", nargs=-1, type=str)
def drakshell(vm_id, cmd):
    """
    Run drakshell session
    """
    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    vm = VirtualMachine(vm_id, install_info, config.network)
    if not vm.is_running:
        click.echo("VM is not running", err=True)
        raise click.Abort()
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    injector = Injector(vm.vm_name, vmi_info, VMI_KERNEL_PROFILE_PATH)

    drakshell = Drakshell(vm.vm_name)
    connected = False
    try:
        drakshell.connect()
        connected = True
    except Exception as e:
        log.warning(f"Failed to connect to drakshell: {str(e)}")

    if not connected:
        log.info("Injecting drakshell...")
        drakshell_path = (
            (PACKAGE_TOOLS_PATH / "drakshell" / "drakshell").resolve().as_posix()
        )
        injector.inject_shellcode(drakshell_path)
        log.info("Injected. Trying to connect.")
        time.sleep(1)
        drakshell.connect()

    info = drakshell.get_info()
    log.info(f"Drakshell active on: {str(info)}")

    process = drakshell.run_interactive(cmd, sys.stdin, sys.stdout, sys.stderr)
    exit_code = process.join()
    log.info(f"Process terminated with exit code {exit_code}")
