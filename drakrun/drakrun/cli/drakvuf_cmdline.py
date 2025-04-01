import logging
import shlex

import click

from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.network_info import NetworkConfiguration
from drakrun.lib.paths import (
    INSTALL_INFO_PATH,
    NETWORK_CONF_PATH,
    VMI_INFO_PATH,
    VMI_KERNEL_PROFILE_PATH,
)
from drakrun.lib.vm import VirtualMachine

log = logging.getLogger(__name__)


@click.command(help="Get base Drakvuf cmdline")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for generating profile",
)
@click.option(
    "--cmd",
    default=None,
    help="Command line to inject for execution",
)
def drakvuf_cmdline(vm_id, cmd):
    install_info = InstallInfo.load(INSTALL_INFO_PATH)
    network_conf = NetworkConfiguration.load(NETWORK_CONF_PATH)

    vm = VirtualMachine(vm_id, install_info, network_conf)
    if not vm.is_running:
        raise RuntimeError("VM is not running")

    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    print(
        shlex.join(
            get_base_drakvuf_cmdline(
                vm.vm_name,
                VMI_KERNEL_PROFILE_PATH.as_posix(),
                vmi_info=vmi_info,
                exec_cmd=cmd,
            )
        )
    )
