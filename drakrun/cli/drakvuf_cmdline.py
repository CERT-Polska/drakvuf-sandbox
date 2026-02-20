import logging
import shlex

import click

from drakrun.lib.config import load_config
from drakrun.lib.drakvuf_cmdline import get_base_drakvuf_cmdline
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.libvmi import VmiInfo
from drakrun.lib.paths import INSTALL_INFO_PATH, VMI_INFO_PATH, VMI_KERNEL_PROFILE_PATH
from drakrun.lib.version_detection import get_drakvuf_version
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
@click.option(
    "--method",
    default="createproc",
    help="Execution method for injection (createproc, shellexec, runas)",
)
def drakvuf_cmdline(vm_id, cmd, method):
    from drakrun.analyzer.startup_command import make_exec_parameters

    config = load_config()
    install_info = InstallInfo.load(INSTALL_INFO_PATH)

    vm = VirtualMachine(vm_id, install_info, config.network)
    vmi_info = VmiInfo.load(VMI_INFO_PATH)
    if cmd is not None:
        drakvuf_version = get_drakvuf_version()
        supports_shellexec = drakvuf_version.supports_shellexec_verb
        exec_parameters = make_exec_parameters(cmd, method, supports_shellexec)
    else:
        exec_parameters = None
    print(
        shlex.join(
            get_base_drakvuf_cmdline(
                vm.vm_name,
                VMI_KERNEL_PROFILE_PATH.as_posix(),
                vmi_info=vmi_info,
                **(
                    dict(
                        exec_cmd=exec_parameters.command,
                        shellexec_args=exec_parameters.shellexec_args,
                        start_method=exec_parameters.start_method,
                    )
                    if exec_parameters
                    else {}
                )
            )
        )
    )
