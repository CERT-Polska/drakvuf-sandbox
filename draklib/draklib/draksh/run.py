import logging
import subprocess

import click
from pathlib import Path

from ..config import Configuration
from ..drakvuf.drakvuf import Drakvuf
from ..drakvuf.vm import DrakvufVM
from .util import check_root

log = logging.getLogger(__name__)


@click.command(help="Run sample in Drakvuf environment")
@click.argument("vm_id", type=int)
@click.argument("sample_path", type=click.Path(exists=True))
@click.argument("out_dir", type=click.Path(file_okay=False))
@click.option(
    "--config-name",
    "config_name",
    default=Configuration.DEFAULT_NAME,
    type=str,
    show_default=True,
    help="Configuration name",
)
@click.option(
    "--timeout",
    "timeout",
    default=60,
    type=int,
    show_default=True,
    help="Analysis timeout",
)
@click.option(
    "--disable-net",
    "disable_net",
    is_flag=True,
    default=False,
    help="Disable network for installation",
)
def run(vm_id, sample_path, out_dir, config_name, timeout, disable_net):
    if not check_root():
        return
    # TODO
    # This is just for test

    guest_sample_path = "%USERPROFILE%\\Desktop\\malwar.exe"

    Path(out_dir).mkdir()
    config = Configuration.load(config_name)
    vm = DrakvufVM(config, vm_id)
    vm.load_runtime_info()
    vm.restore(net_enable=not disable_net)
    try:
        log.info("Running guest preparation script...")
        vm.run_prepare_script()
        log.info(f"Copying sample {sample_path} => {guest_sample_path}")
        result = vm.injector.write_file(sample_path, guest_sample_path)
        real_sample_path = result["ProcessName"]
        log.info(f"Running sample {real_sample_path}")
        drakvuf = Drakvuf(config, vm_id, vm.runtime_info, str(vm.kernel_profile_path))
        cmdline = drakvuf.get_base_drakvuf_cmdline(timeout, guest_sample_path, "C:\\")
        with open("./stdout.log", "w") as stdout, open("./stderr.log", "w") as stderr:
            subprocess.run(
                cmdline,
                stdout=stdout,
                stderr=stderr
            )
        log.info("kbye")
    finally:
        vm.destroy()
