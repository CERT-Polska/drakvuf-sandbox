import logging
import shutil
import subprocess
from pathlib import Path

import click

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
@click.option(
    "--no-prep",
    "no_prep",
    is_flag=True,
    default=False,
    help="Don't run preparation script",
)
def run(vm_id, sample_path, out_dir, config_name, timeout, disable_net, no_prep):
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
        log.info("Preparing analysis dir...")

        dll_hooks_list = out_dir / "hooks.txt"
        shutil.copy(config.etc_dir / "hooks.txt", dll_hooks_list)
        memdump_dir = out_dir / "memdumps"
        memdump_dir.mkdir()
        stdout_path = out_dir / "stdout.log"
        stderr_path = out_dir / "stderr.log"

        log.info("Running guest preparation script...")
        if not no_prep:
            vm.run_prepare_script()
        log.info(f"Copying sample {sample_path} => {guest_sample_path}")
        result = vm.injector.write_file(sample_path, guest_sample_path)
        real_sample_path = result["ProcessName"]
        log.info(f"Running sample {real_sample_path}")
        drakvuf = Drakvuf(config, vm_id, vm.runtime_info, str(vm.kernel_profile_path))
        cmdline = drakvuf.get_base_drakvuf_cmdline(timeout, real_sample_path, "C:\\")
        cmdline.extend(
            [
                "-a",
                "apimon",
                "-a",
                "bsodmon",
                "-a",
                "clipboardmon",
                "-a",
                "cpuidmon",
                "-a",
                "debugmon",
                "-a",
                "delaymon",
                "-a",
                "exmon",
                "-a",
                "filedelete",
                "-a",
                "librarymon",
                "-a",
                "memdump",
                "-a",
                "procdump",
                "-a",
                "procmon",
                "-a",
                "regmon",
                "-a",
                "rpcmon",
                "-a",
                "ssdtmon",
                "-a",
                "tlsmon",
                "-a",
                "windowmon",
                "-a",
                "wmimon",
                "--dll-hooks-list",
                str(dll_hooks_list),
                "--memdump-dir",
                str(memdump_dir),
            ]
        )
        with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
            subprocess.run(cmdline, stdout=stdout, stderr=stderr)
        log.info("kbye")
    finally:
        pass
        # vm.destroy()
