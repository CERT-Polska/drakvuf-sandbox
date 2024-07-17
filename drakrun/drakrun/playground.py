import argparse
import contextlib
import logging
import subprocess
import tempfile
from pathlib import Path
from pathlib import PureWindowsPath as WinPath
from textwrap import dedent

from IPython import embed

from drakrun.draksetup import insert_cd
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import (
    delete_vm_network,
    find_default_interface,
    setup_vm_network,
    start_dnsmasq,
)
from drakrun.lib.paths import ETC_DIR, PROFILE_DIR, RUNTIME_FILE
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.util import RuntimeInfo, graceful_exit
from drakrun.lib.vm import FIRST_CDROM_DRIVE, VirtualMachine, generate_vm_conf

log = logging.getLogger(__name__)


class DrakmonShell:
    def __init__(self, vm_id: int, dns: str):
        install_info = InstallInfo.load()
        backend = get_storage_backend(install_info)

        # vm-0 is not managed by drakplayground.
        # drakplayground should not make a network setup
        # nor restore/destroy VM by itself
        self.vm_managed = vm_id != 0

        if self.vm_managed:
            self.cleanup(vm_id)
            generate_vm_conf(install_info, vm_id)

        self.vm_id = vm_id
        self.vm = VirtualMachine(backend, vm_id)

        if not self.vm_managed and not self.vm.is_running:
            raise RuntimeError(
                "vm-0 is not running. If you want to operate on vm-0, use 'draksetup modify-vm0' first"
            )

        self.dns = dns

        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)
        self.desktop = WinPath(r"%USERPROFILE%") / "Desktop"

        self.kernel_profile = Path(PROFILE_DIR) / "kernel.json"
        self.injector = Injector(
            self.vm.vm_name,
            self.runtime_info,
            str(self.kernel_profile),
        )

    def cleanup(self, vm_id: int):
        log.info(f"Ensuring that drakrun@{vm_id} service is stopped...")
        try:
            subprocess.run(
                ["systemctl", "stop", f"drakrun@{vm_id}"],
                stderr=subprocess.STDOUT,
                check=True,
            )
        except subprocess.CalledProcessError:
            raise Exception(f"drakrun@{vm_id} not stopped")

    def drakvuf(self, plugins, timeout=60):
        d = tempfile.TemporaryDirectory(prefix="drakvuf_")
        workdir = Path(d.name)

        log = open(workdir / "drakmon.log", "wb")

        cmd = ["drakvuf"]
        cmd.extend(
            [
                "-o",
                "json",
                "F",
                "-j",
                "5",
                "-t",
                str(timeout),
                "-i",
                str(self.runtime_info.inject_pid),
                "-k",
                str(self.runtime_info.vmi_offsets.kpgd),
                "-r",
                str(self.kernel_profile),
                "-d",
                self.vm.vm_name,
                "--dll-hooks-list",
                str(Path(ETC_DIR) / "hooks.txt"),
            ]
        )

        if "memdump" in plugins:
            dumps = workdir / "dumps"
            dumps.mkdir()
            cmd.extend(["--memdump-dir", str(dumps)])

        if "ipt" in plugins:
            ipt = workdir / "ipt"
            ipt.mkdir()
            cmd.extend(["--ipt-dir", str(ipt)])

        for chk in (["-a", plugin] for plugin in plugins):
            cmd.extend(chk)

        subprocess.run(cmd, stdout=log)

        return d

    def help(self):
        usage = dedent(
            """\
        Available commands:
        - copy(file_path)   # copy file onto vm desktop
        - mount(iso_path)   # mount iso, useful for installing software, e.g. office
        - drakvuf(plugins)  # start drakvuf with provided set of plugins
        - run(cmd)          # run command inside vm
        - exit()            # exit playground
        """
        )
        print(usage)

    def copy(self, local):
        local = Path(local)
        self.injector.write_file(local, self.desktop / local.name)

    def mount(self, local_iso_path, drive=FIRST_CDROM_DRIVE):
        local_iso_path = Path(local_iso_path)
        insert_cd(self.vm.vm_name, drive, local_iso_path)

    def run(self, cmd):
        self.injector.create_process(cmd)

    def __enter__(self):
        if self.vm_managed:
            setup_vm_network(self.vm_id, True, find_default_interface(), self.dns)
            self.vm.restore()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.vm_managed:
            self.vm.destroy()
            delete_vm_network(self.vm.vm_id)


@contextlib.contextmanager
def start_dnsmasq_if_managed(shell: DrakmonShell):
    if shell.vm_managed:
        with graceful_exit(start_dnsmasq(shell.vm_id, shell.dns)):
            yield
    else:
        yield


def main():
    parser = argparse.ArgumentParser(description="DRAKVUF Sandbox interactive shell")
    parser.add_argument("vm_id", type=int, help="VM id you want to control")
    parser.add_argument("--dns", default="8.8.8.8")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )

    with DrakmonShell(args.vm_id, args.dns) as shell, start_dnsmasq_if_managed(shell):
        helpers = {
            "help": shell.help,
            "copy": shell.copy,
            "mount": shell.mount,
            "drakvuf": shell.drakvuf,
            "vm": shell.vm,
            "run": shell.run,
        }
        banner = dedent(
            """
            *** Welcome to drakrun playground ***
            Your VM is now ready and running with internet connection.
            You can connect to it using VNC (password can be found in /etc/drakrun/scripts/cfg.template)
            Run help() to list available commands.
            """
        )
        embed(banner1=banner, user_ns=helpers, colors="neutral")


if __name__ == "__main__":
    main()
