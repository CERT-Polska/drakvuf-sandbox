import argparse
import logging
import subprocess
import tempfile
from pathlib import Path
from pathlib import PureWindowsPath as WinPath
from textwrap import dedent

from IPython import embed

from drakrun.config import ETC_DIR, PROFILE_DIR, RUNTIME_FILE, InstallInfo
from drakrun.draksetup import find_default_interface, insert_cd
from drakrun.injector import Injector
from drakrun.networking import delete_vm_network, setup_vm_network, start_dnsmasq
from drakrun.storage import get_storage_backend
from drakrun.util import RuntimeInfo, graceful_exit
from drakrun.vm import FIRST_CDROM_DRIVE, VirtualMachine, generate_vm_conf


class DrakmonShell:
    def __init__(self, vm_id: int, dns: str):

        self.cleanup(vm_id)

        install_info = InstallInfo.load()
        backend = get_storage_backend(install_info)

        generate_vm_conf(install_info, vm_id)
        self.vm = VirtualMachine(backend, vm_id)
        self._dns = dns

        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)
        self.desktop = WinPath(r"%USERPROFILE%") / "Desktop"

        self.kernel_profile = Path(PROFILE_DIR) / "kernel.json"
        self.injector = Injector(
            self.vm.vm_name,
            self.runtime_info,
            self.kernel_profile,
        )
        setup_vm_network(vm_id, True, find_default_interface(), dns)

    def cleanup(self, vm_id: int):

        logging.info(f"Ensuring that drakrun@{vm_id} service is stopped...")
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
                self.kernel_profile,
                "-d",
                self.vm.vm_name,
                "--dll-hooks-list",
                Path(ETC_DIR) / "hooks.txt",
            ]
        )

        if "memdump" in plugins:
            dumps = workdir / "dumps"
            dumps.mkdir()
            cmd.extend(["--memdump-dir", dumps])

        if "ipt" in plugins:
            ipt = workdir / "ipt"
            ipt.mkdir()
            cmd.extend(["--ipt-dir", ipt])

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
        self.vm.restore()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.vm.destroy()
        delete_vm_network(self.vm.vm_id, True, find_default_interface(), self._dns)


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

    with DrakmonShell(args.vm_id, args.dns) as shell, graceful_exit(
        start_dnsmasq(args.vm_id, args.dns)
    ):
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
