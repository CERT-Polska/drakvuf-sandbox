import argparse
import tempfile
import subprocess
from pathlib import Path, PureWindowsPath as WinPath
from IPython import embed

from drakrun.networking import (
    setup_vm_network,
    start_dnsmasq,
)
from drakrun.vm import generate_vm_conf, VirtualMachine
from drakrun.config import InstallInfo, PROFILE_DIR, ETC_DIR
from drakrun.storage import get_storage_backend
from drakrun.util import RuntimeInfo, graceful_exit
from drakrun.injector import Injector
from drakrun.draksetup import find_default_interface


class DrakmonShell:
    def __init__(self, vm_id: int, dns: str):
        install_info = InstallInfo.load()
        backend = get_storage_backend(install_info)

        generate_vm_conf(install_info, vm_id)
        self.vm = VirtualMachine(backend, vm_id)

        with open(Path(PROFILE_DIR) / "runtime.json", 'r') as f:
            self.runtime_info = RuntimeInfo.load(f)
        self.desktop = WinPath(r"%USERPROFILE%") / "Desktop"

        self.kernel_profile = Path(PROFILE_DIR) / "kernel.json"
        self.injector = Injector(
            self.vm.vm_name,
            self.runtime_info,
            self.kernel_profile,
        )
        setup_vm_network(vm_id, True, find_default_interface(), dns)

    def drakvuf(self, plugins, timeout=60):
        d = tempfile.TemporaryDirectory(prefix="drakvuf_")
        workdir = Path(d.name)

        log = open(workdir / "drakmon.log", "wb")

        cmd = ["drakvuf"]
        cmd.extend([
            "-o", "json",
            "F",
            "-j", "5",
            "-t", str(timeout),
            "-i", str(self.runtime_info.inject_pid),
            "-k", str(self.runtime_info.vmi_offsets.kpgd),
            "-r", self.kernel_profile,
            "-d", self.vm.vm_name,
            "--dll-hooks-list", Path(ETC_DIR) / "hooks.txt",
        ])

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

    def copy(self, local):
        local = Path(local)
        self.injector.write_file(local, self.desktop / local.name)

    def run(self, cmd):
        self.injector.create_process(cmd)

    def __enter__(self):
        self.vm.restore()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.vm.destroy()


def main():
    parser = argparse.ArgumentParser(description='DRAKVUF Sandbox interactive shell')
    parser.add_argument('vm_id', type=int, help='VM id you want to control')
    parser.add_argument('--dns', default='8.8.8.8')

    args = parser.parse_args()

    with graceful_exit(start_dnsmasq(args.vm_id, args.dns)), \
         DrakmonShell(args.vm_id, args.dns) as shell:
        helpers = {
            'copy': shell.copy,
            'drakvuf': shell.drakvuf,
            'vm': shell.vm
        }
        embed(banner='', user_ns=helpers, colors='neutral')


if __name__ == "__main__":
    main()
