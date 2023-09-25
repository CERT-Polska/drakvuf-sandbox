import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..config import Profile
from .networking import delete_vm_network, setup_vm_network, start_dnsmasq, stop_dnsmasq
from .storage import get_storage_backend
from .xen import eject_cd, insert_cd

log = logging.getLogger(__name__)

FIRST_CDROM_DRIVE = "hdc"
SECOND_CDROM_DRIVE = "hdd"


class VMError(RuntimeError):
    def __init__(self, message: str, vm_name: str, with_qemu_logs: bool = True):
        self.vm_name = vm_name
        if with_qemu_logs:
            log_path = Path(f"/var/log/xen/qemu-dm-{vm_name}.log")
            try:
                message += f"\n---- {str(log_path)}:\n{log_path.read_text()}"
            except Exception:
                log.warning("Failed to read qemu log for additional details")
        super().__init__(message)


class VirtualMachine:
    def __init__(self, profile: Profile, vm_id: int):
        self.profile = profile
        self.storage = get_storage_backend(self.profile)
        self.vm_id = vm_id
        self.vm_name = profile.get_vm_name(vm_id)

    @property
    def is_running(self) -> bool:
        res = subprocess.run(
            ["xl", "list", self.vm_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0

    @property
    def snapshot_path(self) -> Path:
        return self.profile.volumes_dir / "snapshot.sav"

    @property
    def vm_config_path(self) -> Path:
        return self.profile.vm_config_dir / f"vm-{self.vm_id}.cfg"

    def make_vm_config(
        self, first_cd: Optional[Path] = None, second_cd: Optional[Path] = None
    ) -> Path:
        """
        Creates configuration from template and ensures its existence
        """
        template = self.profile.vm_template_path.read_text()

        disks = [self.storage.get_vm_disk_path(self.vm_id)]

        if first_cd:
            disks.append(f"file:{str(first_cd.resolve())},{FIRST_CDROM_DRIVE}:cdrom,r")

        if second_cd:
            disks.append(
                f"file:{str(second_cd.resolve())},{SECOND_CDROM_DRIVE}:cdrom,r"
            )

        install_info = self.profile.install_info
        vm_name = self.vm_name
        vm_id = self.vm_id
        disks_spec = ", ".join(['"{}"'.format(disk) for disk in disks])

        template = template.replace("{{ VM_NAME }}", str(vm_name))
        template = template.replace("{{ VM_ID }}", str(vm_id))
        template = template.replace("{{ DISKS }}", disks_spec)
        template = template.replace("{{ VNC_PORT }}", str(6400 + vm_id))
        template = template.replace("{{ VCPUS }}", str(install_info.vcpus))
        template = template.replace("{{ MEMORY }}", str(install_info.memory))

        # Never destroy vm-0 on reboot, it's installation VM
        # In other cases: VM profiles no longer match vm-0 state after reboot
        # so vm-N should be destroyed (unless user wants different behavior)
        if vm_id == 0:
            template = re.sub("on_reboot[ ]*=(.*)", 'on_reboot = "restart"', template)

        vm_config_path = self.vm_config_path
        with vm_config_path.open("w") as f:
            f.write("# Autogenerated, don't edit this file directly!\n")
            f.write("# Instead please edit /etc/drakrun/scripts/cfg.template\n")
            f.write("# and restart drakrun@<vm_id> service.\n\n")
            f.write(template)

        log.info(f"Generated VM configuration for vm-{vm_id}")
        return vm_config_path

    def setup_network(self, out_interface: str, dns_server: str, net_enable: bool):
        setup_vm_network(
            self.profile, self.vm_id, out_interface, dns_server, net_enable
        )
        if net_enable:
            start_dnsmasq(self.profile, self.vm_id, dns_server, background=True)

    def clean_network(self):
        stop_dnsmasq(self.profile, self.vm_id)
        delete_vm_network(self.profile, self.vm_id)

    def create(
        self,
        paused=False,
        first_cd: Optional[Path] = None,
        second_cd: Optional[Path] = None,
    ):
        vm_config_path = self.make_vm_config(first_cd, second_cd)
        args = ["xl", "create"]
        if paused:
            args += ["-p"]
        args += [str(vm_config_path)]
        log.info(f"Creating VM {self.vm_name}")
        try:
            subprocess.run(args, check=True)
        except subprocess.CalledProcessError:
            raise VMError(f"Failed to launch VM {self.vm_name}", vm_name=self.vm_name)

    def pause(self):
        try:
            subprocess.run(
                ["xl", "pause", self.vm_name],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise VMError(f"Failed to pause VM {self.vm_name}", vm_name=self.vm_name)

    def unpause(self):
        try:
            subprocess.run(
                ["xl", "unpause", self.vm_name],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise VMError(f"Failed to unpause VM {self.vm_name}", vm_name=self.vm_name)

    def save(self, snapshot_path: Path = None, destroy_after=False):
        snapshot_path = snapshot_path or self.snapshot_path
        args = ["xl", "save"]
        if not destroy_after:
            args += ["-c"]
        args += [self.vm_name, str(snapshot_path)]

        logging.info(f"Saving VM {self.vm_name}")
        try:
            # We want to keep it running after saving
            subprocess.run(
                args,
                check=True,
            )
        except subprocess.CalledProcessError:
            raise VMError(f"Failed to save VM {self.vm_name}", vm_name=self.vm_name)

    def restore(self, snapshot_path=None, paused=False):
        snapshot_path = snapshot_path or self.snapshot_path
        if self.is_running:
            self.destroy()
        self.make_vm_config()
        args = ["xl", "restore"]
        if paused is True:
            args += ["-p"]
        # No need to rollback storage for vm-0.
        # The state of vm-0 is correct by definition.
        if self.vm_id != 0:
            self.storage.rollback_vm_storage(self.vm_id)
        args += [str(self.vm_config_path), str(snapshot_path)]
        logging.info(f"Restoring VM {self.vm_name}")
        try:
            # We want to keep it running after saving
            subprocess.run(args, check=True)
        except subprocess.CalledProcessError:
            raise VMError(f"Failed to restore VM {self.vm_name}", vm_name=self.vm_name)

    def destroy(self):
        try:
            subprocess.run(
                ["xl", "destroy", self.vm_name],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise VMError(
                f"Failed to destroy VM {self.vm_name}",
                vm_name=self.vm_name,
                with_qemu_logs=False,
            )

    def eject_cd(self, drive: str):
        try:
            eject_cd(self.vm_name, drive)
        except subprocess.CalledProcessError:
            log.exception("Failed to eject CD, probably already ejected")
            return

    def insert_cd(self, drive: str, iso_path: str):
        insert_cd(self.vm_name, drive, iso_path)


def make_unattended_iso(xml_path, iso_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_xml_path = os.path.join(tmpdir, "autounattend.xml")

        with open(tmp_xml_path, "wb") as fw:
            with open(xml_path, "rb") as fr:
                fw.write(fr.read())

        try:
            subprocess.check_output(
                [
                    "genisoimage",
                    "-o",
                    iso_path,
                    "-J",
                    "-r",
                    tmp_xml_path,
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError:
            logging.exception("Failed to generate unattended.iso.")
