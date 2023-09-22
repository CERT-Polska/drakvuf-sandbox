import datetime
import json
import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Tuple

from ..config import Profile
from ..util import ensure_delete

log = logging.getLogger(__name__)


class StorageBackendBase:
    """Base class for all storage backends

    Defines interface that has to be implemented in order to be
    considered a valid storage backend for DRAKVUF sandbox.

    In DRAKVUF Sandbox, worker virtual machines are named from
    vm-1 to vm-[n] - as configured by max_vms parameter during setup.

    vm-0 is considered special as it is used as a base for running
    other machines. The steps taken from creating vm-0 to running a worker are:
    create vm-0 -> configure vm-0 -> snapshot vm-0 -> restore vm-0 snapshot as vm-[i]
    """

    def __init__(self, profile: Profile):
        self.volume_dir = profile.volumes_dir
        self._install_info = profile.install_info

    def initialize_vm0_volume(self, disk_size: str):
        """Create base volume for vm-0 with given size

        disk_size - string representing volume size with M/G/T suffix, eg. 100G
        """
        raise NotImplementedError

    def snapshot_vm0_volume(self):
        """Saves or snapshots base vm-0 volume for later use by other VMs"""
        raise NotImplementedError

    def get_vm_disk_path(self, vm_id: int) -> str:
        """Returns disk path for given VM as defined by XL configuration"""
        raise NotImplementedError

    def rollback_vm_storage(self, vm_id: int):
        """Rolls back changes and prepares fresh storage for new run of this VM"""
        raise NotImplementedError

    def get_vm0_snapshot_time(self):
        """Get UNIX timestamp of when vm-0 snapshot was last modified"""
        raise NotImplementedError

    def export_vm0(self, file):
        """Export vm-0 disk into a file (symmetric to import_vm0)"""
        raise NotImplementedError

    def import_vm0(self, file):
        """Import vm-0 disk from a file (symmetric to export_vm0)"""
        raise NotImplementedError

    def delete_vm_volume(self, vm_id: int):
        """Delete vm_id disk volume"""
        raise NotImplementedError


class ZfsStorageBackend(StorageBackendBase):
    """Implements storage backend based on ZFS zvols"""

    def __init__(self, profile: Profile):
        super().__init__(profile)
        self.zfs_tank_name = profile.install_info.zfs_tank_name
        if self.zfs_tank_name is None:
            raise RuntimeError("zfs_tank_name is missing from InstallInfo")
        self.check_tools()

    @staticmethod
    def check_tools():
        """Verify existence of zfs command utility"""
        try:
            subprocess.check_output("zfs -?", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Failed to execute zfs command. "
                "Make sure you have ZFS support installed."
            )

    def initialize_vm0_volume(self, disk_size: str):
        vm0_vol = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0"))
        try:
            subprocess.check_output(
                f"zfs destroy -Rfr {vm0_vol}", stderr=subprocess.STDOUT, shell=True
            )
        except subprocess.CalledProcessError as exc:
            if b"dataset does not exist" not in exc.output:
                raise RuntimeError(
                    f"Failed to destroy the existing ZFS volume {vm0_vol}."
                )
        try:
            subprocess.check_output(
                " ".join(
                    [
                        "zfs",
                        "create",
                        "-s",
                        "-V",
                        shlex.quote(disk_size),
                        shlex.quote(os.path.join(self.zfs_tank_name, "vm-0")),
                    ]
                ),
                shell=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to create a new volume using zfs create.")

    def snapshot_vm0_volume(self):
        snap_name = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0@booted"))
        subprocess.check_output(f"zfs snapshot {snap_name}", shell=True)

    def get_vm_disk_path(self, vm_id: int) -> str:
        return f"phy:/dev/zvol/{self.zfs_tank_name}/vm-{vm_id},hda,w"

    def rollback_vm_storage(self, vm_id: int):
        vm_zvol = os.path.join("/dev/zvol", self.zfs_tank_name, f"vm-{vm_id}")
        vm_snap = os.path.join(self.zfs_tank_name, f"vm-{vm_id}@booted")

        if not os.path.exists(vm_zvol):
            subprocess.run(
                [
                    "zfs",
                    "clone",
                    "-p",
                    os.path.join(self.zfs_tank_name, "vm-0@booted"),
                    os.path.join(self.zfs_tank_name, f"vm-{vm_id}"),
                ],
                check=True,
            )

            for _ in range(120):
                if not os.path.exists(vm_zvol):
                    time.sleep(0.1)
                else:
                    break
            else:
                raise RuntimeError(
                    f"Failed to see {vm_zvol} created after executing "
                    "zfs clone command."
                )

            subprocess.run(["zfs", "snapshot", vm_snap], check=True)

        subprocess.run(["zfs", "rollback", vm_snap], check=True)

    def get_vm0_snapshot_time(self):
        base_snap = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0@booted"))
        out = subprocess.check_output(
            f"zfs get -H -p -o value creation {base_snap}", shell=True
        )
        ts = int(out.decode("ascii").strip())
        return ts

    def export_vm0(self, file):
        with open(file, "wb") as snapshot_file:
            subprocess.run(
                ["zfs", "send", f"{self.zfs_tank_name}/vm-0@booted"],
                check=True,
                stdout=snapshot_file,
            )

    def import_vm0(self, file):
        subprocess.run(["zfs", "create", self.zfs_tank_name], check=True)
        with open(file, "rb") as snapshot_file:
            subprocess.run(
                ["zfs", "recv", f"{self.zfs_tank_name}/vm-0@booted"],
                check=True,
                stdin=snapshot_file,
            )

    def delete_vm_volume(self, vm_id: int):
        vm_id_vol = os.path.join(self.zfs_tank_name, f"vm-{vm_id}")
        try:
            log.info(f"Deleting zfs volume {vm_id_vol}")
            subprocess.check_output(
                ["zfs", "destroy", "-Rfr", vm_id_vol], stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError as exc:
            log.error(exc.stdout)
            raise Exception(f"Couldn't delete {vm_id_vol}")

    def delete_zfs_tank(self):
        try:
            log.info("Deleting zfs tank")
            subprocess.run(
                ["zfs", "destroy", "-r", f"{self.zfs_tank_name}"], check=True
            )
        except subprocess.CalledProcessError as exc:
            log.error(exc.stdout)
            raise Exception(f"Couldn't delete {self.zfs_tank_name}")


class Qcow2StorageBackend(StorageBackendBase):
    """Implements storage backend based on QEMU QCOW2 image format"""

    def __init__(self, profile: Profile):
        super().__init__(profile)
        self.check_tools()

    @staticmethod
    def check_tools():
        """Verify existence of qemu-img"""
        try:
            subprocess.check_output("qemu-img --version", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Failed to determine qemu-img version. "
                "Make sure you have qemu-utils installed."
            )

    def initialize_vm0_volume(self, disk_size: str):
        try:
            subprocess.check_output(
                " ".join(
                    [
                        "qemu-img",
                        "create",
                        "-f",
                        "qcow2",
                        str(self.volume_dir / "vm-0.img"),
                        shlex.quote(disk_size),
                    ]
                ),
                shell=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to create a new volume using qemu-img.")

    def snapshot_vm0_volume(self):
        # We'll be using vm-0.img as backing storage
        pass

    def get_vm_disk_path(self, vm_id: int) -> str:
        disk_path = self.volume_dir / f"vm-{vm_id}.img"
        return f"tap:qcow2:{str(disk_path)},xvda,w"

    def rollback_vm_storage(self, vm_id: int):
        volume_path = self.volume_dir / f"vm-{vm_id}.img"
        vm0_path = self.volume_dir / f"vm-0.img"
        volume_path.unlink(missing_ok=True)

        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-o",
                f"backing_file={str(vm0_path)}",
                str(volume_path),
            ],
            check=True,
        )

    def get_vm0_snapshot_time(self):
        vm0_path = self.volume_dir / f"vm-0.img"
        return int(vm0_path.lstat().st_mtime)

    def export_vm0(self, path: str):
        vm0_path = self.volume_dir / f"vm-0.img"
        shutil.copy(vm0_path, path)

    def import_vm0(self, path: str):
        vm0_path = self.volume_dir / f"vm-0.img"
        shutil.copy(path, vm0_path)

    def delete_vm_volume(self, vm_id: str):
        # unmount can be done here
        disk_path = self.volume_dir / f"vm-{vm_id}.img"
        ensure_delete(disk_path, raise_on_error=True)


class LvmStorageBackend(StorageBackendBase):
    """Implements storage backend based on lvm storage"""

    def __init__(self, profile: Profile):
        super().__init__(profile)
        self.lvm_volume_group = profile.install_info.lvm_volume_group
        self.check_tools()
        self.snapshot_disksize = "1G"

    def check_tools(self):
        """Verify existence of lvm command utility"""
        try:
            subprocess.run(
                ["vgs", self.lvm_volume_group], check=True, stdout=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Failed to execute vgs command"
                f"Make sure you have LVM support installed with {self.lvm_volume_group} as a volume group"
            )

    def initialize_vm0_volume(self, disk_size: str):
        """Create base volume for vm-0 with given size

        disk_size - string representing volume size with M/G/T suffix, eg. 100G
        """
        try:
            log.info("Deleting existing logical volume and snapshot")
            subprocess.check_output(
                [
                    "lvremove",
                    "-v",
                    "-y",
                    # "--noudevsync",
                    f"{self.lvm_volume_group}/vm-0",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            if b"Failed to find logical volume" not in exc.output:
                raise RuntimeError(
                    f"Failed to destroy logical volume {self.lvm_volume_group}/vm-0"
                )
        try:
            log.info("Creating new volume vm-0")
            subprocess.run(
                [
                    "lvcreate",
                    "-y",
                    "-L",
                    disk_size,
                    "-n",
                    "vm-0",
                    self.lvm_volume_group,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to create a new volume using lvcreate.")

    def snapshot_vm0_volume(self):
        """Saves or snapshots base vm-0 volume for later use by other VMs"""
        # vm-0 is the original disk being treated as a snapshot
        # vm-0-snap is being created just for the access time of the change in vm snapshot
        subprocess.run(
            ["lvremove", f"{self.lvm_volume_group}/vm-0-snap"],
            stderr=subprocess.DEVNULL,
        )
        try:
            subprocess.check_output(
                [
                    "lvcreate",
                    "-s",
                    "-L",
                    self.snapshot_disksize,
                    "-n",
                    "vm-0-snap",
                    f"{self.lvm_volume_group}/vm-0",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            log.debug(exc.output)
            raise RuntimeError("Couldn't create snapshot")

    def get_vm_disk_path(self, vm_id: int) -> str:
        """Returns disk path for given VM as defined by XL configuration"""
        return f"phy:/dev/{self.lvm_volume_group}/vm-{vm_id},hda,w"

    def rollback_vm_storage(self, vm_id: int):
        """Rolls back changes and prepares fresh storage for new run of this VM"""
        vm_id_vol = os.path.join("/dev", f"{self.lvm_volume_group}", f"vm-{vm_id}")

        if vm_id == 0:
            raise Exception("vm-0 should not be rollbacked")

        log.info(f"Rolling back changes to vm-{vm_id} disk")
        if os.path.exists(vm_id_vol):
            try:
                subprocess.check_output(
                    [
                        "lvremove",
                        "-v",
                        "-y",
                        # "--noudevsync",
                        f"{self.lvm_volume_group}/vm-{vm_id}",
                    ],
                    stderr=subprocess.STDOUT,
                )
            except subprocess.CalledProcessError as exc:
                log.debug(exc.output)
                raise RuntimeError(
                    f"Failed to discard previous logical volume {self.lvm_volume_group}/vm-{vm_id}"
                )

        try:
            subprocess.check_output(
                [
                    "lvcreate",
                    "-s",
                    "-L",
                    self.snapshot_disksize,
                    "-n",
                    f"vm-{vm_id}",
                    f"{self.lvm_volume_group}/vm-0",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as exc:
            log.debug(exc.output)
            raise RuntimeError("Couldn't rollback disk")

    def get_vm0_snapshot_time(self):
        """Get UNIX timestamp of when vm-0 snapshot was last modified"""

        p = subprocess.run(
            ["lvs", "-o", "lv_name,lv_time", "--reportformat", "json"],
            capture_output=True,
            check=True,
        )

        lvs = json.loads(p.stdout.decode("utf-8"))["report"][0]["lv"]
        target_lvs = list(filter(lambda x: x["lv_name"] == "vm-0-snap", lvs))

        if len(target_lvs) > 1:
            raise RuntimeError("Found multiple lvs named vm-0-snap!")

        if len(target_lvs) == 0:
            raise RuntimeError("Failed to find LV vm-0-snap!")

        dt = datetime.datetime.strptime(
            target_lvs[0]["lv_time"], "%Y-%m-%d %H:%M:%S %z"
        )
        return int(dt.timestamp())

    def export_vm0(self, path: str):
        """Export vm-0 disk into a file (symmetric to import_vm0)"""
        # As dd copies empty spaces also
        # Should we use compressions in this? Will it have any issues while importing?
        subprocess.run(
            [
                "dd",
                f"if=/dev/{self.lvm_volume_group}/vm-0",
                f"of={path}",
                "bs=4k",
                "status=progress",
            ],
            check=True,
        )

    def import_vm0(self, path: str):
        """Import vm-0 disk from a file (symmetric to export_vm0)"""
        subprocess.run(
            [
                "dd",
                f"of=/dev/{self.lvm_volume_group}/vm-0",
                f"if={path}",
                "bs=4k",
                "status=progress",
            ],
            check=True,
        )

    def delete_vm_volume(self, vm_id: str):
        try:
            subprocess.check_output(
                [
                    "lvremove",
                    "-v",
                    "-y",
                    # "--noudevsync",
                    f"{self.lvm_volume_group}/vm-{vm_id}",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            log.debug(e.output)
            raise Exception("Could not delete volume")


REGISTERED_BACKENDS = {
    "qcow2": Qcow2StorageBackend,
    "zfs": ZfsStorageBackend,
    "lvm": LvmStorageBackend,
}

REGISTERED_BACKEND_NAMES: Tuple[str] = tuple(REGISTERED_BACKENDS.keys())


class InvalidStorageBackend(Exception):
    """Thrown when tried to create unsupported storage backend"""


def get_storage_backend(profile: Profile) -> StorageBackendBase:
    """Return installed storage backend or throw InvalidStorageBackend"""
    if profile.install_info.storage_backend not in REGISTERED_BACKEND_NAMES:
        raise InvalidStorageBackend

    return REGISTERED_BACKENDS[profile.install_info.storage_backend](profile)
