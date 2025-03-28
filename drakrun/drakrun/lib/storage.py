import datetime
import json
import logging
import os
import shutil
import subprocess
import time
from typing import Tuple

from .install_info import InstallInfo

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

    def __init__(self, install_info: InstallInfo):
        self._install_info = install_info

    def initialize_vm0_volume(self, disk_size: str) -> None:
        """Create base volume for vm-0 with given size

        disk_size - string representing volume size with M/G/T suffix, eg. 100G
        """
        raise NotImplementedError

    def snapshot_vm0_volume(self) -> None:
        """Saves or snapshots base vm-0 volume for later use by other VMs"""
        raise NotImplementedError

    def get_vm_disk_path_by_name(self, volume_name: str) -> str:
        """Returns disk path for given volume name as defined by XL configuration"""
        raise NotImplementedError

    def check_volume_exists(self, volume_name: str) -> bool:
        """Returns True if volume already exists, False otherwise"""
        raise NotImplementedError

    def get_vm_disk_path(self, vm_id: int) -> str:
        """Returns disk path for given VM number"""
        return self.get_vm_disk_path_by_name(f"vm-{vm_id}")

    def get_vm0_modify_disk_path(self) -> str:
        """Returns disk path for VM-0 modification"""
        raise NotImplementedError

    def rollback_vm_storage(self, vm_id: int) -> None:
        """Rolls back changes and prepares fresh storage for new run of this VM"""
        raise NotImplementedError

    def initialize_vm0_modify_storage(self) -> None:
        """Creates storage for vm-0 modification based on current vm-0 state"""
        raise NotImplementedError

    def delete_vm0_modify_storage(self) -> None:
        """Deletes pending vm-0 modification"""
        raise NotImplementedError

    def commit_vm0_modify_storage(self) -> None:
        """Apply vm-0 modification to the base vm-0 snapshot"""
        raise NotImplementedError

    def get_vm0_snapshot_time(self) -> int:
        """Get UNIX timestamp of when vm-0 snapshot was last modified"""
        raise NotImplementedError

    def export_vm0(self, path) -> None:
        """Export vm-0 disk into a file (symmetric to import_vm0)"""
        raise NotImplementedError

    def import_vm0(self, path) -> None:
        """Import vm-0 disk from a file (symmetric to export_vm0)"""
        raise NotImplementedError

    def delete_vm_volume_by_name(self, volume_name: str) -> None:
        raise NotImplementedError

    def delete_vm_volume(self, vm_id: int) -> None:
        """Delete vm_id disk volume"""
        self.delete_vm_volume_by_name(f"vm-{vm_id}")


class ZfsStorageBackend(StorageBackendBase):
    """Implements storage backend based on ZFS zvols"""

    def __init__(self, install_info: InstallInfo) -> None:
        super().__init__(install_info)
        self.zfs_tank_name = install_info.zfs_tank_name
        if self.zfs_tank_name is None:
            raise RuntimeError("zfs_tank_name is missing from InstallInfo")
        self.check_tools()

    @staticmethod
    def check_tools() -> None:
        """Verify existence of zfs command utility"""
        try:
            subprocess.run(
                ["zfs", "-?"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Failed to execute zfs command. "
                "Make sure you have ZFS support installed."
            )

    def initialize_vm0_volume(self, disk_size: str) -> None:
        if self.check_volume_exists("vm-0"):
            self.delete_vm_volume_by_name("vm-0")
        try:
            subprocess.run(
                [
                    "zfs",
                    "create",
                    "-s",
                    "-V",
                    disk_size,
                    os.path.join(self.zfs_tank_name, "vm-0"),
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to create a new volume using zfs create.")

    def snapshot_vm0_volume(self) -> None:
        snap_name = os.path.join(self.zfs_tank_name, "vm-0@booted")
        subprocess.run(["zfs", "snapshot", snap_name], check=True)

    def get_vm_disk_path_by_name(self, volume_name: str) -> str:
        return f"phy:/dev/zvol/{self.zfs_tank_name}/{volume_name},hda,w"

    def get_vm0_modify_disk_path(self) -> str:
        # ZFS has vm-0@booted snapshot that can be easily reverted
        return self.get_vm_disk_path_by_name("vm-0")

    def check_volume_exists(self, volume_name: str) -> bool:
        volume_path = os.path.join("/dev/zvol", self.zfs_tank_name, volume_name)
        return os.path.exists(volume_path)

    def rollback_vm_storage(self, vm_id: int) -> None:
        vm_zvol = os.path.join("/dev/zvol", self.zfs_tank_name, f"vm-{vm_id}")
        vm_snap = os.path.join(self.zfs_tank_name, f"vm-{vm_id}@booted")

        if not self.check_volume_exists(f"vm-{vm_id}"):
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

    def initialize_vm0_modify_storage(self) -> None:
        # Just ensure that vm-0 is rollbacked to the vm-0@booted state
        self.delete_vm0_modify_storage()

    def delete_vm0_modify_storage(self) -> None:
        # Just rollback to the vm-0@booted state
        volume_snap = os.path.join(self.zfs_tank_name, "vm-0@booted")
        subprocess.run(["zfs", "rollback", volume_snap], check=True)

    def commit_vm0_modify_storage(self) -> None:
        # Make a new vm-0@booted snapshot
        volume_snap = os.path.join(self.zfs_tank_name, "vm-0@booted")
        subprocess.run(["zfs", "destroy", "-R", volume_snap], check=True)
        subprocess.run(["zfs", "snapshot", volume_snap], check=True)

    def get_vm0_snapshot_time(self) -> int:
        base_snap = os.path.join(self.zfs_tank_name, "vm-0@booted")
        out = subprocess.check_output(
            [
                "zfs",
                "get",
                "-H",
                "-p",
                "-o",
                "value",
                "creation",
                base_snap,
            ]
        )
        ts = int(out.decode("ascii").strip())
        return ts

    def export_vm0(self, path) -> None:
        with open(path, "wb") as snapshot_file:
            subprocess.run(
                ["zfs", "send", f"{self.zfs_tank_name}/vm-0@booted"],
                check=True,
                stdout=snapshot_file,
            )

    def import_vm0(self, path) -> None:
        subprocess.run(["zfs", "create", self.zfs_tank_name], check=True)
        with open(path, "rb") as snapshot_file:
            subprocess.run(
                ["zfs", "recv", f"{self.zfs_tank_name}/vm-0@booted"],
                check=True,
                stdin=snapshot_file,
            )

    def delete_vm_volume_by_name(self, volume_name: str) -> None:
        volume_path = os.path.join(self.zfs_tank_name, volume_name)
        try:
            log.info(f"Deleting zfs volume {volume_path}")
            subprocess.check_output(
                ["zfs", "destroy", "-Rfr", volume_path], stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError as exc:
            log.error(exc.stdout)
            raise Exception(f"Couldn't delete {volume_path}")


class Qcow2StorageBackend(StorageBackendBase):
    """Implements storage backend based on QEMU QCOW2 image format"""

    def __init__(self, install_info: InstallInfo) -> None:
        super().__init__(install_info)
        self.snapshot_dir = install_info.snapshot_dir
        self.check_tools()

    @staticmethod
    def check_tools() -> None:
        """Verify existence of qemu-img"""
        try:
            subprocess.run(
                ["qemu-img", "--version"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError(
                "Failed to determine qemu-img version. "
                "Make sure you have qemu-utils installed."
            )

    def initialize_vm0_volume(self, disk_size: str) -> None:
        try:
            subprocess.run(
                [
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    (self.snapshot_dir / "vm-0.img").as_posix(),
                    disk_size,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to create a new volume using qemu-img.")

    def snapshot_vm0_volume(self) -> None:
        # We'll be using vm-0.img as backing storage
        pass

    def get_vm_disk_path_by_name(self, volume_name: str) -> str:
        disk_path = (self.snapshot_dir / f"{volume_name}.img").as_posix()
        return f"tap:qcow2:{disk_path},xvda,w"

    def get_vm0_modify_disk_path(self) -> str:
        return self.get_vm_disk_path_by_name("vm-0-modify")

    def check_volume_exists(self, volume_name: str) -> bool:
        return (self.snapshot_dir / f"{volume_name}.img").exists()

    def rollback_vm_storage(self, vm_id: int) -> None:
        volume_path = self.snapshot_dir / f"vm-{vm_id}.img"
        vm0_path = self.snapshot_dir / "vm-0.img"
        self.delete_vm_volume(vm_id)

        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-o",
                f"backing_file={vm0_path.as_posix()}",
                volume_path.as_posix(),
            ],
            check=True,
        )

    def initialize_vm0_modify_storage(self) -> None:
        """Creates storage for vm-0 modification based on current vm-0 state"""
        volume_name = "vm-0-modify"
        volume_path = self.snapshot_dir / f"{volume_name}.img"
        vm0_path = self.snapshot_dir / "vm-0.img"

        if volume_path.exists():
            self.delete_vm_volume_by_name(volume_name)

        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-o",
                f"backing_file={vm0_path.as_posix()}",
                volume_path.as_posix(),
            ],
            check=True,
        )

    def delete_vm0_modify_storage(self) -> None:
        """Deletes pending vm-0 modification"""
        self.delete_vm_volume_by_name("vm-0-modify")

    def commit_vm0_modify_storage(self) -> None:
        """Apply vm-0 modification to the base vm-0 snapshot"""
        volume_name = "vm-0-modify"
        volume_path = self.snapshot_dir / f"{volume_name}.img"
        subprocess.run(
            [
                "qemu-img",
                "commit",
                "-d",
                volume_path.as_posix(),
            ],
            check=True,
        )
        self.delete_vm_volume_by_name(volume_name)

    def get_vm0_snapshot_time(self) -> int:
        volume_path = self.snapshot_dir / "vm-0.img"
        return int(volume_path.lstat().st_mtime)

    def export_vm0(self, path: str) -> None:
        volume_path = self.snapshot_dir / "vm-0.img"
        shutil.copy(volume_path, path)

    def import_vm0(self, path: str) -> None:
        volume_path = self.snapshot_dir / "vm-0.img"
        shutil.copy(path, volume_path)

    def delete_vm_volume_by_name(self, volume_name: str) -> None:
        # unmount can be done here
        (self.snapshot_dir / f"{volume_name}.img").unlink(missing_ok=True)


class LvmStorageBackend(StorageBackendBase):
    """Implements storage backend based on lvm storage"""

    def __init__(self, install_info: InstallInfo) -> None:
        super().__init__(install_info)
        self.lvm_volume_group = install_info.lvm_volume_group
        self.check_tools()
        self.snapshot_disksize = "1G"

    def check_tools(self) -> None:
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

    def initialize_vm0_volume(self, disk_size: str) -> None:
        """Create base volume for vm-0 with given size

        disk_size - string representing volume size with M/G/T suffix, eg. 100G
        """
        if self.check_volume_exists("vm-0"):
            try:
                log.info("Deleting existing logical volume and snapshot")
                subprocess.check_output(
                    [
                        "lvremove",
                        "-v",
                        "-y",
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

    def snapshot_vm0_volume(self) -> None:
        """Saves or snapshots base vm-0 volume for later use by other VMs"""
        # We'll be using vm-0 as backing storage. LVM can't make hierarchy of snapshots
        pass

    def get_vm_disk_path_by_name(self, volume_name: str) -> str:
        """Returns disk path for given VM as defined by XL configuration"""
        return f"phy:/dev/{self.lvm_volume_group}/{volume_name},hda,w"

    def get_vm0_modify_disk_path(self) -> str:
        return self.get_vm_disk_path_by_name("vm-0-modify")

    def check_volume_exists(self, volume_name: str) -> bool:
        volume_path = os.path.join("/dev", f"{self.lvm_volume_group}", volume_name)
        return os.path.exists(volume_path)

    def rollback_vm_storage(self, vm_id: int) -> None:
        """Rolls back changes and prepares fresh storage for new run of this VM"""
        if vm_id == 0:
            raise Exception("vm-0 should not be rollbacked")

        log.info(f"Rolling back changes to vm-{vm_id} disk")
        if self.check_volume_exists(f"vm-{vm_id}"):
            try:
                subprocess.check_output(
                    [
                        "lvremove",
                        "-v",
                        "-y",
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

    def initialize_vm0_modify_storage(self) -> None:
        """Creates storage for vm-0 modification based on current vm-0 state"""
        volume_name = "vm-0-modify"
        volume_path = os.path.join("/dev", f"{self.lvm_volume_group}", volume_name)

        if os.path.exists(volume_path):
            self.delete_vm_volume_by_name(volume_name)

        subprocess.check_output(
            [
                "lvcreate",
                "-s",
                "-L",
                self.snapshot_disksize,
                "-n",
                volume_name,
                f"{self.lvm_volume_group}/vm-0",
            ],
            stderr=subprocess.STDOUT,
        )

    def delete_vm0_modify_storage(self) -> None:
        """Deletes pending vm-0 modification"""
        self.delete_vm_volume_by_name("vm-0-modify")

    def commit_vm0_modify_storage(self) -> None:
        """Apply vm-0 modification to the base vm-0 snapshot"""
        volume_name = "vm-0-modify"
        subprocess.run(
            [
                "lvconvert",
                "--merge",
                f"{self.lvm_volume_group}/{volume_name}",
            ],
            check=True,
        )

    def get_vm0_snapshot_time(self) -> int:
        """Get UNIX timestamp of when vm-0 snapshot was last modified"""

        p = subprocess.run(
            ["lvs", "-o", "lv_name,lv_time", "--reportformat", "json"],
            capture_output=True,
            check=True,
        )

        lvs = json.loads(p.stdout.decode("utf-8"))["report"][0]["lv"]
        target_lvs = list(filter(lambda x: x["lv_name"] == "vm-0", lvs))

        if len(target_lvs) == 0:
            raise RuntimeError("Failed to find LV vm-0")

        dt = datetime.datetime.strptime(
            target_lvs[0]["lv_time"], "%Y-%m-%d %H:%M:%S %z"
        )
        return int(dt.timestamp())

    def export_vm0(self, path: str) -> None:
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

    def import_vm0(self, path: str) -> None:
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

    def delete_vm_volume_by_name(self, volume_name: str) -> None:
        try:
            subprocess.check_output(
                [
                    "lvremove",
                    "-v",
                    "-y",
                    # "--noudevsync",
                    f"{self.lvm_volume_group}/{volume_name}",
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


def get_storage_backend(install_info: InstallInfo) -> StorageBackendBase:
    """Return installed storage backend or throw InvalidStorageBackend"""
    if install_info.storage_backend not in REGISTERED_BACKEND_NAMES:
        raise InvalidStorageBackend

    return REGISTERED_BACKENDS[install_info.storage_backend](install_info)
