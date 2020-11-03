"""
TODO: Add logging
"""
import contextlib
import os
import subprocess
import time
import shlex

from typing import Generator, Tuple
from drakrun.config import InstallInfo, VOLUME_DIR


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

    def initialize_vm0_volume(self, disk_size: str):
        """Create base volume for vm-0 with given size

        disk_size - string representing volume size with M/G/T suffix, eg. 100G
        """
        raise NotImplementedError

    def snapshot_vm0_volume(self):
        """ Saves or snapshots base vm-0 volume for later use by other VMs """
        raise NotImplementedError

    def get_vm_disk_path(self, vm_id: int) -> str:
        """ Returns disk path for given VM as defined by XL configuration """
        raise NotImplementedError

    def rollback_vm_storage(self, vm_id: int):
        """ Rolls back changes and prepares fresh storage for new run of this VM """
        raise NotImplementedError

    def get_vm0_snapshot_time(self):
        """ Get UNIX timestamp of when vm-0 snapshot was last modified """
        raise NotImplementedError

    def vm0_root_as_block(self) -> Generator[str, None, None]:
        """ Mounts vm-0 root partition as block device

        Mounts second partition (C:) on the volume as block device.
        This assumes that first partition is used for booting.
        """
        raise NotImplementedError


class ZfsStorageBackend(StorageBackendBase):
    """Implements storage backend based on ZFS zvols"""

    def __init__(self, install_info: InstallInfo):
        super().__init__(install_info)
        self.zfs_tank_name = install_info.zfs_tank_name
        if self.zfs_tank_name is None:
            raise RuntimeError("zfs_tank_name is missing from InstallInfo")
        self.check_tools()

    @staticmethod
    def check_tools():
        """ Verify existence of zfs command utility """
        try:
            subprocess.check_output("zfs -?", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to execute zfs command. "
                               "Make sure you have ZFS support installed.")

    def initialize_vm0_volume(self, disk_size: str):
        vm0_vol = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0"))
        try:
            subprocess.check_output(
                f"zfs destroy -Rfr {vm0_vol}", stderr=subprocess.STDOUT, shell=True
            )
        except subprocess.CalledProcessError as exc:
            if b"dataset does not exist" not in exc.output:
                raise RuntimeError(f"Failed to destroy the existing ZFS volume {vm0_vol}.")
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
                raise RuntimeError(f"Failed to see {vm_zvol} created after executing "
                                   "zfs clone command.")

            subprocess.run(["zfs", "snapshot", vm_snap], check=True)

        subprocess.run(["zfs", "rollback", vm_snap], check=True)

    def get_vm0_snapshot_time(self):
        base_snap = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0@booted"))
        out = subprocess.check_output(f"zfs get -H -p -o value creation {base_snap}", shell=True)
        ts = int(out.decode('ascii').strip())
        return ts

    @contextlib.contextmanager
    def vm0_root_as_block(self) -> Generator[str, None, None]:
        # workaround for not being able to mount a snapshot
        base_snap = shlex.quote(os.path.join(self.zfs_tank_name, "vm-0@booted"))
        tmp_snap = shlex.quote(os.path.join(self.zfs_tank_name, "tmp"))
        try:
            subprocess.check_output(f"zfs clone {base_snap} {tmp_snap}", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to clone temporary zfs snapshot")

        volume_path = os.path.join("/", "dev", "zvol", self.zfs_tank_name, "tmp-part2")
        # Wait for 60s for the volume to appear in /dev/zvol/...
        for _ in range(60):
            if os.path.exists(volume_path):
                break
            time.sleep(1.0)
        else:
            raise RuntimeError(f"ZFS volume not available at {volume_path}")

        yield volume_path

        subprocess.check_output(f"zfs destroy {tmp_snap}", shell=True)


class Qcow2StorageBackend(StorageBackendBase):
    """ Implements storage backend based on QEMU QCOW2 image format """

    def __init__(self, install_info: InstallInfo):
        super().__init__(install_info)
        self.check_tools()

    @staticmethod
    def check_tools():
        """ Verify existence of qemu-img """
        try:
            subprocess.check_output("qemu-img --version", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to determine qemu-img version. "
                               "Make sure you have qemu-utils installed.")

    def initialize_vm0_volume(self, disk_size: str):
        try:
            subprocess.check_output(
                " ".join(
                    [
                        "qemu-img",
                        "create",
                        "-f",
                        "qcow2",
                        os.path.join(VOLUME_DIR, "vm-0.img"),
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
        disk_path = os.path.join(VOLUME_DIR, f"vm-{vm_id}.img")
        return f"tap:qcow2:{disk_path},xvda,w"

    def rollback_vm_storage(self, vm_id: int):
        volume_path = os.path.join(VOLUME_DIR, f"vm-{vm_id}.img")
        vm0_path = os.path.join(VOLUME_DIR, "vm-0.img")
        try:
            os.unlink(volume_path)
        except FileNotFoundError:
            pass

        subprocess.run(
            [
                "qemu-img",
                "create",
                "-f",
                "qcow2",
                "-o",
                f"backing_file={vm0_path}",
                volume_path
            ],
            check=True,
        )

    def get_vm0_snapshot_time(self):
        return int(os.path.getmtime(os.path.join(VOLUME_DIR, 'vm-0.img')))

    @contextlib.contextmanager
    def vm0_root_as_block(self) -> Generator[str, None, None]:
        try:
            subprocess.check_output("modprobe nbd", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to load nbd kernel module")

        try:
            # TODO: this assumes /dev/nbd0 is free
            volume = os.path.join(VOLUME_DIR, 'vm-0.img')
            subprocess.check_output(
                f"qemu-nbd -c /dev/nbd0 --read-only {volume}",
                shell=True,
            )
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to connect QCOW2 file to /dev/nbd0")

        # we mount 2nd partition, as 1st partition is windows boot related and 2nd partition is C:\\
        dev = "/dev/nbd0p2"

        # wait for the device to appear
        for _ in range(60):
            if os.path.exists(dev):
                break
            time.sleep(1.0)
        else:
            raise RuntimeError(f"NBD volume not available at {dev}")

        yield dev

        subprocess.check_output("qemu-nbd --disconnect /dev/nbd0", shell=True)


REGISTERED_BACKENDS = {
    "qcow2": Qcow2StorageBackend,
    "zfs": ZfsStorageBackend,
}

REGISTERED_BACKEND_NAMES: Tuple[str] = tuple(REGISTERED_BACKENDS.keys())


class InvalidStorageBackend(Exception):
    """ Thrown when tried to create unsupported storage backend """


def get_storage_backend(install_info: InstallInfo) -> StorageBackendBase:
    """ Return installed storage backend or throw InvalidStorageBackend """
    if install_info.storage_backend not in REGISTERED_BACKEND_NAMES:
        raise InvalidStorageBackend

    return REGISTERED_BACKENDS[install_info.storage_backend](install_info)
