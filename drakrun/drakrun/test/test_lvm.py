import pytest

from drakrun.config import InstallInfo
from drakrun.storage import LvmStorageBackend
import subprocess
import os
import logging
import parted

# best way would be to use a new lvm volume group for testing
def backup(install_info):
    # removing old backups, might be risky if the restore hasn't worked due to some issue
    subprocess.run(['lvremove', '-y', f'{install_info.lvm_volume_group}/vm-0-bak'])
    subprocess.run(['lvremove', '-y', f'{install_info.lvm_volume_group}/vm-0-snap-bak'])

    # changing to backup
    subprocess.run(['lvrename', f'{install_info.lvm_volume_group}', 'vm-0', 'vm-0-bak'])
    subprocess.run(['lvrename', f'{install_info.lvm_volume_group}', 'vm-0-snap', 'vm-0-snap-bak'])


def restore(install_info):
    subprocess.run(['lvremove', '-y', f'{install_info.lvm_volume_group}/vm-0'])

    # just to be safe as if it is not deleted, the restore will fail
    # it should automatically be deleted in the vm-0 deletion only
    subprocess.run(['lvremove', '-y', f'{install_info.lvm_volume_group}/vm-0-snap'])

    subprocess.run(['lvrename', f'{install_info.lvm_volume_group}', 'vm-0-bak', 'vm-0'])
    subprocess.run(['lvrename', f'{install_info.lvm_volume_group}', 'vm-0-snap-bak', 'vm-0-snap'])


@pytest.fixture(autouse=True)
def enable_logging():
    logging.basicConfig(
        level=logging.DEBUG,
        format='[%(asctime)s][%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler()]
    )


@pytest.fixture(scope="module")
def backend():
    install_info = InstallInfo.try_load()
    if install_info is None:
        pytest.skip("no install info")
    if install_info.storage_backend != 'lvm':
        pytest.skip("lvm backend not found")

    backup(install_info)

    yield LvmStorageBackend(install_info)

    restore(install_info)


def test_initialize_vm0(backend):
    install_info = InstallInfo.load()

    logging.info("Creating volume")
    backend.initialize_vm0_volume(install_info.disk_size)
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-0"]).returncode == 0


def test_snapshot_lvm(backend):
    install_info = InstallInfo.load()

    logging.info("Snapshot volume")
    backend.snapshot_vm0_volume()
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-0-snap"]).returncode == 0


def test_time(backend):
    # Should not raise any exceptions
    logging.info("Get snapshot time")
    backend.get_vm0_snapshot_time()


def test_vm0_rollback(backend):
    logging.info("Rolling back vm0")
    with pytest.raises(Exception):
        backend.rollback_vm_storage(0)


def test_rollback_vm1_pass1(backend):
    install_info = InstallInfo.load()

    logging.info("Pass 1: rollback vm-1")
    backend.rollback_vm_storage(1)
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-1"]).returncode == 0


def test_rollback_vm1_pass2(backend):
    install_info = InstallInfo.load()

    logging.info("Pass 2: rollback vm-1")
    # rolling back next time should not raise issues
    backend.rollback_vm_storage(1)
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-1"]).returncode == 0


# a mount fixture to unmount incase any error occurs
@pytest.fixture
def mount_vm0():
    install_info = InstallInfo.load()
    device = subprocess.check_output(
        [
            "losetup",
            "-f", "--partscan",
            "--show",
            f"/dev/{install_info.lvm_volume_group}/vm-0",
        ]
    ).decode('ascii').strip('\n').strip()

    yield device

    subprocess.run(f'losetup -d {device}', shell=True)


@pytest.fixture
def create_partitions(mount_vm0):

    logging.info("Creating partitions")
    # creating partitions in new disk to test mount
    vm0 = parted.getDevice(mount_vm0)
    vm0.clobber()
    disk = parted.freshDisk(vm0, 'msdos')

    # boot partition
    geometry1 = parted.Geometry(start=0,
                                length=parted.sizeToSectors(512, 'MiB', vm0.sectorSize),
                                device=vm0)
    filesystem1 = parted.FileSystem(type='fat32', geometry=geometry1)
    partition1 = parted.Partition(disk=disk,
                                  type=parted.PARTITION_NORMAL,
                                  fs=filesystem1,
                                  geometry=geometry1)
    partition1.setFlag(parted.PARTITION_BOOT)
    disk.addPartition(partition1, constraint=vm0.optimalAlignedConstraint)

    # C partition
    geometry2 = parted.Geometry(start=partition1.geometry.end,
                                length=vm0.getLength() - 1,
                                device=vm0)
    filesystem2 = parted.FileSystem(type='ntfs', geometry=geometry2)
    partition2 = parted.Partition(disk=disk,
                                  type=parted.PARTITION_NORMAL,
                                  fs=filesystem2,
                                  geometry=geometry2)
    disk.addPartition(partition2, constraint=vm0.optimalAlignedConstraint)

    # write to disk
    disk.commit()


def test_mount(backend, create_partitions):
    del create_partitions
    logging.info("Testing mounting 2nd partition")
    block_device_path = ''
    with backend.vm0_root_as_block() as block_device:
        block_device_path = block_device

        # /dev/loopX should be mounted
        assert subprocess.run(f"losetup {block_device_path[:-2]}", shell=True).returncode == 0

        # /dev/loopXp2 should be visible
        assert os.path.exists(block_device) is True

    # /dev/loopX should not exist after this block
    assert subprocess.run(f"losetup {block_device_path[:-2]}", shell=True).returncode != 0


def test_import_export(backend):
    pytest.skip('not implemented')
    """
    Any solid testing assertions for export and import?
    """
    # filename = '/tmp/this_file_name_should_not_exists.img'
    # backend.export_vm0(filename)
    #
    # backend.import_vm0(filename)

def test_delete_volume(backend):
    logging.info("Testing deleting volumes")
    install_info = InstallInfo.load()

    backend.delete_vm_volume(1)
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-1"]).returncode != 0

    backend.delete_vm_volume(0)
    assert subprocess.run(['lvs', f"{install_info.lvm_volume_group}/vm-0"]).returncode != 0
