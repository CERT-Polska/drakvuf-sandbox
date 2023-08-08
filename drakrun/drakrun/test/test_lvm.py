import logging
import secrets
import string
import subprocess
import tempfile

import pytest
from _pytest.monkeypatch import MonkeyPatch

from drakrun.config import InstallInfo
from drakrun.machinery.storage import LvmStorageBackend
from drakrun.util import safe_delete

from .common_utils import tool_exists


@pytest.fixture(scope="session")
def monkeysession(request):
    mp = MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def setup(monkeysession):
    if not tool_exists("lvs"):
        pytest.skip("LVM is not found")

    temp_file_name = tempfile.NamedTemporaryFile(delete=False).name
    subprocess.run(
        ["dd", "if=/dev/zero", f"of={temp_file_name}", "bs=1M", "count=100"],
        stderr=subprocess.STDOUT,
        check=True,
    )
    loopback_file = (
        subprocess.check_output(
            ["losetup", "-f", "--show", temp_file_name], stderr=subprocess.STDOUT
        )
        .decode()
        .strip("\n")
    )

    # v is being added in start to ensure the lvm volume group starts with a letter
    # don't know if it is required or not
    volume_group = "v" + "".join(
        secrets.choice(string.ascii_letters + string.digits) for i in range(5)
    )

    # pvcreate is automatically used by this internally
    subprocess.check_output(
        ["vgcreate", volume_group, loopback_file], stderr=subprocess.STDOUT
    )

    def install_patch():
        return InstallInfo(
            vcpus=1,
            memory=512,
            storage_backend="lvm",
            disk_size="25M",
            iso_path=None,  # not being required
            zfs_tank_name=None,
            lvm_volume_group=volume_group,
            enable_unattended=None,
            iso_sha256=None,
        )

    monkeysession.setattr(InstallInfo, "load", install_patch)
    monkeysession.setattr(InstallInfo, "try_load", install_patch)

    yield

    subprocess.run(["vgchange", "-an", volume_group], stderr=subprocess.STDOUT)
    subprocess.run(["vgremove", "-y", volume_group], stderr=subprocess.STDOUT)
    subprocess.run(["losetup", "-d", loopback_file], stderr=subprocess.STDOUT)
    safe_delete(temp_file_name)


@pytest.fixture(scope="module")
def backend(setup):
    yield LvmStorageBackend(InstallInfo.load())


@pytest.fixture
def mount_vm0():
    # a mount fixture to unmount incase any error occurs
    install_info = InstallInfo.load()
    device = (
        subprocess.check_output(
            [
                "losetup",
                "-f",
                "--partscan",
                "--show",
                f"/dev/{install_info.lvm_volume_group}/vm-0",
            ]
        )
        .decode("ascii")
        .strip("\n")
        .strip()
    )

    yield device

    subprocess.run(f"losetup -d {device}", shell=True)


@pytest.mark.incremental
class TestLVM:
    def test_initialize_vm0(self, backend):
        install_info = InstallInfo.load()

        logging.info("Creating volume")
        backend.initialize_vm0_volume(install_info.disk_size)
        assert (
            subprocess.run(["lvs", f"{install_info.lvm_volume_group}/vm-0"]).returncode
            == 0
        )

    def test_disk_path(self, backend):
        """
        A very straight forward test but, if a path will change it future,
        this test will fail telling about changed paths
        """
        install_info = InstallInfo.load()
        for vm_id in range(5):
            assert (
                backend.get_vm_disk_path(vm_id)
                == f"phy:/dev/{install_info.lvm_volume_group}/vm-{vm_id},hda,w"
            )

    def test_snapshot_lvm(self, backend):
        install_info = InstallInfo.load()

        with pytest.raises(Exception):
            backend.get_vm0_snapshot_time()

        logging.info("Snapshot volume")
        backend.snapshot_vm0_volume()
        assert (
            subprocess.run(
                ["lvs", f"{install_info.lvm_volume_group}/vm-0-snap"]
            ).returncode
            == 0
        )

    def test_time(self, backend):
        # Should not raise any exceptions
        logging.info("Get snapshot time")
        assert type(backend.get_vm0_snapshot_time()) == int

    def test_vm0_rollback(self, backend):
        logging.info("Rolling back vm0")
        with pytest.raises(Exception):
            backend.rollback_vm_storage(0)

    def test_rollback_vm1_pass1(self, backend):
        install_info = InstallInfo.load()

        logging.info("Pass 1: rollback vm-1")
        backend.rollback_vm_storage(1)
        assert (
            subprocess.run(["lvs", f"{install_info.lvm_volume_group}/vm-1"]).returncode
            == 0
        )

    def test_rollback_vm1_pass2(self, backend):
        install_info = InstallInfo.load()

        logging.info("Pass 2: rollback vm-1")
        # rolling back next time should not raise issues
        backend.rollback_vm_storage(1)
        assert (
            subprocess.run(["lvs", f"{install_info.lvm_volume_group}/vm-1"]).returncode
            == 0
        )

    def test_import_export(self, backend):
        """
        Any solid testing assertions for export and import?
        """
        # skipping this test causes xfail on the next tests
        # filename = '/tmp/this_file_name_should_not_exists.img'
        # backend.export_vm0(filename)
        #
        # backend.import_vm0(filename)

    # the vm0 drive is mounted
    def test_exception_raises(self, backend, mount_vm0):
        install_info = InstallInfo.load()
        with pytest.raises(Exception):
            backend.initialize_vm0_volume(install_info.disk_size)

        with pytest.raises(Exception):
            backend.delete_vm_volume(0)

    def test_delete_volume(self, backend):
        logging.info("Testing deleting volumes")
        install_info = InstallInfo.load()

        backend.delete_vm_volume(1)
        assert (
            subprocess.run(["lvs", f"{install_info.lvm_volume_group}/vm-1"]).returncode
            != 0
        )

        # try deleting a deleted volume
        with pytest.raises(Exception):
            backend.delete_vm_volume(1)

        backend.delete_vm_volume(0)
        assert (
            subprocess.run(["lvs", f"{install_info.lvm_volume_group}/vm-0"]).returncode
            != 0
        )
