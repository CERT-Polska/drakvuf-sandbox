import logging
import os
import re
import subprocess
import tempfile

import pytest
from _pytest.monkeypatch import MonkeyPatch
from common_utils import remove_files, tool_exists

from drakrun.config import InstallInfo
from drakrun.util import safe_delete
from drakrun.machinery.vm import VirtualMachine


@pytest.fixture(scope="session")
def monkeysession(request):
    mp = MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def patch(monkeysession):
    if not tool_exists("xl"):
        pytest.skip("xen is not found")

    def install_patch():
        return InstallInfo(
            vcpus=1,
            memory=512,
            storage_backend="qcow2",
            disk_size="200M",
            iso_path=None,  # not being required
            zfs_tank_name=None,
            lvm_volume_group=None,
            enable_unattended=None,
            iso_sha256=None,
        )

    monkeysession.setattr(InstallInfo, "load", install_patch)
    monkeysession.setattr(InstallInfo, "try_load", install_patch)

    # being yielded so the the monkeypatch doesn't start cleanup if returned
    yield monkeysession


@pytest.fixture(scope="module")
def test_vm(patch, config):
    test_vm = VirtualMachine(None, 0, "test-hvm64-example", config)

    yield test_vm


@pytest.fixture(scope="module")
def config():
    tmpf = tempfile.NamedTemporaryFile(delete=False).name
    module_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
    cfg_path = os.path.join(module_dir, "tools", "test-hvm64-example.cfg")
    firmware_path = os.path.join(module_dir, "tools", "test-hvm64-example")

    with open(cfg_path, "r") as f:
        test_cfg = (
            f.read().replace("{{ FIRMWARE_PATH }}", firmware_path).encode("utf-8")
        )

    with open(tmpf, "wb") as f:
        f.write(test_cfg)

    yield tmpf
    safe_delete(tmpf)


@pytest.fixture(scope="module")
def snapshot_file():
    tmpf = tempfile.NamedTemporaryFile(delete=False).name
    yield tmpf
    safe_delete(tmpf)


def get_vm_state(vm_name: str) -> str:
    out_lines = subprocess.check_output("xl list", shell=True).decode().split("\n")
    # get the line with vm_name
    out = next((line for line in out_lines if vm_name in line), None)
    if out is None:
        raise Exception(f"{vm_name} not found in xl list")
    else:
        state = re.sub(r" +", " ", out).split(" ")[4].strip().strip("-")
        return state


def destroy_vm(vm_name: str) -> str:
    if (
        subprocess.run(
            f"xl list {vm_name}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    ):
        subprocess.run(
            f"xl destroy {vm_name}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logging.info(f"Destroying {vm_name}")


@pytest.mark.incremental
class TestVM:
    def test_vm_name(self, patch):
        logging.info("testing VM names")
        vm = VirtualMachine(None, 0)
        assert vm.vm_name == "vm-0"
        logging.info("testing VM names with new fmt")
        vm = VirtualMachine(None, 0, "test-vm-{}")
        assert vm.vm_name == "test-vm-0"

    def test_vm_create_and_is_running(self, config, test_vm):

        # initial cleanup
        destroy_vm(test_vm.vm_name)
        assert test_vm.is_running is False

        logging.info("testing vm create with pause=False")
        test_vm.create(pause=False)
        assert get_vm_state(test_vm.vm_name) != "p"
        assert test_vm.is_running is True

        logging.info("testing vm create for a created VM")
        with pytest.raises(Exception):
            test_vm.create(pause=True)

        # second run
        destroy_vm(test_vm.vm_name)

        logging.info("testing vm create with pause=True")
        test_vm.create(pause=True)
        assert get_vm_state(test_vm.vm_name) == "p"

        # destroy the vm
        destroy_vm(test_vm.vm_name)

        logging.info("testing vm create with non-existant file")
        with pytest.raises(Exception):
            new_vm = VirtualMachine(
                None, 0, "test-hvm64-example", "/tmp/unexitant-file"
            )
            new_vm.create()

        logging.info("testing vm create with empty file")
        with tempfile.NamedTemporaryFile() as tempf:
            with pytest.raises(Exception):
                new_vm = VirtualMachine(None, 0, "test-hvm64-example", tempf.name)
                new_vm.create()

        # check if vm is shutdown
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

    def test_vm_unpause(self, test_vm):
        test_vm.create(pause=True)
        assert get_vm_state(test_vm.vm_name) == "p"

        logging.info("testing vm unpause")
        test_vm.unpause()
        assert get_vm_state(test_vm.vm_name) != "p"

        # it shows stderr but rc is 0

        # logging.info("testing vm unpause on an unpaused VM")
        # with pytest.raises(Exception):
        #     test_vm.unpause()

        # it is a short lived VM so we will create a new one whenever we unpause
        destroy_vm(test_vm.vm_name)

    def test_vm_save(self, test_vm, snapshot_file):
        # test-hvm64-example VM can't be snapshotted in unpaused state
        """
        root@debian:/home/user/drakvuf-sandbox/drakrun/drakrun/test# xl create /tmp/tmpjyoganif && xl save -c test-hvm64-example /tmp/test.sav
        Parsing config from /tmp/tmpjyoganif
        libxl: error: libxl_qmp.c:1334:qmp_ev_lock_aquired: Domain 122:Failed to connect to QMP socket /var/run/xen/qmp-libxl-122: No such file or directory
        unable to retrieve domain configuration
        """

        # test_vm.create(pause=True)
        # test_vm.unpause()
        # test_vm.save(snapshot_file, cont=True)
        # assert get_vm_state(test_vm.vm_name) != 'p'

        # reset

        # destroy_vm(test_vm.vm_name)
        test_vm.create(pause=True)
        assert get_vm_state(test_vm.vm_name) == "p"

        logging.info("test vm save with pause=True")
        test_vm.save(snapshot_file, pause=True)
        assert get_vm_state(test_vm.vm_name) == "p"

        # should destroy the vm
        logging.info("test vm save with with no pause/cont args")
        test_vm.save(snapshot_file)
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

    def test_vm_pause(self, test_vm):
        # initialize the VM after previous destruction
        test_vm.create()

        assert get_vm_state(test_vm.vm_name) != "p"

        # test-hvm64-example goes to shutdown immediately, we get `--ps--` state during assertion

        # logging.info("testing pause on VM")
        # test_vm.pause()
        # assert get_vm_state(test_vm.vm_name) == 'p'

        # manual test shows, xl pause on a paused VM doesn't give any errors but pauses the VM again
        # requiring the VM be unpaused twice for reaching running state

        # logging.info("testing pause on a paused vm VM")
        # with pytest.raises(Exception):
        #     test_vm.pause()

        destroy_vm(test_vm.vm_name)

    def test_vm_restore(self, config, snapshot_file, test_vm):
        # if snapshot doesn't exist
        logging.info("test vm restore without snapshot file")
        with remove_files([snapshot_file]):
            with pytest.raises(Exception):
                test_vm.restore(snapshot_path=snapshot_file)
                assert test_vm.is_running is False

        # if configuration file doesn't exist
        logging.info("test vm restore without config")
        with remove_files([config]):
            with pytest.raises(Exception):
                test_vm.restore(snapshot_path=snapshot_file)
                assert test_vm.is_running is False

        # although test-hvm64-example doesn't depend on storage backend
        # some test like this would have been good where storage backend doesn't exist
        # and it is trying to restore from vm-1 or vm-0
        # vm-0 should fail but vm-1 should succeed
        # if backend.exists_vm(0) is False:
        #     with pytest.raises(Exception):
        #         test_vm.restore()
        #         assert test_vm.is_running is False

        # should not raise any exceptions if everything is fine
        logging.info("test vm with proper args")
        test_vm.restore(snapshot_path=snapshot_file)
        assert get_vm_state(test_vm.vm_name) != "p"

        destroy_vm(test_vm.vm_name)

        logging.info("test vm with proper args and pause=True")
        test_vm.restore(snapshot_path=snapshot_file, pause=True)
        assert get_vm_state(test_vm.vm_name) == "p"

        logging.info("restoring a restored VM")
        test_vm.restore(snapshot_path=snapshot_file)
        # should get the new state
        assert get_vm_state(test_vm.vm_name) != "p"

        destroy_vm(test_vm.vm_name)

    def test_vm_destroy(self, test_vm):
        test_vm.create(pause=True)

        logging.info("test vm destroy")
        test_vm.destroy()
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

        # should not raise any exception
        logging.info("test vm destroy on a destroyed VM")
        test_vm.destroy()
        assert test_vm.is_running is False
