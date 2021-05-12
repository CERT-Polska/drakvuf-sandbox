import pytest

from drakrun.config import InstallInfo, VM_CONFIG_DIR, VOLUME_DIR
from drakrun.vm import (
    VirtualMachine,
    generate_vm_conf,
    get_all_vm_conf,
    delete_vm_conf
)
from drakrun.util import safe_delete
from _pytest.monkeypatch import MonkeyPatch
from drakrun.storage import get_storage_backend
from drakrun.draksetup import find_default_interface
from drakrun.networking import setup_vm_network, delete_vm_network
from common_utils import remove_files, tool_exists
import tempfile
import secrets
import string
import drakrun
import subprocess
import os
import re
import shutil
import logging

logging = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def monkeysession(request):
    mp = MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture(scope="module")
def patch(monkeysession):
    if not tool_exists('xl'):
        pytest.skip("xen is not found")

    def install_patch():
        return InstallInfo(
            vcpus=1,
            memory=512,
            storage_backend='qcow2',
            disk_size='200M',
            iso_path=None,  # not being required
            zfs_tank_name=None,
            lvm_volume_group=None,
            enable_unattended=None,
            iso_sha256=None
        )
    monkeysession.setattr(InstallInfo, "load", install_patch)
    monkeysession.setattr(InstallInfo, "try_load", install_patch)

    # being yielded so the the monkeypatch doesn't start cleanup if returned
    yield monkeysession


@pytest.fixture(scope="module")
def test_vm(patch):
    monkeysession = patch

    @property
    def vm_name(self):
        return "test-hvm64-example"
    monkeysession.setattr(VirtualMachine, "vm_name", vm_name)
    test_vm = VirtualMachine(None, 0, "test-hvm64-example")

    yield test_vm


@pytest.fixture(scope="module")
def config():
    tmpf = tempfile.NamedTemporaryFile(delete=False).name
    module_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..')
    cfg_path = os.path.join(module_dir, "tools", "test-hvm64-example.cfg")
    firmware_path = os.path.join(module_dir, "tools", "test-hvm64-example")

    with open(cfg_path, 'r') as f:
        test_cfg = f.read().replace('{{ FIRMWARE_PATH }}', firmware_path).encode('utf-8')

    with open(tmpf, 'wb') as f:
        f.write(test_cfg)

    yield tmpf
    safe_delete(tmpf)


@pytest.fixture(scope="module")
def snapshot_file():
    tmpf = tempfile.NamedTemporaryFile(delete=False).name
    yield tmpf
    safe_delete(tmpf)


def get_vm_state(vm_name: str) -> str:
    out_lines = subprocess.check_output("xl list", shell=True).decode().split('\n')
    # get the line with vm_name
    out = next((line for line in out_lines if vm_name in line), None)
    if out is None:
        raise Exception(f"{vm_name} not found in xl list")
    else:
        state = re.sub(r' +', ' ', out).split(' ')[4].strip().strip('-')
        return state


def destroy_vm(vm_name: str) -> str:
    if subprocess.run(f"xl list {vm_name}", shell=True).returncode == 0:
        subprocess.run(f"xl destroy {vm_name}", shell=True)


@pytest.mark.incremental
class TestVM:
    def test_vm_name(self, patch):
        vm = VirtualMachine(None, 0)
        assert vm.vm_name == 'vm-0'
        vm = VirtualMachine(None, 0, "test-vm-{}")
        assert vm.vm_name == 'test-vm-0'

    def test_vm_create_and_is_running(self, config, test_vm):

        # initial cleanup
        destroy_vm(test_vm.vm_name)
        assert test_vm.is_running is False

        test_vm.create(config, pause=False)
        assert get_vm_state(test_vm.vm_name) != 'p'
        assert test_vm.is_running is True

        # second run
        destroy_vm(test_vm.vm_name)

        test_vm.create(config, pause=True)
        assert get_vm_state(test_vm.vm_name) == 'p'

        # trying with non existing files
        with pytest.raises(Exception):
            test_vm.create('/tmp/unexitant-file')

        # trying with empty file (no specific to config formats)
        with tempfile.NamedTemporaryFile() as tempf:
            with pytest.raises(Exception):
                test_vm.create(tempf)

        # check if vm is shutdown
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

    def test_vm_unpause(self, config, test_vm):
        assert get_vm_state(test_vm.vm_name) == 'p'

        test_vm.unpause()
        assert get_vm_state(test_vm.vm_name) != 'p'

        # it is a short lived VM so we will create a new one whenever we unpause
        destroy_vm(test_vm.vm_name)

    def test_vm_save(self, config, test_vm, snapshot_file):
        test_vm.create(config, pause=False)
        test_vm.save(snapshot_file, cont=True)
        assert get_vm_state(test_vm.vm_name) != 'p'

        # reset
        destroy_vm(test_vm.vm_name)
        test_vm.create(config, pause=False)

        test_vm.save(snapshot_file, pause=True)
        assert get_vm_state(test_vm.vm_name) == 'p'

        # should destroy the vm
        test_vm.save(snapshot_file)
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

    def test_vm_pause(self, config, test_vm):
        # initialize the VM after previous destruction
        test_vm.create(config)

        assert get_vm_state(test_vm.vm_name) != 'p'

        test_vm.pause()
        assert get_vm_state(test_vm.vm_name) == 'p'

        destroy_vm(test_vm.vm_name)

    def test_vm_restore(self, snapshot_file, config, test_vm):
        # if snapshot doesn't exist
        with remove_files(snapshot_file):
            with pytest.raises(Exception):
                test_vm.restore(cfg_path=config, snapshot_path=snapshot_file)
                assert test_vm.is_running is False

        # if configuration file doesn't exist
        with remove_files(config):
            with pytest.raises(Exception):
                test_vm.restore(cfg_path=config, snapshot_path=snapshot_file)
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
        test_vm.restore(cfg_path=config, snapshot_path=snapshot_file)
        assert get_vm_state(test_vm.vm_name) != 'p'

        destroy_vm(test_vm.vm_name)

        test_vm.restore(cfg_path=config, snapshot_path=snapshot_file, pause=True)
        assert get_vm_state(test_vm.vm_name) == 'p'

        # restoring a restored VM
        # what should be the expected behavior?
        # test_vm.restore(cfg_path= config, snapshot_path = snapshot_file)

    def test_vm_destroy(self, config, test_vm):
        # VM should be running from the previous test
        test_vm.create(config, pause=True)

        test_vm.destroy()
        with pytest.raises(Exception):
            get_vm_state(test_vm.name)

        # should 2nd time destory raise/log exceptions and then handle it?
        # test_vm.destroy()
        # assert test_vm.is_running is False
