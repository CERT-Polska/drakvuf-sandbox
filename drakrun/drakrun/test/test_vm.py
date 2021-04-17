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
import shutil
import logging


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

    # being used so the the monkeypatch doesn't start cleanup if returned
    yield monkeysession


@pytest.fixture(scope="module")
def changevmname(patch):
    monkeysession = patch

    @property
    def vm_name(self):
        return f"test-vm-{self.vm_id}"
    monkeysession.setattr(VirtualMachine, "vm_name", vm_name)
    yield monkeysession


@pytest.mark.incremental
class TestVM:
    def test_vm_name(self, patch):
        backend = get_storage_backend(InstallInfo.load())
        vm = VirtualMachine(backend, 0)
        assert vm.vm_name == 'vm-0'

    def test_monkeypatch_vm_name(self, changevmname):
        backend = get_storage_backend(InstallInfo.load())
        vm = VirtualMachine(backend, 0)
        assert vm.vm_name == 'test-vm-0'

    def test_backend(self, changevmname):
        # monkeypatching the backend location is required
        pytest.skip("incomplete")
        backend = get_storage_backend(InstallInfo.load())
        assert backend.exists_vm(0) is False
        backend.initialize_vm0_volume()
        assert backend.exists_vm(0) is True

    def test_vm_create(self, changevmname):
        # which dummy vm to create, we have the configs for hvm64
        # we can try with that or create a new one
        pass
        
    def test_vm_save(self):
        pass

    def test_vm_pause(self):
        # either we can parse the xl list test-vm-0 command
        # to check for VM state ( OR )
        # either just check if this command throws any exceptions
        pass

    def test_vm_unpause(self):
        pass

    def test_vm_restore(self, changevmname):
        backend = get_storage_backend(InstallInfo.load())
        vm = VirtualMachine(backend,0)

        # I think this part should be abstracted and automatically handled when creating or destroying VMs
        setup_vm_network(0, True, find_default_interface(), '8.8.8.8')

        # if snapshot doesn't exist
        with remove_files([os.path.join(VOLUME_DIR, 'snapshot.sav')]):
            with pytest.raises(Exception):
                self.vm.restore()
                assert self.vm.is_running is False

        # if configuration file doesn't exist
        with remove_files([os.path.join(VM_CONFIG_DIR, 'vm-0.cfg')]):
            with pytest.raises(Exception):
                self.vm.restore()
                assert self.vm.is_running is False

        # monkeypatch will be required to hide the storage backend
        if backend.exists_vm(0) is False:
            with pytest.raises(Exception):
                self.vm.restore()
                assert self.vm.is_running is False

        # should not raise any exceptions if everything is fine
        self.vm.restore()
        assert self.vm.is_running is True

        # restoring a restored VM
        # what should be the expected behavior?
        # self.vm.restore()

        delete_vm_network(0, True, find_default_interface(), '8.8.8.8')

    def test_vm_destroy(self, backend):
        self.vm = VirtualMachine(backend, 0)

        # VM should be running from the previous test

        self.vm.destroy()
        assert self.vm.is_running is False

        # should 2nd time destory raise/log exceptions and then handle it?
        # vm.destroy()
        # assert vm.is_running is False
