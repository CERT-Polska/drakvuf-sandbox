import pytest

from drakrun.config import InstallInfo, VM_CONFIG_DIR, VOLUME_DIR
from drakrun.vm import (
    VirtualMachine,
    generate_vm_conf,
    get_all_vm_conf,
    delete_vm_conf
)
from drakrun.storage import get_storage_backend
from common_utils import remove_files
import drakrun
import subprocess
import os
import shutil
import logging


def backup(install_info):
    pass


def restore(install_info):
    pass


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
    backend = get_storage_backend(install_info)

    backup(install_info)

    yield backend

    restore(install_info)


@pytest.mark.incremental
class TestVM:
    def test_vm_name(self, backend):
        self.vm = VirtualMachine(backend, 0)
        assert self.vm.vm_name == 'vm-0'

    def test_backend(self, backend):
        # else restore tests will fail
        assert backend.exists_vm(0) is True

    def test_vm_restore(self, backend):
        self.vm = VirtualMachine(backend, 0)

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

    def test_vm_destroy(self):
        self.vm = VirtualMachine(backend, 0)

        # VM should be running from the previous test

        self.vm.destroy()
        assert self.vm.is_running is False

        # should 2nd time destory raise/log exceptions and then handle it?
        # vm.destroy()
        # assert vm.is_running is False
