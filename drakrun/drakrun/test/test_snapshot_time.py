import pytest

from drakrun.config import InstallInfo
from drakrun.storage import LvmStorageBackend


@pytest.fixture
def backend():
    install_info = InstallInfo.try_load()
    if install_info is None:
        pytest.skip("no install info")
    if install_info.storage_backend != 'lvm':
        pytest.skip("lvm backend not found")
    return LvmStorageBackend(install_info)


def test_vm0_snapshot_time(backend):
    backend.get_vm0_snapshot_time()
