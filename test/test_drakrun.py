import pytest

@pytest.fixture(scope="session")
def pytest_installed(drakmon_vm):
    """ Ensure that pytest is installed """
    drakmon_vm.run(". /opt/venvs/drakrun/bin/activate && pip install pytest==6.2.2 pytest-steps==1.7.3")

@pytest.fixture(scope="session")
def drakrun_test_dir(pytest_installed, drakmon_vm):
    """ Find location of tests """
    res = drakmon_vm.run(
    """
    . /opt/venvs/drakrun/bin/activate &&  \
    python -c "import os; import drakrun.test.conftest; print(os.path.dirname(drakrun.test.conftest.__file__))"
    """)

    return res.stdout.strip()

def test_lvm(drakmon_vm, drakrun_test_dir):
    drakmon_vm.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_lvm.py")

def test_util(drakmon_vm, drakrun_test_dir):
    drakmon_vm.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_util.py")

def test_network(drakmon_vm, drakrun_test_dir):
    drakmon_vm.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_network.py")

def test_vm(drakmon_vm, drakrun_test_dir):
    drakmon_vm.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_vm.py")
