import pytest


@pytest.fixture(scope="session")
def pytest_installed(drakmon_ssh):
    """ Ensure that pytest is installed """
    drakmon_ssh.run(". /opt/venvs/drakrun/bin/activate && pip install pytest==6.2.2 pytest-steps==1.7.3")


@pytest.fixture(scope="session")
def drakrun_test_dir(pytest_installed, drakmon_ssh):
    """ Find location of tests """
    res = drakmon_ssh.run(
    """
    . /opt/venvs/drakrun/bin/activate &&  \
    python -c "import os; import drakrun.test.conftest; print(os.path.dirname(drakrun.test.conftest.__file__))"
    """)

    return res.stdout.strip()


def test_lvm(drakmon_ssh, drakrun_test_dir):
    drakmon_ssh.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_lvm.py")


def test_util(drakmon_ssh, drakrun_test_dir):
    drakmon_ssh.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_util.py")


def test_network(drakmon_ssh, drakrun_test_dir):
    drakmon_ssh.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_network.py")


def test_vm(drakmon_ssh, drakrun_test_dir):
    drakmon_ssh.run(f". /opt/venvs/drakrun/bin/activate && pytest {drakrun_test_dir}/test_vm.py")


def test_draksetup_test(drakmon_ssh):
    drakmon_ssh.run(f"draksetup test")
