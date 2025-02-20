import time
import json
import pytest

from utils import get_hypervisor_type, get_service_info, Drakcore
from conftest import DRAKMON_SERVICES


@pytest.fixture
def drakcore(drakmon_vm):
    return Drakcore(drakmon_vm)


def test_running_on_xen(drakmon_ssh):
    assert get_hypervisor_type(drakmon_ssh) == "xen"


def test_services_running(drakmon_ssh):
    def check_status():
        infos = [get_service_info(drakmon_ssh, service) for service in DRAKMON_SERVICES]

        for info in infos:
            assert info["LoadState"] == "loaded"
            assert info["ActiveState"] == "active"
            assert info["SubState"] == "running"

    # Wait up to 5 seconds for the services to be up
    for _ in range(5):
        try:
            check_status()
            break
        except AssertionError:
            pass
        time.sleep(1.0)
    else:
        raise Exception("Services down")


def test_web_ui_reachable(drakcore):
    response = drakcore.get("/")
    response.raise_for_status()


def test_sample_analysis(drakcore):
    task_uuid = drakcore.upload(open("test.exe", "rb"), timeout=120)

    # wait until end of analysis
    while True:
        r = drakcore.check_status(task_uuid)
        if r["status"] != "pending":
            break
        time.sleep(10.0)

    # give it a bit more time?
    time.sleep(10.0)

    # check logs if our binary was ran
    response = drakcore.analysis_log(task_uuid, "filetracer")
    for line in response.iter_lines():
        d = json.loads(line)
        # our sample tried to create a file
        if d.get("Method") == "NtCreateFile" and "test.txt" in d.get("FileName"):
            break
    else:
        raise Exception("No matching entry found")

def test_drak_tester_analysis(drakcore):
    task_uuid = drakcore.upload(open("bin/drakvuf_tester.exe", "rb"), timeout=120)

    # wait until end of analysis
    while True:
        r = drakcore.check_status(task_uuid)
        if r["status"] != "pending":
            break
        time.sleep(10.0)

    # give it a bit more time?
    time.sleep(10.0)

    # check logs if our binary was ran
    response = drakcore.analysis_log(task_uuid, "filetracer")
    for line in response.iter_lines():
        d = json.loads(line)
        # our sample tried to create a file
        if d.get("Method") == "NtCreateFile" and "test.txt" in d.get("FileName"):
            break
    else:
        raise Exception("No matching entry found")
    