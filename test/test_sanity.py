import time
import json
import requests
import pytest

from utils import get_hypervisor_type, get_service_info, Drakcore
from conftest import VM_HOST, DRAKMON_SERVICES


def test_running_on_xen(drakmon_vm):
    assert get_hypervisor_type(drakmon_vm) == "xen"


def test_services_running(drakmon_vm):
    def check_status():
        infos = [get_service_info(drakmon_vm, service) for service in DRAKMON_SERVICES]

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


def test_web_ui_reachable(drakmon_vm):
    response = requests.get(f"http://{VM_HOST}:6300/")
    response.raise_for_status()


@pytest.fixture
def drakcore(karton_bucket):
    return Drakcore(f"http://{VM_HOST}:6300")


def test_sample_analysis(drakmon_vm, drakcore):
    task_uuid = drakcore.upload(open("test.exe", "rb"), timeout=120)

    # wait until end of analysis
    while True:
        r = drakcore.check_status(task_uuid)
        if r["status"] != "pending":
            break
        time.sleep(10.0)

    # check logs if our binary was ran
    response = drakcore.analysis_log(task_uuid, "filetracer")
    for line in response.iter_lines():
        d = json.loads(line)
        # our sample tried to create a file
        if d["Method"] == "NtCreateFile" and "test.txt" in d["FileName"]:
            break
    else:
        raise Exception("No matching entry found")
