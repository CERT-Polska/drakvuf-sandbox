import time
import json
import requests

from utils import get_hypervisor_type, get_service_info, Drakcore
from conftest import VM_HOST

import pytest


def test_running_on_xen(drakmon_vm):
    assert get_hypervisor_type(drakmon_vm) == "xen"


def test_services_running(drakmon_vm):
    infos = (
        get_service_info(drakmon_vm, "drak-system.service"),
        get_service_info(drakmon_vm, "drak-minio.service"),
        get_service_info(drakmon_vm, "drak-web.service"),
        get_service_info(drakmon_vm, "drak-postprocess.service"),
        get_service_info(drakmon_vm, "redis-server.service"),
    )

    for info in infos:
        assert info["LoadState"] == "loaded"
        assert info["ActiveState"] == "active"
        assert info["SubState"] == "running"


def test_web_ui_reachable(drakmon_vm):
    response = requests.get(f"http://{VM_HOST}:6300/")
    response.raise_for_status()


@pytest.fixture
def drakcore():
    return Drakcore(f"http://{VM_HOST}:6300")


def test_sample_analysis(drakmon_vm, drakcore):
    task_uuid = drakcore.upload(open("test.exe", "rb"))

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
