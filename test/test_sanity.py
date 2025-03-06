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
    print("test_drak_tester_analysis")
    task_uuid = drakcore.upload(open("drak-tester/drakvuf_tester.exe", "rb"), timeout=120)

    # wait until end of analysis
    while True:
        r = drakcore.check_status(task_uuid)
        if r["status"] != "pending":
            break
        time.sleep(10.0)

    # give it a bit more time?
    time.sleep(10.0)

    # check logs if our binary was ran
    response = drakcore.analysis_log(task_uuid, "memdump")
    drak_tester_check_memdump_hooks(response)


def drak_tester_check_memdump_hooks(memdump_log):
    print("drak_tester_check_memdump_hooks")
    all_passed = True
    hooks = (
        "NtFreeVirtualMemory",
        "NtProtectVirtualMemory",
        "NtTerminateProcess",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtSetInformationThread"
        )
    sample_name = "sample.exe"
    hooks_map = {
        "NtFreeVirtualMemory": False,
        "NtProtectVirtualMemory": False,
        "NtTerminateProcess": False,
        "NtWriteVirtualMemory": False,
        "NtCreateThreadEx": False,
        "NtSetInformationThread": False,
    }
    method_field = "Method"
    filename_field = "FileName"

    # check memdump log for memdump hooks
    for line in memdump_log.iter_lines():
        d = json.loads(line)
        # our sample tried to create a file
        method = d.get(method_field)
        if method in hooks and sample_name in d.get(filename_field):
            hooks[method] = True

    for k in hooks_map:
        if hooks_map[k] == False:
            print(f"{k} not found in memdump.log")
            all_passed = False

    if not all_passed:
        raise Exception("No matching entry found")
