from io import StringIO

import pytest

from drakrun.util import RuntimeInfo, VmiOffsets

win_offsets_output = """
win_ntoskrnl:0x2618000
win_ntoskrnl_va:0xfffff80002618000
win_tasks:0x188
win_pdbase:0x28
win_pid:0x180
win_pname:0x2e0
win_kdvb:0x0
win_sysproc:0xfffffa8001821b30
win_kpcr:0x0
win_kdbg:0x0
kpgd:0x187000
"""

missing_kpgd = """
win_ntoskrnl:0x2618000
win_ntoskrnl_va:0xfffff80002618000
win_tasks:0x188
win_pdbase:0x28
win_pid:0x180
win_pname:0x2e0
win_kdvb:0x0
win_sysproc:0xfffffa8001821b30
win_kpcr:0x0
win_kdbg:0x0
"""


@pytest.fixture
def vmi_offsets():
    return VmiOffsets.from_tool_output(win_offsets_output)


def test_missing_info():
    with pytest.raises(TypeError):
        VmiOffsets.from_tool_output(missing_kpgd)


def test_tool_output(vmi_offsets):
    assert vmi_offsets.win_ntoskrnl == 0x2618000
    assert vmi_offsets.win_ntoskrnl_va == 0xFFFFF80002618000
    assert vmi_offsets.win_tasks == 0x188
    assert vmi_offsets.win_pdbase == 0x28
    assert vmi_offsets.win_pid == 0x180
    assert vmi_offsets.win_pname == 0x2E0
    assert vmi_offsets.win_kdvb == 0x0
    assert vmi_offsets.win_sysproc == 0xFFFFFA8001821B30
    assert vmi_offsets.win_kpcr == 0x0
    assert vmi_offsets.win_kdbg == 0x0
    assert vmi_offsets.kpgd == 0x187000


@pytest.fixture
def runtime_info(vmi_offsets):
    return RuntimeInfo(vmi_offsets=vmi_offsets, inject_pid=1337)


@pytest.fixture
def serialized_runtime_info(runtime_info):
    return runtime_info.to_json()


def test_runtime_info_load(serialized_runtime_info):
    stream = StringIO(serialized_runtime_info)
    RuntimeInfo.load(stream)
