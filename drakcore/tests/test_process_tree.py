import os
import pytest
from drakcore.pstree import ProcessTree


def test_empty_tree():
    pstree = ProcessTree()
    assert pstree.get_roots_pids() == []
    assert pstree.as_dict() == []


def test_single():
    singleton_tree = ProcessTree()
    singleton_tree.add_process(10, None, "A")
    assert singleton_tree.get_roots_pids() == [10]
    result = [{"pid": 10, "procname": "A", "children": []}]
    assert result == singleton_tree.as_dict()


def test_simple():
    pstree = ProcessTree()
    pstree.add_process(10, 1, "A")
    pstree.add_process(11, 1, "B")
    pstree.add_process(12, 1, "C")
    pstree.add_process(13, 12, "D")
    assert pstree.get_roots_pids() == [1]
    result = [
        {
            "pid": 1,
            "procname": None,
            "children": [
                {"pid": 10, "procname": "A", "children": []},
                {"pid": 11, "procname": "B", "children": []},
                {
                    "pid": 12,
                    "procname": "C",
                    "children": [{"pid": 13, "procname": "D", "children": []}],
                },
            ],
        }
    ]
    assert result == pstree.as_dict()
