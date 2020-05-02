import json
from dataclasses import dataclass, field
from io import BytesIO
from typing import List, Set, Optional, Dict, Any
from drakcore.postprocess import postprocess
from karton2 import Task, Resource


@dataclass
class Process:
    pid: Optional[int] = None
    ppid: Optional[int] = None
    procname: Optional[str] = None
    children: Set[int] = field(default_factory=set)


class ProcessTree:
    def __init__(self):
        self.process: Dict[int, Process] = {}

    def add_process(self, pid: int, ppid: int, procname: str):
        proc = self._get_proc(pid)
        proc.ppid = ppid
        proc.procname = procname

        if ppid is not None:
            self._get_proc(ppid).children.add(pid)

    def _get_proc(self, pid: int) -> Process:
        if pid not in self.process:
            proc = Process(pid)
            self.process[pid] = proc
        else:
            proc = self.process[pid]
        return proc

    def _subtree_dict(self, pid: int) -> Dict[str, Any]:
        proc = self._get_proc(pid)
        children = [self._subtree_dict(child) for child in proc.children]
        return {
            "pid": proc.pid,
            "procname": proc.procname,
            "children": children,
        }

    def as_dict(self) -> List[Dict[str, Any]]:
        return [self._subtree_dict(pid) for pid in self.get_roots_pids()]

    def get_roots_pids(self):
        return [pid for (pid, proc) in self.process.items() if proc.ppid is None]

    def print_tree(self):
        def print_recursive(indent, proc):
            print("  " * indent + str(proc))
            for child in proc.children:
                print_recursive(indent + 1, self._get_proc(child))

        for pid in self.get_roots_pids():
            proc = self._get_proc(pid)
            print_recursive(0, proc)


def tree_from_log(file):
    pstree = ProcessTree()
    for line in file.readlines():
        entry = json.loads(line)
        pstree.add_process(entry["PID"], entry["PPID"], entry["ProcessName"])
    return pstree.as_dict()


@postprocess(required=["procmon.log"])
def build_process_tree(task: Task, resources: Dict[str, Resource], minio):
    res_log = resources["procmon.log"]
    log = BytesIO(res_log.content)
    data = json.dumps(tree_from_log(log)).encode()
    file = BytesIO(data)
    analysis_uid = task.payload["analysis_uid"]

    minio.put_object("drakrun", f"{analysis_uid}/process_tree.json", file, len(data))
