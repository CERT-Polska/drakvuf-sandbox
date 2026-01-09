import json
import logging
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TextIO

import mslex

logger = logging.getLogger(__name__)


@dataclass
class Process:
    seqid: int
    pid: int
    ppid: int  # This PPID may not be real and may not be an active process
    ts_from: float
    ts_to: Optional[float]
    evtid_from: Optional[int]
    evtid_to: Optional[int]
    exit_code: Optional[int]
    exit_code_str: Optional[str]
    killed_by: Optional[int]
    procname: str
    args: List[str]
    parent: Optional["Process"] = None
    children: List["Process"] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{pathlib.PureWindowsPath(self.procname).name}(pid={self.pid}, seq={self.seqid}) {self.args}"

    def as_dict(self) -> Dict[str, Any]:
        return {
            "seqid": self.seqid,
            "pid": self.pid,
            "ppid": self.ppid,
            "procname": self.procname,
            "args": self.args,
            "ts_from": self.ts_from,
            "ts_to": self.ts_to,
            "evtid_from": self.evtid_from,
            "evtid_to": self.evtid_to,
            "exit_code": self.exit_code,
            "exit_code_str": self.exit_code_str,
            "killed_by": self.killed_by,
        }

    def change_parent(self, new_parent: "Process") -> None:
        if self.parent is not None:
            self.parent.children.remove(self)
        new_parent.children.append(self)
        self.parent = new_parent
        self.ppid = new_parent.ppid


class ProcessTree:
    def __init__(self):
        self.processes: List[Process] = []

    def add_process(
        self,
        pid: int,
        ppid: int,
        evtid_from: Optional[int],
        ts_from: float,
        procname: str,
        parent: Optional[Process],
        args: Optional[List[str]] = None,
    ) -> Process:
        """
        Add a new process to tree, assign sequential id and return Process object
        """
        process = Process(
            seqid=len(self.processes),
            pid=pid,
            ppid=ppid,
            ts_from=ts_from,
            ts_to=None,
            evtid_from=evtid_from,
            evtid_to=None,
            procname=procname,
            parent=parent,
            args=args or [],
            exit_code=None,
            exit_code_str=None,
            killed_by=None,
        )
        existing_process = self.get_process(pid)
        if existing_process is not None and existing_process.ts_to is None:
            # Found another process with the same PID
            # Let's assume it's no longer active, it may happen in parse_running_process_entry
            existing_process.evtid_to = evtid_from - 1
            existing_process.ts_to = ts_from

        self.processes.append(process)
        if parent:
            parent.children.append(process)
        return process

    def get_process_for_evtid(self, pid: int, evtid: int) -> Optional[Process]:
        for process in self.processes:
            if process.pid == pid:
                if evtid >= process.evtid_from and (
                    (not process.evtid_to) or evtid <= process.evtid_to
                ):
                    return process
        return None

    def get_process(self, pid: int) -> Optional[Process]:
        """
        Get last seen active process with given PID.
        """
        for process in reversed(self.processes):
            if process.pid == pid:
                return process
        return None

    def get_process_by_pid_ppid(self, pid: int, ppid: int) -> Optional[Process]:
        for process in reversed(self.processes):
            if process.pid == pid and process.ppid == ppid:
                return process
        return None

    def __str__(self):
        def print_tree_rec(depth: int, root: Process) -> str:
            res = "\t" * depth + str(root) + "\n"
            res += "".join([print_tree_rec(depth + 1, c) for c in root.children])
            return res

        roots = [p for p in self.processes if p.parent is None]
        subtrees = [print_tree_rec(0, r) for r in roots]
        return "\n".join(subtrees)

    def as_dict(self) -> List[Dict[str, Any]]:
        def tree_as_dict(root) -> Dict[str, Any]:
            subtrees = [tree_as_dict(c) for c in root.children]
            return {
                **root.as_dict(),
                "children": subtrees,
            }

        roots = [p for p in self.processes if p.parent is None]
        root_subtrees = [tree_as_dict(r) for r in roots]
        return root_subtrees


def parse_running_process_entry(pstree: ProcessTree, entry: Dict[str, Any]) -> None:
    # We assume here that running processes are enumerated in order of creation
    # (created by appending new entries to the end of EPROCESS linked list)
    parent = pstree.get_process(entry["PPID"])
    pstree.add_process(
        pid=entry["PID"],
        ppid=entry["PPID"],
        ts_from=0.0,
        evtid_from=0,
        procname=entry["RunningProcess"],
        parent=parent,
    )


def split_commandline(cmdline: str) -> [str]:
    # Procmon plugin performs extra cmdline encoding.
    cmdline = cmdline.encode().decode("unicode_escape")
    try:
        return mslex.split(cmdline, check=False, like_cmd=False)
    except Exception:
        # If we fail to parse cmdline, wrap it into list, so we don't
        # lose any information.
        logger.info("Failed to convert commandline to args")
        return [cmdline]


def parse_nt_create_user_process_entry(
    pstree: ProcessTree, entry: Dict[str, Any]
) -> None:
    # NtCreateUserProcess method is used to create processes from Vista+.
    if int(entry["Status"], 16) != 0:
        # Ignore unsuccessful entries.
        return
    process_pid = entry["NewPid"]
    process_ppid = entry["PID"]
    evtid = int(entry["EventUID"], 16)
    parent = pstree.get_process(process_ppid)
    if parent is None:
        # Parent must be alive at the process creation time, but who knows what happened
        logger.warning(
            f"Parent process not found at the process creation time (PID: {process_pid}, PPID: {process_ppid})"
        )

    pstree.add_process(
        pid=process_pid,
        ppid=process_ppid,
        ts_from=float(entry["TimeStamp"]),
        evtid_from=evtid,
        procname=entry["ImagePathName"],
        parent=parent,
        args=split_commandline(entry["CommandLine"]) if entry["CommandLine"] else [],
    )


def parse_nt_create_process_ex_entry(
    pstree: ProcessTree, entry: Dict[str, Any]
) -> None:
    # NtCreateProcessEx method was used to create processes up to Windows XP.
    if int(entry["Status"], 16) != 0:
        # Ignore unsuccessful entries.
        return
    process_pid = entry["NewPid"]
    process_ppid = entry["PID"]
    evtid = int(entry["EventUID"], 16)
    parent = pstree.get_process(process_ppid)
    if parent is None:
        # Parent must be alive at the process creation time, but who knows what happened
        logger.warning(
            f"Parent process not found at the process creation time (PID: {process_pid}, PPID: {process_ppid})"
        )
    pstree.add_process(
        pid=process_pid,
        ppid=process_ppid,
        ts_from=float(entry["TimeStamp"]),
        evtid_from=evtid,
        procname="Unnamed",
        parent=parent,
    )


def parse_mm_clean_process_address_space_entry(
    pstree: ProcessTree, entry: Dict[str, Any]
) -> None:
    pid = entry["ExitPid"]
    evtid = int(entry["EventUID"], 16)
    p = pstree.get_process(pid)
    if p is None:
        logger.warning(f"Process not found at the process exit time (PID: {pid})")
        return
    p.ts_to = float(entry["TimeStamp"])
    p.evtid_to = evtid


def parse_mm_terminate_process(pstree: ProcessTree, entry: Dict[str, Any]):
    pid = entry["ExitPid"]
    killer_pid = None
    if pid == 0:
        # Terminate self
        pid = entry["PID"]
    else:
        killer_pid = entry["PID"]
    p = pstree.get_process(pid)
    if p is None:
        logger.warning(
            f"Process not found at the process termination request (PID: {pid})"
        )
        return
    if killer_pid is not None:
        killer = pstree.get_process(killer_pid)
        if killer is None:
            logger.warning(
                f"Process not found at the NtTerminateProcess call time (PID: {killer_pid})"
            )
        p.killed_by = killer.seqid
    p.exit_code = int(entry["ExitStatus"], 16)
    p.exit_code_str = entry["ExitStatusStr"]


def tree_from_log(file: TextIO) -> ProcessTree:
    pstree = ProcessTree()
    prev_line = None
    for line in file:
        try:
            if line == prev_line:
                # There is still some unfixed bug in drakvuf, that duplicates some entries.
                # Just ignore the duplicate.
                continue
            prev_line = line

            entry = json.loads(line)
            if "RunningProcess" in entry:
                # Process has been created before the analysis started.
                parse_running_process_entry(pstree, entry)
            elif "Method" in entry:
                if entry["Method"] == "NtCreateUserProcess":
                    # Process has been created after the analysis started.
                    parse_nt_create_user_process_entry(pstree, entry)
                elif entry["Method"] == "NtCreateProcessEx":
                    # Process has been created after the analysis started.
                    parse_nt_create_process_ex_entry(pstree, entry)
                elif entry["Method"] == "MmCleanProcessAddressSpace":
                    # Process has been terminated.
                    parse_mm_clean_process_address_space_entry(pstree, entry)
                elif entry["Method"] == "NtTerminateProcess":
                    parse_mm_terminate_process(pstree, entry)
                elif "PID" in entry and "PPID" in entry:
                    pid = entry["PID"]
                    ppid = entry["PPID"]
                    process = pstree.get_process(pid)
                    if (
                        process is not None
                        and process.ts_to is None
                        and process.ppid != ppid
                    ):
                        # Found elevated process: rebind to another parent
                        new_parent = pstree.get_process(ppid)
                        if new_parent is not None:
                            process.change_parent(new_parent)
        except json.JSONDecodeError as e:
            logger.warning(f"Line cannot be parsed as JSON\n{e}")
            continue
        except Exception as e:
            logger.warning(f"Failed to process {entry}")
            raise e
    return pstree


def tree_from_dict(tree_dict: List[Dict[str, Any]]) -> ProcessTree:
    """
    Parses ProcessTree.as_dict result back to ProcessTree object.
    """
    process_tree = ProcessTree()

    def parse_children(
        children: List[Dict[str, Any]], parent: Optional[Process] = None
    ):
        for entry in children:
            process = Process(
                seqid=entry["seqid"],
                pid=entry["pid"],
                ppid=entry["ppid"],
                procname=entry["procname"],
                args=entry["args"],
                ts_from=entry["ts_from"],
                ts_to=entry["ts_to"],
                evtid_from=entry["evtid_from"],
                evtid_to=entry["evtid_to"],
                parent=parent,
                children=[],
                exit_code=entry.get("exit_code"),
                exit_code_str=entry.get("exit_code_str"),
                killed_by=entry.get("killed_by"),
            )
            process_tree.processes.append(process)
            if parent is not None:
                parent.children.append(process)
            if entry["children"]:
                parse_children(entry["children"], parent=process)

    parse_children(tree_dict)
    process_tree.processes = sorted(process_tree.processes, key=lambda p: p.seqid)
    return process_tree
