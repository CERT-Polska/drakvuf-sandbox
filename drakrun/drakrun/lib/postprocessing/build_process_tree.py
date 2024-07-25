import json
import logging
import pathlib
import shlex
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TextIO

logger = logging.getLogger(__name__)


@dataclass
class Process:
    """
    Process is uniquely identified by pid + ts_from + ts_to, as there can be only one
    process with selected `pid` value at a time.
    """

    pid: int
    procname: str = "Unnamed"
    args: List[str] = field(default_factory=list)
    ts_from: Optional[float] = None
    ts_to: Optional[float] = None
    parent: Optional["Process"] = None
    children: List["Process"] = field(default_factory=list)

    def __str__(self):
        return f"{pathlib.PureWindowsPath(self.procname).name}({self.pid}) {self.args}"


class ProcessTree:
    def __init__(self):
        self.processes: List[Process] = []

    def add_process(self, p: Process) -> None:
        processes = self.get_processes(p.pid, p.ts_from, p.ts_from)
        if len(processes) != 0:
            raise MultipleProcessesReturned(processes)

        self.processes.append(p)

    def get_processes(self, pid: int, ts_from: float, ts_to: float) -> List[Process]:
        """
        Retrieves all processes with given pid that were alive in provided time period: [ts_from, ts_to].
        """
        processes = []
        for p in self.processes:
            if (
                pid == p.pid
                and (p.ts_to is None or ts_from <= p.ts_to)
                and p.ts_from <= ts_to
            ):
                processes.append(p)
        return processes

    def get_single_process(self, pid, ts_from, ts_to) -> Optional[Process]:
        """
        Retrieves process with given pid that was alive in provided time period.
        Fails if there is more than 1 process that fulfills this condidions.
        """
        processes = self.get_processes(pid, ts_from, ts_to)
        if len(processes) > 1:
            raise MultipleProcessesReturned(processes)
        return next(iter(processes), None)

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
                "pid": root.pid,
                "procname": root.procname,
                "args": root.args,
                "ts_from": root.ts_from,
                "ts_to": root.ts_to,
                "children": subtrees,
            }

        roots = [p for p in self.processes if p.parent is None]
        root_subtrees = [tree_as_dict(r) for r in roots]
        return root_subtrees


class MultipleProcessesReturned(Exception):
    def __init__(self, processes: List[Process]):
        processs_str = ", ".join([str(p) for p in processes])
        message = f"More than one proces fulfills condition: {processs_str}"
        super().__init__(message)


def parse_running_process_entry(pstree: ProcessTree, entry: Dict[str, Any]) -> None:
    # We assume here that running processes are enumerated in order of creation
    # (created by appending new entries to the end of EPROCESS linked list)
    parent = pstree.get_single_process(entry["PPID"], 0, float(entry["TimeStamp"]))
    p = Process(
        pid=entry["PID"],
        procname=entry["RunningProcess"],
        ts_from=0.0,  # We don't know when the process was created.
        # At this point, we don't know yet when the process will be terminated.
        ts_to=None,
        parent=parent,
    )
    parent.children.append(p)
    pstree.add_process(p)


def split_commandline(cmdline: str) -> [str]:
    # Procmon plugin performs extra cmdline encoding.
    cmdline = cmdline.encode().decode("unicode_escape")
    try:
        return shlex.split(cmdline, posix=False)
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
    parent = pstree.get_single_process(
        process_ppid, float(entry["TimeStamp"]), float(entry["TimeStamp"])
    )
    p = Process(
        pid=process_pid,
        procname=entry["ImagePathName"],
        ts_from=float(entry["TimeStamp"]),
        # At this point, we don't know yet when the process will be terminated.
        ts_to=None,
        parent=parent,
        args=split_commandline(entry["CommandLine"]) if entry["CommandLine"] else [],
    )
    if parent is None:
        # Parent must be alive at the process creation time, but who knows what happened
        logger.debug(
            f"Parent process not found at the process creation time (PID: {process_pid}, PPID: {process_ppid})"
        )
    else:
        parent.children.append(p)
    pstree.add_process(p)


def parse_nt_create_process_ex_entry(
    pstree: ProcessTree, entry: Dict[str, Any]
) -> None:
    # NtCreateProcessEx method was used to create processes up to Windows XP.
    if int(entry["Status"], 16) != 0:
        # Ignore unsuccessful entries.
        return
    process_pid = entry["NewPid"]
    process_ppid = entry["PID"]
    parent = pstree.get_single_process(
        process_ppid, float(entry["TimeStamp"]), float(entry["TimeStamp"])
    )
    p = Process(
        pid=process_pid,
        procname="Unnamed",
        ts_from=float(entry["TimeStamp"]),
        # At this point, we don't know yet when the process will be terminated.
        ts_to=None,
        parent=parent,
    )
    if parent is None:
        # Parent must be alive at the process creation time, but who knows what happened
        logger.debug(
            f"Parent process not found at the process creation time (PID: {process_pid}, PPID: {process_ppid})"
        )
    else:
        parent.children.append(p)
    pstree.add_process(p)


def parse_mm_clean_process_address_space_entry(
    pstree: ProcessTree, entry: Dict[str, Any]
) -> None:
    pid = entry["ExitPid"]
    p = pstree.get_single_process(
        pid, float(entry["TimeStamp"]), float(entry["TimeStamp"])
    )
    if p is None:
        # Maybe we had already marked it.
        return
    p.ts_to = float(entry["TimeStamp"])


def tree_from_log(file: TextIO) -> List[Dict[str, Any]]:
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
            elif "Method" in entry and entry["Method"] in ["NtCreateUserProcess"]:
                # Process has been created after the analysis started.
                parse_nt_create_user_process_entry(pstree, entry)
            elif "Method" in entry and entry["Method"] == "NtCreateProcessEx":
                # Process has been created after the analysis started.
                parse_nt_create_process_ex_entry(pstree, entry)
            elif "Method" in entry and entry["Method"] == "MmCleanProcessAddressSpace":
                # Process has been terminated.
                parse_mm_clean_process_address_space_entry(pstree, entry)
        except json.JSONDecodeError as e:
            logger.warning(f"Line cannot be parsed as JSON\n{e}")
            continue
        except Exception as e:
            logger.warning(f"Failed to process {entry}")
            raise e
    return pstree.as_dict()


def build_process_tree(analysis_dir: pathlib.Path) -> None:
    procmon_log_path = analysis_dir / "procmon.log"
    process_tree_path = analysis_dir / "process_tree.json"

    with procmon_log_path.open("r") as procmon_log:
        process_tree = tree_from_log(procmon_log)
        data = json.dumps(process_tree)
        process_tree_path.write_text(data)
