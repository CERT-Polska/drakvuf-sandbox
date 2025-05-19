import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import orjson

from ..process_tree import ProcessTree, tree_from_dict

logger = logging.getLogger(__name__)


def epoch_to_timestring(unix_time: Optional[float]) -> Optional[str]:
    # This method converts a unix epoch time into a formated time string.
    # Example:
    #   Input: 1716998460.000
    #   Return: '2024-05-29 17:01:00'
    if not unix_time:
        # Sometimes the time in the logs would be zero or None
        return None

    time = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    return time.isoformat()


def parse_apicall(apicall: Dict) -> Dict:
    # This method takes in an apimon entry and fetches the necessary information from it.
    # Unix epoch times are converted to printable time strings.
    return {
        "TimeStamp": epoch_to_timestring(float(apicall["TimeStamp"])),
        "CalledFrom": apicall["CalledFrom"],
        "Method": apicall["Method"],
        "ReturnValue": apicall["ReturnValue"],
        "Argument": [arg.split("=", maxsplit=1)[1] for arg in apicall["Arguments"]],
    }


def parse_apimon(
    process_tree: ProcessTree, apimon_file: Path
) -> Dict[int, List[Dict[str, Any]]]:
    def get_apicall_tuple(call):
        return call["CalledFrom"], call["Method"], call["ReturnValue"], call["Argument"]

    # This method parses each entry of the apimon.log file and appends
    # it to the appropriate process in the report.
    apicalls = defaultdict(list)
    with apimon_file.open("r", errors="ignore") as f:
        for line in f:
            call = orjson.loads(line)
            if call["Event"] == "api_called":
                process = process_tree.get_process_for_evtid(
                    call["PID"], int(call["EventUID"], 16)
                )
                parsed_apicall = parse_apicall(call)
                if apicalls[process.seqid]:
                    previous_apicall = apicalls[process.seqid][-1]
                    if get_apicall_tuple(parsed_apicall) == get_apicall_tuple(
                        previous_apicall
                    ):
                        previous_apicall["Repeated"] = (
                            previous_apicall.get("Repeated", 1) + 1
                        )
                        continue
                apicalls[process.seqid].append(parsed_apicall)
    return dict(apicalls)


def parse_ttps(
    process_tree: ProcessTree, ttps_file: Path
) -> Dict[int, List[Dict[str, Any]]]:
    # This method parses the TTPs in the ttps.json file and appends
    # it to the appropriate process in the report.
    ttps = defaultdict(list)
    ppid_pid_mapping = {}
    for process in process_tree.processes:
        ppid_pid_key = (process.ppid, process.pid)
        if ppid_pid_key in ppid_pid_mapping:
            logger.warning(
                "Found duplicate ppid:pid (%d:%d). TTPs will be assigned to the first found process",
                process.ppid,
                process.pid,
            )
            continue
        ppid_pid_mapping[ppid_pid_key] = process

    with ttps_file.open("r") as f:
        for line in f:
            ttp: Dict = orjson.loads(line)
            occurrences = ttp.pop("occurrences")
            for occurrence in occurrences:
                process = ppid_pid_mapping[(occurrence["ppid"], occurrence["pid"])]
                ttps[process.seqid].append(ttp)
    return dict(ttps)


def parse_memdumps(
    process_tree: ProcessTree, memdumps_file: Path
) -> Dict[int, List[Dict[str, Any]]]:
    # This method parses the memdump.log file and appends all memory dump
    # information into the appropriate process in the report
    memdumps = defaultdict(list)
    with memdumps_file.open("r") as f:
        for line in f:
            memdump: Dict = orjson.loads(line)
            process = process_tree.get_process_for_evtid(
                memdump["PID"], int(memdump["EventUID"], 16)
            )
            memdumps[process.seqid].append(
                {
                    "reason": memdump["DumpReason"],
                    "addr": memdump["DumpAddr"],
                    "size": memdump["DumpSize"],
                    "filename": memdump["DumpFilename"],
                    "count": memdump["DumpsCount"],
                }
            )
    return dict(memdumps)


def parse_processtree(processtree_file: Path) -> ProcessTree:
    with processtree_file.open("r") as f:
        processtree = orjson.loads(f.read())

    return tree_from_dict(processtree)


def get_metadata(analysis_dir: Path) -> Dict:
    # Currently, all metadata is contained in the metadata.json file
    metadata_file = analysis_dir / "metadata.json"
    with metadata_file.open("r") as f:
        metadata = orjson.loads(f.read())

    return metadata


def get_processes(analysis_dir: Path) -> List[Dict[str, Any]]:
    # generate a dictionary of indexed processes
    process_tree = parse_processtree(analysis_dir / "process_tree.json")
    process_dicts = list(
        map(
            lambda procdict: {
                **procdict,
                "ts_from": epoch_to_timestring(procdict["ts_from"]),
                "ts_to": epoch_to_timestring(procdict["ts_to"]),
            },
            [process.as_dict() for process in process_tree.processes],
        )
    )
    # parse api calls into the indexed process dictionary
    if (analysis_dir / "apimon.log").is_file():
        apimon = parse_apimon(process_tree, analysis_dir / "apimon.log")
        for seqid, apicalls in apimon.items():
            process_dicts[seqid]["apicalls"] = apicalls
    # parse ttps into the indexed process dictionary
    if (analysis_dir / "ttps.json").is_file():
        ttps = parse_ttps(process_tree, analysis_dir / "ttps.json")
        for seqid, ttpset in ttps.items():
            process_dicts[seqid]["ttps"] = ttpset

    # parse memory dumps log into the indexed process dictionary
    if (analysis_dir / "memdump.log").is_file():
        memdumps = parse_memdumps(process_tree, analysis_dir / "memdump.log")
        for seqid, memdump_set in memdumps.items():
            process_dicts[seqid]["memdumps"] = memdump_set

    return process_dicts


def build_report(analysis_dir: Path) -> None:
    report = {
        "info": get_metadata(analysis_dir),
        "processes": get_processes(analysis_dir),
    }

    with (analysis_dir / "report.json").open("wb") as f:
        f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2))


if __name__ == "__main__":
    from sys import argv

    if len(argv) < 2:
        print("missing analysis directory")
        exit(1)

    analysis_dir = Path(argv[1])
    if not analysis_dir.exists() or not any(analysis_dir.iterdir()):
        print("analysis directory is empty or non-existant")
        exit(1)

    build_report(analysis_dir)
