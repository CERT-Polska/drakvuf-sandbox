from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Union

import orjson


def epoch_to_timestring(unix_time: Union[int, float, str]) -> str:
    # This method converts a unix epoch time into a formated time string.
    # Example:
    #   Input: 1716998460
    #   Return: '2024-05-29 17:01:00'
    if isinstance(unix_time, str):
        unix_time = float(unix_time)

    if not unix_time or unix_time == 0:
        # Sometimes the time in the logs would be zero or None
        return "not available"

    return str(datetime.fromtimestamp(unix_time))


def parse_metadata(metadata_file: Path) -> Dict:
    # This method parses the metadata.json file
    # Unix epoch timestamps are converted to printable time strings as well.
    with metadata_file.open("r") as f:
        metadata = orjson.loads(f.read())

    metadata["time_started"] = epoch_to_timestring(metadata["time_started"])
    metadata["time_finished"] = epoch_to_timestring(metadata["time_finished"])

    return metadata


def process_key(ppid: int, pid: int) -> str:
    # This method defines the way we use to address and differentiate between processes.
    # The convention used by default is ppid_pid.
    return "_".join((str(ppid), str(pid)))


def parse_apicall(apicall: Dict) -> Dict:
    # This method takes in an apimon entry and fetches the necessary information from it.
    # Unix epoch times are converted to printable time strings.
    return {
        "TimeStamp": epoch_to_timestring(apicall["TimeStamp"]),
        "CalledFrom": apicall["CalledFrom"],
        "Method": apicall["Method"],
        "ReturnValue": apicall["ReturnValue"],
        "Argument": dict(arg.split("=", maxsplit=1) for arg in apicall["Arguments"]),
    }


def parse_apimon(processes: Dict, apimon_file: Path) -> None:
    # This method parses each entry of the apimon.log file and appends
    # it to the appropriate process in the report.
    with apimon_file.open("r", errors="ignore") as f:
        for line in f:
            call = orjson.loads(line)
            if call["Event"] == "api_called":
                pkey = process_key(call["PPID"], call["PID"])
                processes[pkey]["api_calls"].append(parse_apicall(call))


def parse_ttps(processes: Dict, ttps_file: Path) -> None:
    # This method parses the TTPs in the ttps.json file and appends
    # it to the appropriate process in the report.
    with ttps_file.open("r") as f:
        for line in f:
            ttp: Dict = orjson.loads(line)
            occurrences = ttp.pop("occurrences")
            for occurrence in occurrences:
                pkey = process_key(occurrence["ppid"], occurrence["pid"])
                processes[pkey]["ttps"].append(ttp)


def parse_memdumps(processes: Dict, memdumps_file: Path) -> None:
    # This method parses the memdump.log file and appends all memory dump
    # information into the appropriate process in the report
    with memdumps_file.open("r") as f:
        for line in f:
            memdump: Dict = orjson.loads(line)
            pkey = process_key(memdump["PPID"], memdump["PID"])
            processes[pkey]["memdumps"].append(
                {
                    "reason": memdump["DumpReason"],
                    "addr": memdump["DumpAddr"],
                    "size": memdump["DumpSize"],
                    "filename": memdump["DumpFilename"],
                    "count": memdump["DumpsCount"],
                }
            )


def parse_processtree(processtree_file: Path) -> List[Dict]:
    # This method extracts all the processes and their associated information
    # from the process_tree.json file.
    def rec(processes: List[Dict], parent=0) -> Iterator[Dict]:
        # This is a helper recursive function that parses the process tree
        for process in processes:
            yield {
                "pid": process["pid"],
                "ppid": parent,
                "procname": process["procname"],
                "args": process["args"],
                "ts_from": epoch_to_timestring(process["ts_from"]),
                "ts_to": epoch_to_timestring(process["ts_to"]),
                "children": [
                    process_key(process["pid"], child["pid"])
                    for child in process["children"]
                ],
                "api_calls": [],  # to be filled later by parse_apimon()
                "ttps": [],  # to be filled later by parse_ttps()
                "memdumps": [],  # to be filled later by parse_memdumps()
            }
            yield from rec(process["children"], parent=process["pid"])

    with processtree_file.open("r") as f:
        processtree = orjson.loads(f.read())

    return {
        process_key(process["ppid"], process["pid"]): process
        for process in rec(processtree)
    }


def get_metadata(analysis_dir: Path) -> Dict:
    # Currently, all metadata is contained in the metadata.json file
    return parse_metadata(analysis_dir / "metadata.json")


def get_processes(analysis_dir: Path) -> Dict:
    # generate a dictionary of indexed processes
    processes = parse_processtree(analysis_dir / "process_tree.json")
    # parse api calls into the indexed process dictionary
    parse_apimon(processes, analysis_dir / "apimon.log")
    # parse ttps into the indexed process dictionary
    parse_ttps(processes, analysis_dir / "ttps.json")
    # parse memory dumps log into the indexed process dictionary
    parse_memdumps(processes, analysis_dir / "memdump.log")

    return processes


def build_report(analysis_dir: Path) -> None:
    report = dict()

    report.update({"info": get_metadata(analysis_dir)})
    report.update({"processes": get_processes(analysis_dir)})

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
