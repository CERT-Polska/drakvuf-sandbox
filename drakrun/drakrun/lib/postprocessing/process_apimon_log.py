import json
import logging
import pathlib

logger = logging.getLogger(__name__)


def process_apimon_log(analysis_dir: pathlib.Path) -> None:
    apimon_log_path = analysis_dir / "apimon.log"
    target_dir = analysis_dir / "apicall"
    pid_files = {}

    target_dir.mkdir()

    with apimon_log_path.open("r") as apimon_log:
        for line_no, line in enumerate(apimon_log):
            # I don't expect any encoding problems as they
            # should be resolved by split_drakmon_log
            entry = json.loads(line)
            if entry["Event"] != "api_called":
                continue
            if "PID" not in entry:
                logger.warning(f"Missing PID in {apimon_log_path}:{line_no}")
            pid = entry["PID"]
            filtered_entry = {
                "pid": pid,
                "timestamp": entry["TimeStamp"],
                "method": entry["Method"],
                "arguments": entry["Arguments"],
                "returnvalue": entry["ReturnValue"],
            }
            if pid not in pid_files:
                pid_files[pid] = (target_dir / f"{pid}.json").open("w")
            pid_files[pid].write(json.dumps(filtered_entry) + "\n")

    for pid_file in pid_files.values():
        pid_file.close()
