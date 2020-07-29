import json
import os
import logging
from io import BytesIO
from collections import defaultdict
from drakcore.postprocess import postprocess
from karton2 import Task, RemoteResource
from typing import Dict
from tempfile import NamedTemporaryFile


def process_logfile(log):
    temp_files = {}

    for line in log:
        try:
            entry = json.loads(line)
            pid = entry["PID"]
            r = {
                "pid": pid,
                "timestamp": entry["TimeStamp"],
                "method": entry["Method"],
                "arguments": entry["Arguments"],
            }
        except KeyError as e:
            logging.warning(f"JSON is missing a required field\n{e}")
            continue
        except json.JSONDecodeError as e:
            logging.warning(f"line cannot be parsed as JSON\n{e}")
            continue

        out_line = json.dumps(r).encode()
        if pid in temp_files:
            out_file = temp_files[pid]
            out_file.write(b"\n")
            out_file.write(out_line)
        else:
            out_file = NamedTemporaryFile(delete=False)
            temp_files[pid] = out_file
            out_file.write(out_line)
    return temp_files


@postprocess(required=["apimon.log"])
def process_api_log(task: Task, resources: Dict[str, RemoteResource], minio):
    with resources["apimon.log"].download_temporary_file() as tmp_file:
        out_files = process_logfile(tmp_file)

    analysis_uid = task.payload["analysis_uid"]
    for pid, file in out_files.items():
        size = file.tell()
        file.seek(0)
        minio.put_object("drakrun", f"{analysis_uid}/apicall/{pid}.json", file, size)

        file.close()
        os.unlink(file.name)
