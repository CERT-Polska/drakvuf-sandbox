import json
import os
from io import BytesIO
from collections import defaultdict
from drakcore.postprocess import postprocess
from karton2 import Task, RemoteResource
from typing import Dict
from tempfile import NamedTemporaryFile


def process_logfile(log):
    temp_files = {}
    for line in log:
        entry = json.loads(line)
        pid = entry["PID"]
        r = {
            "pid": pid,
            "timestamp": entry["TimeStamp"],
            "method": entry["Method"],
            "arguments": entry["Arguments"],
        }

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
    res_log = resources["apimon.log"]
    with NamedTemporaryFile() as tmp_file:
        res_log.download_content_to_file(minio, tmp_file.name)

        with open(tmp_file.name) as log:
            out_files = process_logfile(log)

    analysis_uid = task.payload["analysis_uid"]
    for pid, file in out_files.items():
        size = file.tell()
        file.seek(0)
        minio.put_object("drakrun", f"{analysis_uid}/apicall/{pid}.json", file, size)

        file.close()
        os.unlink(file.name)
