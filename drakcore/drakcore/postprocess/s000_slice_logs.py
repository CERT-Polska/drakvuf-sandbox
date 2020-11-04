import re
import json
import tempfile
import logging

from typing import Dict
from karton2 import Task, RemoteResource
from collections import Counter
from pathlib import Path
from drakcore.postprocess import postprocess


@postprocess(required=["drakmon.log"])
def slice_drakmon_logs(task: Task, resources: Dict[str, RemoteResource], minio):
    analysis_uid = task.payload["analysis_uid"]

    with resources["drakmon.log"].download_temporary_file() as drakmon_log_f:
        with tempfile.TemporaryDirectory() as target_dir:
            target_dir = Path(target_dir)
            plugin_fd = {}
            failures = Counter()

            error_path = target_dir / 'parse_errors.log'

            with open(error_path, 'wb') as parse_errors:
                for line in drakmon_log_f:
                    try:
                        line_s = line.strip().decode()
                        obj = json.loads(line_s)

                        plugin = obj.get('Plugin', 'unknown')

                        if plugin not in plugin_fd:
                            plugin_fd[plugin] = open(target_dir / f'{plugin}.log', 'w')
                        else:
                            plugin_fd[plugin].write('\n')

                        plugin_fd[plugin].write(json.dumps(obj))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        # Log the failure and count statistics

                        plugin_heuristic: bytes = r'"Plugin": "(\w+)"'.encode()
                        match = re.match(plugin_heuristic, line)
                        if match:
                            # we've matched a unicode word, this shouldn't fail
                            plugin = match.group(1).decode('utf-8', 'replace')
                        else:
                            plugin = "unknown"

                        failures[plugin] += 1
                        parse_errors.write(line + b"\n")

            for plugin, count in failures.items():
                logging.error("Failed to parse %d lines generated by %s", count, plugin)

            # Remove file if empty
            if len(failures) == 0:
                error_path.unlink()

            for plugin_name, fd in plugin_fd.items():
                fd.close()
                minio.fput_object("drakrun", f"{analysis_uid}/{plugin_name}.log", target_dir / f'{plugin_name}.log')
                yield f"{plugin_name}.log"
