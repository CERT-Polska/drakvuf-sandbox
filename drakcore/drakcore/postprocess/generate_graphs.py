import logging
import os
import subprocess
import tempfile
from typing import Dict

from karton.core import RemoteResource, Task

from drakcore.postprocess.drakparse import parse_logs


def generate_graphs(task: Task, resources: Dict[str, RemoteResource], minio):
    analysis_uid = task.payload["analysis_uid"]

    if not os.path.exists("/opt/procdot/procmon2dot"):
        return

    with resources["drakmon.log"].download_temporary_file() as f:
        with tempfile.TemporaryDirectory() as output_dir:
            with open(os.path.join(output_dir, "drakmon.csv"), "w") as o:
                for csv_line in parse_logs(f):
                    if csv_line.strip():
                        o.write(csv_line.strip() + "\n")
                    else:
                        logging.warning("generate_graphs: empty line?")

            try:
                subprocess.run(
                    [
                        "/opt/procdot/procmon2dot",
                        os.path.join(output_dir, "drakmon.csv"),
                        os.path.join(output_dir, "graph.dot"),
                        "procdot,forceascii",
                    ],
                    cwd=output_dir,
                    check=True,
                )
            except subprocess.CalledProcessError:
                logging.exception("Failed to generate graph using procdot")

            minio.fput_object(
                "drakrun",
                f"{analysis_uid}/graph.dot",
                os.path.join(output_dir, "graph.dot"),
            )
