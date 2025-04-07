import logging
import os
import pathlib
import subprocess

from .drakparse import parse_logs

logger = logging.getLogger(__name__)


def generate_graphs(analysis_dir: pathlib.Path) -> None:
    if not os.path.exists("/opt/procdot/procmon2dot"):
        return

    drakmon_log_path = analysis_dir / "drakmon.log"

    with drakmon_log_path.open("rb") as drakmon_log:
        with (analysis_dir / "drakmon.csv").open("w") as f:
            for csv_line in parse_logs(drakmon_log):
                if csv_line.strip():
                    f.write(csv_line.strip() + "\n")
                else:
                    logger.warning("generate_graphs: empty line?")

        try:
            subprocess.run(
                [
                    "/opt/procdot/procmon2dot",
                    (analysis_dir / "drakmon.csv").as_posix(),
                    (analysis_dir / "graph.dot").as_posix(),
                    "procdot,forceascii",
                ],
                cwd=analysis_dir,
                check=True,
            )
        except subprocess.CalledProcessError:
            logger.exception("Failed to generate graph using procdot")
