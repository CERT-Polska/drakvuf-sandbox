from typing import Optional

from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def get_ttps_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_ttps(data: dict) -> Optional[dict]:
        pid_occurrences = data["occurrences"]
        processes = []
        for process in pid_occurrences:
            process = process_tree.get_process_by_pid_ppid(
                process["pid"], process["ppid"]
            )
            if process:
                processes.append(process.seqid)
        return {"name": data["name"], "att&ck": data["att&ck"], "processes": processes}

    ttps_log = parse_log(analysis_dir / "ttps.json", filter_ttps)
    context.update_report({"ttps": [data for data in ttps_log]})
