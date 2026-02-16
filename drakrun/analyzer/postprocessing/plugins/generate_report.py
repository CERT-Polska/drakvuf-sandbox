import logging
from pathlib import Path
from typing import Dict, Optional

import orjson

from ..process_tree import ProcessTree
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def get_inject_info(analysis_dir: Path, process_tree: Optional[ProcessTree]) -> Dict:
    inject_file = analysis_dir / "inject.log"
    if not inject_file.exists():
        return {}
    with inject_file.open("r") as f:
        inject = orjson.loads(f.read().strip())
    status = inject.get("Status")
    if status == "Success":
        pid = inject.get("InjectedPid")
        if pid and process_tree:
            process = process_tree.get_process_for_evtid(pid, 0)
        else:
            process = None
        inject_info = {
            "status": inject["Status"],
            "process_name": inject.get("ProcessName"),
            "arguments": inject.get("Arguments"),
            "pid": pid,
            "process": process.seqid if process else None,
        }
    elif status == "Error":
        inject_info = {
            "status": inject["Status"],
            "error_code": inject.get("ErrorCode"),
            "error": inject.get("Error"),
        }
    else:
        logger.warning("Unknown status found in inject.log")
        inject_info = {}

    return inject_info


def generate_report(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context._process_tree
    report = {
        "info": context.metadata.model_dump(mode="json", exclude_none=True),
        "startup": get_inject_info(analysis_dir, process_tree),
        **context.report,
    }

    with (analysis_dir / "report.json").open("wb") as f:
        f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2))
