import json
import logging

from ..process_tree import tree_from_log
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def build_process_tree(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    procmon_log_path = analysis_dir / "procmon.log"
    process_tree_path = analysis_dir / "process_tree.json"

    with procmon_log_path.open("r") as procmon_log:
        process_tree = tree_from_log(procmon_log)

    data = json.dumps(process_tree.as_dict())
    process_tree_path.write_text(data)

    context.process_tree = process_tree
