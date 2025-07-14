import json
import logging

from .. import PostprocessContext
from ..process_tree import tree_from_log

logger = logging.getLogger(__name__)


def build_process_tree(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    procmon_log_path = analysis_dir / "procmon.log"
    process_tree_path = analysis_dir / "process_tree.json"

    with procmon_log_path.open("r") as procmon_log:
        process_tree = tree_from_log(procmon_log).as_dict()
        data = json.dumps(process_tree)
        process_tree_path.write_text(data)
