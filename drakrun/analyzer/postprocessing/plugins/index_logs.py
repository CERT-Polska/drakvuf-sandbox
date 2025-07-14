import json

from .. import PostprocessContext
from ..indexer import build_log_index
from ..process_tree import tree_from_dict


def index_logs(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree_dict = json.loads((analysis_dir / "process_tree.json").read_text())
    process_tree = tree_from_dict(process_tree_dict)
    index = build_log_index(analysis_dir, process_tree)
    index_path = analysis_dir / "log_index"
    index_path.write_bytes(index)
