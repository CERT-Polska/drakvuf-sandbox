from ..indexer import build_log_index
from .plugin_base import PostprocessContext


def index_logs(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree
    index = build_log_index(analysis_dir, process_tree)
    index_path = analysis_dir / "log_index"
    index_path.write_bytes(index)
