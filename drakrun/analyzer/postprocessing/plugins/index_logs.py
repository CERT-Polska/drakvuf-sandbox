import json
import pathlib

from ..indexer import index_log_file
from ..process_tree import tree_from_log


def index_logs(analysis_dir: pathlib.Path) -> None:
    index_dir = analysis_dir / "index"
    index_dir.mkdir(exist_ok=True)

    # TODO: I need ProcessTree object but right now
    #       I can't easily load it from process_tree.json

    procmon_log_path = analysis_dir / "procmon.log"
    with procmon_log_path.open("r") as procmon_log:
        process_tree = tree_from_log(procmon_log)

    for log_file_path in analysis_dir.glob("*.log"):
        plugin_name = log_file_path.stem
        if plugin_name == "drakrun":
            continue
        index = index_log_file(
            log_file_path,
            process_tree,
            key="Method",
        )

        for seqid in index.keys():
            index_path = index_dir / f"{plugin_name}.{seqid}.json"
            index_path.write_text(json.dumps(index[seqid]))
