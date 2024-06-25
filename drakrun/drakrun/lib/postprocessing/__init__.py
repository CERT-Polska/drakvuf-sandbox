import pathlib
from typing import Any, Dict, List, NamedTuple, Optional, Protocol

from .build_process_tree import build_process_tree
from .compress_ipt import compress_ipt
from .crop_dumps import crop_dumps
from .generate_graphs import generate_graphs
from .generate_wireshark_key_file import generate_wireshark_key_file
from .index_logs import index_logs
from .process_apimon_log import process_apimon_log
from .split_drakmon_log import split_drakmon_log


class PostprocessFunction(Protocol):
    def __call__(self, analysis_dir: pathlib.Path) -> Optional[Dict[str, Any]]:
        ...


class PostprocessPlugin(NamedTuple):
    function: PostprocessFunction
    # Paths that are required by plugin to run
    requires: List[str]
    # Paths that are products of processing and plugin is not run when they exist
    generates: List[str]


POSTPROCESS_PLUGINS = [
    PostprocessPlugin(
        function=generate_graphs, requires=["drakmon.log"], generates=["graph.dot"]
    ),
    PostprocessPlugin(
        function=split_drakmon_log, requires=["drakmon.log"], generates=[]
    ),
    PostprocessPlugin(
        function=process_apimon_log, requires=["apimon.log"], generates=["apicalls"]
    ),
    PostprocessPlugin(
        function=generate_wireshark_key_file,
        requires=["tlsmon.log"],
        generates=["wireshark_key_file.txt"],
    ),
    PostprocessPlugin(
        function=build_process_tree,
        requires=["procmon.log"],
        generates=["process_tree.json"],
    ),
    PostprocessPlugin(function=crop_dumps, requires=["dumps"], generates=["dumps.zip"]),
    PostprocessPlugin(function=compress_ipt, requires=["ipt"], generates=["ipt.zip"]),
    PostprocessPlugin(function=index_logs, requires=[], generates=["index"]),
]
