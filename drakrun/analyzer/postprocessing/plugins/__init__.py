from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP, IPT_DIR, IPT_ZIP

from .build_process_tree import build_process_tree
from .capa_plugin.capa_processor import capa_analysis
from .compress_ipt import compress_ipt
from .crop_dumps import crop_dumps
from .generate_graphs import generate_graphs
from .generate_report import build_report
from .generate_wireshark_key_file import generate_wireshark_key_file
from .index_logs import index_logs
from .plugin_base import PostprocessPlugin
from .screenshot_metadata import screenshot_metadata
from .split_drakmon_log import split_drakmon_log

POSTPROCESS_PLUGINS = [
    PostprocessPlugin(
        function=generate_graphs, requires=["drakmon.log"], generates=["graph.dot"]
    ),
    PostprocessPlugin(
        function=split_drakmon_log, requires=["drakmon.log"], generates=[]
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
    PostprocessPlugin(
        function=capa_analysis,
        requires=[
            "process_tree.json",
            "inject.log",
        ],
        generates=["ttps.json"],
    ),
    PostprocessPlugin(
        function=build_report,
        requires=[],
        generates=["report.json"],
    ),
    PostprocessPlugin(
        function=screenshot_metadata,
        requires=["screenshots.json"],
        generates=[],
    ),
    PostprocessPlugin(function=crop_dumps, requires=[DUMPS_DIR], generates=[DUMPS_ZIP]),
    PostprocessPlugin(function=compress_ipt, requires=[IPT_DIR], generates=[IPT_ZIP]),
    PostprocessPlugin(
        function=index_logs, requires=["procmon.log"], generates=["index"]
    ),
]
