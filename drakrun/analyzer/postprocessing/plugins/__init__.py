from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP, IPT_DIR, IPT_ZIP

from .build_process_tree import build_process_tree
from .capa_plugin.capa_processor import capa_analysis
from .compress_ipt import compress_ipt
from .generate_report import generate_report
from .generate_wireshark_key_file import generate_wireshark_key_file
from .get_http_info import get_http_info
from .get_modified_files_info import get_modified_files_info
from .get_socket_info import get_socket_info
from .get_ttps_info import get_ttps_info
from .gzip_syscalls import gzip_syscalls
from .index_logs import index_logs
from .plugin_base import PostprocessPlugin
from .process_dumps import process_dumps
from .screenshot_metadata import screenshot_metadata
from .split_drakmon_log import split_drakmon_log

POSTPROCESS_PLUGINS = [
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
        generates=[],  # Always regenerate
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
        function=screenshot_metadata,
        requires=["screenshots.json"],
        generates=[],
    ),
    PostprocessPlugin(
        function=process_dumps,
        requires=[DUMPS_DIR, "memdump.log", "process_tree.json"],
        generates=[DUMPS_ZIP],
    ),
    PostprocessPlugin(function=compress_ipt, requires=[IPT_DIR], generates=[IPT_ZIP]),
    PostprocessPlugin(
        function=gzip_syscalls, requires=["syscall.log"], generates=["syscall.log.gz"]
    ),
    PostprocessPlugin(
        function=get_http_info,
        requires=["process_tree.json", "apimon.log"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_modified_files_info,
        requires=["process_tree.json", "filetracer.log"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_socket_info,
        requires=["process_tree.json", "socketmon.log"],
        generates=[],
    ),
    PostprocessPlugin(
        function=get_ttps_info,
        requires=["process_tree.json", "ttps.json"],
        generates=[],
    ),
    PostprocessPlugin(
        function=generate_report,
        requires=[],
        generates=[],
    ),
    PostprocessPlugin(
        function=index_logs, requires=["process_tree.json"], generates=["log_index"]
    ),
]
