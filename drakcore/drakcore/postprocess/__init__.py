from collections import namedtuple

from drakcore.postprocess.apicall import process_api_log
from drakcore.postprocess.cache_update import insert_metadata
from drakcore.postprocess.generate_graphs import generate_graphs
from drakcore.postprocess.log_index import generate_log_index
from drakcore.postprocess.pstree import build_process_tree
from drakcore.postprocess.slice_logs import slice_drakmon_logs
from drakcore.postprocess.delete_drakmon_log import delete_drakmon_log

PostprocessPlugin = namedtuple("PostprocessPlugin", ('handler', 'required'))

REGISTERED_PLUGINS = [
    # yields graph.dot
    PostprocessPlugin(generate_graphs, required=['drakmon.log']),
    # raw log is sliced into per-plugin log files,
    # yields e.g. procmon.log, syscalls.log etc.
    # deletes drakmon.log
    PostprocessPlugin(slice_drakmon_logs, required=['drakmon.log']),

    # yields apicall/{pid}.json
    PostprocessPlugin(process_api_log, required=['apimon.log']),
    # yields process_tree.json
    PostprocessPlugin(build_process_tree, required=['procmon.log']),

    # yields index/{name}
    PostprocessPlugin(generate_log_index, required=[]),
    # this should be the final step
    PostprocessPlugin(insert_metadata, required=['metadata.json'])
]
