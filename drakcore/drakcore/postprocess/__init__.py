import importlib
import os.path
from collections import namedtuple

REGISTERED_PLUGINS = []

PostprocessPlugin = namedtuple("PostprocessPlugin", ('required', 'handler'))


def postprocess(required=[]):
    """ Register function as analysis postprocess """
    def wrapper(func):
        plugin = PostprocessPlugin(required, func)
        REGISTERED_PLUGINS.append(plugin)
    return wrapper


# plugins will be called in load order
# preliminary stage
import drakcore.postprocess.slice_logs

# middle stage
import drakcore.postprocess.pstree
import drakcore.postprocess.apicall
import drakcore.postprocess.generate_graphs

# final stage
import drakcore.postprocess.log_index
import drakcore.postprocess.cache_update
