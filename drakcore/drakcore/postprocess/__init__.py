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


fdir = os.path.dirname(__file__)
for module in sorted(os.listdir(fdir)):
    # skip __init__ or __pycache__
    if module.startswith("__") or not module.endswith(".py"):
        continue
    modname = module[:-3]
    importlib.import_module(f"drakcore.postprocess.{modname}")
