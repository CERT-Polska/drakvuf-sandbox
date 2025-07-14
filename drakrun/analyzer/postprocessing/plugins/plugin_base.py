import pathlib
from typing import Any, Dict, List, NamedTuple, Optional, Protocol

from drakrun.lib.config import DrakrunConfig


class PostprocessContext:
    def __init__(self, analysis_dir: pathlib.Path, config: DrakrunConfig) -> None:
        self.analysis_dir = analysis_dir
        self.config = config


class PostprocessFunction(Protocol):
    def __call__(self, context: PostprocessContext) -> Optional[Dict[str, Any]]: ...


class PostprocessPlugin(NamedTuple):
    function: PostprocessFunction
    # Paths that are required by plugin to run
    requires: List[str]
    # Paths that are products of processing and plugin is not run when they exist
    generates: List[str]
