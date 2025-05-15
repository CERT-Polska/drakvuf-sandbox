import pathlib
from typing import Any, Dict, List, NamedTuple, Optional, Protocol


class PostprocessFunction(Protocol):
    def __call__(self, analysis_dir: pathlib.Path) -> Optional[Dict[str, Any]]: ...


class PostprocessPlugin(NamedTuple):
    function: PostprocessFunction
    # Paths that are required by plugin to run
    requires: List[str]
    # Paths that are products of processing and plugin is not run when they exist
    generates: List[str]
