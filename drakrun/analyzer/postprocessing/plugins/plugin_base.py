import pathlib
from typing import Any, Dict, List, NamedTuple, Optional, Protocol

from drakrun.lib.config import DrakrunConfig

from ...analysis_options import AnalysisOptions
from ..process_tree import ProcessTree


class PostprocessContext:
    def __init__(
        self,
        analysis_dir: pathlib.Path,
        config: DrakrunConfig,
        options: Optional[AnalysisOptions] = None,
    ) -> None:
        self.analysis_dir = analysis_dir
        self.config = config
        self.options = options
        self._process_tree: Optional[ProcessTree] = None
        # Quick metadata fetched along with analysis status
        self.metadata = {}
        # More verbose data to be placed in report.json
        self.report = {}

    @property
    def process_tree(self) -> ProcessTree:
        if self._process_tree is None:
            raise RuntimeError("Process tree not initialized")
        return self._process_tree

    @process_tree.setter
    def process_tree(self, value: ProcessTree) -> None:
        self._process_tree = value

    def update_metadata(self, metadata: Dict[str, Any]) -> None:
        self.metadata.update(metadata)

    def update_report(self, report: Dict[str, Any]) -> None:
        self.report.update(report)


class PostprocessFunction(Protocol):
    def __call__(self, context: PostprocessContext) -> None: ...


class PostprocessPlugin(NamedTuple):
    function: PostprocessFunction
    # Paths that are required by plugin to run
    requires: List[str]
    # Paths that are products of processing and plugin is not run when they exist
    generates: List[str]
