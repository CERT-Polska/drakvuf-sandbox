from typing import Optional

from pydantic import BaseModel

from analyzer.analysis_options import AnalysisOptions


class FileMetadata(BaseModel):
    name: str
    type: str
    sha256: str

    def to_dict(self):
        return self.model_dump(mode="json")


class AnalysisMetadata(BaseModel):
    id: str
    options: AnalysisOptions
    time_started: str
    time_finished: Optional[str]
    time_execution_started: Optional[str]
    vm_id: Optional[int]
    file: Optional[FileMetadata]
    postprocess: Optional[dict]
