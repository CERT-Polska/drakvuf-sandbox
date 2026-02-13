from typing import Optional

from pydantic import BaseModel, ConfigDict

from drakrun.analyzer.analysis_options import AnalysisOptions


class FileMetadata(BaseModel):
    name: str
    type: str
    sha256: str

    def to_dict(self):
        return self.model_dump(mode="json")


class AnalysisMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    options: AnalysisOptions
    time_started: str
    time_finished: Optional[str] = None
    time_execution_started: Optional[str] = None
    # Status of the job
    status: Optional[str] = None
    # Detailed status (doesn't occur in metadata.json)
    substatus: Optional[str] = None
    # Guest VM id where sample was executed
    vm_id: Optional[int] = None
    # File metadata (None in case of fileless analysis - possible via CLI)
    file: Optional[FileMetadata] = None
