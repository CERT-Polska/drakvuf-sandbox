import hashlib
import json
import pathlib
from typing import Any, Optional

import magic
from pydantic import BaseModel, ConfigDict

from drakrun.analyzer.analysis_options import AnalysisOptions


class FileMetadata(BaseModel):
    name: str
    type: str
    sha256: str

    @classmethod
    def evaluate(cls, file_path: pathlib.Path, file_name: Optional[str] = None):
        sample_sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(32 * 4096), b""):
                sample_sha256.update(chunk)
        sample_magic = magic.from_file(file_path)
        if not file_name:
            file_name = file_path.name
        return cls(
            name=file_name,
            type=sample_magic,
            sha256=sample_sha256.hexdigest(),
        )

    def to_dict(self):
        return self.model_dump(mode="json")


class AnalysisMetadata(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    options: AnalysisOptions
    time_started: Optional[str] = None
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

    @classmethod
    def load_from_dict(cls, obj: dict[str, Any]):
        return cls.model_validate(obj)

    @classmethod
    def load_from_file(cls, path: pathlib.Path):
        with path.open("r") as f:
            json_obj = json.load(f)
        return cls.load_from_dict(json_obj)

    def store_to_dict(self):
        return self.model_dump(mode="json", exclude_none=True)

    def store_to_file(self, path: pathlib.Path):
        json_obj = self.store_to_dict()
        with path.open("w") as f:
            json.dump(json_obj, f)
