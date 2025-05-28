import uuid
from typing import Annotated, List, Optional

from flask_openapi3 import FileStorage
from pydantic import AfterValidator, BaseModel, Field, RootModel


class APIErrorResponse(BaseModel):
    error: str = Field(description="Error message")


class UploadFileForm(BaseModel):
    file: FileStorage
    timeout: Optional[int] = Field(default=None, description="Analysis timeout")
    file_name: Optional[str] = Field(default=None, description="Target file name")
    start_command: Optional[str] = Field(default=None, description="Start command")
    plugins: Optional[List[str]] = Field(
        default=None, description="Plugins to use (in JSON array string)"
    )


class UploadAnalysisResponse(BaseModel):
    task_uid: str = Field(description="Unique analysis ID")


class AnalysisResponse(BaseModel):
    id: str = Field(description="Unique analysis ID")
    status: str = Field(description="Analysis status")
    time_started: Optional[str] = Field(
        default=None, description="Analysis start time in ISO format"
    )
    time_ended: Optional[str] = Field(
        default=None, description="Analysis end time in ISO format"
    )


AnalysisListResponse = RootModel[List[AnalysisResponse]]


class AnalysisRequestPath(BaseModel):
    task_uid: Annotated[str, AfterValidator(lambda x: str(uuid.UUID(x, version=4)))] = (
        Field(description="Unique analysis ID")
    )


class ProcessedRequestPath(AnalysisRequestPath):
    which: str


class LogsRequestPath(AnalysisRequestPath):
    log_type: str


class ProcessInfoRequestPath(AnalysisRequestPath):
    seqid: int


class ProcessLogsRequestPath(AnalysisRequestPath):
    log_type: str
    seqid: int


class ScreenshotRequestPath(AnalysisRequestPath):
    which: int
