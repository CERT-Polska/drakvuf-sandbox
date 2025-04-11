from pydantic import BaseModel


class FileMetadata(BaseModel):
    name: str
    type: str
    sha256: str

    def to_dict(self):
        return self.model_dump(mode="json")
