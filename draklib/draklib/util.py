import json
import logging
from pathlib import Path

from dataclasses_json import DataClassJsonMixin

log = logging.getLogger(__name__)


def ensure_delete(file_path: Path, raise_on_error: bool = False) -> bool:
    try:
        if file_path.exists():
            file_path.unlink()
            log.info(f"Deleted {file_path}")
        else:
            log.info(f"Already deleted {file_path}")
        return True
    except OSError as e:
        if raise_on_error:
            raise
        logging.warning(f"{e.filename}: {e.strerror}")
        return False


class DataClassConfigMixin(DataClassJsonMixin):
    _FILENAME: str

    @classmethod
    def load(cls, config_dir_path: Path):
        with (config_dir_path / cls._FILENAME).open("r") as f:
            return cls.from_json(f.read())

    @classmethod
    def try_load(cls, config_dir_path: Path):
        try:
            return cls.load(config_dir_path)
        except FileNotFoundError:
            return None

    @classmethod
    def delete(cls, config_dir_path: Path):
        ensure_delete(config_dir_path / cls._FILENAME, raise_on_error=True)

    def save(self, config_dir_path: Path):
        with (config_dir_path / self._FILENAME).open("w") as f:
            f.write(json.dumps(self.to_dict(), indent=4))
