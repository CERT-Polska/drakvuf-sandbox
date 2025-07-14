import logging
import pathlib
from typing import Callable, Iterator, Optional

import orjson

logger = logging.getLogger(__name__)


def parse_log(
    log_file: pathlib.Path, filter_cb: Callable[[dict], Optional[dict]]
) -> Iterator[dict]:
    with log_file.open("r") as f:
        for line_no, line in enumerate(f):
            try:
                data = orjson.loads(line)
                if result := filter_cb(data):
                    yield result
            except Exception:
                logger.exception(
                    "Failed to parse line %d of %s", line_no + 1, log_file.as_posix()
                )
