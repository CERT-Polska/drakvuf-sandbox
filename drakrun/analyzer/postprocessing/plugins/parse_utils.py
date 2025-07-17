import ast
import logging
import pathlib
import string
from datetime import datetime, timezone
from typing import Callable, Iterator, List, Optional, Union

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


def trim_method_name(method: str) -> str:
    """
    WinAPI has two variants for each method using strings: Unicode (W) and ANSI (A).
    We don't care about it, it's easier to trim it from the method name while processing.
    """
    if method[-1] in ["A", "W"] and method[-2] in (
        string.ascii_lowercase + string.digits
    ):
        return method[:-1]
    return method


def parse_apimon_arguments(args: List[str]) -> List[Union[int, str]]:
    parsed_args = []
    for arg in args:
        if not arg.startswith("Arg"):
            raise RuntimeError(f"Wrong argument format: {arg}")
        _, value = arg.split("=", 1)
        if ":" not in value:
            parsed_args.append(int(value, 16))
            continue
        _, str_value = arg.split(":", 1)
        parsed_args.append(ast.literal_eval(str_value))
    return parsed_args


def epoch_to_timestring(unix_time: Optional[float]) -> Optional[str]:
    # This method converts a unix epoch time into a formated time string.
    # Example:
    #   Input: 1716998460.000
    #   Return: '2024-05-29 17:01:00'
    if not unix_time:
        # Sometimes the time in the logs would be zero or None
        return None

    tm = datetime.fromtimestamp(unix_time, tz=timezone.utc)
    return tm.isoformat()
