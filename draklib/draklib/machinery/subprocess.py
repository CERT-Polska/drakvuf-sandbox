"""
Subprocess with logging
"""
import functools
import logging
import subprocess
from typing import Any, Callable, TypeVar

log = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


def decorate_with_logger(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        log.debug(f"Running shell command '{args[0]}'")
        return fn(*args, **kwargs)

    return wrapper


check_output = decorate_with_logger(subprocess.check_output)
run = decorate_with_logger(subprocess.run)
Popen = decorate_with_logger(subprocess.Popen)
