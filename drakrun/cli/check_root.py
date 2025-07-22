import functools
import logging
import os

import click


def check_root(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if os.geteuid() != 0:
            logging.error("You need to have root privileges to run this command.")
            raise click.Abort()
        return fn(*args, **kwargs)

    return wrapper
