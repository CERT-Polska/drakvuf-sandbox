import shutil
import os
import contextlib


@contextlib.contextmanager
def remove_files(paths):

    # change names
    for i in paths:
        try:
            shutil.move(i, f"{i}.bak")
        except FileNotFoundError:
            pass

    yield

    # restore the names
    for i in paths:
        try:
            shutil.move(f"{i}.bak", i)
        except FileNotFoundError:
            pass
