import logging
import os


def check_root():
    if os.getuid() != 0:
        logging.error("Please run the command as root")
        return False
    else:
        return True
