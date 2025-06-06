import logging
import textwrap

log = logging.getLogger(__name__)


def banner(banner_text):
    log.info("-" * 80)
    for banner_line in textwrap.dedent(banner_text).splitlines():
        log.info(banner_line)
    log.info("-" * 80)
