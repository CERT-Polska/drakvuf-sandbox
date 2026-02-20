import logging

import click

from drakrun.lib.version_detection import (
    MINIMUM_SUPPORTED_DRAKVUF_VERSION,
    get_drakvuf_version,
    is_drakvuf_supported,
)
from drakrun.version import __version__

log = logging.getLogger(__name__)


@click.command("version", help="Show Drakvuf and Drakvuf Sandbox version information")
def version():
    drakvuf_version = get_drakvuf_version()
    log.info("DRAKVUF Sandbox version: %s", __version__)
    log.info(
        "DRAKVUF version: %s.%s-%s",
        drakvuf_version.major,
        drakvuf_version.minor,
        drakvuf_version.build,
    )
    log.info(" - Debug build: %s", drakvuf_version.debug_build)
    log.info(
        " - ShellExecute verb support: %s", drakvuf_version.supports_shellexec_verb
    )

    if not is_drakvuf_supported(drakvuf_version):
        log.warning(
            "Current DRAKVUF version is not supported. Minimum supported version is %d.%d",
            *MINIMUM_SUPPORTED_DRAKVUF_VERSION[0]
        )
