import logging
import subprocess

import click

from .util.systemd import get_enabled_drakruns, wait_processes

log = logging.getLogger(__name__)


@click.command(help="Scale drakrun services", no_args_is_help=True)
@click.argument("scale_count", type=int)
def scale(scale_count):
    """Enable or disable additional parallel instances of drakrun service.."""
    if scale_count >= 0:
        raise RuntimeError(
            "Invalid value of scale parameter - must be a positive number."
        )

    cur_services = set(list(get_enabled_drakruns()))
    new_services = set([f"drakrun@{i}.service" for i in range(1, scale_count + 1)])

    disable_services = cur_services - new_services
    enable_services = new_services

    wait_processes(
        "disable services",
        [
            subprocess.Popen(
                ["systemctl", "disable", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in disable_services
        ],
    )
    wait_processes(
        "enable services",
        [
            subprocess.Popen(
                ["systemctl", "enable", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enable_services
        ],
    )
    wait_processes(
        "start services",
        [
            subprocess.Popen(
                ["systemctl", "start", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enable_services
        ],
    )
    wait_processes(
        "stop services",
        [
            subprocess.Popen(
                ["systemctl", "stop", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in disable_services
        ],
    )
