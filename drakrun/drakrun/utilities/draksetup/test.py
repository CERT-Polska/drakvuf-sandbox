import sys

import click

from ._xen_check import sanity_check


@click.command(help="Perform self-test to check Xen installation")
def test():
    if not sanity_check():
        sys.exit(1)
