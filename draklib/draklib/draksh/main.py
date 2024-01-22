import logging

import click


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def main(verbose):
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="[%(asctime)s][%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler()],
    )
