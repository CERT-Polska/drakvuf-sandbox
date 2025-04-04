import pathlib

import click

from drakrun.analyzer.postprocessing import postprocess_output_dir


@click.command("postprocess")
@click.argument(
    "output_dir",
    type=click.Path(exists=True),
)
def postprocess(output_dir):
    """
    Run postprocessing on analysis output
    """
    output_dir = pathlib.Path(output_dir)
    postprocess_output_dir(output_dir)
