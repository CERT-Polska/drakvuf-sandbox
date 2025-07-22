import pathlib

import click

from drakrun.lib.config import load_config


@click.command("postprocess")
@click.argument(
    "output_dir",
    type=click.Path(exists=True),
)
def postprocess(output_dir):
    """
    Run postprocessing on analysis output
    """
    from drakrun.analyzer.postprocessing import (
        append_metadata_to_analysis,
        postprocess_analysis_dir,
    )

    config = load_config()
    output_dir = pathlib.Path(output_dir)
    extra_metadata = postprocess_analysis_dir(output_dir, config)
    append_metadata_to_analysis(output_dir, extra_metadata)
