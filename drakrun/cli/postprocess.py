import json
import pathlib

import click

from drakrun.analyzer.analysis_metadata import AnalysisMetadata
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
    from drakrun.analyzer.postprocessing import postprocess_analysis_dir

    config = load_config()
    output_dir = pathlib.Path(output_dir)

    metadata_file = output_dir / "metadata.json"
    metadata_dict = json.loads(metadata_file.read_text())
    metadata = AnalysisMetadata.model_validate(metadata_dict)

    extra_metadata = postprocess_analysis_dir(output_dir, config, metadata)
    metadata.model_extra.update(extra_metadata)
    metadata_file.write_text(
        json.dumps(metadata.model_dump(mode="json", exclude_none=True))
    )
