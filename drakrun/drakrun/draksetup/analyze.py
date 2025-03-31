import pathlib
from datetime import datetime

import click

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.analyzer import analyze_file


@click.command("analyze")
@click.option(
    "--vm-id",
    "vm_id",
    default=1,
    type=int,
    show_default=True,
    help="VM id to use for analysis",
)
@click.option(
    "--output-dir",
    "output_dir",
    default=None,
    type=click.Path(exists=False),
    show_default=True,
    help="Output directory for analysis (default is analysis_<timestamp>)",
)
@click.option(
    "--sample",
    "sample",
    default=None,
    type=click.Path(exists=True),
    show_default=True,
    help="Sample to inject and execute (if not provided, assumes that executable will be executed manually)",
)
def analyze(vm_id, output_dir, sample):
    if output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_dir = pathlib.Path("./analysis_{}".format(timestamp))
    output_dir.mkdir(exist_ok=True)
    options = AnalysisOptions(
        vm_id=vm_id,
        output_dir=output_dir,
        sample_path=sample,
    )
    analyze_file(options)
