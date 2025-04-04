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
@click.option(
    "--timeout",
    "timeout",
    default=None,
    type=int,
    help="Analysis timeout (default is None, analysis interrupted on CTRL-C)",
)
@click.option(
    "--options",
    "options_file",
    default=None,
    type=click.Path(exists=True),
    show_default=True,
    help="File with additional analysis options",
)
def analyze(vm_id, output_dir, sample, timeout, options_file):
    """
    Run a CLI analysis using Drakvuf
    """
    if output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_dir = pathlib.Path("./analysis_{}".format(timestamp))
    if sample is not None:
        sample = pathlib.Path(sample)
    options = AnalysisOptions(
        vm_id=vm_id,
        output_dir=output_dir,
        sample_path=sample,
        timeout=timeout,
    )
    if options_file is not None:
        options = options.load(options_file)
    analyze_file(options)
