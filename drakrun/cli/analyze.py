import pathlib
from datetime import datetime

import click

from .check_root import check_root


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
    "--preset",
    "preset",
    default=None,
    type=str,
    help="Use specified defaults preset from configuration",
)
@click.option(
    "--target-filename",
    "target_filename",
    default=None,
    type=str,
    help="Target file name where sample will be copied on a VM",
)
@click.option(
    "--target-filepath",
    "target_filepath",
    default=None,
    type=str,
    help="Target file path where sample will be copied on a VM",
)
@click.option(
    "--start-command",
    "start_command",
    default=None,
    type=str,
    help="Start command to use for sample execution",
)
@click.option(
    "--plugin",
    "plugins",
    default=None,
    multiple=True,
    help="Plugin name to use instead of default list (you can provide multiple ones)",
)
@click.option(
    "--net-enable/--net-disable",
    "net_enable",
    default=None,
    help="Enable/disable Internet access for analysis",
)
@click.option(
    "--no-restore",
    "no_restore",
    is_flag=True,
    help="Don't restore VM for analysis (assume it's already running)",
)
@click.option(
    "--no-post-restore",
    "no_post_restore",
    is_flag=True,
    help="Don't run a post-restore script",
)
@click.option(
    "--no-screenshotter",
    "no_screenshotter",
    is_flag=True,
    help="Don't make screenshots during analysis",
)
@click.option(
    "--extract-archive",
    "extract_archive",
    is_flag=True,
    help="Treat file as an ZIP archive and extract it during analysis",
)
@click.option(
    "--archive-password",
    "archive_password",
    type=str,
    help="Optional password to use for extracting archive (works only when 7-zip is used for extraction)",
)
@check_root
def analyze(
    vm_id,
    output_dir,
    sample,
    timeout,
    preset,
    target_filename,
    target_filepath,
    start_command,
    plugins,
    net_enable,
    no_restore,
    no_post_restore,
    no_screenshotter,
    extract_archive,
    archive_password,
):
    """
    Run a CLI analysis using Drakvuf
    """
    from drakrun.analyzer.analysis_options import AnalysisOptions
    from drakrun.analyzer.analyzer import analyze_file
    from drakrun.analyzer.postprocessing import append_metadata_to_analysis
    from drakrun.lib.config import load_config

    config = load_config()
    if output_dir is None:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        output_dir = pathlib.Path("./analysis_{}".format(timestamp))
    else:
        output_dir = pathlib.Path(output_dir)
        if output_dir.exists():
            click.echo(f"{output_dir} already exists.")
            raise click.Abort()

    output_dir.mkdir()

    if sample is not None:
        sample = pathlib.Path(sample)

    if not plugins:
        # If plugins not provided, pass None to indicate
        # that we want to use a configured default.
        # Click passes empty list there.
        plugins = None

    options = AnalysisOptions(
        config=config,
        preset=preset,
        sample_path=sample,
        timeout=timeout,
        net_enable=net_enable,
        target_filename=target_filename,
        start_command=start_command,
        plugins=plugins,
        no_vm_restore=no_restore,
        no_post_restore=no_post_restore,
        no_screenshotter=no_screenshotter,
        extract_archive=extract_archive,
        archive_password=archive_password,
    )

    if target_filepath is not None:
        options.target_filepath = pathlib.PureWindowsPath(target_filepath)

    extra_metadata = analyze_file(vm_id=vm_id, output_dir=output_dir, options=options)
    append_metadata_to_analysis(output_dir, extra_metadata)
