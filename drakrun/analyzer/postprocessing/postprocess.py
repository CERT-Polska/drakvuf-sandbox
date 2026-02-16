import logging
import pathlib

from drakrun.lib.config import DrakrunConfig

from ..analysis_metadata import AnalysisMetadata
from .plugins import POSTPROCESS_PLUGINS
from .plugins.plugin_base import PostprocessContext, PostprocessPlugin

logger = logging.getLogger(__name__)


def check_plugin_requirements(
    analysis_dir: pathlib.Path, plugin: PostprocessPlugin
) -> bool:
    plugin_name = plugin.function.__name__
    for required_path in plugin.requires:
        if not (analysis_dir / required_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {required_path} does not exist"
            )
            return False
    for generated_path in plugin.generates:
        if (analysis_dir / generated_path).exists():
            logger.warning(
                f"{plugin_name} won't be run because {generated_path} already exists"
            )
            return False
    return True


def run_postprocessing(context: PostprocessContext):
    for plugin in POSTPROCESS_PLUGINS:
        plugin_name = plugin.function.__name__
        if not check_plugin_requirements(context.analysis_dir, plugin):
            continue
        try:
            plugin.function(context)
        except Exception:
            logger.exception(f"{plugin_name} failed with uncaught exception")


def postprocess_analysis_dir(
    analysis_dir: pathlib.Path, config: DrakrunConfig, metadata: AnalysisMetadata
):
    context = PostprocessContext(
        analysis_dir=analysis_dir,
        config=config,
        metadata=metadata,
    )
    run_postprocessing(context)
    return context.metadata
