import json
import logging
import pathlib
from typing import Any, Dict

from drakrun.lib.config import DrakrunConfig

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


def append_metadata_to_analysis(
    analysis_dir: pathlib.Path, extra_metadata: Dict[str, Any]
):
    metadata_path = analysis_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
    metadata.update(extra_metadata)
    metadata_path.write_text(json.dumps(metadata))


def postprocess_analysis_dir(analysis_dir: pathlib.Path, config: DrakrunConfig):
    context = PostprocessContext(
        analysis_dir=analysis_dir,
        config=config,
    )
    run_postprocessing(context)
    return context.metadata
