import json
import logging
import pathlib
from typing import Any, Dict

from .plugins import POSTPROCESS_PLUGINS
from .plugins.plugin_base import PostprocessPlugin

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


def run_postprocessing(analysis_dir: pathlib.Path):
    extra_metadata = {}
    for plugin in POSTPROCESS_PLUGINS:
        plugin_name = plugin.function.__name__
        if not check_plugin_requirements(analysis_dir, plugin):
            continue
        try:
            plugin_metadata = plugin.function(analysis_dir)
            if plugin_metadata:
                extra_metadata.update(plugin_metadata)
        except Exception:
            logger.exception(f"{plugin_name} failed with uncaught exception")
    return extra_metadata


def append_metadata_to_analysis(
    analysis_dir: pathlib.Path, extra_metadata: Dict[str, Any]
):
    metadata_path = analysis_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text())
    metadata.update(extra_metadata)
    metadata_path.write_text(json.dumps(metadata))


def postprocess_output_dir(output_dir: pathlib.Path):
    return run_postprocessing(output_dir)
