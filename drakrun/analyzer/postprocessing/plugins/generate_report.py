import logging
from pathlib import Path
from typing import Dict

import orjson

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def get_metadata(analysis_dir: Path) -> Dict:
    # Currently, all metadata is contained in the metadata.json file
    metadata_file = analysis_dir / "metadata.json"
    with metadata_file.open("r") as f:
        metadata = orjson.loads(f.read())

    return metadata


def generate_report(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    report = {"info": get_metadata(analysis_dir), **context.report}

    with (analysis_dir / "report.json").open("wb") as f:
        f.write(orjson.dumps(report, option=orjson.OPT_INDENT_2))
