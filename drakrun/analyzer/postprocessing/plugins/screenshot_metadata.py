import json

from .plugin_base import PostprocessContext


def screenshot_metadata(context: PostprocessContext) -> None:
    """
    Checks if every line is parseable and exposes screenshot amount in metadata object.
    We can perform some postprocessing here if needed in the future.
    """
    analysis_dir = context.analysis_dir
    screenshots_data = (analysis_dir / "screenshots.json").read_text().splitlines()
    last_index = 0
    for dataline in screenshots_data:
        if dataline:
            screenshot_data = json.loads(dataline)
            last_index = screenshot_data["index"]
    context.update_metadata({"screenshots": last_index})
