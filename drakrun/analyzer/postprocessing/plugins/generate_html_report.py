import base64
import json
import logging

from drakrun.lib.paths import PACKAGE_DIR

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

HTML_TEMPLATE = PACKAGE_DIR / "web/frontend/dist/embedded/index.html"
OFFLINE_FILES_PLACEHOLDER = "window.OFFLINE_FILES = {};"


def png_bytes_to_data_uri(png_bytes: bytes):
    encoded = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def generate_html_report(context: PostprocessContext):
    offline_files = {}

    metadata_file = context.analysis_dir / "metadata.json"
    with metadata_file.open("r") as f:
        offline_files["metadata.json"] = json.load(f)

    report_file = context.analysis_dir / "report.json"
    with report_file.open("r") as f:
        offline_files["report.json"] = json.load(f)

    process_tree_file = context.analysis_dir / "process_tree.json"
    if process_tree_file.exists():
        with process_tree_file.open("r") as f:
            offline_files["process_tree.json"] = json.load(f)

    screenshots_count = offline_files["metadata.json"].get("screenshots", 0)
    for which in range(screenshots_count):
        with (context.analysis_dir / f"screenshots/screenshot_{which}.png").open(
            "rb"
        ) as f:
            screenshot_data_uri = png_bytes_to_data_uri(f.read())
            offline_files["screenshots"].append(screenshot_data_uri)

    html_report = HTML_TEMPLATE.read_text().replace(
        OFFLINE_FILES_PLACEHOLDER, f"window.OFFLINE_FILES={json.dumps(offline_files)};"
    )
    (context.analysis_dir / "report.html").write_text(html_report)
    return {"html_report": True}
