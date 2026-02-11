import base64
import json

from drakrun.lib.config import S3StorageConfigSection
from drakrun.lib.paths import PACKAGE_DIR

from .storage import read_analysis_file, read_analysis_json

HTML_TEMPLATE = PACKAGE_DIR / "web/frontend/dist/embedded/index.html"
OFFLINE_FILES_PLACEHOLDER = "window.OFFLINE_FILES = {};"


def png_bytes_to_data_uri(png_bytes: bytes):
    encoded = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def generate_html_report(analysis_id: str, s3_config: S3StorageConfigSection):
    offline_files = {
        "metadata.json": read_analysis_json(analysis_id, "metadata.json", s3_config),
        "report.json": read_analysis_file(analysis_id, "report.json", s3_config),
        "screenshots": [],
    }
    try:
        offline_files["process_tree.json"] = read_analysis_file(
            analysis_id, "process_tree.json", s3_config
        )
    except FileNotFoundError:
        pass

    screenshots_count = offline_files["metadata.json"].get("screenshots", 0)
    for which in range(screenshots_count):
        screenshot_data_uri = png_bytes_to_data_uri(
            read_analysis_file(
                analysis_id, f"screenshots/screenshot_{which}.png", s3_config
            )
        )
        offline_files["screenshots"].append(screenshot_data_uri)

    return HTML_TEMPLATE.read_text().replace(
        OFFLINE_FILES_PLACEHOLDER, f"window.OFFLINE_FILES={json.dumps(offline_files)};"
    )
