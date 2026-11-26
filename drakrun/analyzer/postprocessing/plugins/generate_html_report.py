import base64
import gzip
import json
import logging

from drakrun.lib.paths import PACKAGE_DIR

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)

HTML_TEMPLATE = PACKAGE_DIR / "web/frontend/dist/embedded/index.html"
# Must match drakrun/web/frontend/embedded/index.html and html_report_main.jsx
OFFLINE_FILES_PLACEHOLDER = 'window.OFFLINE_FILES_GZIP_BASE64 = "";'


def encode_offline_files(offline_files) -> str:
    """
    Encode the report data for embedding in report.html: JSON, gzip, base64.

    The data contains strings controlled by the analyzed sample (process command
    lines, file paths, domains...), so it must not be embedded as JSON source text:
    a string like "</script>" would end the <script> element and the markup after
    it would run when the report is opened. Base64 output uses only
    [A-Za-z0-9+/=], which can't end a JS string literal or the <script> element.
    Gzip makes up for the base64 overhead (the JSON part compresses several times).
    """
    compressed = gzip.compress(json.dumps(offline_files).encode("utf-8"))
    return base64.b64encode(compressed).decode("ascii")


def png_bytes_to_data_uri(png_bytes: bytes):
    encoded = base64.b64encode(png_bytes).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def generate_html_report(context: PostprocessContext) -> None:
    offline_files = {
        "metadata.json": {
            **context.metadata.store_to_dict(),
            **context.extra_metadata,
        }
    }

    report_file = context.analysis_dir / "report.json"
    with report_file.open("r") as f:
        offline_files["report.json"] = json.load(f)

    process_tree_file = context.analysis_dir / "process_tree.json"
    if process_tree_file.exists():
        with process_tree_file.open("r") as f:
            offline_files["process_tree.json"] = json.load(f)

    offline_files["screenshots"] = []
    screenshots_count = offline_files["metadata.json"].get("screenshots", 0)
    for which in range(screenshots_count):
        with (context.analysis_dir / f"screenshots/screenshot_{which+1}.png").open(
            "rb"
        ) as f:
            screenshot_data_uri = png_bytes_to_data_uri(f.read())
            offline_files["screenshots"].append(screenshot_data_uri)

    template = HTML_TEMPLATE.read_text()
    if OFFLINE_FILES_PLACEHOLDER not in template:
        raise RuntimeError(
            f"{HTML_TEMPLATE} has no report data placeholder, rebuild the web frontend"
        )
    encoded = encode_offline_files(offline_files)
    html_report = template.replace(
        OFFLINE_FILES_PLACEHOLDER, f'window.OFFLINE_FILES_GZIP_BASE64 = "{encoded}";'
    )
    (context.analysis_dir / "report.html").write_text(html_report)
    context.update_metadata({"html_report": True})
