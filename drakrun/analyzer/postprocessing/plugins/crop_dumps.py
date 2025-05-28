import logging
import os
import pathlib
import re
import zipfile
from typing import Any, Dict, List, Tuple

from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP

logger = logging.getLogger(__name__)


def crop_dumps(analysis_dir: pathlib.Path) -> Dict[str, Any]:
    dumps_path = analysis_dir / DUMPS_DIR
    target_zip = analysis_dir / DUMPS_ZIP
    zipf = zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED)

    dumps: List[Tuple[pathlib.Path, os.stat_result]] = sorted(
        ((dump, dump.stat()) for dump in dumps_path.iterdir() if dump.is_file()),
        key=lambda el: el[1].st_ctime,
    )

    max_total_size = 300 * 1024 * 1024  # 300 MB
    current_size = 0
    dumps_metadata = []

    for dump, dump_stat in dumps:
        current_size += dump_stat.st_size
        if current_size <= max_total_size:
            # Store files under dumps/
            file_basename = dump.name
            if re.fullmatch(r"[a-f0-9]{4,16}_[a-f0-9]{16}", file_basename):
                # If file is memory dump then append metadata that can be
                # later attached as payload when creating an `analysis` task.
                dump_base = hex(int(file_basename.split("_")[0], 16))
                dumps_metadata.append(
                    {
                        "filename": os.path.join(DUMPS_DIR, file_basename),
                        "base_address": dump_base,
                    }
                )
            zipf.write(dump, os.path.join(DUMPS_DIR, file_basename))
        dump.unlink()

    # No dumps, force empty directory
    if current_size == 0:
        zipf.writestr(zipfile.ZipInfo(f"{DUMPS_DIR}/"), "")

    if current_size > max_total_size:
        logger.warning(
            "Some dumps were deleted, because the configured size threshold was exceeded."
        )
    return {"dumps_metadata": dumps_metadata}
