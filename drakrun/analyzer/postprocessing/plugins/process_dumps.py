import logging
import os
import shutil
import zipfile
from collections import defaultdict
from typing import Any, Dict, Optional

from drakrun.lib.paths import DUMPS_DIR, DUMPS_ZIP

from .parse_utils import parse_log
from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def process_dumps(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree
    memdump_config = context.config.memdump

    def parse_memdump(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)
        memdump_data = {
            "index": data["DumpsCount"],
            "dump_reason": data["DumpReason"],
            "method": data["Method"],
            "process": process,
            "address": data["DumpAddr"],
            "size": int(data["DumpSize"], 16),
            "filename": data["DumpFilename"],
        }
        if "TargetPID" in data and "WriteAddr" in data:
            target_pid = data["TargetPID"]
            target_process = process_tree.get_process_for_evtid(target_pid, event_uid)
            memdump_data["target_process"] = target_process.seqid
            memdump_data["target_addr"] = data["WriteAddr"]
        return memdump_data

    memdump_log = parse_log(analysis_dir / "memdump.log", parse_memdump)

    dumps_path = analysis_dir / DUMPS_DIR
    target_zip = analysis_dir / DUMPS_ZIP

    region_count = defaultdict(int)
    filtered_dumps = []

    filtered_out_count = 0

    # First, we're pre-filtering single dumps
    for idx, entry in enumerate(memdump_log):
        dump_file = dumps_path / entry["filename"]
        metadata_file = (
            dumps_path / f"memdump.{str(entry['index']).rjust(6, '0')}.metadata"
        )
        if not dump_file.exists():
            logger.warning(f"{dump_file} does not exist")
            continue
        if not metadata_file.exists():
            logger.warning(f"{metadata_file} does not exist")
            continue
        if memdump_config.filter_out_system_pid and entry["process"].pid == 4:
            filtered_out_count += 1
            continue
        dump_size = entry["size"]
        if not (
            memdump_config.min_single_dump_size
            <= dump_size
            <= memdump_config.max_single_dump_size
        ):
            filtered_out_count += 1
            continue
        region = (entry["process"].pid, entry["address"])
        region_count[region] += 1
        filtered_dumps.append(
            {
                **entry,
                "dump_file": dump_file,
                "region_count": region_count[region],
            }
        )

    logger.info("Filtered out %d dumps.", filtered_out_count)

    filtered_dumps = sorted(
        filtered_dumps,
        key=lambda x: (
            x["region_count"],
            x["index"],
        ),
    )
    current_size = 0
    dumps_to_pack = []

    for idx, dump in enumerate(filtered_dumps):
        if current_size > memdump_config.max_total_dumps_size:
            logger.warning(
                "%d dumps were deleted, because the configured size threshold was exceeded. "
                "Regions with the most copies have been removed.",
                len(filtered_dumps) - idx,
            )
            break
        current_size += dump["size"]
        dumps_to_pack.append(dump)

    dumps_to_pack = sorted(dumps_to_pack, key=lambda x: x["index"])
    dumps_metadata = []
    dumps_per_process = defaultdict(list)
    with zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED) as zipf:
        for dump in dumps_to_pack:
            dump_file = dump["dump_file"]
            dump_zip_name = os.path.join(DUMPS_DIR, dump["filename"])
            dumps_metadata.append(
                {
                    "filename": dump_zip_name,
                    "base_address": dump["address"],
                }
            )
            dumps_per_process[dump["process"].seqid].append(dump_zip_name)
            zipf.write(dump_file, dump_zip_name)

        # No dumps, force empty directory
        if not dumps_metadata:
            zipf.writestr(zipfile.ZipInfo(f"{DUMPS_DIR}/"), "")

    shutil.rmtree(dumps_path)
    context.update_metadata({"dumps_metadata": dumps_metadata})
    context.update_report(
        {
            "memdumps": [
                {
                    "process": process_seqid,
                    "dumps": [
                        {k: v for k, v in dump.items() if k not in ["process"]}
                        for dump in dumps_per_process[process_seqid]
                    ],
                }
                for process_seqid in sorted(dumps_per_process.keys())
            ]
        }
    )
