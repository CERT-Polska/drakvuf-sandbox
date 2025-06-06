import logging
import pathlib
from collections import defaultdict
from typing import List, Optional

import msgpack
import orjson

from .process_tree import ProcessTree

logger = logging.getLogger(__name__)


def index_log_file(
    log_file: pathlib.Path,
    process_tree: ProcessTree,
    key: str = None,
):
    index = defaultdict(lambda: {"blocks": [], "values": [], "mapping": []})
    processes = {}

    with log_file.open("r") as f:
        while True:
            data_start = f.tell()
            entry_data = f.readline()
            if not entry_data:
                break
            try:
                entry = orjson.loads(entry_data)
                pid = entry.get("PID")
                event_id = entry.get("EventUID")
                value = entry.get(key) if key is not None else None
                if not pid or not event_id:
                    continue
                event_id = int(event_id, 16)

                if (pid not in processes) or (
                    processes[pid].evtid_to and processes[pid].evtid_to < event_id
                ):
                    process = process_tree.get_process_for_evtid(pid, event_id)
                    if not process:
                        raise RuntimeError(
                            f"No process found for event. Bug? (PID={pid} EventUID={event_id})"
                        )
                    processes[pid] = process
                else:
                    process = processes[pid]

                entry_seqid = process.seqid
                index_entry = index[entry_seqid]
                value_index = None
                if key is not None:
                    try:
                        value_index = index_entry["values"].index(value)
                    except ValueError:
                        index_entry["values"].append(value)
                        value_index = len(index_entry["values"]) - 1
                if (
                    index_entry["blocks"]
                    and data_start == index_entry["blocks"][-1][1]
                    and (
                        value_index is None or index_entry["mapping"][-1] == value_index
                    )
                ):
                    # If adjacent blocks belong to the same mapping
                    index_entry["blocks"][-1][1] = f.tell()
                else:
                    index_entry["blocks"].append([data_start, f.tell()])
                    if key is not None:
                        index_entry["mapping"].append(value_index)
            except Exception:
                logger.exception("Failed to process entry")
    return dict(index)


def build_log_index(analysis_dir: pathlib.Path, process_tree: ProcessTree) -> bytes:
    log_index = [dict() for _ in range(len(process_tree.processes))]
    for log_file_path in analysis_dir.glob("*.log"):
        plugin_name = log_file_path.stem
        if plugin_name == "drakrun":
            continue
        index = index_log_file(
            log_file_path,
            process_tree,
            key="Method",
        )
        for proc_seqid in index.keys():
            log_index[proc_seqid][plugin_name] = index[proc_seqid]

    serialized_indexes = []
    serialized_indexes_current = 0
    index_toc = [dict() for _ in range(len(process_tree.processes))]
    for proc_seqid, proc_log_index in enumerate(log_index):
        for plugin_name, plugin_index in proc_log_index.items():
            serialized_index = msgpack.packb(plugin_index)
            index_toc[proc_seqid][plugin_name] = serialized_indexes_current
            serialized_indexes.append(serialized_index)
            serialized_indexes_current += len(serialized_index)
    serialized_index_toc = msgpack.packb(index_toc)
    return serialized_index_toc + b"".join(serialized_indexes)


def get_plugin_names_for_process(index_file: pathlib.Path, seqid: int):
    with index_file.open("rb") as f:
        unpacker = msgpack.Unpacker(f)
        index_toc = unpacker.unpack()
        if seqid >= len(index_toc):
            return []
        return list(index_toc[seqid].keys())


def get_log_index_for_process(index_file: pathlib.Path, seqid: int, plugin_name: str):
    with index_file.open("rb") as f:
        unpacker = msgpack.Unpacker(f)
        index_toc = unpacker.unpack()
        log_pos = unpacker.tell()
        if seqid >= len(index_toc):
            return None
        if plugin_name not in index_toc[seqid]:
            return None
        start = index_toc[seqid][plugin_name]
        # Seek to the specific point of file
        f.seek(log_pos + start)
        unpacker = msgpack.Unpacker(f)
        return unpacker.unpack()


def scattered_read_file(
    log_file: pathlib.Path,
    offsets: List[List[int]],
    skip: int = 0,
    length: Optional[int] = None,
):
    bytes_scanned = 0
    bytes_read = 0
    with log_file.open("rb") as f:
        for offset_start, offset_end in offsets:
            block_length = offset_end - offset_start
            if skip < (bytes_scanned + block_length):
                block_skip = max(0, skip - bytes_scanned)
                f.seek(offset_start + block_skip)
                block_read = block_length - block_skip
                if length is not None:
                    block_read = min(length - bytes_read, block_read)
                yield f.read(block_read)
                bytes_read += block_read
            bytes_scanned += block_length
