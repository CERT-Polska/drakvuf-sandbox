"""
Index generated log files

DRAKVUF logs are in ndJSON (newline delimited) format. Size of output from
each plugin varies from very small (< 1KB) to very large (>1GB).

In order to present the logs in web UI, we have to load them in chunks of
some reasonable size. Unfortunately, length of JSON records is also variable
so we build and index, to quickly look up where n-th line begins.

"""
import io
import json
from karton2 import Task, RemoteResource
from typing import Dict


def line_marker(line, offset):
    return dict(line=line, offset=offset)


def generate_file_index(file, chunk_size=1024 * 1024):
    markers = []
    markers.append(line_marker(0, 0))

    current_chunk_size = 0
    file_offset = 0
    for i, line in enumerate(file, start=1):
        # when we've reached the limit insert new marker
        if current_chunk_size + len(line) >= chunk_size:
            markers.append(line_marker(i, file_offset))
            # and reset current size
            current_chunk_size = 0

        current_chunk_size += len(line)
        file_offset += len(line)

    return {
        # Chunk markers
        "markers": markers,
        # Total number of lines in file
        "num_lines": i,
        # Chunk size used for indexing
        "chunk_size": chunk_size,
    }


def generate_log_index(task: Task, resources: Dict[str, RemoteResource], minio):
    analysis_uid = task.payload["analysis_uid"]

    for name, resource in resources.items():
        # Process only newline-delimited *.log files
        # TODO - use resource metadata
        if not name.endswith(".log"):
            continue
        with resource.download_temporary_file() as tmp_file:
            index = generate_file_index(tmp_file)
            data = json.dumps(index).encode()
            stream = io.BytesIO(data)
            minio.put_object("drakrun", f"{analysis_uid}/index/{name}", stream, len(data))
