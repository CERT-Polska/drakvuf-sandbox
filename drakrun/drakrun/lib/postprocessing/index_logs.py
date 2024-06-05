"""
Index generated log files

DRAKVUF logs are in ndJSON (newline delimited) format. Size of output from
each plugin varies from very small (< 1KB) to very large (>1GB).

In order to present the logs in web UI, we have to load them in chunks of
some reasonable size. Unfortunately, length of JSON records is also variable
so we build and index, to quickly look up where n-th line begins.

"""
import json
import pathlib
from typing import List, TypedDict


class LineMarker(TypedDict):
    line: int
    offset: int


def generate_file_index(file, chunk_size=1024 * 1024):
    markers: List[LineMarker] = [LineMarker(line=0, offset=0)]

    current_chunk_size = 0
    file_offset = 0
    index = 0
    for index, line in enumerate(file, start=1):
        # when we've reached the limit insert new marker
        if current_chunk_size + len(line) >= chunk_size:
            markers.append(LineMarker(line=index, offset=file_offset))
            # and reset current size
            current_chunk_size = 0

        current_chunk_size += len(line)
        file_offset += len(line)

    return {
        # Chunk markers
        "markers": markers,
        # Total number of lines in file
        "num_lines": index,
        # Chunk size used for indexing
        "chunk_size": chunk_size,
    }


def index_logs(analysis_dir: pathlib.Path) -> None:
    index_dir = analysis_dir / "index"
    index_dir.mkdir(exist_ok=True)
    for log_file_path in analysis_dir.glob("*.log"):
        with log_file_path.open("rb") as log_file:
            index = generate_file_index(log_file)
            index_path = index_dir / f"{log_file.name}.json"
            index_data = json.dumps(index)
            index_path.write_text(index_data)
