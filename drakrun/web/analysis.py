import json
import os
import pathlib
from io import BytesIO

from botocore.client import BaseClient
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from drakrun.analyzer.postprocessing.indexer import (
    get_log_index_for_process,
    get_plugin_names_for_process,
)
from drakrun.analyzer.postprocessing.process_tree import tree_from_dict
from drakrun.lib.paths import ANALYSES_DIR


def check_path(path: pathlib.Path, base: pathlib.Path) -> pathlib.Path:
    # Throws ValueError if not relative
    path.resolve().relative_to(base.resolve())
    return path


class StoredAnalysisBase:
    def __init__(self, analysis_id: str):
        self.analysis_id = analysis_id

    def open_file(self, path: str):
        raise NotImplementedError

    def open_seekable_file(self, path: str):
        raise NotImplementedError

    def get_metadata(self):
        f = self.open_file("metadata.json")
        if f is None:
            return None
        try:
            return json.loads(f.read())
        finally:
            f.close()

    def get_process_tree(self):
        f = self.open_file("process_tree.json")
        if f is None:
            return None
        try:
            return json.loads(f.read())
        finally:
            f.close()

    def get_log(self, log_name):
        return self.open_seekable_file(f"{log_name}.log")

    def get_log_index(self):
        return self.open_seekable_file("log_index")

    def get_pcap_dump(self):
        """Download dump.pcap file."""
        return self.open_file("dump.pcap")

    def get_wireshark_key_file(self):
        """
        Download tls session keys in format that is accepted by wireshark.
        """
        return self.open_file("wireshark_key_file.txt")

    def get_dumps(self):
        """Download memory dumps"""
        return self.open_file("dumps.zip")

    def get_graph(self):
        """Download ProcDOT graph"""
        return self.open_file("graph.dot")

    def get_screenshot(self, which):
        return self.open_file(f"screenshots/screenshot_{which}.png")

    def get_process_info(self, which):
        process_tree_dict = self.get_process_tree()
        if not process_tree_dict:
            return {}
        process_tree = tree_from_dict(process_tree_dict)
        process = process_tree.processes[which]
        log_index = self.get_log_index()
        logs = {}
        if log_index is not None:
            try:
                plugin_names = get_plugin_names_for_process(log_index, which)
                for plugin_name in plugin_names:
                    log_index.seek(0)
                    process_log_index = get_log_index_for_process(
                        log_index, which, plugin_name
                    )
                    if process_log_index:
                        logs[plugin_name] = process_log_index["values"]
            finally:
                log_index.close()
        return {
            "process": process.as_dict(),
            "logs": logs,
        }


class SeekableStreamingBody:
    """
    Wraps StreamingBody and restarts request when seek arrives
    """

    def __init__(self, s3_client, s3_bucket, key, body: StreamingBody):
        self.s3_client = s3_client
        self.s3_bucket = s3_bucket
        self.key = key
        self.body = body
        self.readahead_buffer = self._readahead()
        self.current = 0

    def _readahead(self, readahead_size=128 * 1024):
        readahead_buffer = BytesIO()
        while readahead_size > 0:
            chunk = self.body.read(readahead_size)
            if not chunk:
                break
            readahead_buffer.write(chunk)
            readahead_size -= len(chunk)
        readahead_buffer.seek(0)
        return readahead_buffer

    def read(self, n=None):
        if n is None:
            # Exhaust all streams
            readahead = self.readahead_buffer.read()
            body = self.body.read()
            self.current += len(readahead) + len(body)
            return readahead + body
        buffer = b""
        while n > 0:
            chunk = self.readahead_buffer.read(n)
            if not chunk:
                # If readahead is empty, let's try to read more
                self.readahead_buffer = self._readahead()
                if self.readahead_buffer.getbuffer().nbytes == 0:
                    # If readahead is still empty, we've reached end of file
                    break
            self.current += len(chunk)
            buffer += chunk
            n -= len(chunk)
        return buffer

    def seek(self, offset, whence=os.SEEK_SET):
        if whence != os.SEEK_SET:
            raise NotImplementedError
        readahead_start = self.current - self.readahead_buffer.tell()
        readahead_len = self.readahead_buffer.getbuffer().nbytes
        if readahead_start <= offset < (readahead_start + readahead_len):
            # Seek within readahead_buffer
            self.readahead_buffer.seek(offset - readahead_start)
            self.current = offset
            return offset
        # If it's impossible to seek within readahead, restart stream
        self.body = self.s3_client.get_object(
            Bucket=self.s3_bucket, Key=self.key, Range=f"bytes={offset}-"
        )["Body"]
        self.current = offset
        self.readahead_buffer = self._readahead()
        return offset

    def tell(self):
        return self.current

    def close(self):
        return self.body.close()


class FileStoredAnalysis(StoredAnalysisBase):
    def __init__(self, analysis_id: str):
        super().__init__(analysis_id)
        analysis_dir = ANALYSES_DIR / analysis_id
        self.analysis_dir = check_path(analysis_dir, ANALYSES_DIR)

    def _check_path(self, path):
        return check_path(path, self.analysis_dir)

    def open_file(self, path: str):
        path = self._check_path(self.analysis_dir / path)
        if not path.exists():
            return None
        return path.open("rb")

    def open_seekable_file(self, path: str):
        return self.open_file(path)


class S3StoredAnalysis(StoredAnalysisBase):
    def __init__(self, analysis_id: str, s3_client: BaseClient, s3_bucket: str):
        super().__init__(analysis_id)
        self.s3_client = s3_client
        self.s3_bucket = s3_bucket
        self.s3_prefix = "/".join([*analysis_id[0:4], analysis_id])

    def open_file(self, path: str):
        key = self.s3_prefix + "/" + path
        try:
            return self.s3_client.get_object(Bucket=self.s3_bucket, Key=key)["Body"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return None
            else:
                raise

    def open_seekable_file(self, path: str):
        key = self.s3_prefix + "/" + path
        body = self.open_file(path)
        if body is None:
            return None
        return SeekableStreamingBody(
            s3_client=self.s3_client, s3_bucket=self.s3_bucket, key=key, body=body
        )


def get_analysis_data(uid: str):
    analysis_dir = ANALYSES_DIR / uid
    if not analysis_dir.exists():
        raise RuntimeError(f"Analysis directory {analysis_dir} does not exist")
    return AnalysisStorage(analysis_dir)
