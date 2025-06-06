import contextlib
import json
import os
import pathlib
from io import BytesIO

from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from flask import Response, request, send_file

from drakrun.lib.config import S3StorageConfigSection
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.lib.s3_storage import get_s3_client, is_s3_enabled


def check_path(path: pathlib.Path, base: pathlib.Path) -> pathlib.Path:
    # Throws ValueError if not relative
    path.resolve().relative_to(base.resolve())
    return path


class SeekableStreamingBody:
    """
    Wraps StreamingBody and restarts request when seek arrives.
    Performs readahead to optimize for multiple forward lookups, which may
    occur while reading filtered logs.
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
            # In case of higher readaheads, it's good idea to
            # limit the amt to reasonable value.
            # Hardcoded 128kB doesn't require that.
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
        self.body.close()
        try:
            self.body = self.s3_client.get_object(
                Bucket=self.s3_bucket, Key=self.key, Range=f"bytes={offset}-"
            )["Body"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRange":
                # We have reached the end of the stream
                # Seek on file allows to go arbitrary far, but returns
                # empty buffer on read. Let's mimic that behavior.
                self.current = offset
                self.readahead_buffer = BytesIO()
                self.body = BytesIO()
                return offset
            else:
                raise
        self.current = offset
        self.readahead_buffer = self._readahead()
        return offset

    def tell(self):
        return self.current

    def close(self):
        return self.body.close()


def get_s3_prefix(analysis_id):
    return "/".join([*analysis_id[0:4], analysis_id])


def read_analysis_json(analysis_id: str, path: str, s3_config: S3StorageConfigSection):
    if not is_s3_enabled(s3_config):
        base_path = ANALYSES_DIR / analysis_id
        path_to_file = check_path(base_path / path, base_path)
        if not path_to_file.exists():
            raise FileNotFoundError
        data = path_to_file.read_bytes()
    else:
        s3_client = get_s3_client(s3_config)
        object_key = get_s3_prefix(analysis_id) + "/" + path
        try:
            data = s3_client.get_object(Bucket=s3_config.bucket, Key=object_key)[
                "Body"
            ].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                raise FileNotFoundError from e
            else:
                raise
    return json.loads(data)


def send_analysis_file(
    analysis_id: str, path: str, mimetype: str, s3_config: S3StorageConfigSection
):
    if not is_s3_enabled(s3_config):
        base_path = ANALYSES_DIR / analysis_id
        path_to_file = check_path(base_path / path, base_path)
        if not path_to_file.exists():
            return dict(error="Data not found"), 404
        return send_file(path_to_file, mimetype=mimetype)

    # S3 handling
    s3_client = get_s3_client(s3_config)
    object_key = get_s3_prefix(analysis_id) + "/" + path
    try:
        if request.range:
            if len(request.range.ranges) > 1:
                return dict(error="Multiple ranges unsupported"), 400
            range_start, range_stop = request.range.ranges[0]
            if range_stop is None:
                range_stop = ""
            response = s3_client.get_object(
                Bucket=s3_config.bucket,
                Key=object_key,
                Range=f"bytes={range_start}-{range_stop}",
            )
            body = response["Body"]
            return Response(
                body.iter_chunks(32 * 1024),
                mimetype=mimetype,
                status=206,
                headers={
                    "Content-Range": response.get("ContentRange"),
                },
            )
        else:
            body = s3_client.get_object(Bucket=s3_config.bucket, Key=object_key)["Body"]
            return Response(body.iter_chunks(32 * 1024), mimetype=mimetype)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return dict(error="Data not found"), 404
        elif e.response["Error"]["Code"] == "InvalidRange":
            return dict(error="Invalid range"), 416
        else:
            raise


@contextlib.contextmanager
def open_seekable_stream(
    analysis_id: str, path: str, s3_config: S3StorageConfigSection
):
    if not is_s3_enabled(s3_config):
        base_path = ANALYSES_DIR / analysis_id
        path_to_file = check_path(base_path / path, base_path)
        if not path_to_file.exists():
            raise FileNotFoundError
        with path_to_file.open("rb") as file:
            yield file

    # S3 handling
    s3_client = get_s3_client(s3_config)
    object_key = get_s3_prefix(analysis_id) + "/" + path
    try:
        body = s3_client.get_object(Bucket=s3_config.bucket, Key=object_key)["Body"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            raise FileNotFoundError from e
        else:
            raise
    file = SeekableStreamingBody(
        s3_client, s3_bucket=s3_config.bucket, key=object_key, body=body
    )
    try:
        yield file
    finally:
        file.close()


def list_analysis_logs(analysis_id: str, s3_config: S3StorageConfigSection):
    if not is_s3_enabled(s3_config):
        base_path = ANALYSES_DIR / analysis_id
        if not base_path.exists():
            raise FileNotFoundError
        return list([path.name for path in base_path.glob("*.log")])
    # S3 handling
    s3_client = get_s3_client(s3_config)
    analysis_key = get_s3_prefix(analysis_id) + "/"
    response = s3_client.list_objects_v2(Bucket=s3_config.bucket, Prefix=analysis_key)[
        "Contents"
    ]
    keys = []
    for obj in response:
        object_name = obj["Key"].split("/")[-1]
        if object_name.endswith(".log"):
            keys.append(object_name)
    return keys
