import hashlib
import json
import logging
import shutil
import uuid
from tempfile import NamedTemporaryFile
from typing import List, Optional
from zipfile import ZIP_DEFLATED, ZipFile

import magic
import orjson
from flask import Response, jsonify, request, send_file
from flask_openapi3 import APIBlueprint, FileStorage
from pydantic import BaseModel, Field
from rq.exceptions import NoSuchJobError
from rq.job import Job, JobStatus

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.file_metadata import FileMetadata
from drakrun.analyzer.postprocessing.indexer import scattered_read_file
from drakrun.analyzer.worker import (
    analysis_job_to_status_dict,
    enqueue_analysis,
    get_redis_connection,
)
from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.web.analysis import get_analysis_data
from drakrun.web.analysis_list import add_analysis_to_recent, get_recent_analysis_list

api = APIBlueprint("api", __name__, url_prefix="/api")

config = load_config()
redis = get_redis_connection(config.redis)
logger = logging.getLogger(__name__)


class APIErrorResponse(BaseModel):
    error: str = Field(description="Error message")


class UploadFileForm(BaseModel):
    file: FileStorage
    timeout: Optional[int] = Field(default=None, description="Analysis timeout")
    file_name: Optional[str] = Field(default=None, description="Target file name")
    start_command: Optional[str] = Field(default=None, description="Start command")
    plugins: Optional[str] = Field(
        default=None, description="Plugins to use (in JSON array string)"
    )


class NewAnalysisResponse(BaseModel):
    task_uid: str = Field(description="Unique analysis ID")


@api.post("/upload", responses={200: NewAnalysisResponse})
def upload_sample(form: UploadFileForm):
    request_file = form.file
    job_id = str(uuid.uuid4())

    analysis_path = ANALYSES_DIR / job_id
    analysis_path.mkdir()

    sample_path = analysis_path / "sample"
    sample_sha256 = hashlib.sha256()
    try:
        with sample_path.open("wb") as f:
            for chunk in iter(lambda: request_file.read(32 * 4096), b""):
                f.write(chunk)
                sample_sha256.update(chunk)
        sample_magic = magic.from_file(sample_path.as_posix())

        timeout = form.timeout
        if not timeout:
            timeout = config.default_timeout
        filename = form.file_name
        if not filename:
            filename = request_file.filename
        start_command = form.start_command
        plugins = form.plugins
        if plugins:
            plugins = json.loads(plugins)

        file_metadata = FileMetadata(
            name=filename,
            type=sample_magic,
            sha256=sample_sha256.hexdigest(),
        )
        analysis_options = AnalysisOptions(
            config=config,
            sample_path=sample_path,
            target_filename=filename,
            start_command=start_command,
            plugins=plugins,
            timeout=timeout,
            job_timeout_leeway=config.drakrun.job_timeout_leeway,
        )
        enqueue_analysis(
            job_id=job_id,
            file_metadata=file_metadata,
            options=analysis_options,
            connection=redis,
        )
        add_analysis_to_recent(connection=redis, analysis_id=job_id)
        return jsonify({"task_uid": job_id})
    except Exception:
        shutil.rmtree(analysis_path)
        raise


class AnalysisResponse(BaseModel):
    id: str = Field(description="Unique analysis ID")
    status: str = Field(description="Analysis status")
    time_started: Optional[str] = Field(
        default=None, description="Analysis start time in ISO format"
    )
    time_ended: Optional[str] = Field(
        default=None, description="Analysis end time in ISO format"
    )


class AnalysisListResponse(BaseModel):
    __root__: List[AnalysisResponse]


@api.get("/list", responses={200: AnalysisListResponse})
def list_analyses():
    analysis_list = get_recent_analysis_list(redis)
    return jsonify([analysis_job_to_status_dict(job) for job in analysis_list])


@api.get(
    "/status/<uuid:task_uid>", responses={200: AnalysisResponse, 404: APIErrorResponse}
)
def status(task_uid):
    try:
        job = Job.fetch(task_uid, connection=redis)
    except NoSuchJobError:
        job = None

    if job is not None and job.get_status() not in [
        JobStatus.FINISHED,
        JobStatus.FAILED,
    ]:
        return jsonify(analysis_job_to_status_dict(job))

    analysis = get_analysis_data(task_uid)
    metadata = analysis.get_metadata()
    # Handling old tasks, to be removed in future
    if "id" not in metadata:
        metadata = {"id": task_uid, **metadata}
    if metadata is None:
        return jsonify({"error": "Job not found"}), 404
    else:
        return jsonify(metadata)


@api.get("/processed/<uuid:task_uid>/<which>")
def processed(task_uid, which):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_processed(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/json")


@api.get("/logs/<uuid:task_uid>/<log_type>")
def logs(task_uid, log_type):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_log(log_type)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@api.get("/process_info/<uuid:task_uid>/<int:seqid>")
def process_info(task_uid, seqid):
    analysis = get_analysis_data(task_uid)
    process_info = analysis.get_process_info(seqid)
    if process_info is None:
        return dict(error="Data not found"), 404
    return jsonify(process_info)


@api.get("/logs/<uuid:task_uid>/<log_type>/process/<int:seqid>")
def process_logs(task_uid, log_type, seqid):
    analysis = get_analysis_data(task_uid)
    index_path = analysis.get_log_index(f"{log_type}.{seqid}.json")
    if not index_path.exists():
        return dict(error="Data not found"), 404
    index = orjson.loads(index_path.read_text())
    blocks = index["blocks"]
    filter_values = request.args.getlist("filter[]")
    if filter_values:
        filter_indices = [
            index["values"].index(filter_value)
            for filter_value in filter_values
            if filter_value in index["values"]
        ]
        blocks = [
            block
            for (block, mapping) in zip(index["blocks"], index["mapping"])
            if mapping in filter_indices
        ]
    log_path = analysis.get_log(log_type)
    if request.range:
        if len(request.range.ranges) > 1:
            return dict(error="Multiple ranges unsupported"), 400
        range_start, range_stop = request.range.ranges[0]
        skip = range_start
        length = (range_stop - range_start + 1) if range_stop is not None else None
    else:
        skip, length = 0, None
    scattered_read = scattered_read_file(log_path, blocks, skip=skip, length=length)
    return Response(b"".join(scattered_read), mimetype="text/plain")


@api.get("/pcap_dump/<uuid:task_uid>")
def pcap_dump(task_uid):
    """
    Return archive containing dump.pcap along with extracted tls sessions
    keys in format acceptable by wireshark.
    """
    analysis = get_analysis_data(task_uid)
    path = analysis.get_pcap_dump()
    if not path.exists():
        return dict(error="Data not found"), 404
    with NamedTemporaryFile() as f_archive:
        with ZipFile(f_archive, "w", ZIP_DEFLATED) as archive:
            archive.write(path, "dump.pcap")
            path = analysis.get_wireshark_key_file()
            if path.exists():
                archive.write(path, "dump.keys")
        f_archive.seek(0)
        return send_file(f_archive.name, mimetype="application/zip")


@api.get("/dumps/<uuid:task_uid>")
def dumps(task_uid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_dumps()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/zip")


@api.get("/logs/<uuid:task_uid>")
def list_logs(task_uid):
    analysis = get_analysis_data(task_uid)
    return jsonify(list(analysis.list_logs()))


@api.get("/graph/<uuid:task_uid>")
def graph(task_uid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_graph()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@api.get("/screenshot/<uuid:task_uid>/<int:which>")
def screenshot(task_uid, which):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_screenshot(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="image/png")
