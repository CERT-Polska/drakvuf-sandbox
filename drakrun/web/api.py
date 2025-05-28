import hashlib
import logging
import shutil
import uuid
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

import magic
import orjson
from flask import Response, jsonify, request, send_file
from flask_openapi3 import APIBlueprint
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
from drakrun.web.schema import (
    AnalysisListResponse,
    AnalysisRequestPath,
    AnalysisResponse,
    APIErrorResponse,
    LogsRequestPath,
    ProcessedRequestPath,
    ProcessInfoRequestPath,
    ProcessLogsRequestPath,
    ScreenshotRequestPath,
    UploadAnalysisResponse,
    UploadFileForm,
)

api = APIBlueprint("api", __name__, url_prefix="/api")

config = load_config()
redis = get_redis_connection(config.redis)
logger = logging.getLogger(__name__)


@api.post("/upload", responses={200: UploadAnalysisResponse})
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


@api.get("/list", responses={200: AnalysisListResponse})
def list_analyses():
    analysis_list = get_recent_analysis_list(redis)
    return jsonify([analysis_job_to_status_dict(job) for job in analysis_list])


@api.get("/status/<task_uid>", responses={200: AnalysisResponse, 404: APIErrorResponse})
def status(path: AnalysisRequestPath):
    task_uid = path.task_uid
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


@api.get("/processed/<task_uid>/<which>")
def processed(path: ProcessedRequestPath):
    task_uid = path.task_uid
    which = path.which
    analysis = get_analysis_data(task_uid)
    path = analysis.get_processed(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/json")


@api.get("/logs/<task_uid>/<log_type>")
def logs(path: LogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    analysis = get_analysis_data(task_uid)
    path = analysis.get_log(log_type)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@api.get("/process_info/<task_uid>/<seqid>")
def process_info(path: ProcessInfoRequestPath):
    task_uid = path.task_uid
    seqid = path.seqid
    analysis = get_analysis_data(task_uid)
    process_info = analysis.get_process_info(seqid)
    if process_info is None:
        return dict(error="Data not found"), 404
    return jsonify(process_info)


@api.get("/logs/<task_uid>/<log_type>/process/<seqid>")
def process_logs(path: ProcessLogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    seqid = path.seqid
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


@api.get("/pcap_dump/<task_uid>")
def pcap_dump(path: AnalysisRequestPath):
    """
    Return archive containing dump.pcap along with extracted tls sessions
    keys in format acceptable by wireshark.
    """
    task_uid = path.task_uid
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


@api.get("/dumps/<task_uid>")
def dumps(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis = get_analysis_data(task_uid)
    path = analysis.get_dumps()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/zip")


@api.get("/logs/<task_uid>")
def list_logs(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis = get_analysis_data(task_uid)
    return jsonify(list(analysis.list_logs()))


@api.get("/graph/<task_uid>")
def graph(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis = get_analysis_data(task_uid)
    path = analysis.get_graph()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@api.get("/screenshot/<task_uid>/<which>")
def screenshot(path: ScreenshotRequestPath):
    task_uid = path.task_uid
    which = path.which
    analysis = get_analysis_data(task_uid)
    path = analysis.get_screenshot(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="image/png")
