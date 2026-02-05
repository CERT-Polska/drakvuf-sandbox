import hashlib
import logging
import pathlib
import uuid

import magic
from flask import Response, jsonify, request
from flask_openapi3 import APIBlueprint
from rq.exceptions import NoSuchJobError
from rq.job import Job, JobStatus

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.file_metadata import FileMetadata
from drakrun.analyzer.postprocessing.indexer import (
    get_log_index_for_process,
    get_plugin_names_for_process,
    scattered_read_file,
)
from drakrun.analyzer.postprocessing.process_tree import tree_from_dict
from drakrun.analyzer.worker import (
    analysis_job_to_status_dict,
    enqueue_analysis,
    get_analyses_list,
    get_redis_connection,
    truncate_analysis_list,
)
from drakrun.lib.config import load_config
from drakrun.lib.paths import UPLOADS_DIR
from drakrun.lib.s3_storage import get_s3_client, is_s3_enabled, upload_sample_to_s3
from drakrun.web.schema import (
    AnalysisFileRequestQuery,
    AnalysisListResponse,
    AnalysisRequestPath,
    AnalysisResponse,
    APIErrorResponse,
    LogsRequestPath,
    ProcessInfoRequestPath,
    ProcessLogsRequestPath,
    ScreenshotRequestPath,
    UploadAnalysisResponse,
    UploadFileForm,
)
from drakrun.web.storage import (
    list_analysis_files,
    list_analysis_logs,
    open_seekable_stream,
    read_analysis_json,
    send_analysis_file,
)

ANALYSES_LIST_MAX_LENGTH = 100
api = APIBlueprint("api", __name__, url_prefix="/api")

config = load_config()
redis = get_redis_connection(config.redis)
logger = logging.getLogger(__name__)


@api.post("/upload", responses={200: UploadAnalysisResponse})
def upload_sample(form: UploadFileForm):
    request_file = form.file
    job_id = str(uuid.uuid4())

    timeout = form.timeout
    if not timeout:
        timeout = config.default_timeout
    sample_filename = form.file_name
    if not sample_filename:
        sample_filename = request_file.filename
    start_command = form.start_command
    plugins = form.plugins
    preset = form.preset
    no_internet = form.no_internet
    no_screenshots = form.no_screenshots

    UPLOADS_DIR.mkdir(exist_ok=True)
    tmp_upload_path = UPLOADS_DIR / f"{job_id}.sample"

    try:
        request_file.save(tmp_upload_path)
        sample_sha256 = hashlib.sha256()
        with open(tmp_upload_path, "rb") as f:
            for chunk in iter(lambda: f.read(32 * 4096), b""):
                sample_sha256.update(chunk)
        sample_magic = magic.from_file(tmp_upload_path)

        file_metadata = FileMetadata(
            name=sample_filename,
            type=sample_magic,
            sha256=sample_sha256.hexdigest(),
        )

        if is_s3_enabled(config.s3):
            s3_client = get_s3_client(config.s3)
            s3_bucket = config.s3.bucket
            with tmp_upload_path.open("rb") as f:
                upload_sample_to_s3(job_id, f, s3_client, s3_bucket)
            tmp_upload_path.unlink()
            sample_path = None
        else:
            sample_path = tmp_upload_path.as_posix()

        analysis_options = AnalysisOptions(
            config=config,
            preset=preset,
            host_sample_path=pathlib.Path(sample_path) if sample_path else None,
            sample_filename=sample_filename,
            start_command=start_command,
            plugins=plugins,
            timeout=timeout,
            job_timeout_leeway=config.drakrun.job_timeout_leeway,
        )
        if no_internet:
            analysis_options.net_enable = False
        if no_screenshots:
            analysis_options.no_screenshotter = True
        if form.file_path:
            analysis_options.guest_target_directory = pathlib.PureWindowsPath(form.file_path)
        if form.extract_archive:
            logger.info(f"Archive upload: extract_archive=True, archive_entry_path={form.archive_entry_path}")
            analysis_options.extract_archive = True
            analysis_options.archive_password = form.archive_password
            # For archives, archive_entry_path contains the entry path to execute (e.g., "dir/malware.exe")
            analysis_options.guest_archive_entry_path = form.archive_entry_path
            logger.info(f"Archive upload: set guest_archive_entry_path={analysis_options.guest_archive_entry_path}")
        enqueue_analysis(
            job_id=job_id,
            file_metadata=file_metadata,
            options=analysis_options,
            connection=redis,
            result_ttl=config.drakrun.result_ttl,
        )
    except Exception:
        tmp_upload_path.unlink(missing_ok=True)
        raise

    truncate_analysis_list(connection=redis, limit=ANALYSES_LIST_MAX_LENGTH)
    return jsonify({"task_uid": job_id})


@api.get("/list", responses={200: AnalysisListResponse})
def list_analyses():
    analysis_list = get_analyses_list(connection=redis)
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

    try:
        metadata = read_analysis_json(task_uid, "metadata.json", config.s3)
        if "id" not in metadata:
            metadata = {"id": task_uid, **metadata}
        if "status" not in metadata:
            metadata = {"status": "unknown", **metadata}
    except FileNotFoundError:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(metadata)


@api.get("/processed/<task_uid>/process_tree")
def process_tree(path: AnalysisRequestPath):
    task_uid = path.task_uid
    try:
        process_tree = read_analysis_json(task_uid, "process_tree.json", config.s3)
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404
    return jsonify(process_tree)


@api.get("/logs/<task_uid>/<log_type>")
def logs(path: LogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    return send_analysis_file(
        task_uid, f"{log_type}.log", mimetype="text/plain", s3_config=config.s3
    )


@api.get("/process_info/<task_uid>/<seqid>")
def process_info(path: ProcessInfoRequestPath):
    task_uid = path.task_uid
    seqid = path.seqid
    try:
        process_tree_dict = read_analysis_json(task_uid, "process_tree.json", config.s3)
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404
    process_tree = tree_from_dict(process_tree_dict)
    process = process_tree.processes[seqid]
    try:
        with open_seekable_stream(task_uid, "log_index", config.s3) as log_index:
            plugin_names = get_plugin_names_for_process(log_index, seqid)
            logs = {}
            for plugin_name in plugin_names:
                log_index.seek(0)
                process_log_index = get_log_index_for_process(
                    log_index, seqid, plugin_name
                )
                if process_log_index:
                    logs[plugin_name] = process_log_index["values"]
            return jsonify({"process": process.as_dict(), "logs": logs})
    except FileNotFoundError:
        return jsonify({"error": "Data not found"}), 404


@api.get("/logs/<task_uid>/<log_type>/process/<seqid>")
def process_logs(path: ProcessLogsRequestPath):
    task_uid = path.task_uid
    log_type = path.log_type
    seqid = path.seqid
    try:
        with open_seekable_stream(task_uid, "log_index", config.s3) as log_index:
            index = get_log_index_for_process(log_index, seqid, log_type)
            if not index:
                return dict(error="Data not found"), 404
    except FileNotFoundError:
        return dict(error="Data not found"), 404
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
    if request.range:
        if len(request.range.ranges) > 1:
            return dict(error="Multiple ranges unsupported"), 400
        range_start, range_stop = request.range.ranges[0]
        skip = range_start
        length = (range_stop - range_start + 1) if range_stop is not None else None
    else:
        skip, length = 0, None
    try:
        with open_seekable_stream(task_uid, f"{log_type}.log", config.s3) as log_file:
            scattered_read = scattered_read_file(
                log_file, blocks, skip=skip, length=length
            )
            return Response(b"".join(scattered_read), mimetype="text/plain")
    except FileNotFoundError:
        return dict(error="Data not found"), 404


@api.get("/pcap_file/<task_uid>")
def pcap_file(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "dump.pcap",
        mimetype="application/octet-stream",
        s3_config=config.s3,
        download_name=f"{task_uid}_dump.pcap",
    )


@api.get("/pcap_keys/<task_uid>")
def pcap_keys(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "wireshark_key_file.txt",
        mimetype="application/octet-stream",
        s3_config=config.s3,
        download_name=f"{task_uid}_wireshark_key_file.txt",
    )


@api.get("/dumps/<task_uid>")
def dumps(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "dumps.zip",
        mimetype="application/zip",
        s3_config=config.s3,
        download_name=f"{task_uid}_dumps.zip",
    )


@api.get("/report/<task_uid>")
def report(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        "report.json",
        mimetype="application/json",
        s3_config=config.s3,
    )


@api.get("/logs/<task_uid>")
def list_logs(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis_logs = list_analysis_logs(task_uid, s3_config=config.s3)
    return jsonify(analysis_logs)


@api.get("/files/<task_uid>")
def list_files(path: AnalysisRequestPath):
    task_uid = path.task_uid
    analysis_files = list_analysis_files(task_uid, s3_config=config.s3)
    return jsonify(analysis_files)


@api.get("/files/<task_uid>/download")
def download_analysis_file(path: AnalysisRequestPath, query: AnalysisFileRequestQuery):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid,
        query.filename,
        s3_config=config.s3,
        mimetype="application/octet-stream",
        download_name=query.filename.split("/")[-1],
    )


@api.get("/graph/<task_uid>")
def graph(path: AnalysisRequestPath):
    task_uid = path.task_uid
    return send_analysis_file(
        task_uid, "graph.dot", mimetype="text/plain", s3_config=config.s3
    )


@api.get("/screenshot/<task_uid>/<which>")
def screenshot(path: ScreenshotRequestPath):
    task_uid = path.task_uid
    which = path.which
    return send_analysis_file(
        task_uid,
        f"screenshots/screenshot_{which}.png",
        mimetype="image/png",
        s3_config=config.s3,
    )
