import hashlib
import json
import os
import shutil
import uuid
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

import magic
import rq_dashboard
from flask import Flask, Response, jsonify, request, send_file
from orjson import orjson
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

from .analysis import get_analysis_data
from .analysis_list import add_analysis_to_recent, get_recent_analysis_list

app = Flask(__name__, static_folder="frontend/dist/assets")
drakrun_conf = load_config()
redis = get_redis_connection(drakrun_conf.redis)
app.config.update(
    {
        "RQ_DASHBOARD_REDIS_URL": drakrun_conf.redis.make_url(),
    }
)
rq_dashboard.web.setup_rq_connection(app)
app.register_blueprint(rq_dashboard.blueprint, url_prefix="/rq")


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error="Object not found"), 404


if os.environ.get("DRAKRUN_CORS_ALL"):

    @app.after_request
    def add_header(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Range"
        return response


@app.route("/upload", methods=["POST"])
def upload_sample():
    if "file" not in request.files:
        return jsonify(error="No file part"), 400

    request_file = request.files["file"]
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

        timeout = request.form.get("timeout")
        if not timeout:
            timeout = drakrun_conf.default_timeout
        filename = request.form.get("file_name")
        if not filename:
            filename = request_file.filename
        start_command = request.form.get("start_command")
        plugins = request.form.get("plugins")
        if plugins:
            plugins = json.loads(plugins)

        file_metadata = FileMetadata(
            name=filename,
            type=sample_magic,
            sha256=sample_sha256.hexdigest(),
        )
        analysis_options = AnalysisOptions(
            config=drakrun_conf,
            sample_path=sample_path,
            target_filename=filename,
            start_command=start_command,
            plugins=plugins,
            timeout=timeout,
            job_timeout_leeway=drakrun_conf.drakrun.job_timeout_leeway,
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


@app.route("/list")
def list_analyses():
    analysis_list = get_recent_analysis_list(redis)
    return jsonify([analysis_job_to_status_dict(job) for job in analysis_list])


@app.route("/status/<task_uid>")
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


@app.route("/processed/<task_uid>/<which>")
def processed(task_uid, which):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_processed(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/json")


@app.route("/logs/<task_uid>/<log_type>")
def logs(task_uid, log_type):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_log(log_type)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@app.route("/process_info/<task_uid>/<seqid>")
def process_info(task_uid, seqid):
    analysis = get_analysis_data(task_uid)
    if not seqid.isdigit():
        return dict(error="Incorrect process id"), 400
    seqid = int(seqid)
    process_info = analysis.get_process_info(seqid)
    if process_info is None:
        return dict(error="Data not found"), 404
    return jsonify(process_info)


@app.route("/logs/<task_uid>/<log_type>/process/<seqid>")
def process_logs(task_uid, log_type, seqid):
    analysis = get_analysis_data(task_uid)
    if not seqid.isdigit():
        return dict(error="Incorrect process id"), 400
    seqid = int(seqid)
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


@app.route("/pcap_dump/<task_uid>")
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


@app.route("/dumps/<task_uid>")
def dumps(task_uid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_dumps()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="application/zip")


@app.route("/logs/<task_uid>")
def list_logs(task_uid):
    analysis = get_analysis_data(task_uid)
    return jsonify(list(analysis.list_logs()))


@app.route("/graph/<task_uid>")
def graph(task_uid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_graph()
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="text/plain")


@app.route("/screenshot/<task_uid>/<which>")
def screenshot(task_uid, which):
    analysis = get_analysis_data(task_uid)
    if not which.isdigit():
        return dict(error="Wrong screenshot number"), 400
    which = int(which)
    path = analysis.get_screenshot(which)
    if not path.exists():
        return dict(error="Data not found"), 404
    return send_file(path, mimetype="image/png")


@app.route("/")
def index():
    return send_file("frontend/dist/index.html")


@app.route("/<path:path>")
def catchall(path):
    return send_file("frontend/dist/index.html")
