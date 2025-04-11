import hashlib
import json
import shutil
import uuid
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

import magic
from flask import Flask, jsonify, request, send_file, send_from_directory
from rq.exceptions import NoSuchJobError
from rq.job import Job

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.file_metadata import FileMetadata
from drakrun.analyzer.worker import enqueue_analysis, get_redis_connection
from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR

from .analysis import get_analysis_data
from .analysis_list import add_analysis_to_recent, get_recent_analysis_list

app = Flask(__name__, static_folder="frontend/build/static")
drakrun_conf = load_config()
redis = get_redis_connection(drakrun_conf.redis)


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error="Object not found"), 404


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


def analysis_job_to_dict(job: Job):
    job_status = job.get_status()
    job_meta = job.get_meta()
    return {
        "id": job.id,
        "status": job_status.value if job_status is not None else None,
        "substatus": job.meta.get("substatus"),
        "file": job_meta.get("file"),
        "options": job_meta.get("options"),
        "vm_id": job_meta.get("vm_id"),
        "time_started": job.started_at.isoformat()
        if job.started_at is not None
        else None,
        "time_finished": job.ended_at.isoformat() if job.ended_at is not None else None,
    }


@app.route("/list")
def list_analyses():
    analysis_list = get_recent_analysis_list(redis)
    return jsonify([analysis_job_to_dict(job) for job in analysis_list])


@app.route("/status/<task_uid>")
def status(task_uid):
    try:
        job = Job.fetch(task_uid, connection=redis)
        return jsonify(analysis_job_to_dict(job))
    except NoSuchJobError:
        # TODO: If job no longer stored in redis, we should check the storage
        ...
        return jsonify({"error": "Job not found"}), 404


@app.route("/processed/<task_uid>/<which>")
def processed(task_uid, which):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_processed(which)
    return send_file(path, mimetype="application/json")


@app.route("/processed/<task_uid>/apicall/<pid>")
def apicall(task_uid, pid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_apicalls(pid)
    return send_file(path, mimetype="application/json")


@app.route("/logs/<task_uid>/<log_type>")
def logs(task_uid, log_type):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_log(log_type)
    return send_file(path, mimetype="application/json")


@app.route("/logindex/<task_uid>/<log_type>")
def logindex(task_uid, log_type):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_log_index(log_type)
    return send_file(path, mimetype="application/json")


@app.route("/pcap_dump/<task_uid>")
def pcap_dump(task_uid):
    """
    Return archaive containing dump.pcap along with extracted tls sessions
    keys in format acceptable by wireshark.
    """
    analysis = get_analysis_data(task_uid)
    with NamedTemporaryFile() as f_archive:
        with ZipFile(f_archive, "w", ZIP_DEFLATED) as archive:
            path = analysis.get_pcap_dump()
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
    return send_file(path, mimetype="application/zip")


@app.route("/logs/<task_uid>")
def list_logs(task_uid):
    analysis = get_analysis_data(task_uid)
    return jsonify(list(analysis.list_logs()))


@app.route("/graph/<task_uid>")
def graph(task_uid):
    analysis = get_analysis_data(task_uid)
    path = analysis.get_graph()
    return send_file(path, mimetype="text/plain")


@app.route("/metadata/<task_uid>")
def metadata(task_uid):
    analysis = get_analysis_data(task_uid)
    return jsonify(analysis.get_metadata())


@app.route("/")
def index():
    return send_file("frontend/build/index.html")


@app.route("/robots.txt")
def robots():
    return send_file("frontend/build/robots.txt")


@app.route("/assets/<path:path>")
def send_assets(path):
    return send_from_directory("frontend/build/assets", path)


@app.route("/<path:path>")
def catchall(path):
    return send_file("frontend/build/index.html")
