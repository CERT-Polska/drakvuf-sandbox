import hashlib
import json
import shutil
import uuid
from tempfile import NamedTemporaryFile
from zipfile import ZIP_DEFLATED, ZipFile

import magic
from flask import Flask, abort, jsonify, request, send_file, send_from_directory

from drakrun.analyzer.analysis_options import AnalysisOptions
from drakrun.analyzer.file_metadata import FileMetadata
from drakrun.analyzer.worker import enqueue_analysis, get_redis_connection
from drakrun.lib.analysis_status import (
    AnalysisStatus,
    create_analysis_status,
    get_analysis_status_list,
)
from drakrun.lib.config import load_config
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.web.analysis import AnalysisProxy

app = Flask(__name__, static_folder="frontend/build/static")
drakrun_conf = load_config()
redis = get_redis_connection(drakrun_conf.redis)


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify(error="Object not found"), 404


@app.route("/upload", methods=["POST"])
def upload():
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
            ...
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
            job_timeout_leeway=drakrun_conf.job_timeout_leeway,
        )
        enqueue_analysis(
            job_id=job_id,
            file_metadata=file_metadata,
            options=analysis_options,
            connection=redis,
        )
        return jsonify({"task_uid": job_id})
    except Exception:
        shutil.rmtree(analysis_path)
        raise


def get_analysis_metadata(analysis_uid):
    analysis = AnalysisProxy(minio, analysis_uid)
    return analysis.get_metadata()


@app.route("/list")
def route_list():
    return jsonify(get_analysis_status_list(backend.redis))


@app.route("/processed/<task_uid>/<which>")
def processed(task_uid, which):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as f:
        analysis.get_processed(f, which)
        return send_file(f.name, mimetype="application/json")


@app.route("/processed/<task_uid>/apicall/<pid>")
def apicall(task_uid, pid):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as f:
        analysis.get_apicalls(f, pid)
        return send_file(f.name)


@app.route("/logs/<task_uid>/<log_type>")
def logs(task_uid, log_type):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as f:
        # Copy Range header if it exists
        headers = {}
        if "Range" in request.headers:
            headers["Range"] = request.headers["Range"]
        analysis.get_log(log_type, f, headers=headers)
        return send_file(f.name, mimetype="text/plain")


@app.route("/logindex/<task_uid>/<log_type>")
def logindex(task_uid, log_type):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as f:
        analysis.get_log_index(log_type, f)
        return send_file(f.name)


@app.route("/pcap_dump/<task_uid>")
def pcap_dump(task_uid):
    """
    Return archaive containing dump.pcap along with extracted tls sessions
    keys in format acceptable by wireshark.
    """
    analysis = AnalysisProxy(minio, task_uid)
    try:
        with NamedTemporaryFile() as f_pcap, NamedTemporaryFile() as f_keys, NamedTemporaryFile() as f_archive:
            with ZipFile(f_archive, "w", ZIP_DEFLATED) as archive:
                analysis.get_pcap_dump(f_pcap)
                archive.write(f_pcap.name, "dump.pcap")
                try:
                    analysis.get_wireshark_key_file(f_keys)
                    archive.write(f_keys.name, "dump.keys")
                except NoSuchKey:
                    # No dumped keys.
                    pass
            f_archive.seek(0)
            return send_file(f_archive.name, mimetype="application/zip")
    except NoSuchKey:
        abort(404, description="No network traffic avaible.")


@app.route("/dumps/<task_uid>")
def dumps(task_uid):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as tmp:
        analysis.get_dumps(tmp)
        return send_file(tmp.name, mimetype="application/zip")


@app.route("/logs/<task_uid>")
def list_logs(task_uid):
    analysis = AnalysisProxy(minio, task_uid)
    return jsonify(list(analysis.list_logs()))


@app.route("/graph/<task_uid>")
def graph(task_uid):
    analysis = AnalysisProxy(minio, task_uid)
    with NamedTemporaryFile() as tmp:
        analysis.get_graph(tmp)
        return send_file(tmp.name, mimetype="text/plain")


@app.route("/metadata/<task_uid>")
def metadata(task_uid):
    return jsonify(get_analysis_metadata(task_uid))


@app.route("/status/<task_uid>")
def status(task_uid):
    res = {"status": "done"}

    for task in backend.get_all_tasks():
        if task.root_uid == task_uid:
            if task.status != TaskState.FINISHED:
                res["status"] = "pending"
                break

    res["vm_id"] = backend.redis.get(f"drakvnc:{task_uid}")
    return jsonify(res)


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
