import json
import os
from tempfile import NamedTemporaryFile
from io import BytesIO

import requests

from flask import Flask, jsonify, request, send_file, redirect, send_from_directory, Response
from karton2 import Config, Producer, Resource, Task
from minio.error import NoSuchKey
from datetime import datetime
from time import mktime

from drakcore.system import SystemService
from drakcore.util import find_config
from drakcore.pstree import generate_process_tree


app = Flask(__name__, static_folder='frontend/build/static')
conf = Config(find_config())

drakmon_cfg = {k: v for k, v in conf.config.items("drakmon")}

rs = SystemService(conf).rs
minio = SystemService(conf).minio


@app.after_request
def add_header(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response


@app.route("/list")
def route_list():
    analyses = []
    res = minio.list_objects_v2("drakrun")

    for obj in res:
        try:
            meta = minio.get_object("drakrun", os.path.join(obj.object_name, "metadata.json"))
        except minio.error.NoSuchKey:
            meta = {}

        analyses.append({"id": obj.object_name.strip('/'), "meta": json.loads(meta.read())})

    return jsonify(sorted(analyses, key=lambda o: o.get('meta', {}).get('time_finished', 0), reverse=True))


@app.route("/upload", methods=['POST'])
def upload():
    producer = Producer(conf)

    with NamedTemporaryFile() as f:
        request.files['file'].save(f.name)

        with open(f.name, "rb") as fr:
            sample = Resource("sample", fr.read())

    task = Task({"type": "sample", "stage": "recognized", "platform": "win32"})
    task.payload["override_uid"] = task.uid
    task.add_resource("sample", sample)

    producer.send_task(task)
    return jsonify({"task_uid": task.uid})


@app.route("/logs/<task_uid>/<log_type>")
def logs(task_uid, log_type):
    with NamedTemporaryFile() as f:
        minio.fget_object("drakrun", task_uid + "/" + log_type + ".log", f.name)
        return send_file(f.name, mimetype='text/plain')


def processed_generic(func, obj_name: str, mime: str = "application/json"):
    def wrapper(task_uid: str):
        gen_name = f"{task_uid}/processed/{obj_name}"
        try:
            # Fast path: object exists
            with NamedTemporaryFile() as tmp_file:
                minio.fget_object("drakrun", gen_name, tmp_file.name)
                return send_file(tmp_file.name, mime)
        except NoSuchKey:
            pass
        # Slow path: generate and upload to minio
        data = func(minio, task_uid)
        file = BytesIO(data)
        minio.put_object("drakrun", gen_name, file, length=len(data))
        return Response(data, mimetype=mime)

    return wrapper


processed_generators = {
    "process_tree.json": processed_generic(generate_process_tree, "process_tree.json"),
}


@app.route("/processed/<task_uid>/<which>")
def processed(task_uid, which):
    return processed_generators[which](task_uid)


@app.route("/logs/<task_uid>")
def list_logs(task_uid):
    try:
        objects = minio.list_objects_v2("drakrun", task_uid + "/")
    except NoSuchKey:
        return jsonify(None)
    return jsonify([x.object_name for x in objects if ".log" in x.object_name])


@app.route("/graph/<task_uid>")
def graph(task_uid):
    with NamedTemporaryFile() as f:
        try:
            minio.fget_object("drakrun", task_uid + "/graph.dot", f.name)
        except NoSuchKey:
            return jsonify(None)
        return send_file(f.name, mimetype='text/plain')


@app.route("/status/<task_uid>")
def status(task_uid):
    tasks = rs.keys("karton.task:*")

    for task_key in tasks:
        task = json.loads(rs.get(task_key))

        if task["root_uid"] == task_uid and task["status"] != "Finished":
            return jsonify({"status": "pending"})

    return jsonify({"status": "done"})


@app.route("/")
def index():
    return send_file("frontend/build/index.html")


@app.route("/robots.txt")
def robots():
    return send_file("frontend/build/robots.txt")


@app.route('/assets/<path:path>')
def send_assets(path):
    return send_from_directory('frontend/build/assets', path)


@app.route("/<path:path>")
def catchall(path):
    return send_file("frontend/build/index.html")


def main():
    app.run(host=drakmon_cfg["listen_host"], port=drakmon_cfg["listen_port"])


if __name__ == "__main__":
    main()
