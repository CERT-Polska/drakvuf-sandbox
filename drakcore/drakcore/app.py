import json
import os
from tempfile import NamedTemporaryFile

import requests

from flask import Flask, jsonify, request, send_file, redirect, send_from_directory, Response, abort
from karton2 import Config, Producer, Resource, Task
from minio.error import NoSuchKey
from datetime import datetime
from time import mktime

from drakcore.system import SystemService
from drakcore.util import find_config


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
            tmp = minio.get_object("drakrun", os.path.join(obj.object_name, "metadata.json"))
            meta = json.loads(tmp.read())
        except NoSuchKey:
            meta = {}

        analyses.append({"id": obj.object_name.strip('/'), "meta": meta})

    return jsonify(sorted(analyses, key=lambda o: o.get('meta', {}).get('time_finished', 0), reverse=True))


@app.route("/upload", methods=['POST'])
def upload():
    producer = Producer(conf)

    with NamedTemporaryFile() as f:
        request.files['file'].save(f.name)

        with open(f.name, "rb") as fr:
            sample = Resource("sample", fr.read())

    task = Task({"type": "sample", "stage": "recognized", "platform": "win32"})
    task.add_resource("override_uid", task.uid)

    # Add analysis timeout to task
    timeout = request.form.get("timeout")
    if timeout:
        task.add_resource("timeout", int(timeout))

    # Add filename override to task
    filename = request.form.get("file_name")
    if filename:
        task.add_resource("file_name", filename)

    # Add startup command to task
    start_command = request.form.get("start_command")
    if start_command:
        task.add_resource("start_command", filename)

    task.add_resource("sample", sample)
    producer.send_task(task)

    return jsonify({"task_uid": task.uid})


@app.route("/processed/<task_uid>/<which>")
def processed(task_uid, which):
    try:
        with NamedTemporaryFile() as f:
            minio.fget_object("drakrun", f"{task_uid}/{which}.json", f.name)
            return send_file(f.name, mimetype='application/json')
    except NoSuchKey:
        abort(404)


@app.route("/processed/<task_uid>/apicall/<pid>")
def apicall(task_uid, pid):
    try:
        with NamedTemporaryFile() as f:
            minio.fget_object("drakrun", f"{task_uid}/apicall/{pid}.json", f.name)
            return send_file(f.name)
    except NoSuchKey:
        abort(404)


@app.route("/logs/<task_uid>/<log_type>")
def logs(task_uid, log_type):
    with NamedTemporaryFile() as f:
        minio.fget_object("drakrun", task_uid + "/" + log_type + ".log", f.name)
        return send_file(f.name, mimetype='text/plain')


@app.route("/dumps/<task_uid>")
def dumps(task_uid):
    with NamedTemporaryFile() as f:
        minio.fget_object("drakrun", task_uid + "/" + "dumps.zip", f.name)
        return send_file(f.name, mimetype='text/plain')


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
    res = {"status": "done"}

    for task_key in tasks:
        task = json.loads(rs.get(task_key))

        if task["root_uid"] == task_uid:
            if task["status"] != "Finished":
                res["status"] = "pending"

            if "vm_id" in task["payload"]:
                res["vm_id"] = task["payload"]["vm_id"]

    return jsonify(res)


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
