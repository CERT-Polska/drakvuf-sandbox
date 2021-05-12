import os
import logging
import json
import functools
import contextlib
import pathlib
import subprocess
from io import StringIO
from tempfile import NamedTemporaryFile, TemporaryDirectory

from drakcore.version import __version__ as DRAKCORE_VERSION
from karton.core import Karton, RemoteResource, LocalResource, Task
from drakcore.postprocess import REGISTERED_PLUGINS
from drakcore.util import get_config
from drakcore.analysis import AnalysisProxy
from drakcore.ipt_disasm import get_executed_blocks


class LocalLogBuffer(logging.Handler):
    FIELDS = (
        "levelname",
        "message",
        "created",
    )

    def __init__(self):
        super().__init__()
        self.buffer = []

    def emit(self, record):
        entry = {k: v for (k, v) in record.__dict__.items() if k in self.FIELDS}
        self.buffer.append(entry)


# TODO: Deduplicate this, once we have shared code between drakcore and drakrun
def with_logs(object_name):
    def decorator(method):
        @functools.wraps(method)
        def wrapper(self: Karton, *args, **kwargs):
            handler = LocalLogBuffer()
            try:
                # Register new log handler
                self.log.addHandler(handler)
                method(self, *args, **kwargs)
            except Exception:
                self.log.exception("Analysis failed")
            finally:
                # Unregister local handler
                self.log.removeHandler(handler)
                try:
                    buffer = StringIO()
                    for idx, entry in enumerate(handler.buffer):
                        if idx > 0:
                            buffer.write("\n")
                        buffer.write(json.dumps(entry))

                    res = LocalResource(
                        object_name, buffer.getvalue(), bucket="drakrun"
                    )
                    task_uid = (
                        self.current_task.payload.get("analysis_uid")
                        or self.current_task.uid
                    )
                    res._uid = f"{task_uid}/{res.name}"

                    # Karton rejects empty resources
                    # Ensure that we upload it only when some data was actually generated
                    if buffer.tell() > 0:
                        res.upload(self.backend)
                except Exception:
                    self.log.exception("Failed to upload analysis logs")

        return wrapper

    return decorator


def find_pid_cr3(fileobj, pid: int):
    # Find process CR3
    for line in fileobj:
        entry = json.loads(line)
        if entry["PID"] == pid:
            return int(entry["CR3"], 16)
    return None


@contextlib.contextmanager
def open_temporary(*args, **kwargs):
    file = open(*args, **kwargs)
    try:
        yield file
    finally:
        file.close()
        os.remove(file.name)


class AnalysisProcessor(Karton):
    version = DRAKCORE_VERSION
    identity = "karton.drakrun.processor"
    filters = [
        {"type": "analysis-raw", "kind": "drakrun-internal"},
        {"type": "drakcore-request", "kind": "drakrun-internal"},
    ]

    def __init__(self, config, enabled_plugins):
        super().__init__(config)
        if len(enabled_plugins) == 0:
            raise ValueError("No plugins enabled")
        self.plugins = enabled_plugins
        self.log.setLevel(logging.INFO)

    def process(self, task):
        if task.headers["type"] == "analysis-raw":
            self.process_analysis()
        elif task.headers["type"] == "drakcore-request":
            self.process_request(task)

    def process_request(self, task):
        analysis_uid = task.get_payload("analysis_uid")
        pid = int(task.get_payload("pid"))
        analysis = AnalysisProxy(self.backend.minio, analysis_uid)

        with NamedTemporaryFile() as ipt_zip, TemporaryDirectory() as analysis_dir, open_temporary(
            pathlib.Path(analysis_dir) / "codemon.log", "wb"
        ) as codemon_log:
            analysis_dir = pathlib.Path(analysis_dir)
            ipt_dir = analysis_dir / "ipt"
            # Get IPT artifacts
            analysis.get_log("codemon", codemon_log)

            with open(codemon_log.name) as f:
                cr3 = find_pid_cr3(f, pid)
            if not cr3:
                return "PID not found", 404

            analysis.get_ipt(ipt_zip)
            subprocess.run(["unzip", ipt_zip.name, "-d", analysis_dir])

            blocks = set()
            for cpu in ipt_dir.glob("ipt_stream_*"):
                for block in get_executed_blocks(
                    pathlib.Path(analysis_dir), cr3, cpu, use_blocks=False
                ):
                    # print(hex(block))
                    blocks.add(block)

            block_list = list(blocks)
            block_list.sort()
            res = list(map(hex, block_list))

            self.backend.redis.set(
                f"drakipt:{analysis_uid}.{pid}",
                json.dumps(res),
                ex=60 * 10
            )

    @with_logs("drak-postprocess.log")
    def process_analysis(self):
        # downloaded resource cache
        task_resources = dict(self.current_task.iterate_resources())
        for plugin in self.plugins:
            name = plugin.handler.__name__
            if any(map(lambda r: r not in task_resources.keys(), plugin.required)):
                self.log.info("Skipping %s, missing resources", name)
                continue

            try:
                self.log.debug("Running postprocess - %s", plugin.handler.__name__)
                outputs = plugin.handler(
                    self.current_task, task_resources, self.backend.minio
                )

                if outputs:
                    for out in outputs:
                        self.log.debug(
                            f"Step {plugin.handler.__name__} outputted new resource: {out}"
                        )
                        res_name = os.path.join(
                            self.current_task.payload["analysis_uid"], out
                        )
                        task_resources[out] = RemoteResource(
                            res_name,
                            uid=res_name,
                            bucket="drakrun",
                            backend=self.backend,
                        )
            except Exception:
                self.log.error("Postprocess failed", exc_info=True)

        task = Task(
            {
                "type": "analysis",
                "kind": "drakrun",
            }
        )

        # Add metadata information about dumps within dumps.zip
        task.add_payload(
            "dumps_metadata", self.current_task.get_payload("dumps_metadata")
        )

        for (name, resource) in task_resources.items():
            task.add_payload(name, resource)
        self.send_task(task)


def main():
    conf = get_config()
    processor = AnalysisProcessor(conf, REGISTERED_PLUGINS)
    processor.loop()


if __name__ == "__main__":
    main()
