import os
import logging
import json
import functools
from io import StringIO

from karton2 import Consumer, Config, Karton, LocalResource
from minio.error import NoSuchKey
from drakcore.postprocess import REGISTERED_PLUGINS
from drakcore.util import find_config


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

                    res = LocalResource(object_name,
                                        buffer.getvalue(),
                                        bucket="drakrun")
                    task_uid = self.current_task.payload.get('analysis_uid') or self.current_task.uid
                    res._uid = f"{task_uid}/{res.name}"
                    res.upload(self.minio)
                except Exception:
                    self.log.exception("Failed to upload analysis logs")
        return wrapper

    return decorator


class AnalysisProcessor(Consumer):
    identity = "karton.drakrun.processor"
    filters = [{"type": "analysis", "kind": "drakrun"}]

    def __init__(self, config, enabled_plugins):
        super().__init__(config)
        if len(enabled_plugins) == 0:
            raise ValueError("No plugins enabled")
        self.plugins = enabled_plugins

    @with_logs('drak-postprocess.log')
    def process(self):
        # downloaded resource cache
        task_resources = dict(self.current_task.iterate_resources())
        for plugin in self.plugins:
            name = plugin.handler.__name__
            if any(map(lambda r: r not in task_resources.keys(), plugin.required)):
                self.log.info("Skipping %s, missing resources", name)
                continue

            try:
                self.log.info("Running postprocess - %s", plugin.handler.__name__)
                plugin.handler(self.current_task, task_resources, self.minio)
            except Exception:
                self.log.error("Postprocess failed", exc_info=True)


def main():
    conf = Config(find_config())
    processor = AnalysisProcessor(conf, REGISTERED_PLUGINS)
    processor.loop()


if __name__ == "__main__":
    main()
