import os
from karton2 import Consumer, Config
from io import BytesIO
import json
from drakcore.postprocess import REGISTERED_PLUGINS
from drakcore.util import find_config
from minio.error import NoSuchKey


class AnalysisProcessor(Consumer):
    identity = "karton.drakrun.processor"
    filters = [{"type": "analysis", "kind": "drakrun"}]

    def __init__(self, config, enabled_plugins):
        super().__init__(config)
        if len(enabled_plugins) == 0:
            raise ValueError("No plugins enabled")
        self.plugins = enabled_plugins

    def process(self):
        # downloaded resource cache
        task_resources = {}
        for plugin in self.plugins:
            for resource in plugin.required:
                if resource in task_resources:
                    continue
                r = self.current_task.get_resource(resource)
                if r is None:
                    break
                task_resources[resource] = r
            else:
                try:
                    plugin.handler(self.current_task, task_resources, self.minio)
                except Exception as e:
                    self.log.error("%s", e)


def main():
    conf = Config(find_config())
    processor = AnalysisProcessor(conf, REGISTERED_PLUGINS)
    processor.loop()


if __name__ == "__main__":
    main()
