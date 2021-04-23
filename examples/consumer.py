#!/usr/bin/python3
import json
import os
import argparse
import tempfile

from karton.core import Karton, Config

class DrakrunAnalysisConsumer(Karton):
    identity = "karton.drakrun.archiver"
    filters = [
        {
            "type": "analysis",
            "kind": "drakrun"
        }
    ]

    def process(self):
        tmp_dir = tempfile.mkdtemp(prefix="drakrun")
        analysis_uid = self.current_task.payload['analysis_uid']

        self.log.info(f"Storing analysis {analysis_uid} into {tmp_dir}")

        for name, resource in self.current_task.iterate_resources():
            resource.download_to_file(os.path.join(tmp_dir, name))

        with open(os.path.join(tmp_dir, "procmon.log"), "r") as f:
            self.log.info(f"First 10 lines of procmon output for analysis {self.current_task.uid}")

            for obj in map(json.loads, f.read().split('\n')[:10]):
                self.log.info(obj)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exemplary DRAKVUF Sandbox analysis consumer')
    args = parser.parse_args()

    conf = Config(os.path.join(os.path.dirname(__file__), "config.ini"))
    c = DrakrunAnalysisConsumer(conf)
    c.loop()
