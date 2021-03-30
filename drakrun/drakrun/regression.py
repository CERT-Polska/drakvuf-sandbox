import argparse
import hashlib
import json
import os
import threading
import tempfile
import logging
from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

from karton.core import Karton, Task, Producer, Resource, Config
from malduck.extractor import ExtractManager, ExtractorModules
from mwdblib import MWDB
from drakrun.version import __version__ as DRAKRUN_VERSION
from contextlib import contextmanager


@contextmanager
def changedLogLevel(logger, level):
    old_level = logger.level
    logger.setLevel(level)
    yield
    logger.setLevel(old_level)

@dataclass
class TestCase:
    sha256: str
    extension: str
    ripped: str
    path: Optional[str] = None

    def get_sample(self) -> bytes:
        # If user provided file path for the sample
        if self.path:
            data = open(self.path, "rb").read()

            h = hashlib.sha256()
            h.update(data)
            if h.hexdigest() != self.sha256:
                raise RuntimeError(f"Expected {self.sha256}, got {h.hexdigest()}")
            return data

        # Otherwise try to fetch the sample from MWDB
        mwdb = MWDB(api_key=os.getenv("MWDB_API_KEY"))
        sample = mwdb.query_file(self.sha256)
        return sample.download()


class RegressionTester(Karton):
    identity = "karton.drakrun.regression-tester"
    version = DRAKRUN_VERSION
    persistent = False

    # Must be kept in sync with DEFAULT_TEST_HEADERS from drakrun.main
    filters = [
        {
            "type": "analysis-test",
            "kind": "drakrun",
        },
    ]

    def __init__(self, config: Config, modules: str, testcases: List[TestCase]):
        super().__init__(config)
        self.modules = modules
        self.rip_map = {}

        for test in testcases:
            self.rip_map[test.sha256] = test.ripped

    def analyze_dumps(self, sample, dump_dir):
        manager = ExtractManager(ExtractorModules(self.modules))
        dumps = Path(dump_dir) / "dumps"
        family = None
        for f in dumps.glob("*.metadata"):
            with open(f, "rb") as metafile:
                metadata = json.load(metafile)
            va = int(metadata["DumpAddress"], 16)
            name = dumps / metadata["DataFileName"]

            with changedLogLevel(logging.getLogger(), logging.ERROR):
                res = manager.push_file(name, base=va)
                family = family or res
        return family

    def process(self, task: Task):
        dumps = task.get_resource("dumps.zip")
        sample = task.get_resource("sample")
        with dumps.extract_temporary() as temp:
            family = self.analyze_dumps(sample, temp)

            expected_family = self.rip_map.get(sample.sha256)
            if family is None or expected_family != family:
                self.log.error(f"Failed to rip {sample.sha256}. Expected {expected_family}, ripped {family}")
            else:
                self.log.info(f"Ripping {sample.sha256} OK: {family}")

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument(
            "modules",
            help="Malduck extractor modules directory",
        )
        parser.add_argument("tests")
        parser.add_argument("--timeout", type=int)
        return parser

    @classmethod
    def main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(args.config_file)

        with open(args.tests) as tests:
            testcases = [TestCase(**case) for case in json.load(tests)]

        consumer = RegressionTester(config, args.modules, testcases)
        consumer_thread = threading.Thread(
            target=lambda c: c.loop(), args=(consumer,)
        )
        consumer_thread.start()

        for test in testcases:
            sample = test.get_sample()
            print(f"Submitting {test.sha256}")

            t = Task(headers=dict(type="sample-test", platform="win64"))
            t.add_payload("sample", Resource("malwar", sample))
            if args.timeout:
                t.add_payload("timeout", args.timeout)

            p = Producer(config)
            p.send_task(t)


if __name__ == "__main__":
    RegressionTester.main()
