import hashlib
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional, cast

from dataclasses_json import DataClassJsonMixin
from karton.core import (
    Config,
    Karton,
    LocalResource,
    Producer,
    RemoteResource,
    Resource,
    Task,
)
from karton.core.task import TaskState
from malduck.extractor import ExtractManager, ExtractorModules
from mwdblib import MWDB
from tqdm import tqdm

from ..__version__ import __version__
from ..paths import DRAKRUN_CONFIG_PATH


@contextmanager
def changedLogLevel(logger, level):
    old_level = logger.level
    logger.setLevel(level)
    yield
    logger.setLevel(old_level)


class RegressionTester(Karton):
    identity = "karton.drakrun.regression-tester"
    version = __version__
    persistent = False

    # Must be kept in sync with DEFAULT_TEST_HEADERS from drakrun.main
    filters = [
        {
            "type": "analysis-test",
            "kind": "drakrun-internal",
        },
    ]

    def analyze_dumps(self, sample, dump_dir, dumps_metadata):
        manager = ExtractManager(
            ExtractorModules(self.config.config["draktestd"]["modules"])
        )
        family = None
        for dump_metadata in dumps_metadata:
            dump_path = os.path.join(dump_dir, dump_metadata["filename"])
            va = int(dump_metadata["base_address"], 16)

            with changedLogLevel(logging.getLogger(), logging.ERROR):
                res = manager.push_file(dump_path, base=va)
                family = family or res
        return family

    def process(self, task: Task):
        dumps = cast(RemoteResource, task.get_resource("dumps.zip"))
        dumps_metadata = task.get_payload("dumps_metadata")
        sample = cast(RemoteResource, task.get_resource("sample"))

        with dumps.extract_temporary() as temp:
            family = self.analyze_dumps(sample, temp, dumps_metadata)

            testcase = TestCase.from_json(task.payload["testcase"])
            expected_family = testcase.ripped

            if family is None or expected_family != family:
                self.log.error(
                    f"Failed to rip {sample.sha256}. Expected {expected_family}, "
                    f"ripped {family}"
                )
                result = "FAIL"
            else:
                self.log.info(f"Ripping {sample.sha256} OK: {family}")
                result = "OK"

            out_res = json.dumps(
                {
                    "sample": sample.sha256,
                    "family": {"expected": expected_family, "ripped": family},
                    "result": result,
                }
            )

            result_task = Task({"type": "analysis-test-result", "kind": "drakrun"})
            res = LocalResource(name=task.root_uid, bucket="draktestd", content=out_res)
            res._uid = res.name
            result_task.add_payload("result", res)
            self.send_task(result_task)

    @classmethod
    def args_parser(cls):
        parser = super().args_parser()
        parser.add_argument("tests")
        parser.add_argument("--timeout", type=int)
        return parser

    @classmethod
    def main(cls):
        config = Config(DRAKRUN_CONFIG_PATH)
        consumer = RegressionTester(config)

        if not consumer.backend.minio.bucket_exists("draktestd"):
            consumer.backend.minio.make_bucket(bucket_name="draktestd")

        consumer.loop()

    @classmethod
    def get_finished_tasks(cls, backend, root_uids):
        root_uids = set(root_uids)
        running = set()

        for task in backend.get_all_tasks():
            if task.root_uid not in root_uids or task.root_uid in running:
                continue

            if task.status not in [TaskState.FINISHED, TaskState.CRASHED]:
                running.add(task.root_uid)

        return root_uids - running

    @classmethod
    def submit_main(cls):
        parser = cls.args_parser()
        args = parser.parse_args()

        config = Config(DRAKRUN_CONFIG_PATH)

        with open(args.tests) as tests:
            testcases = [TestCase(**case) for case in json.load(tests)]

        root_uids = []

        for test in testcases:
            sample = test.get_sample()
            sys.stderr.write(f"Submitting {test.sha256}\n")

            t = Task(headers=dict(type="sample-test", platform="win64"))
            t.add_payload("sample", Resource("malwar", sample))
            t.add_payload("testcase", test.to_json())

            if args.timeout:
                t.add_payload("timeout", args.timeout)

            p = Producer(config)
            p.send_task(t)
            root_uids.append(t.root_uid)

        consumer = RegressionTester(config)
        results = {}

        with tqdm(total=len(root_uids)) as pbar:
            while len(results) != len(root_uids):
                for root_uid in cls.get_finished_tasks(consumer.backend, root_uids):
                    if root_uid not in results:
                        res = json.load(
                            consumer.backend.minio.get_object("draktestd", root_uid)
                        )
                        results[root_uid] = res
                        print(json.dumps(results[root_uid]))
                        pbar.update(1)

                time.sleep(1)

        print(json.dumps(list(results.values())))


@dataclass
class TestCase(DataClassJsonMixin):
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
            if h.hexdigest() != self.sha256.lower():
                raise RuntimeError(f"Expected {self.sha256}, got {h.hexdigest()}")
            return data

        # Otherwise try to fetch the sample from MWDB
        mwdb = MWDB(api_key=os.getenv("MWDB_API_KEY"))
        sample = mwdb.query_file(self.sha256)
        if sample is None:
            raise RuntimeError(f"Sample {self.sha256} not found")
        return sample.download()


if __name__ == "__main__":
    RegressionTester.main()
