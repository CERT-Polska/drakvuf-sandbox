#!/usr/bin/python3

import argparse
import contextlib
import hashlib
import json
import logging
import os
import pathlib
import shutil
import socket
import tempfile
from pathlib import Path
from typing import Dict, Optional, Union, cast

import magic
from karton.core import Config, Karton, LocalResource, RemoteResource, Resource, Task

from drakrun.analyzer import AnalysisOptions, UnretryableAnalysisError, analyze_sample
from drakrun.lib.analysis_status import (
    AnalysisStatus,
    create_or_update_analysis_status,
    update_analysis_status,
)
from drakrun.lib.bindings.xen import get_xen_info, parse_xen_commandline
from drakrun.lib.config import load_config
from drakrun.lib.drakpdb import dll_file_list
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    PROFILE_DIR,
    RUNTIME_FILE,
    VOLUME_DIR,
)
from drakrun.lib.util import RuntimeInfo, file_sha256
from drakrun.lib.vm import generate_vm_conf
from drakrun.version import __version__ as DRAKRUN_VERSION

MAX_TASK_TIMEOUT = 60 * 20  # Never run samples for longer than this

log = logging.getLogger(__name__)


class XenCommandlineCheckError(Exception):
    """
    Xen command line was incorrect and drakrun was instructed to fail in that case
    """


@contextlib.contextmanager
def scoped_file_logger(filename: pathlib.Path, logger: logging.Logger):
    handler = logging.FileHandler(filename, mode="w")
    try:
        logger.addHandler(handler)
        yield
    finally:
        logger.removeHandler(handler)
        handler.close()


def get_sample_sha256(sample_path: pathlib.Path) -> str:
    sha256 = hashlib.sha256()
    with sample_path.open("rb") as f:
        while True:
            block = f.read(65536)
            if not block:
                break
            sha256.update(block)
    return sha256.hexdigest()


class DrakrunKarton(Karton):
    version = DRAKRUN_VERSION
    identity = "karton.drakrun-prod"
    filters = [
        {
            "type": "sample",
            "stage": "recognized",
            "platform": "win32",
            "execute": "!False",
        },
        {
            "type": "sample",
            "stage": "recognized",
            "platform": "win64",
            "execute": "!False",
        },
    ]

    def __init__(self, config: Config, instance_id: int, *args, **kwargs) -> None:
        super().__init__(config, *args, **kwargs)
        self.drakconfig = load_config()
        self.instance_id = instance_id
        self.install_info = InstallInfo.load()
        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)

        xen_cmdline_check = self.drakconfig.drakrun.xen_cmdline_check
        if xen_cmdline_check != "no":
            validate_xen_commandline(xen_cmdline_check == "ignore")

        generate_vm_conf(self.install_info, self.instance_id)

        self.log.info("Calculating snapshot hash...")
        self.snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))
        self.analysis_dir = pathlib.Path(f"/tmp/drakrun/vm-{self.instance_id}")

    def setup_logger(self, level: Optional[Union[str, int]] = None) -> None:
        """
        Called by KartonBase.__init__. In case of drakrun we want to handle logging
        on root logger level to catch logs from other modules and utilities.
        We also need to turn on propagation from self.log that is turned off by Karton
        """
        # Let Karton make a proper setup
        super().setup_logger(level)
        # Then move handlers from Karton logger to root logger
        root_logger = logging.getLogger()
        for handler in self.log.handlers:
            root_logger.addHandler(handler)
        self.log.handlers.clear()
        self.log.propagate = True

    def timeout_for_task(self, task: Task) -> int:
        """Return a timeout for task - a default for quality or specified by task."""
        if (
            task.headers.get("quality", "high") == "low"
            and self.drakconfig.drakrun.analysis_low_timeout
        ):
            default_timeout = self.drakconfig.drakrun.analysis_low_timeout
        else:
            default_timeout = self.drakconfig.drakrun.analysis_timeout
        return task.payload.get("timeout", default_timeout)

    def update_vnc_info(self) -> None:
        """
        Put analysis ID -> drakrun node mapping into Redis.
        Required to know where to connect VNC client
        """
        self.backend.redis.set(
            f"drakvnc:{self.analysis_uid}", self.instance_id, ex=3600  # 1h
        )

    def upload_artifacts(self, analysis_uid: str, outdir: str, subdir: str = ""):
        for fn in os.listdir(os.path.join(outdir, subdir)):
            file_path = os.path.join(outdir, subdir, fn)

            if os.path.isfile(file_path):
                object_name = os.path.join(analysis_uid, subdir, fn)
                res_name = os.path.join(subdir, fn)
                resource = LocalResource(
                    name=res_name, bucket="drakrun", path=file_path, uid=object_name
                )
                yield resource
            elif os.path.isdir(file_path):
                yield from self.upload_artifacts(
                    analysis_uid, outdir, os.path.join(subdir, fn)
                )

    def build_profile_payload(self) -> Dict[str, LocalResource]:
        with tempfile.TemporaryDirectory() as tmp_path:
            tmp_dir = Path(tmp_path)

            for profile in dll_file_list:
                fpath = Path(PROFILE_DIR) / f"{profile.dest}.json"
                if fpath.is_file():
                    shutil.copy(fpath, tmp_dir / fpath.name)

            return Resource.from_directory(name="profiles", directory_path=tmp_dir)

    def send_raw_analysis(self, sample, outdir: str, metadata, quality: str) -> None:
        """Offload drakrun-prod by sending raw analysis output to be processed by
        drakrun.processor.
        """

        headers = {
            "type": "analysis",
            "kind": "drakrun",
        }
        task = Task(headers, payload=metadata)
        task.add_payload("sample", sample)

        # Support for regression tests
        if "testcase" in self.current_task.payload:
            task.add_payload("testcase", self.current_task.payload["testcase"])

        if self.drakconfig.drakrun.attach_profiles:
            self.log.info("Collecting profiles...")
            task.add_payload("profiles", self.build_profile_payload())

        if self.drakconfig.drakrun.attach_apiscout_profile:
            self.log.info("Collecting static ApiScout profile...")
            task.add_payload(
                "static_apiscout_profile.json",
                LocalResource(
                    name="static_apiscout_profile.json",
                    path=Path(APISCOUT_PROFILE_DIR) / "static_apiscout_profile.json",
                ),
            )

        self.log.info("Collecting artifacts...")
        for resource in self.upload_artifacts(self.analysis_uid, outdir):
            task.add_payload(resource.name, resource)

        self.log.info("Uploading task...")
        self.send_task(task)

    @property
    def analysis_uid(self) -> str:
        override_uid = self.current_task.payload.get("override_uid")

        if override_uid:
            return override_uid

        if self.drakconfig.drakrun.use_root_uid:
            return self.current_task.root_uid

        return self.current_task.uid

    def _prepare_analysis_directory(self) -> pathlib.Path:
        if self.analysis_dir.exists():
            shutil.rmtree(self.analysis_dir)
        self.analysis_dir.mkdir(parents=True)
        output_dir = self.analysis_dir / "output"
        output_dir.mkdir()
        return output_dir

    def _ensure_clean_output_dir(self) -> pathlib.Path:
        output_dir = self.analysis_dir / "output"
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.mkdir()
        return output_dir

    def process_task(self, task: Task) -> None:
        timeout = self.timeout_for_task(task)
        if timeout > MAX_TASK_TIMEOUT:
            self.log.error(
                "Tried to run the analysis for more than hard limit of %d seconds",
                MAX_TASK_TIMEOUT,
            )
            return

        sample: RemoteResource = cast(RemoteResource, task.get_resource("sample"))
        output_dir = self._prepare_analysis_directory()
        drakrun_log_path = output_dir / "drakrun.log"

        with scoped_file_logger(drakrun_log_path, logging.getLogger()):
            sample_path = self.analysis_dir / "sample"
            sample.download_to_file(str(sample_path))
            sha256sum = get_sample_sha256(sample_path)

            self.log.info(f"Running on: {socket.gethostname()}")
            self.log.info(f"Sample SHA256: {sha256sum}")
            self.log.info(f"Analysis UID: {self.analysis_uid}")
            self.log.info(f"Snapshot SHA256: {self.snapshot_sha256}")

            magic_output = magic.from_file(sample_path)

            # TODO: unify this default path somewhere
            hooks_path = pathlib.Path(ETC_DIR) / "hooks.txt"
            # If task contains 'custom_hooks' override local defaults
            if task.has_payload("custom_hooks"):
                hooks_path = self.analysis_dir / "hooks.txt"
                custom_hooks = cast(RemoteResource, task.get_resource("custom_hooks"))
                custom_hooks.download_to_file(str(hooks_path))

            user_start_command = task.payload.get("start_command")
            extension = task.headers.get("extension")

            # You can request a subset of supported plugins in task payload
            task_quality = self.current_task.headers.get("quality", "high")
            supported_plugins = self.drakconfig.drakvuf_plugins.get_plugin_list(
                task_quality
            )
            requested_plugins = self.current_task.payload.get(
                "plugins", self.drakconfig.drakvuf_plugins.get_plugin_list(task_quality)
            )
            plugins = list(set(supported_plugins) & set(requested_plugins))
            self.update_vnc_info()

            metadata = {
                "analysis_uid": self.analysis_uid,
                "sample_sha256": sha256sum,
                "snapshot_sha256": self.snapshot_sha256,
                "magic_output": magic_output,
            }

            create_or_update_analysis_status(
                self.backend.redis, self.analysis_uid, AnalysisStatus.STARTED, metadata
            )

            analysis_options = AnalysisOptions(
                sample_path=sample_path,
                vm_id=self.instance_id,
                output_dir=output_dir,
                plugins=plugins,
                timeout=timeout,
                hooks_path=hooks_path,
                start_command=user_start_command,
                extension=extension,
                sample_filename=sample.name,
                dns_server=self.drakconfig.drakrun.dns_server,
                out_interface=self.drakconfig.drakrun.out_interface,
                net_enable=self.drakconfig.drakrun.net_enable,
                anti_hammering_threshold=self.drakconfig.drakrun.anti_hammering_threshold,
                syscall_filter=self.drakconfig.drakrun.syscall_filter,
                raw_memory_dump=self.drakconfig.drakrun.raw_memory_dump,
            )

            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    self.log.info(
                        f"Trying to analyze sample (attempt {attempt+1}/{max_attempts})"
                    )
                    analysis_metadata = analyze_sample(analysis_options)
                    break
                except UnretryableAnalysisError:
                    self.log.exception("Analysis attempt failed with unretryable error")
                    raise
                except Exception:
                    self.log.exception("Analysis attempt failed. Retrying...")
                # Clean output dir before next try
                self._ensure_clean_output_dir()
            else:
                raise RuntimeError(f"Giving up after {max_attempts} failures...")

            metadata = {**metadata, **analysis_metadata}
            (output_dir / "metadata.json").write_text(json.dumps(metadata))

            quality = task.headers.get("quality", "high")
            self.send_raw_analysis(
                sample,
                str(output_dir),
                metadata,
                quality,
            )

            update_analysis_status(
                self.backend.redis, self.analysis_uid, AnalysisStatus.FINISHED, metadata
            )

    def process(self, task: Task) -> None:
        try:
            self.process_task(task)
        except Exception:
            update_analysis_status(
                self.backend.redis, self.analysis_uid, AnalysisStatus.CRASHED
            )
            raise

    @classmethod
    def args_parser(cls) -> argparse.ArgumentParser:
        parser = super().args_parser()
        parser.add_argument("instance", type=int, help="Instance identifier")
        return parser

    @classmethod
    def karton_from_args(cls, args: Optional[argparse.Namespace] = None) -> None:
        if args is None:
            parser = cls.args_parser()
            args = parser.parse_args()
        conf_path = os.path.join(ETC_DIR, "config.ini")
        config = Config(path=args.config_file or conf_path)
        cls.config_from_args(config, args)
        return cls(config=config, instance_id=args.instance)


def validate_xen_commandline(ignore_failure: bool) -> None:
    """Validate XEN command line and print found misconfigurations.
    Will exit process on failure, unless ignore_failure parameter is passed"""
    required_cmdline = {
        "sched": "credit",
        "force-ept": "1",
        "ept": "ad=0",
        "hap_1gb": "0",
        "hap_2mb": "0",
        "altp2m": "1",
        "hpet": "legacy-replacement",
    }
    xen_info = get_xen_info()
    xen_cmdline = parse_xen_commandline(xen_info["xen_commandline"])

    unrecommended = []
    for key, recommended_value in required_cmdline.items():
        actual_value = xen_cmdline.get(key)
        if actual_value != recommended_value:
            unrecommended.append((key, recommended_value, actual_value))

    if unrecommended:
        log.warning("-" * 80)
        log.warning(
            "You don't have the recommended settings in your Xen's command line."
        )
        log.warning(
            "Please amend settings in your GRUB_CMDLINE_XEN_DEFAULT in /etc/default/grub.d/xen.cfg file."
        )

        for k, v, actual_v in unrecommended:
            if actual_v is not None:
                log.warning(f"- Set {k}={v} (instead of {k}={actual_v})")
            else:
                log.warning(f"- Set {k}={v} ({k} is not set right now)")

        log.warning(
            "Then, please execute the following commands as root: update-grub && reboot"
        )
        log.warning("-" * 80)
        log.warning(
            "This check can be skipped by adding xen_cmdline_check=ignore in [drakrun] section of drakrun's config."
        )
        log.warning(
            "Please be aware that some bugs may arise when using unrecommended settings."
        )

        if ignore_failure:
            log.warning(
                "ATTENTION! Configuration specified that check result should be ignored, continuing anyway..."
            )
        else:
            log.error(
                "Exitting due to above warnings. Please ensure that you are using recommended Xen's command line."
            )
            raise XenCommandlineCheckError()


if __name__ == "__main__":
    DrakrunKarton.main()
