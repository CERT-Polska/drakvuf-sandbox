#!/usr/bin/python3

import argparse
import contextlib
import functools
import hashlib
import json
import logging
import ntpath
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from io import StringIO
from itertools import chain
from pathlib import Path
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_SIZE
from typing import Any, Dict, List, Optional, Tuple

import magic
from karton.core import Config, Karton, LocalResource, Resource, Task

import drakrun.lib.sample_startup as sample_startup
from drakrun.lib.config import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    PROFILE_DIR,
    RUNTIME_FILE,
    VOLUME_DIR,
    InstallInfo,
)
from drakrun.lib.drakpdb import dll_file_list
from drakrun.lib.injector import Injector
from drakrun.lib.networking import (
    setup_vm_network,
    start_dnsmasq,
    start_tcpdump_collector,
)
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.util import (
    RuntimeInfo,
    file_sha256,
    get_xen_commandline,
    get_xl_info,
    graceful_exit,
)
from drakrun.lib.vm import VirtualMachine, generate_vm_conf
from drakrun.version import __version__ as DRAKRUN_VERSION

# fmt: off
# List of default plugins, and at the same time list of all supported plugins.
SUPPORTED_PLUGINS = [
    "apimon", "bsodmon", "clipboardmon", "cpuidmon", "crashmon", "debugmon",
    "delaymon", "exmon", "filedelete", "filetracer", "librarymon", "memdump",
    "procdump", "procmon", "regmon", "rpcmon", "ssdtmon", "syscalls", "tlsmon",
    "windowmon", "wmimon",
]
# fmt: on

MAX_TASK_TIMEOUT = 60 * 20  # Never run samples for longer than this

log = logging.getLogger(__name__)


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
                raise
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
                        self.current_task.payload.get("override_uid")
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


class DrakrunConfig:
    """A typed wrapper for a Drakrun config. In the future, this will be handled
    by Karton's typedconfig more directly
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    def get(self, option: str, fallback: Any) -> Any:
        return self.config.config.get("drakrun", option, fallback=fallback)

    def getint(self, option: str, fallback: int) -> int:
        return self.config.config.getint("drakrun", option, fallback=fallback)

    def getboolean(self, option: str, fallback: bool) -> bool:
        return self.config.config.getboolean("drakrun", option, fallback=fallback)

    @property
    def out_interface(self) -> str:
        return self.get("out_interface", fallback="")

    @property
    def default_timeout(self) -> int:
        """Default timeout for normal and high priority tasks."""
        return self.getint("analysis_timeout", fallback=60 * 10)

    @property
    def default_low_timeout(self) -> int:
        """Default timeout for lwo priority tasks."""
        return self.getint("analysis_low_timeout", fallback=self.default_timeout)

    @property
    def net_enable(self) -> bool:
        """Should network be enabled for this analysis?"""
        return self.getboolean("net_enable", fallback=False)

    @property
    def attach_profiles(self) -> bool:
        """Should profiles payload be attached to the analysis?"""
        return self.getboolean("attach_profiles", fallback=False)

    @property
    def attach_apiscout_profile(self) -> bool:
        """Should apiscout profile be attached to the analysis results?"""
        return self.getboolean("attach_apiscout_profile", fallback=False)

    @property
    def use_root_uid(self) -> bool:
        """Should analysis use root UID or task UID as a s3 key for upload"""
        return self.getboolean("use_root_uid", fallback=False)

    @property
    def anti_hammering_threshold(self) -> int:
        return self.getint("anti_hammering_threshold", fallback=0)

    @property
    def syscall_filter(self) -> Optional[str]:
        return self.get("syscall_filter", fallback=None)

    @property
    def dns_server(self) -> str:
        """Get a DNS server used for analysis. `use-gateway-address` is special"""
        return self.get("dns_server", fallback="8.8.8.8")

    @property
    def raw_memory_dump(self) -> bool:
        return self.getboolean("raw_memory_dump", fallback=False)

    def plugins(self) -> Dict[str, List[str]]:
        plugins = {}
        for quality, list_str in self.config.config.items("drakvuf_plugins"):
            plugins[quality] = [x.strip() for x in list_str.split(",")]
        return plugins


class DrakrunKarton(Karton):
    version = DRAKRUN_VERSION
    identity = "karton.drakrun-prod"
    filters = [
        {"type": "sample", "stage": "recognized", "platform": "win32"},
        {"type": "sample", "stage": "recognized", "platform": "win64"},
    ]

    def __init__(self, config: Config, instance_id: int) -> None:
        super().__init__(config)
        self.drakconfig = DrakrunConfig(config)

        # Now that karton is set up we can plug in our logger
        moduleLogger = logging.getLogger()
        for handler in self.log.handlers:
            moduleLogger.addHandler(handler)
        moduleLogger.setLevel(logging.INFO)

        self.instance_id = instance_id
        self.install_info = InstallInfo.load()
        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)
        self.active_plugins = self.find_active_plugins()

        generate_vm_conf(self.install_info, self.instance_id)

        if not self.backend.minio.bucket_exists("drakrun"):
            self.backend.minio.make_bucket(bucket_name="drakrun")

        setup_vm_network(
            self.instance_id,
            self.drakconfig.net_enable,
            self.drakconfig.out_interface,
            self.drakconfig.dns_server,
        )

        self.log.info("Calculating snapshot hash...")
        self.snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))

    def find_active_plugins(self) -> Dict[str, List[str]]:
        """Parse active plugins from config, with a default value for _all_"""
        plugins = self.drakconfig.plugins()
        plugins["_all_"] = SUPPORTED_PLUGINS
        return plugins

    def timeout_for_task(self, task: Task) -> int:
        """Return a timeout for task - a default for quality or specified by task."""
        default_timeout = (
            self.drakconfig.default_low_timeout
            if task.headers.get("quality", "high") == "low"
            else self.drakconfig.default_timeout
        )
        return task.payload.get("timeout", default_timeout)

    def filename_for_task(self, task: Task, magic_output: str) -> Tuple[str, str]:
        """Return a tuple of (filename, extension) for a given task.
        This depends on the content magic, "extension" header and "file_name" payload.
        """
        # headers["extensions"] may exist and be None
        extension = (task.headers.get("extension") or "exe").lower()
        if "(DLL)" in magic_output:
            extension = "dll"

        file_name = task.payload.get("file_name", "malwar") + f".{extension}"
        if not re.match(r"^[a-zA-Z0-9\._\-]+$", file_name):
            raise RuntimeError("Filename contains invalid characters")

        return file_name, extension

    def generate_plugin_cmdline(self, plugin_list: List[str]) -> List[str]:
        if len(plugin_list) == 0:
            # Disable all plugins explicitly as all plugins are enabled by default.
            return list(
                chain.from_iterable(
                    ["-x", plugin] for plugin in sorted(self.active_plugins["_all_"])
                )
            )
        else:
            return list(
                chain.from_iterable(["-a", plugin] for plugin in sorted(plugin_list))
            )

    def get_plugin_list(self, quality: str, requested_plugins: List[str]) -> List[str]:
        """
        Determine final plugin list that will be used during analysis.
        """
        plugin_list = self.active_plugins["_all_"]
        if quality in self.active_plugins:
            plugin_list = self.active_plugins[quality]
        plugin_list = list(set(plugin_list) & set(requested_plugins))

        if "ipt" in plugin_list and "codemon" not in plugin_list:
            self.log.info("Using ipt plugin implies using codemon")
            plugin_list.append("codemon")
        return plugin_list

    @property
    def vm_name(self) -> str:
        return f"vm-{self.instance_id}"

    def crop_dumps(self, dirpath: str, target_zip: str) -> List[Dict[str, Any]]:
        zipf = zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED)

        entries = (os.path.join(dirpath, fn) for fn in os.listdir(dirpath))
        entries = ((os.stat(path), path) for path in entries)

        entries = (
            (stat[ST_CTIME], path, stat[ST_SIZE])
            for stat, path in entries
            if S_ISREG(stat[ST_MODE])
        )

        max_total_size = 300 * 1024 * 1024  # 300 MB
        current_size = 0

        dumps_metadata = []
        for _, path, size in sorted(entries):
            current_size += size

            if current_size <= max_total_size:
                # Store files under dumps/
                file_basename = os.path.basename(path)
                if re.fullmatch(r"[a-f0-9]{4,16}_[a-f0-9]{16}", file_basename):
                    # If file is memory dump then append metadata that can be
                    # later attached as payload when creating an `analysis` task.
                    dump_base = self._get_base_from_drakrun_dump(file_basename)
                    dumps_metadata.append(
                        {
                            "filename": os.path.join("dumps", file_basename),
                            "base_address": dump_base,
                        }
                    )
                zipf.write(path, os.path.join("dumps", file_basename))
            os.unlink(path)

        # No dumps, force empty directory
        if current_size == 0:
            zipf.writestr(zipfile.ZipInfo("dumps/"), "")

        if current_size > max_total_size:
            self.log.warning(
                "Some dumps were deleted, because the configured size threshold was exceeded."
            )
        return dumps_metadata

    def _get_base_from_drakrun_dump(self, dump_name: str) -> str:
        """
        Drakrun dumps come in form: <base>_<hash> e.g. 405000_688f58c58d798ecb,
        that can be read as a dump from address 0x405000 with a content hash
        equal to 688f58c58d798ecb.
        """
        return hex(int(dump_name.split("_")[0], 16))

    def update_vnc_info(self) -> None:
        """
        Put analysis ID -> drakrun node mapping into Redis.
        Required to know where to connect VNC client
        """
        self.backend.redis.set(
            f"drakvnc:{self.analysis_uid}", self.instance_id, ex=3600  # 1h
        )

    def compress_ipt(self, dirpath: str, target_zip: str) -> None:
        """
        Compress the directory specified by dirpath to target_zip file.
        """
        zipf = zipfile.ZipFile(target_zip, "w", zipfile.ZIP_DEFLATED)

        for root, dirs, files in os.walk(dirpath):
            for file in files:
                zipf.write(
                    os.path.join(root, file),
                    os.path.join(
                        "ipt", os.path.relpath(os.path.join(root, file), dirpath)
                    ),
                )
                os.unlink(os.path.join(root, file))

    def upload_artifacts(self, analysis_uid: str, outdir: str, subdir: str = ""):
        for fn in os.listdir(os.path.join(outdir, subdir)):
            file_path = os.path.join(outdir, subdir, fn)

            if os.path.isfile(file_path):
                object_name = os.path.join(analysis_uid, subdir, fn)
                res_name = os.path.join(subdir, fn)
                resource = LocalResource(
                    name=res_name, bucket="drakrun", path=file_path
                )
                resource._uid = object_name
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

    def send_raw_analysis(
        self, sample, outdir: str, metadata, dumps_metadata, quality: str
    ) -> None:
        """Offload drakrun-prod by sending raw analysis output to be processed by
        drakrun.processor.
        """

        headers = {
            "type": "analysis-raw",
            "kind": "drakrun-internal",
            "quality": quality,
        }
        task = Task(headers, payload=metadata)
        task.add_payload("sample", sample)
        task.add_payload("dumps_metadata", dumps_metadata)

        # Support for regression tests
        if "testcase" in self.current_task.payload:
            task.add_payload("testcase", self.current_task.payload["testcase"])

        if self.drakconfig.attach_profiles:
            self.log.info("Uploading profiles...")
            task.add_payload("profiles", self.build_profile_payload())

        if self.drakconfig.attach_apiscout_profile:
            self.log.info("Uploading static ApiScout profile...")
            task.add_payload(
                "static_apiscout_profile.json",
                LocalResource(
                    name="static_apiscout_profile.json",
                    path=Path(APISCOUT_PROFILE_DIR) / "static_apiscout_profile.json",
                ),
            )

        self.log.info("Uploading artifacts...")
        for resource in self.upload_artifacts(self.analysis_uid, outdir):
            task.add_payload(resource.name, resource)

        self.send_task(task)

    @staticmethod
    def get_profile_list() -> List[str]:
        files = os.listdir(PROFILE_DIR)

        out = []

        for profile in dll_file_list:
            if profile.arg is None:
                continue
            if f"{profile.dest}.json" in files:
                out.extend(
                    [profile.arg, os.path.join(PROFILE_DIR, f"{profile.dest}.json")]
                )

        return out

    @contextlib.contextmanager
    def run_vm(self):
        backend = get_storage_backend(self.install_info)
        vm = VirtualMachine(backend, self.instance_id)

        try:
            vm.restore()
        except subprocess.CalledProcessError:
            self.log.exception(f"Failed to restore VM {self.vm_name}")
            with open(f"/var/log/xen/qemu-dm-{self.vm_name}.log", "rb") as f:
                self.log.error(f.read())

        self.log.info("VM restored")

        try:
            yield vm
        finally:
            try:
                vm.destroy()
            except Exception:
                self.log.exception("Failed to destroy VM")

    @property
    def analysis_uid(self) -> str:
        override_uid = self.current_task.payload.get("override_uid")

        if override_uid:
            return override_uid

        if self.drakconfig.use_root_uid:
            return self.current_task.root_uid

        return self.current_task.uid

    def _prepare_workdir(self) -> Tuple[str, str]:
        workdir = os.path.join("/tmp/drakrun", self.vm_name)

        try:
            if os.path.isdir(workdir):
                shutil.rmtree(workdir)
        except OSError:
            self.log.exception("Failed to clean work directory")

        os.makedirs(workdir, exist_ok=True)

        outdir = os.path.join(workdir, "output")
        os.mkdir(outdir)
        os.mkdir(os.path.join(outdir, "dumps"))
        os.mkdir(os.path.join(outdir, "ipt"))

        return (workdir, outdir)

    def build_drakvuf_cmdline(
        self,
        timeout: int,
        cwd: str,
        full_cmd: str,
        dump_dir: str,
        ipt_dir: str,
        workdir: str,
        enabled_plugins,
    ) -> List[str]:
        hooks_list = os.path.join(workdir, "hooks.txt")
        kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")

        drakvuf_cmd = (
            ["drakvuf"]
            + self.generate_plugin_cmdline(enabled_plugins)
            + [
                "-o",
                "json",
                # be aware of https://github.com/tklengyel/drakvuf/pull/951
                "-F",  # enable fast singlestep
                "-j",
                "60",
                "-t",
                str(timeout),
                "-i",
                str(self.runtime_info.inject_pid),
                "-k",
                hex(self.runtime_info.vmi_offsets.kpgd),
                "-d",
                self.vm_name,
                "--dll-hooks-list",
                hooks_list,
                "--memdump-dir",
                dump_dir,
                "--ipt-dir",
                ipt_dir,
                "--ipt-trace-user",
                "--codemon-dump-dir",
                ipt_dir,
                "--codemon-log-everything",
                "--codemon-analyse-system-dll-vad",
                "-r",
                kernel_profile,
                "-e",
                full_cmd,
                "-c",
                cwd,
            ]
        )

        if self.drakconfig.anti_hammering_threshold:
            drakvuf_cmd.extend(
                ["--traps-ttl", str(self.drakconfig.anti_hammering_threshold)]
            )

        drakvuf_cmd.extend(self.get_profile_list())

        if self.drakconfig.syscall_filter:
            drakvuf_cmd.extend(["-S", self.drakconfig.syscall_filter])

        return drakvuf_cmd

    def log_startup_failure(self, log_path: str) -> None:
        self.log.warning("Injection succeeded but the sample didn't execute properly")

        with open(log_path, "r") as drakvuf_log:
            # There should be only line line
            for line in drakvuf_log:
                entry = json.loads(line)
                if entry["Plugin"] == "inject":
                    self.log.info("Injection failed with error: %s", entry["Error"])
                    break

    def analyze_sample(
        self,
        sample_path: str,
        workdir: str,
        outdir: str,
        start_command: str,
        timeout: int,
    ) -> Dict[str, Any]:
        analysis_info = dict()
        drakmon_log_fp = os.path.join(outdir, "drakmon.log")

        with self.run_vm() as vm, graceful_exit(
            start_dnsmasq(self.instance_id, self.drakconfig.dns_server)
        ), graceful_exit(start_tcpdump_collector(self.instance_id, outdir)), open(
            drakmon_log_fp, "wb"
        ) as drakmon_log:

            analysis_info["snapshot_version"] = vm.backend.get_vm0_snapshot_time()

            kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")

            self.log.info("Copying sample to VM...")
            injector = Injector(self.vm_name, self.runtime_info, kernel_profile)
            result = injector.write_file(
                sample_path, f"%USERPROFILE%\\Desktop\\{os.path.basename(sample_path)}"
            )

            try:
                injected_fn = json.loads(result.stdout)["ProcessName"]
            except ValueError as e:
                self.log.error(
                    "JSON decode error occurred when tried to parse injector's logs."
                )
                self.log.error(f"Raw log line: {result.stdout}")
                raise e

            # don't include our internal maintanance commands
            start_command = start_command.replace("%f", injected_fn)
            analysis_info["start_command"] = start_command
            self.log.info("Using command: %s", start_command)

            if self.drakconfig.net_enable:
                max_attempts = 3
                for i in range(max_attempts):
                    try:
                        self.log.info(
                            f"Trying to setup network (attempt {i + 1}/{max_attempts})"
                        )
                        injector.create_process(
                            "cmd /C ipconfig /release >nul", wait=True, timeout=120
                        )
                        injector.create_process(
                            "cmd /C ipconfig /renew >nul", wait=True, timeout=120
                        )
                        break
                    except Exception:
                        self.log.exception("Analysis attempt failed. Retrying...")
                else:
                    self.log.warning(f"Giving up after {max_attempts} failures...")
                    raise RuntimeError("Failed to setup VM network after 3 attempts")

            task_quality = self.current_task.headers.get("quality", "high")
            requested_plugins = self.current_task.payload.get(
                "plugins", self.active_plugins["_all_"]
            )
            analysis_info["plugins"] = self.get_plugin_list(
                task_quality, requested_plugins
            )

            drakvuf_cmd = self.build_drakvuf_cmdline(
                timeout=timeout,
                cwd=subprocess.list2cmdline([ntpath.dirname(injected_fn)]),
                full_cmd=start_command,
                dump_dir=os.path.join(outdir, "dumps"),
                ipt_dir=os.path.join(outdir, "ipt"),
                workdir=workdir,
                enabled_plugins=analysis_info["plugins"],
            )

            try:
                subprocess.run(
                    drakvuf_cmd, stdout=drakmon_log, check=True, timeout=timeout + 60
                )
            except subprocess.CalledProcessError as e:
                # see DRAKVUF src/exitcodes.h for more details
                INJECTION_UNSUCCESSFUL = 4

                if e.returncode == INJECTION_UNSUCCESSFUL:
                    self.log_startup_failure(drakmon_log_fp)
                else:
                    # Something bad happened
                    raise e
            except subprocess.TimeoutExpired as e:
                self.log.exception("DRAKVUF timeout expired")
                raise e

            if self.drakconfig.raw_memory_dump:
                vm.memory_dump(os.path.join(outdir, "post_sample.raw_memdump.gz"))

        return analysis_info

    @with_logs("drakrun.log")
    def process(self, task: Task) -> None:
        # Tasks with {"execute": false} header are not scheduled for execution.
        # When the header is missing, the default is to execute the sample.
        if not task.headers.get("execute", True):
            return

        timeout = self.timeout_for_task(task)
        if timeout > MAX_TASK_TIMEOUT:
            self.log.error(
                "Tried to run the analysis for more than hard limit of %d seconds",
                MAX_TASK_TIMEOUT,
            )
            return

        sample = task.get_resource("sample")
        sha256sum = hashlib.sha256(sample.content).hexdigest()
        self.log.info(f"Running on: {socket.gethostname()}")
        self.log.info(f"Sample SHA256: {sha256sum}")
        self.log.info(f"Analysis UID: {self.analysis_uid}")
        self.log.info(f"Snapshot SHA256: {self.snapshot_sha256}")

        magic_output = magic.from_buffer(sample.content)
        file_name, extension = self.filename_for_task(task, magic_output)
        self.log.info("Using file name %s", file_name)

        # workdir - configs, sample, etc.
        # outdir - analysis artifacts
        workdir, outdir = self._prepare_workdir()

        sample_path = os.path.join(workdir, file_name)
        sample.download_to_file(sample_path)

        # Try to come up with a start command for this file
        # or use the one provided by the sender
        start_command = task.payload.get(
            "start_command",
            sample_startup.get_sample_startup_command(extension, sample, sample_path),
        )
        if not start_command:
            # We should have a start up command at this point
            self.log.error(
                "Unable to run malware sample. Could not generate any suitable command to run it."
            )
            return
        if "%f" not in start_command:
            self.log.warning("No file name in start command")

        # If task contains 'custom_hooks' override local defaults
        with open(os.path.join(workdir, "hooks.txt"), "wb") as hooks:
            if task.has_payload("custom_hooks"):
                custom_hooks = task.get_resource("custom_hooks")
                assert custom_hooks.content is not None
                hooks.write(custom_hooks.content)
            else:
                with open(os.path.join(ETC_DIR, "hooks.txt"), "rb") as default_hooks:
                    hooks.write(default_hooks.read())

        self.update_vnc_info()

        metadata = {
            "analysis_uid": self.analysis_uid,
            "sample_sha256": sha256sum,
            "snapshot_sha256": self.snapshot_sha256,
            "magic_output": magic_output,
            "time_started": int(time.time()),
        }

        max_attempts = 3
        for i in range(max_attempts):
            try:
                self.log.info(
                    f"Trying to analyze sample (attempt {i + 1}/{max_attempts})"
                )
                info = self.analyze_sample(
                    sample_path, workdir, outdir, start_command, timeout
                )
                metadata.update(info)
                break
            except Exception:
                self.log.exception("Analysis attempt failed. Retrying...")
        else:
            self.log.warning(f"Giving up after {max_attempts} failures...")
            return

        self.log.info("Analysis done. Collecting artifacts...")

        # Make sure dumps have a reasonable size.
        # Calculate dumps_metadata as it's required by the `analysis` task format.
        dumps_metadata = self.crop_dumps(
            os.path.join(outdir, "dumps"), os.path.join(outdir, "dumps.zip")
        )

        # Compress IPT traces, they're quite large however they compress well
        self.compress_ipt(os.path.join(outdir, "ipt"), os.path.join(outdir, "ipt.zip"))

        metadata["time_finished"] = int(time.time())

        with open(os.path.join(outdir, "metadata.json"), "w") as f:
            f.write(json.dumps(metadata))

        quality = task.headers.get("quality", "high")
        self.send_raw_analysis(sample, outdir, metadata, dumps_metadata, quality)


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

    parsed_xl_info = get_xl_info()
    xen_cmdline = get_xen_commandline(parsed_xl_info)

    unrecommended = []

    for k, v in required_cmdline.items():
        actual_v = xen_cmdline.get(k)

        if actual_v != v:
            unrecommended.append((k, v, actual_v))

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
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description="Kartonized drakrun <3")
    parser.add_argument("instance", type=int, help="Instance identifier")
    args = parser.parse_args()

    conf_path = os.path.join(ETC_DIR, "config.ini")
    conf = Config(conf_path)

    if not conf.config.get("minio", "access_key").strip():
        log.warning(
            f"Detected blank value for minio access_key in {conf_path}. "
            "This service may not work properly."
        )

    xen_cmdline_check = conf.config.get("drakrun", "xen_cmdline_check", fallback="fail")
    validate_xen_commandline(xen_cmdline_check == "ignore")

    c = DrakrunKarton(conf, args.instance)
    c.loop()


if __name__ == "__main__":
    main()
