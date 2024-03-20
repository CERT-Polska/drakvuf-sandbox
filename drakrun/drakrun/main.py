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

from drakrun.lib.bindings.xen import get_xen_info, parse_xen_commandline
from drakrun.lib.config import load_config
from drakrun.lib.drakpdb import dll_file_list
from drakrun.lib.injector import Injector
from drakrun.lib.install_info import InstallInfo
from drakrun.lib.networking import (
    setup_vm_network,
    start_dnsmasq,
    start_tcpdump_collector,
)
from drakrun.lib.paths import (
    APISCOUT_PROFILE_DIR,
    ETC_DIR,
    PROFILE_DIR,
    RUNTIME_FILE,
    VOLUME_DIR,
)
from drakrun.lib.sample_startup import (
    get_sample_entrypoints,
    get_sample_startup_command,
)
from drakrun.lib.storage import get_storage_backend
from drakrun.lib.util import RuntimeInfo, file_sha256, graceful_exit
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


class DrakrunKarton(Karton):
    version = DRAKRUN_VERSION
    identity = "karton.drakrun-prod"
    filters = [
        {"type": "sample", "stage": "recognized", "platform": "win32"},
        {"type": "sample", "stage": "recognized", "platform": "win64"},
    ]

    def __init__(self, config: Config, instance_id: int) -> None:
        super().__init__(config)
        self.drakconfig = load_config()

        # Now that karton is set up we can plug in our logger
        moduleLogger = logging.getLogger()
        for handler in self.log.handlers:
            moduleLogger.addHandler(handler)
        moduleLogger.setLevel(logging.INFO)

        self.instance_id = instance_id
        self.install_info = InstallInfo.load()
        self.runtime_info = RuntimeInfo.load(RUNTIME_FILE)

        generate_vm_conf(self.install_info, self.instance_id)

        if not self.backend.minio.bucket_exists("drakrun"):
            self.backend.minio.make_bucket(bucket_name="drakrun")

        setup_vm_network(
            self.instance_id,
            self.drakconfig.drakrun.net_enable,
            self.drakconfig.drakrun.out_interface,
            self.drakconfig.drakrun.dns_server,
        )

        self.log.info("Calculating snapshot hash...")
        self.snapshot_sha256 = file_sha256(os.path.join(VOLUME_DIR, "snapshot.sav"))

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

    def filename_for_task(self, task: Task, magic_output: str) -> Tuple[str, str]:
        """Return a tuple of (filename, extension) for a given task.
        This depends on the content magic, "extension" header and "file_name" payload.
        """
        # headers["extensions"] may exist and be None
        extension = task.headers.get("extension")
        if not extension:
            if "(DLL)" in magic_output:
                extension = "dll"
            else:
                extension = "exe"
        # Make sure the extension is lowercase
        extension = extension.lower()
        file_name = task.payload.get("file_name", "malwar") + f".{extension}"
        if not re.match(r"^[a-zA-Z0-9\._\-]+$", file_name):
            raise RuntimeError("Filename contains invalid characters")

        return file_name, extension

    def generate_plugin_cmdline(self, plugin_list: List[str]) -> List[str]:
        return list(
            chain.from_iterable(["-a", plugin] for plugin in sorted(plugin_list))
        )

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

        if self.drakconfig.drakrun.attach_profiles:
            self.log.info("Uploading profiles...")
            task.add_payload("profiles", self.build_profile_payload())

        if self.drakconfig.drakrun.attach_apiscout_profile:
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

        if self.drakconfig.drakrun.use_root_uid:
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
        hooks_path: str,
        enabled_plugins,
    ) -> List[str]:
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
                hooks_path,
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

        if self.drakconfig.drakrun.anti_hammering_threshold:
            drakvuf_cmd.extend(
                ["--traps-ttl", str(self.drakconfig.drakrun.anti_hammering_threshold)]
            )

        drakvuf_cmd.extend(self.get_profile_list())

        if self.drakconfig.drakrun.syscall_filter:
            drakvuf_cmd.extend(["-S", self.drakconfig.drakrun.syscall_filter])

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
        sample_extension: str,
        sample_entrypoints: List[str],
        hooks_path: str,
        outdir: str,
        user_start_command: Optional[str],
        timeout: int,
    ) -> Dict[str, Any]:
        analysis_info = dict()
        drakmon_log_fp = os.path.join(outdir, "drakmon.log")

        with self.run_vm() as vm, graceful_exit(
            start_dnsmasq(self.instance_id, self.drakconfig.drakrun.dns_server)
        ), graceful_exit(start_tcpdump_collector(vm.get_domid(), outdir)), open(
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

            if user_start_command:
                start_command = user_start_command.replace("%f", injected_fn)
            else:
                start_command = get_sample_startup_command(
                    injected_fn, sample_extension, sample_entrypoints
                )
            analysis_info["start_command"] = start_command
            self.log.info("Using command: %s", start_command)

            if self.drakconfig.drakrun.net_enable:
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

            # You can request a subset of supported plugins in task payload
            task_quality = self.current_task.headers.get("quality", "high")
            supported_plugins = self.drakconfig.drakvuf_plugins.get_plugin_list(
                task_quality
            )
            requested_plugins = self.current_task.payload.get(
                "plugins", self.drakconfig.drakvuf_plugins.get_plugin_list(task_quality)
            )
            analysis_info["plugins"] = list(
                set(supported_plugins) & set(requested_plugins)
            )

            drakvuf_cmd = self.build_drakvuf_cmdline(
                timeout=timeout,
                cwd=ntpath.dirname(injected_fn),
                full_cmd=start_command,
                dump_dir=os.path.join(outdir, "dumps"),
                ipt_dir=os.path.join(outdir, "ipt"),
                hooks_path=hooks_path,
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

            if self.drakconfig.drakrun.raw_memory_dump:
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

        user_start_command = task.payload.get("start_command")
        sample_entrypoints = get_sample_entrypoints(extension, sample.content)

        # workdir - configs, sample, etc.
        # outdir - analysis artifacts
        workdir, outdir = self._prepare_workdir()

        sample_path = os.path.join(workdir, file_name)
        sample.download_to_file(sample_path)

        # If task contains 'custom_hooks' override local defaults
        hooks_path = os.path.join(workdir, "hooks.txt")
        with open(hooks_path, "wb") as hooks:
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
                    sample_path,
                    extension,
                    sample_entrypoints,
                    hooks_path,
                    outdir,
                    user_start_command,
                    timeout,
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
