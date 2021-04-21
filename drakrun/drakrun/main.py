#!/usr/bin/python3

import contextlib
import logging
import sys
import os
import shutil
import argparse
import subprocess
import hashlib
import socket
import time
import zipfile
import json
import re
import functools
import tempfile
from io import StringIO
from typing import List, Dict
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_SIZE
from configparser import NoOptionError
from itertools import chain
from pathlib import Path

import pefile
import magic
import ntpath
from karton.core import Karton, Config, Task, LocalResource, Resource

import drakrun.office as d_office
from drakrun.version import __version__ as DRAKRUN_VERSION
from drakrun.drakpdb import dll_file_list
from drakrun.config import InstallInfo, ETC_DIR, VM_CONFIG_DIR, VOLUME_DIR, PROFILE_DIR
from drakrun.storage import get_storage_backend
from drakrun.networking import start_tcpdump_collector, start_dnsmasq, setup_vm_network
from drakrun.util import (
    patch_config,
    get_xl_info,
    get_xen_commandline,
    graceful_exit,
    RuntimeInfo,
)
from drakrun.vm import generate_vm_conf, VirtualMachine
from drakrun.injector import Injector


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
                    task_uid = self.current_task.payload.get('override_uid') or self.current_task.uid
                    res._uid = f"{task_uid}/{res.name}"
                    res.upload(self.backend)
                except Exception:
                    self.log.exception("Failed to upload analysis logs")
        return wrapper
    return decorator


class DrakrunKarton(Karton):
    version = DRAKRUN_VERSION
    # Karton configuration defaults, may be overriden by config file
    DEFAULT_IDENTITY = "karton.drakrun-prod"
    DEFAULT_FILTERS = [
        {
            "type": "sample",
            "stage": "recognized",
            "platform": "win32"
        },
        {
            "type": "sample",
            "stage": "recognized",
            "platform": "win64"
        }
    ]
    DEFAULT_HEADERS = {
        "type": "analysis",
        "kind": "drakrun",
    }

    # Filters and headers used for testing sample analysis
    DEFAULT_TEST_FILTERS = [
        {
            "type": "sample-test",
            "platform": "win32",
        },
        {
            "type": "sample-test",
            "platform": "win64",
        },
    ]
    DEFAULT_TEST_HEADERS = {
        "type": "analysis-test",
        "kind": "drakrun",
    }

    def __init__(self, config: Config, instance_id: int):
        super().__init__(config)

        # Now that karton is set up we can plug in our logger
        logger = logging.getLogger("drakrun")
        for handler in self.log.handlers:
            logger.addHandler(handler)
        logger.setLevel(logging.INFO)

        self.instance_id = instance_id
        self.install_info = InstallInfo.load()
        self.default_timeout = int(self.config.config['drakrun'].get('analysis_timeout') or 60 * 10)
        with open(os.path.join(PROFILE_DIR, "runtime.json"), 'r') as runtime_f:
            self.runtime_info = RuntimeInfo.load(runtime_f)

        self.active_plugins = {}
        self.active_plugins["_all_"] = [
            'apimon', 'bsodmon', 'clipboardmon', 'cpuidmon', 'crashmon',
            'debugmon', 'delaymon', 'exmon', 'filedelete', 'filetracer',
            'librarymon', 'memdump', 'procdump', 'procmon', 'regmon',
            'rpcmon', 'ssdtmon', 'syscalls', 'tlsmon', 'windowmon',
            'wmimon']

        for quality, list_str in self.config.config.items('drakvuf_plugins'):
            plugins = [x for x in list_str.split(',') if x.strip()]
            self.active_plugins[quality] = plugins

    def generate_plugin_cmdline(self, quality, enabled_plugins):
        plugin_list = self.active_plugins["_all_"]
        if quality in self.active_plugins:
            plugin_list = self.active_plugins[quality]

        plugin_list = list(set(plugin_list) & set(enabled_plugins))

        if "ipt" in plugin_list and "codemon" not in plugin_list:
            self.log.info("Using ipt plugin implies using codemon")
            plugin_list.append("codemon")

        return list(chain.from_iterable(["-a", plugin] for plugin in sorted(plugin_list)))

    @classmethod
    def reconfigure(cls, config: Dict[str, str]):
        """ Reconfigure DrakrunKarton class """
        def load_json(config, key):
            try:
                return json.loads(config.get(key)) if key in config else None
            except json.JSONDecodeError:
                raise RuntimeError(f"Key '{key}' in section [drakrun] is not valid JSON")

        cls.identity = config.get('identity', cls.DEFAULT_IDENTITY)
        cls.filters = load_json(config, 'filters') or cls.DEFAULT_FILTERS
        cls.headers = load_json(config, 'headers') or cls.DEFAULT_HEADERS
        cls.test_headers = load_json(config, 'test_headers') or cls.DEFAULT_TEST_HEADERS
        cls.test_filters = load_json(config, 'test_filters') or cls.DEFAULT_TEST_FILTERS

        # If testing is enabled, add additional test filters from the configuration
        # or fall back to hardcoded
        if config.getboolean("sample_testing", fallback=False):
            cls.filters.extend(cls.test_filters)

    @property
    def net_enable(self) -> bool:
        return self.config.config['drakrun'].getboolean('net_enable', fallback=False)

    @property
    def test_run(self) -> bool:
        # If testing is disabled, it's not a test run
        if not self.config.config['drakrun'].getboolean('sample_testing', fallback=False):
            return False

        return self.current_task.matches_filters(self.test_filters)

    @property
    def vm_name(self) -> str:
        return f"vm-{self.instance_id}"

    def init_drakrun(self):
        generate_vm_conf(self.install_info, self.instance_id)

        if not self.backend.minio.bucket_exists('drakrun'):
            self.backend.minio.make_bucket(bucket_name='drakrun')

        out_interface = self.config.config['drakrun'].get('out_interface', '')
        dns_server = self.config.config['drakrun'].get('dns_server', '')

        setup_vm_network(self.instance_id, self.net_enable, out_interface, dns_server)

    @staticmethod
    def _get_dll_run_command(pe_data):
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        pe = pefile.PE(data=pe_data, fast_load=True)
        pe.parse_data_directories(directories=d)

        try:
            exports = [(e.ordinal, e.name.decode('utf-8', 'ignore')) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            return 'regsvr32 /s %f'

        for export in exports:
            if export[1] == 'DllRegisterServer':
                return 'regsvr32 /s %f'

            if 'DllMain' in export[1]:
                return 'rundll32 %f,{}'.format(export[1])

        if exports:
            if exports[0][1]:
                return 'rundll32 %f,{}'.format(export[1].split('@')[0])
            elif exports[0][0]:
                return 'rundll32 %f,#{}'.format(export[0])

        return 'regsvr32 /s %f'

    @staticmethod
    def _get_office_file_run_command(extension, file_path):
        start_command = ['cmd.exe', '/C', 'start']
        if d_office.is_office_word_file(extension):
            start_command.append('winword.exe')
        else:
            start_command.append('excel.exe')
        start_command.extend(['/t', '%f'])

        outer_macros = d_office.get_outer_nodes_from_vba_file(file_path)
        if not outer_macros:
            outer_macros = []
        for outer_macro in outer_macros:
            start_command.append(f'/m{outer_macro}')

        return subprocess.list2cmdline(start_command)

    def _get_start_command(self, extension, sample, file_path):
        if extension == 'dll':
            start_command = self.current_task.payload.get("start_command", self._get_dll_run_command(sample.content))
        elif extension in ['exe', 'vbs']:
            start_command = '%f'
        elif d_office.is_office_file(extension):
            start_command = self._get_office_file_run_command(extension, file_path)
        elif extension == 'ps1':
            start_command = 'powershell.exe -executionpolicy bypass -File %f'
        else:
            self.log.error("Unknown file extension - %s", extension)
            start_command = None
        return start_command

    def crop_dumps(self, dirpath, target_zip):
        zipf = zipfile.ZipFile(target_zip, 'w', zipfile.ZIP_DEFLATED)

        entries = (os.path.join(dirpath, fn) for fn in os.listdir(dirpath))
        entries = ((os.stat(path), path) for path in entries)

        entries = ((stat[ST_CTIME], path, stat[ST_SIZE])
                   for stat, path in entries if S_ISREG(stat[ST_MODE]))

        max_total_size = 300 * 1024 * 1024  # 300 MB
        current_size = 0

        for _, path, size in sorted(entries):
            current_size += size

            if current_size <= max_total_size:
                # Store files under dumps/
                zipf.write(path, os.path.join("dumps", os.path.basename(path)))
            os.unlink(path)

        # No dumps, force empty directory
        if current_size == 0:
            zipf.writestr(zipfile.ZipInfo("dumps/"), "")

        if current_size > max_total_size:
            self.log.error('Some dumps were deleted, because the configured size threshold was exceeded.')

    def update_vnc_info(self):
        """
        Put analysis ID -> drakrun node mapping into Redis.
        Required to know where to connect VNC client
        """
        self.backend.redis.set(
            f"drakvnc:{self.analysis_uid}",
            self.instance_id,
            ex=3600  # 1h
        )

    def compress_ipt(self, dirpath, target_zip):
        zipf = zipfile.ZipFile(target_zip, 'w', zipfile.ZIP_DEFLATED)

        for root, dirs, files in os.walk(dirpath):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.join("ipt", os.path.relpath(os.path.join(root, file), dirpath)))
                os.unlink(os.path.join(root, file))

    def upload_artifacts(self, analysis_uid, outdir, subdir=''):
        for fn in os.listdir(os.path.join(outdir, subdir)):
            file_path = os.path.join(outdir, subdir, fn)

            if os.path.isfile(file_path):
                object_name = os.path.join(analysis_uid, subdir, fn)
                res_name = os.path.join(subdir, fn)
                if self.test_run:
                    # If it's a test run upload artifacts to karton-managed bucket
                    # They'll be cleaned up by karton-system
                    resource = LocalResource(name=res_name, path=file_path)
                else:
                    # If it's not a test run, put them into drakrun bucket
                    resource = LocalResource(name=res_name, bucket='drakrun', path=file_path)
                    resource._uid = object_name
                yield resource
            elif os.path.isdir(file_path):
                yield from self.upload_artifacts(analysis_uid, outdir, os.path.join(subdir, fn))

    def build_profile_payload(self) -> Dict[str, LocalResource]:
        with tempfile.TemporaryDirectory() as tmp_path:
            tmp_dir = Path(tmp_path)

            for profile in dll_file_list:
                fpath = Path(PROFILE_DIR) / f"{profile.dest}.json"
                if fpath.is_file():
                    shutil.copy(fpath, tmp_dir / fpath.name)

            return Resource.from_directory(name="profiles", directory_path=tmp_dir)

    def send_analysis(self, sample, outdir, metadata, quality):
        payload = {"analysis_uid": self.analysis_uid}
        payload.update(metadata)

        if self.test_run:
            headers = dict(self.test_headers)
        else:
            headers = dict(self.headers)

        headers["quality"] = quality

        task = Task(headers, payload=payload)
        task.add_payload('sample', sample)

        if self.test_run:
            task.add_payload('testcase', self.current_task.payload['testcase'])

        if self.config.config.getboolean("drakrun", "attach_profiles", fallback=False):
            self.log.info("Uploading profiles...")
            task.add_payload("profiles", self.build_profile_payload())

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
                out.extend([profile.arg, os.path.join(PROFILE_DIR, f"{profile.dest}.json")])

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
                logging.error(f.read())

        self.log.info("VM restored")

        try:
            yield vm
        finally:
            try:
                vm.destroy()
            except Exception:
                self.log.exception("Failed to destroy VM")

    @property
    def analysis_uid(self):
        override_uid = self.current_task.payload.get('override_uid')

        if override_uid:
            return override_uid

        if self.config.config.getboolean('drakrun', 'use_root_uid', fallback=False):
            return self.current_task.root_uid

        return self.current_task.uid

    def _prepare_workdir(self):
        workdir = os.path.join("/tmp/drakrun", self.vm_name)

        try:
            if os.path.isdir(workdir):
                shutil.rmtree(workdir)
        except OSError:
            self.log.exception("Failed to clean work directory")

        os.makedirs(workdir, exist_ok=True)

        outdir = os.path.join(workdir, 'output')
        os.mkdir(outdir)
        os.mkdir(os.path.join(outdir, 'dumps'))
        os.mkdir(os.path.join(outdir, 'ipt'))

        return (workdir, outdir)

    def build_drakvuf_cmdline(self, timeout, cwd, full_cmd, dump_dir, ipt_dir, workdir):
        hooks_list = os.path.join(workdir, "hooks.txt")
        kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")

        task_quality = self.current_task.headers.get("quality", "high")
        requested_plugins = self.current_task.payload.get("plugins", self.active_plugins['_all_'])

        drakvuf_cmd = ["drakvuf"] + self.generate_plugin_cmdline(task_quality, requested_plugins) + \
                      ["-o", "json",
                       # be aware of https://github.com/tklengyel/drakvuf/pull/951
                       "-F",  # enable fast singlestep
                       "-j", "60",
                       "-t", str(timeout),
                       "-i", str(self.runtime_info.inject_pid),
                       "-k", hex(self.runtime_info.vmi_offsets.kpgd),
                       "-d", self.vm_name,
                       "--dll-hooks-list", hooks_list,
                       "--memdump-dir", dump_dir,
                       "--ipt-dir", ipt_dir,
                       "--ipt-trace-user",
                       "--codemon-dump-dir", ipt_dir,
                       "--codemon-log-everything",
                       "--codemon-analyse-system-dll-vad",
                       "-r", kernel_profile,
                       "-e", full_cmd,
                       "-c", cwd]

        anti_hammering_threshold = self.config.config['drakrun'].getint('anti_hammering_threshold', fallback=None)

        if anti_hammering_threshold:
            drakvuf_cmd.extend(["--traps-ttl", anti_hammering_threshold])

        drakvuf_cmd.extend(self.get_profile_list())

        syscall_filter = self.config.config['drakrun'].get('syscall_filter', None)
        if syscall_filter:
            drakvuf_cmd.extend(["-S", syscall_filter])

        return drakvuf_cmd

    def analyze_sample(self, sample_path, workdir, outdir, start_command, timeout):
        analysis_info = dict()

        dns_server = self.config.config['drakrun'].get('dns_server', '8.8.8.8')
        drakmon_log_fp = os.path.join(outdir, "drakmon.log")

        with self.run_vm() as vm, \
             graceful_exit(start_dnsmasq(self.instance_id, dns_server)), \
             graceful_exit(start_tcpdump_collector(self.instance_id, outdir)), \
             open(drakmon_log_fp, "wb") as drakmon_log:

            analysis_info['snapshot_version'] = vm.backend.get_vm0_snapshot_time()

            kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")

            self.log.info("Copying sample to VM...")
            injector = Injector(self.vm_name, self.runtime_info, kernel_profile)
            result = injector.write_file(
                sample_path,
                f"%USERPROFILE%\\Desktop\\{os.path.basename(sample_path)}"
            )

            try:
                injected_fn = json.loads(result.stdout)['ProcessName']
            except ValueError as e:
                self.log.error("JSON decode error occurred when tried to parse injector's logs.")
                self.log.error(f"Raw log line: {result.stdout}")
                raise e

            if "%f" not in start_command:
                self.log.warning("No file name in start command")
            cur_start_command = start_command.replace("%f", injected_fn)

            # don't include our internal maintanance commands
            analysis_info['start_command'] = cur_start_command
            self.log.info("Using command: %s", cur_start_command)

            if self.net_enable:
                self.log.info("Setting up network...")
                injector.create_process("cmd /C ipconfig /renew >nul", wait=True, timeout=120)

            drakvuf_cmd = self.build_drakvuf_cmdline(
                timeout=timeout,
                cwd=subprocess.list2cmdline([ntpath.dirname(injected_fn)]),
                full_cmd=cur_start_command,
                dump_dir=os.path.join(outdir, "dumps"),
                ipt_dir=os.path.join(outdir, "ipt"),
                workdir=workdir,
            )

            try:
                subprocess.run(
                    drakvuf_cmd,
                    stdout=drakmon_log,
                    check=True,
                    timeout=timeout + 60
                )
            except subprocess.CalledProcessError as e:
                if e.returncode == 4:
                    self.log.error("Injection succeeded but the sample didn't execute properly. Check drakmon.log for details.")
                else:
                    raise e
            except subprocess.TimeoutExpired as e:
                self.log.exception("DRAKVUF timeout expired")
                raise e

        return analysis_info

    @with_logs('drakrun.log')
    def process(self, task: Task):
        # Gather basic facts
        sample = task.get_resource("sample")
        magic_output = magic.from_buffer(sample.content)
        sha256sum = hashlib.sha256(sample.content).hexdigest()

        self.log.info(f"Running on: {socket.gethostname()}")
        self.log.info(f"Sample SHA256: {sha256sum}")
        self.log.info(f"Analysis UID: {self.analysis_uid}")

        # Timeout sanity check
        timeout = task.payload.get('timeout') or self.default_timeout
        hard_time_limit = 60 * 20
        if timeout > hard_time_limit:
            self.log.error(
                "Tried to run the analysis for more than hard limit of %d seconds",
                hard_time_limit
            )
            return

        self.update_vnc_info()

        # Get sample extension. If none set, fall back to exe/dll
        extension = task.headers.get("extension", "exe").lower()
        if '(DLL)' in magic_output:
            extension = 'dll'
        self.log.info("Running file as %s", extension)

        # Prepare sample file name
        file_name = task.payload.get("file_name", "malwar") + f".{extension}"
        # Alphanumeric, dot, underscore, dash
        if not re.match(r"^[a-zA-Z0-9\._\-]+$", file_name):
            self.log.error("Filename contains invalid characters")
            return
        self.log.info("Using file name %s", file_name)

        # workdir - configs, sample, etc.
        # outdir - analysis artifacts
        workdir, outdir = self._prepare_workdir()

        sample_path = os.path.join(workdir, file_name)
        sample.download_to_file(sample_path)

        # Try to come up with a start command for this file
        # or use the one provided by the sender
        cmd = self._get_start_command(
            extension,
            sample,
            sample_path
        )

        start_command = task.payload.get("start_command", cmd)
        if not start_command:
            self.log.error(
                "Unable to run malware sample. Could not generate any suitable"
                " command to run it."
            )
            return
        self.log.info("Start command: %s", start_command)

        # If task contains 'custom_hooks' override local defaults
        with open(os.path.join(workdir, "hooks.txt"), "wb") as hooks:
            if task.has_payload("custom_hooks"):
                custom_hooks = task.get_resource("custom_hooks")
                assert custom_hooks.content is not None
                hooks.write(custom_hooks.content)
            else:
                with open(os.path.join(ETC_DIR, "hooks.txt"), "rb") as default_hooks:
                    hooks.write(default_hooks.read())

        metadata = {
            "sample_sha256": sha256sum,
            "magic_output": magic_output,
            "time_started": int(time.time())
        }

        max_attempts = 3
        for i in range(max_attempts):
            try:
                self.log.info(f"Trying to analyze sample (attempt {i + 1}/{max_attempts})")
                info = self.analyze_sample(sample_path, workdir, outdir, start_command, timeout)
                metadata.update(info)
                break
            except Exception:
                self.log.exception("Analysis attempt failed. Retrying...")
        else:
            self.log.error(f"Giving up after {max_attempts} failures...")
            return

        self.log.info("Analysis done. Collecting artifacts...")

        # Make sure dumps have a reasonable size
        self.crop_dumps(os.path.join(outdir, 'dumps'), os.path.join(outdir, 'dumps.zip'))

        # Compress IPT traces, they're quite large however they compress well
        self.compress_ipt(os.path.join(outdir, 'ipt'), os.path.join(outdir, 'ipt.zip'))

        metadata['time_finished'] = int(time.time())

        with open(os.path.join(outdir, 'metadata.json'), 'w') as f:
            f.write(json.dumps(metadata))

        quality = task.headers.get("quality", "high")
        self.send_analysis(sample, outdir, metadata, quality)


def validate_xen_commandline():
    required_cmdline = {
        "sched": "credit",
        "force-ept": "1",
        "ept": "pml=0",
        "hap_1gb": "0",
        "hap_2mb": "0",
        "altp2m": "1"
    }

    parsed_xl_info = get_xl_info()
    xen_cmdline = get_xen_commandline(parsed_xl_info)

    unrecommended = []

    for k, v in required_cmdline.items():
        actual_v = xen_cmdline.get(k)

        if actual_v != v:
            unrecommended.append((k, v, actual_v))

    return unrecommended


def cmdline_main():
    parser = argparse.ArgumentParser(description='Kartonized drakrun <3')
    parser.add_argument('instance', type=int, help='Instance identifier')
    args = parser.parse_args()

    main(args)


def main(args):
    conf_path = os.path.join(ETC_DIR, "config.ini")
    conf = patch_config(Config(conf_path))

    if not conf.config.get('minio', 'access_key').strip():
        logging.warning(f"Detected blank value for minio access_key in {conf_path}. "
                        "This service may not work properly.")

    unrecommended = validate_xen_commandline()

    if unrecommended:
        logging.warning("-" * 80)
        logging.warning("You don't have the recommended settings in your Xen's command line.")
        logging.warning("Please amend settings in your GRUB_CMDLINE_XEN_DEFAULT in /etc/default/grub.d/xen.cfg file.")

        for k, v, actual_v in unrecommended:
            if actual_v is not None:
                logging.warning(f"- Set {k}={v} (instead of {k}={actual_v})")
            else:
                logging.warning(f"- Set {k}={v} ({k} is not set right now)")

        logging.warning("Then, please execute the following commands as root: update-grub && reboot")
        logging.warning("-" * 80)
        logging.warning("This check can be skipped by adding xen_cmdline_check=ignore in [drakrun] section of drakrun's config.")
        logging.warning("Please be aware that some bugs may arise when using unrecommended settings.")

        try:
            xen_cmdline_check = conf.config.get('drakrun', 'xen_cmdline_check')
        except NoOptionError:
            xen_cmdline_check = 'fail'

        if xen_cmdline_check == 'ignore':
            logging.warning("ATTENTION! Configuration specified that check result should be ignored, continuing anyway...")
        else:
            logging.error("Exitting due to above warnings. Please ensure that you are using recommended Xen's command line.")
            sys.exit(1)

    # Apply Karton configuration overrides
    drakrun_conf = conf.config["drakrun"] if conf.config.has_section("drakrun") else {}
    DrakrunKarton.reconfigure(drakrun_conf)

    c = DrakrunKarton(conf, args.instance)
    c.init_drakrun()
    c.loop()


if __name__ == "__main__":
    cmdline_main()
