#!/usr/bin/python3

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
from collections import Counter
from io import StringIO
from typing import Optional, List
from pathlib import Path
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_SIZE
from configparser import NoOptionError

import pefile
import magic
import ntpath
from karton2 import Karton, Config, Task, LocalResource

import drakrun.office as d_office
from drakrun.drakpdb import dll_file_list
from drakrun.drakparse import parse_logs
from drakrun.config import InstallInfo, ETC_DIR, VM_CONFIG_DIR, VOLUME_DIR, PROFILE_DIR
from drakrun.storage import get_storage_backend
from drakrun.networking import start_tcpdump_collector, start_dnsmasq, setup_vm_network
from drakrun.util import patch_config, get_domid_from_instance_id, get_xl_info, get_xen_commandline, RuntimeInfo
from drakrun.vmconf import generate_vm_conf


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
                    res.upload(self.minio)
                except Exception:
                    self.log.exception("Failed to upload analysis logs")
        return wrapper
    return decorator


class DrakrunKarton(Karton):
    # this might be changed by initialization
    # if different identity name is specified in config
    identity = "karton.drakrun-prod"
    filters = [
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

    def __init__(self, config: Config, instance_id: int):
        super().__init__(config)
        self.instance_id = instance_id
        self.install_info = InstallInfo.load()

    @property
    def vm_name(self) -> str:
        return f"vm-{self.instance_id}"

    def init_drakrun(self):
        generate_vm_conf(self.install_info, self.instance_id)

        if not self.minio.bucket_exists('drakrun'):
            self.minio.make_bucket(bucket_name='drakrun')

        net_enable = int(self.config.config['drakrun'].get('net_enable', '0'))
        out_interface = self.config.config['drakrun'].get('out_interface', '')
        dns_server = self.config.config['drakrun'].get('dns_server', '')

        setup_vm_network(self.instance_id, net_enable, out_interface, dns_server)

    @staticmethod
    def _get_dll_run_command(pe_data):
        d = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        pe = pefile.PE(data=pe_data, fast_load=True)
        pe.parse_data_directories(directories=d)

        try:
            exports = [(e.ordinal, e.name.decode('utf-8', 'ignore')) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        except AttributeError:
            return None

        for export in exports:
            if export[1] == 'DllRegisterServer':
                return 'regsvr32 %f'

            if 'DllMain' in export[1]:
                return 'rundll32 %f,{}'.format(export[1])

        if exports:
            if exports[0][1]:
                return 'rundll32 %f,{}'.format(export[1].split('@')[0])
            elif exports[0][0]:
                return 'rundll32 %f,#{}'.format(export[0])

        return None

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
        elif extension == 'exe':
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

        if current_size > max_total_size:
            self.log.error('Some dumps were deleted, because the configured size threshold was exceeded.')

    def generate_graphs(self, workdir):
        with open(os.path.join(workdir, 'drakmon.log'), 'r') as f:
            with open(os.path.join(workdir, 'drakmon.csv'), 'w') as o:
                for csv_line in parse_logs(f):
                    if csv_line.strip():
                        o.write(csv_line.strip() + "\n")
                    else:
                        print('empty line?')

        try:
            subprocess.run(['/opt/procdot/procmon2dot', os.path.join(workdir, 'drakmon.csv'), os.path.join(workdir, 'graph.dot'), 'procdot,forceascii'], cwd=workdir, check=True)
        except subprocess.CalledProcessError:
            self.log.exception("Failed to generate graph using procdot")

        os.unlink(os.path.join(workdir, 'drakmon.csv'))

    def slice_logs(self, workdir):
        workdir = Path(workdir)
        log_path = workdir / 'drakmon.log'
        error_path = workdir / 'parse_errors.log'

        plugin_fd = {}
        failures = Counter()

        with open(log_path, 'rb') as drakvuf_log, \
                open(error_path, 'wb') as parse_errors:
            for line in drakvuf_log:
                try:
                    line_s = line.strip().decode()
                    obj = json.loads(line_s)

                    plugin = obj.get('Plugin', 'unknown')

                    if plugin not in plugin_fd:
                        plugin_fd[plugin] = open(workdir / f'{plugin}.log', 'w')
                    else:
                        plugin_fd[plugin].write('\n')

                    plugin_fd[plugin].write(json.dumps(obj))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    # Log the failure and count statistics

                    plugin_heuristic: bytes = r'"Plugin": "(\w+)"'.encode()
                    match = re.match(plugin_heuristic, line)
                    if match:
                        # we've matched a unicode word, this shouldn't fail
                        plugin = match.group(1).decode('utf-8', 'replace')
                    else:
                        plugin = "unknown"

                    failures[plugin] += 1
                    parse_errors.write(line + b"\n")

        for plugin, count in failures.items():
            self.log.error("Failed to parse %d lines generated by %s", count, plugin)

        # Remove file if empty
        if len(failures) == 0:
            error_path.unlink()

        for fd in plugin_fd.values():
            fd.close()

        log_path.unlink()

    def upload_artifacts(self, analysis_uid, workdir, subdir=''):
        base_path = os.path.join(workdir, 'output')

        for fn in os.listdir(os.path.join(base_path, subdir)):
            file_path = os.path.join(base_path, subdir, fn)

            if os.path.isfile(file_path):
                object_name = os.path.join(analysis_uid, subdir, fn)
                res_name = os.path.join(subdir, fn)
                resource = LocalResource(name=res_name, bucket='drakrun', path=file_path)
                resource._uid = object_name
                yield resource
            elif os.path.isdir(file_path):
                yield from self.upload_artifacts(analysis_uid, workdir, os.path.join(subdir, fn))

    @staticmethod
    def get_profile_list() -> List[str]:
        files = os.listdir(PROFILE_DIR)

        out = []

        for profile in dll_file_list:
            if f"{profile.dest}.json" in files:
                out.extend([profile.arg, os.path.join(PROFILE_DIR, f"{profile.dest}.json")])

        return out

    def run_vm(self):
        try:
            subprocess.check_output(["xl", "destroy", self.vm_name], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            pass

        storage_backend = get_storage_backend(self.install_info)
        snapshot_version = storage_backend.get_vm0_snapshot_time()
        storage_backend.rollback_vm_storage(self.instance_id)

        try:
            subprocess.run(["xl", "-vvv", "restore",
                            os.path.join(VM_CONFIG_DIR, f"{self.vm_name}.cfg"),
                            os.path.join(VOLUME_DIR, "snapshot.sav")], check=True)
        except subprocess.CalledProcessError:
            logging.exception(f"Failed to restore VM {self.vm_name}")

            with open(f"/var/log/xen/qemu-dm-{self.vm_name}.log", "rb") as f:
                logging.error(f.read())

        return snapshot_version

    @with_logs('drakrun.log')
    def process(self):
        sample = self.current_task.get_resource("sample")
        self.log.info("hostname: {}".format(socket.gethostname()))
        sha256sum = hashlib.sha256(sample.content).hexdigest()
        magic_output = magic.from_buffer(sample.content)
        self.log.info("running sample sha256: {}".format(sha256sum))

        timeout = self.current_task.payload.get('timeout') or 60 * 10
        hard_time_limit = 60 * 20
        if timeout > hard_time_limit:
            self.log.error("Tried to run the analysis for more than hard limit of %d seconds", hard_time_limit)
            return

        analysis_uid = self.current_task.uid
        override_uid = self.current_task.payload.get('override_uid')

        self.log.info(f"analysis UID: {analysis_uid}")

        if override_uid:
            analysis_uid = override_uid
            self.log.info(f"override UID: {override_uid}")
            self.log.info("note that artifacts will be stored under this overriden identifier")

        self.rs.set(f"drakvnc:{analysis_uid}", self.instance_id, ex=3600)  # 1h

        workdir = f"/tmp/drakrun/{self.vm_name}"

        extension = self.current_task.headers.get("extension", "exe").lower()
        if '(DLL)' in magic_output:
            extension = 'dll'
        self.log.info("Running file as %s", extension)

        file_name = self.current_task.payload.get("file_name", "malwar") + f".{extension}"
        # Alphanumeric, dot, underscore, dash
        if not re.match(r"^[a-zA-Z0-9\._\-]+$", file_name):
            self.log.error("Filename contains invalid characters")
            return
        self.log.info("Using file name %s", file_name)

        # Save sample to disk here as some branches of _get_start_command require file path.
        try:
            shutil.rmtree(workdir)
        except Exception as e:
            print(e)
        os.makedirs(workdir, exist_ok=True)
        with open(os.path.join(workdir, file_name), 'wb') as f:
            f.write(sample.content)

        start_command = self.current_task.payload.get("start_command", self._get_start_command(extension, sample, os.path.join(workdir, file_name)))
        if not start_command:
            self.log.error("Unable to run malware sample, could not generate any suitable command to run it.")
            return

        outdir = os.path.join(workdir, 'output')
        os.mkdir(outdir)
        os.mkdir(os.path.join(outdir, 'dumps'))

        metadata = {
            "sample_sha256": sha256sum,
            "magic_output": magic_output,
            "time_started": int(time.time())
        }

        with open(os.path.join(outdir, 'sample_sha256.txt'), 'w') as f:
            f.write(hashlib.sha256(sample.content).hexdigest())

        watcher_tcpdump = None
        watcher_dnsmasq = None

        for _ in range(3):
            try:
                self.log.info("Running VM {}".format(self.instance_id))
                watcher_dnsmasq = start_dnsmasq(self.instance_id, self.config.config['drakrun'].get('dns_server', '8.8.8.8'))

                snapshot_version = self.run_vm()
                metadata['snapshot_version'] = snapshot_version

                watcher_tcpdump = start_tcpdump_collector(self.instance_id, outdir)

                self.log.info("running monitor {}".format(self.instance_id))

                kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
                runtime_profile = os.path.join(PROFILE_DIR, "runtime.json")
                with open(runtime_profile, 'r') as runtime_f:
                    runtime_info = RuntimeInfo.load(runtime_f)

                hooks_list = os.path.join(ETC_DIR, "hooks.txt")
                dump_dir = os.path.join(outdir, "dumps")
                drakmon_log_fp = os.path.join(outdir, "drakmon.log")

                injector_cmd = ["injector",
                                "-o", "json",
                                "-d", self.vm_name,
                                "-r", kernel_profile,
                                "-i", str(runtime_info.inject_pid),
                                "-k", hex(runtime_info.vmi_offsets.kpgd),
                                "-m", "writefile",
                                "-e", f"%USERPROFILE%\\Desktop\\{file_name}",
                                "-B", os.path.join(workdir, file_name)]

                self.log.info("Running injector (write sample to VM)...")
                injector = subprocess.Popen(injector_cmd, stdout=subprocess.PIPE)
                outs, errs = injector.communicate(b"", 60)

                if injector.returncode != 0:
                    raise subprocess.CalledProcessError(injector.returncode, injector_cmd)

                injected_fn = json.loads(outs)['ProcessName']
                net_enable = int(self.config.config['drakrun'].get('net_enable', '0'))

                if "%f" not in start_command:
                    self.log.warning("No file name in start command")

                cwd = subprocess.list2cmdline([ntpath.dirname(injected_fn)])
                cur_start_command = start_command.replace("%f", injected_fn)

                # don't include our internal maintanance commands
                metadata['start_command'] = cur_start_command

                if net_enable:
                    injector_cmd = ["injector",
                                    "-o", "json",
                                    "-d", self.vm_name,
                                    "-r", kernel_profile,
                                    "-i", str(runtime_info.inject_pid),
                                    "-k", hex(runtime_info.vmi_offsets.kpgd),
                                    "-m", "createproc",
                                    "-e", "cmd /C ipconfig /renew >nul",
                                    "-w"]

                    self.log.info("Running injector...")
                    injector = subprocess.Popen(injector_cmd, stdout=subprocess.PIPE)
                    outs, errs = injector.communicate(b"", 120)

                    if injector.returncode != 0:
                        logging.info("Injector failed!")

                full_cmd = cur_start_command
                self.log.info("Using command: %s", full_cmd)

                drakvuf_cmd = ["drakvuf",
                               "-o", "json",
                               "-x", "poolmon",
                               "-x", "objmon",
                               "-x", "socketmon",
                               "-x", "dkommon",
                               "-x", "envmon",
                               "-j", "5",
                               "-t", str(timeout),
                               "-i", str(runtime_info.inject_pid),
                               "-k", hex(runtime_info.vmi_offsets.kpgd),
                               "-d", self.vm_name,
                               "--dll-hooks-list", hooks_list,
                               "--memdump-dir", dump_dir,
                               "-r", kernel_profile,
                               "-e", full_cmd,
                               "-c", cwd]

                drakvuf_cmd.extend(self.get_profile_list())

                syscall_filter = self.config.config['drakrun'].get('syscall_filter', None)
                if syscall_filter:
                    drakvuf_cmd.extend(["-S", syscall_filter])

                with open(drakmon_log_fp, "wb") as drakmon_log:
                    drakvuf = subprocess.Popen(drakvuf_cmd, stdout=drakmon_log)

                    try:
                        exit_code = drakvuf.wait(timeout + 60)
                    except subprocess.TimeoutExpired as e:
                        logging.error("BUG: Monitor command doesn\'t terminate automatically after timeout expires.")
                        logging.error("Trying to terminate DRAKVUF...")
                        drakvuf.terminate()
                        drakvuf.wait(10)
                        logging.error("BUG: Monitor command also doesn\'t terminate after sending SIGTERM.")
                        drakvuf.kill()
                        drakvuf.wait()
                        logging.error("Monitor command was forcefully killed.")
                        raise e

                    if exit_code != 0:
                        raise subprocess.CalledProcessError(exit_code, drakvuf_cmd)
                break
            except subprocess.CalledProcessError:
                self.log.info("Something went wrong with the VM {}".format(self.instance_id), exc_info=True)
            finally:
                try:
                    subprocess.run(["xl", "destroy", self.vm_name], cwd=workdir, check=True)
                except subprocess.CalledProcessError:
                    self.log.info("Failed to destroy VM {}".format(self.instance_id), exc_info=True)

                if watcher_dnsmasq:
                    watcher_dnsmasq.terminate()
        else:
            self.log.info("Failed to analyze sample after 3 retries, giving up.")
            return

        self.log.info("waiting for tcpdump to exit")

        if watcher_tcpdump:
            try:
                watcher_tcpdump.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self.log.exception("tcpdump doesn't exit cleanly after 60s")

        self.crop_dumps(os.path.join(outdir, 'dumps'), os.path.join(outdir, 'dumps.zip'))
        if os.path.exists("/opt/procdot/procmon2dot"):
            self.generate_graphs(outdir)
        self.slice_logs(outdir)
        self.log.info("uploading artifacts")

        metadata['time_finished'] = int(time.time())

        with open(os.path.join(outdir, 'metadata.json'), 'w') as f:
            f.write(json.dumps(metadata))

        payload = {"analysis_uid": analysis_uid}
        payload.update(metadata)

        t = Task(
            {
                "type": "analysis",
                "kind": "drakrun",
                "quality": self.current_task.headers.get("quality", "high")
            },
            payload=payload
        )

        for resource in self.upload_artifacts(analysis_uid, workdir):
            t.add_payload(resource.name, resource)

        t.add_payload('sample', sample)
        self.send_task(t)


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

    try:
        identity = conf.config.get('drakrun', 'identity')
    except NoOptionError:
        pass
    else:
        DrakrunKarton.identity = identity
        logging.warning(f"Overriding identity to: {identity}")

    c = DrakrunKarton(conf, args.instance)
    c.init_drakrun()
    c.loop()


if __name__ == "__main__":
    cmdline_main()
