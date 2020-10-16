#!/usr/bin/python3

import logging
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
from io import StringIO
from typing import Optional, List
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_SIZE
from configparser import NoOptionError

import pefile
import magic
import ntpath
from karton2 import Karton, Config, Task, LocalResource

import drakrun.office as d_office
from drakrun.drakpdb import dll_file_list
from drakrun.drakparse import parse_logs
from drakrun.config import ETC_DIR, LIB_DIR, InstallInfo
from drakrun.storage import get_storage_backend
from drakrun.util import patch_config

INSTANCE_ID = None
PROFILE_DIR = os.path.join(LIB_DIR, "profiles")


def get_domid_from_instance_id(instance_id: str) -> int:
    output = subprocess.check_output(["xl", "domid", f"vm-{instance_id}"])
    return int(output.decode('utf-8').strip())


def start_tcpdump_collector(instance_id: str, outdir: str) -> Optional[subprocess.Popen]:
    domid = get_domid_from_instance_id(instance_id)

    try:
        subprocess.check_output("tcpdump --version", shell=True)
    except subprocess.CalledProcessError:
        logging.warning("Seems like tcpdump is not working/not installed on your system. Pcap will not be recorded.")
        return None

    return subprocess.Popen([
        "tcpdump",
        "-i",
        f"vif{domid}.0-emu",
        "-w",
        f"{outdir}/dump.pcap"
    ])


def start_dnsmasq(vm_id: int, dns_server: str) -> Optional[subprocess.Popen]:
    try:
        subprocess.check_output("dnsmasq --version", shell=True)
    except subprocess.CalledProcessError:
        logging.warning("Seems like dnsmasq is not working/not installed on your system."
                        "Guest networking may not be fully functional.")
        return None

    if dns_server == "use-gateway-address":
        dns_server = f"10.13.{vm_id}.1"

    return subprocess.Popen([
        "dnsmasq",
        "--no-daemon",
        "--conf-file=/dev/null",
        "--bind-interfaces",
        f"--interface=drak{vm_id}",
        "--port=0",
        "--no-hosts",
        "--no-resolv",
        "--no-poll",
        "--leasefile-ro",
        f"--dhcp-range=10.13.{vm_id}.100,10.13.{vm_id}.200,255.255.255.0,12h",
        f"--dhcp-option=option:dns-server,{dns_server}"
    ])


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

    @staticmethod
    def _add_iptable_rule(rule):
        try:
            subprocess.check_output(f"iptables -C {rule}", shell=True)
        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                # rule doesn't exist
                subprocess.check_output(f"iptables -A {rule}", shell=True)
            else:
                # some other error
                raise RuntimeError(f'Failed to check for iptables rule: {rule}')

    def init_drakrun(self):
        if not self.minio.bucket_exists('drakrun'):
            self.minio.make_bucket(bucket_name='drakrun')

        try:
            subprocess.check_output(f'brctl addbr drak{INSTANCE_ID}', stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            if b'already exists' in e.output:
                logging.info(f"Bridge drak{INSTANCE_ID} already exists.")
            else:
                logging.exception(f"Failed to create bridge drak{INSTANCE_ID}.")
        else:
            subprocess.check_output(f'ip addr add 10.13.{INSTANCE_ID}.1/24 dev drak{INSTANCE_ID}', shell=True)

        subprocess.check_output(f'ip link set dev drak{INSTANCE_ID} up', shell=True)
        self._add_iptable_rule(f"INPUT -i drak{INSTANCE_ID} -p udp --dport 67:68 --sport 67:68 -j ACCEPT")
        self._add_iptable_rule(f"INPUT -i drak{INSTANCE_ID} -d 0.0.0.0/0 -j DROP")

        net_enable = int(self.config.config['drakrun'].get('net_enable', '0'))
        out_interface = self.config.config['drakrun'].get('out_interface', '')
        dns_server = self.config.config['drakrun'].get('dns_server', '')

        if dns_server == "use-gateway-address":
            self._add_iptable_rule(f"INPUT -i drak{INSTANCE_ID} -p udp --dport 52 --sport 52 -j ACCEPT")

        if net_enable:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')

            self._add_iptable_rule(f"POSTROUTING -t nat -s 10.13.{INSTANCE_ID}.0/24 -o {out_interface} -j MASQUERADE")
            self._add_iptable_rule(f"FORWARD -i drak{INSTANCE_ID} -o {out_interface} -j ACCEPT")
            self._add_iptable_rule(f"FORWARD -i {out_interface} -o drak{INSTANCE_ID} -j ACCEPT")

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
                return 'start regsvr32 %f'

            if 'DllMain' in export[1]:
                return 'start rundll32 %f,{}'.format(export[1])

        if exports:
            if exports[0][1]:
                return 'start rundll32 %f,{}'.format(export[1].split('@')[0])
            elif exports[0][0]:
                return 'start rundll32 %f,#{}'.format(export[0])

        return None

    @staticmethod
    def _get_office_file_run_command(extension, file_path):
        start_command = ['start']
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
            start_command = 'start %f'
        elif d_office.is_office_file(extension):
            start_command = self._get_office_file_run_command(extension, file_path)
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
        plugin_fd = {}

        with open(os.path.join(workdir, 'drakmon.log'), 'rb') as f:
            while True:
                line = f.readline()

                if not line:
                    break

                try:
                    line_s = line.strip().decode('utf-8')
                    obj = json.loads(line_s)
                except UnicodeDecodeError:
                    self.log.exception("BUG: Failed to decode UTF-8 from drakmon.log line: {}".format(line))
                except json.JSONDecodeError:
                    self.log.exception("BUG: Failed to JSON parse drakmon.log line: {}".format(line))

                if 'Plugin' not in obj:
                    obj['Plugin'] = 'unknown'

                if obj['Plugin'] not in plugin_fd:
                    plugin_fd[obj['Plugin']] = open(os.path.join(workdir, obj['Plugin'] + '.log'), 'w')
                else:
                    plugin_fd[obj['Plugin']].write('\n')

                plugin_fd[obj['Plugin']].write(json.dumps(obj))

        for fd in plugin_fd.values():
            fd.close()

        os.unlink(os.path.join(workdir, 'drakmon.log'))

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

    @staticmethod
    def run_vm(vm_id):
        install_info = InstallInfo.load()

        try:
            subprocess.check_output(["xl", "destroy", "vm-{vm_id}".format(vm_id=vm_id)], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            pass

        storage_backend = get_storage_backend(install_info)
        snapshot_version = storage_backend.get_vm0_snapshot_time()
        storage_backend.rollback_vm_storage(vm_id)

        try:
            subprocess.run(["xl", "-vvv", "restore",
                            os.path.join(ETC_DIR, "configs/vm-{vm_id}.cfg".format(vm_id=vm_id)),
                            os.path.join(LIB_DIR, "volumes/snapshot.sav")], check=True)
        except subprocess.CalledProcessError:
            logging.exception("Failed to restore VM {vm_id}".format(vm_id=vm_id))

            with open("/var/log/xen/qemu-dm-vm-{vm_id}.log".format(vm_id=vm_id), "rb") as f:
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

        self.rs.set(f"drakvnc:{analysis_uid}", INSTANCE_ID, ex=3600)  # 1h

        workdir = '/tmp/drakrun/vm-{}'.format(int(INSTANCE_ID))

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
                self.log.info("running vm {}".format(INSTANCE_ID))
                watcher_dnsmasq = start_dnsmasq(INSTANCE_ID, self.config.config['drakrun'].get('dns_server', '8.8.8.8'))

                snapshot_version = self.run_vm(INSTANCE_ID)
                metadata['snapshot_version'] = snapshot_version

                watcher_tcpdump = start_tcpdump_collector(INSTANCE_ID, outdir)

                self.log.info("running monitor {}".format(INSTANCE_ID))

                kernel_profile = os.path.join(PROFILE_DIR, "kernel.json")
                runtime_profile = os.path.join(PROFILE_DIR, "runtime.json")
                with open(runtime_profile, 'r') as runtime_f:
                    rp = json.loads(runtime_f.read())
                    inject_pid = rp['inject_pid']
                    kpgd = rp['vmi_offsets']['kpgd']

                hooks_list = os.path.join(ETC_DIR, "hooks.txt")
                dump_dir = os.path.join(outdir, "dumps")
                drakmon_log_fp = os.path.join(outdir, "drakmon.log")

                injector_cmd = ["injector",
                                "-o", "json",
                                "-d", "vm-{vm_id}".format(vm_id=INSTANCE_ID),
                                "-r", kernel_profile,
                                "-i", inject_pid,
                                "-k", kpgd,
                                "-m", "writefile",
                                "-e", f"%USERPROFILE%\\Desktop\\{file_name}",
                                "-B", os.path.join(workdir, file_name)]

                self.log.info("Running injector...")
                injector = subprocess.Popen(injector_cmd, stdout=subprocess.PIPE)
                outs, errs = injector.communicate(b"", 20)

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
                cur_start_command = f"cd {cwd} & " + cur_start_command

                if net_enable:
                    cur_start_command = "ipconfig /renew & " + cur_start_command

                full_cmd = subprocess.list2cmdline(["cmd.exe", "/C", cur_start_command])
                self.log.info("Using command: %s", full_cmd)

                drakvuf_cmd = ["drakvuf",
                               "-o", "json",
                               "-x", "poolmon",
                               "-x", "objmon",
                               "-x", "socketmon",
                               "-j", "5",
                               "-t", str(timeout),
                               "-i", inject_pid,
                               "-k", kpgd,
                               "-d", "vm-{vm_id}".format(vm_id=INSTANCE_ID),
                               "--dll-hooks-list", hooks_list,
                               "--memdump-dir", dump_dir,
                               "-r", kernel_profile,
                               "-e", full_cmd]

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
                self.log.info("Something went wrong with the VM {}".format(INSTANCE_ID), exc_info=True)
            finally:
                try:
                    subprocess.run(["xl", "destroy", "vm-{}".format(INSTANCE_ID)], cwd=workdir, check=True)
                except subprocess.CalledProcessError:
                    self.log.info("Failed to destroy VM {}".format(INSTANCE_ID), exc_info=True)

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


def cmdline_main():
    parser = argparse.ArgumentParser(description='Kartonized drakrun <3')
    parser.add_argument('instance', type=int, help='Instance identifier')
    args = parser.parse_args()

    global INSTANCE_ID
    INSTANCE_ID = args.instance
    main()


def main():
    conf_path = os.path.join(ETC_DIR, "config.ini")
    conf = patch_config(Config(conf_path))

    if not conf.config.get('minio', 'access_key').strip():
        logging.warning(f"Detected blank value for minio access_key in {conf_path}. "
                        "This service may not work properly.")

    try:
        identity = conf.config.get('drakrun', 'identity')
    except NoOptionError:
        pass
    else:
        DrakrunKarton.identity = identity
        logging.warning(f"Overriding identity to: {identity}")

    c = DrakrunKarton(conf)
    c.init_drakrun()
    c.loop()


if __name__ == "__main__":
    cmdline_main()
