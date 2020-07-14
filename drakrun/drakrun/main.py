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
from typing import Optional, List

import pefile
import json
import re
import io
import magic
from karton2 import Karton, Config, Task, LocalResource
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_SIZE
import drakrun.run as d_run
from drakrun.drakpdb import dll_file_list
from drakrun.drakparse import parse_logs
from drakrun.config import LIB_DIR, ETC_DIR

INSTANCE_ID = None


def get_domid_from_instance_id(instance_id: str) -> int:
    output = subprocess.check_output(["xl", "domid", f"vm-{instance_id}"])
    return int(output.decode('utf-8').strip())


def start_tcpdump_collector(instance_id: str, outdir: str) -> Optional[subprocess.Popen]:
    domid = get_domid_from_instance_id(instance_id)

    try:
        subprocess.check_output("tcpdump --version", shell=True)
    except subprocess.CalledProcessError:
        logging.warning("Seems like tcpdump is not working/not installed on your system. Pcap will not be recorded.")
        return

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
        return

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


class DrakrunKarton(Karton):
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

    def _add_iptable_rule(self, rule):
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

    def _get_dll_run_command(self, pe_data):
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

    def _get_start_command(self, extension, sample):
        if extension == 'dll':
            start_command = self.current_task.payload.get("start_command", self._get_dll_run_command(sample.content))
        elif extension == 'exe':
            start_command = 'start %f'
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

        for cdate, path, size in sorted(entries):
            current_size += size

            if current_size <= max_total_size:
                zipf.write(path)

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

        with open(os.path.join(workdir, 'drakmon.log'), 'r') as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    self.log.exception("BUG: Failed to parse drakmon.log line: {}".format(line))

                if 'Plugin' not in obj:
                    obj['Plugin'] = 'unknown'

                if obj['Plugin'] not in plugin_fd:
                    plugin_fd[obj['Plugin']] = open(os.path.join(workdir, obj['Plugin'] + '.log'), 'w')
                else:
                    plugin_fd[obj['Plugin']].write('\n')

                plugin_fd[obj['Plugin']].write(json.dumps(obj))

        for key, fd in plugin_fd.items():
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

    def get_profile_list(self) -> List[str]:
        files = os.listdir(os.path.join(LIB_DIR, "profiles"))

        out = []

        for profile in dll_file_list:
            if f"{profile.dest}.json" in files:
                out.extend([profile.arg, os.path.join(LIB_DIR, "profiles", f"{profile.dest}.json")])

        return out

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

        workdir = '/tmp/drakrun/vm-{}'.format(int(INSTANCE_ID))

        extension = self.current_task.headers.get("extension", "exe").lower()
        if '(DLL)' in magic_output:
            extension = 'dll'
        self.log.info("Running file as %s", extension)

        file_name = self.current_task.payload.get("file_name", f"malwar.{extension}")
        # Alphanumeric, dot, underscore, dash
        if not re.match(r"^[a-zA-Z0-9\._\-]+$", file_name):
            self.log.error("Filename contains invalid characters")
            return

        self.log.info("Using file name %s", file_name)
        start_command = self.current_task.payload.get("start_command", self._get_start_command(extension, sample))
        if not start_command:
            self.log.error("Unable to run malware sample, could not generate any suitable command to run it.")
            return

        start_command = start_command.replace("%f", file_name)
        self.log.info("Using command: %s", start_command)

        if "%f" not in start_command:
            self.log.warning("No file name in start command")

        try:
            shutil.rmtree(workdir)
        except Exception as e:
            print(e)

        outdir = os.path.join(workdir, 'output')
        os.makedirs(workdir, exist_ok=True)
        os.mkdir(outdir)
        os.mkdir(os.path.join(outdir, 'dumps'))

        metadata = {
            "sample_sha256": sha256sum,
            "magic_output": magic_output,
            "time_started": int(time.time()),
            "start_command": start_command
        }

        with open(os.path.join(outdir, 'sample_sha256.txt'), 'w') as f:
            f.write(hashlib.sha256(sample.content).hexdigest())

        with open(os.path.join(workdir, 'run.bat'), 'w', encoding='ascii', newline='\r\n') as f:
            f.write('ipconfig /renew\n')
            f.write(f'xcopy D:\\{file_name} %USERPROFILE%\\Desktop\\\n')
            f.write('C:\n')
            f.write('cd %USERPROFILE%\\Desktop\n')
            f.write(start_command)

        with open(os.path.join(workdir, file_name), 'wb') as f:
            f.write(sample.content)

        try:
            subprocess.run(["genisoimage", "-o", os.path.join(workdir, 'malwar.iso'), os.path.join(workdir, file_name), os.path.join(workdir, 'run.bat')], cwd=workdir, check=True)
        except subprocess.CalledProcessError as e:
            logging.exception("Failed to generate CD ISO image. Please install genisoimage")
            raise e

        watcher_tcpdump = None
        watcher_dnsmasq = None

        for _ in range(3):
            try:
                self.log.info("running vm {}".format(INSTANCE_ID))
                watcher_dnsmasq = start_dnsmasq(INSTANCE_ID, self.config.config['drakrun'].get('dns_server', '8.8.8.8'))

                d_run.logging = self.log
                d_run.run_vm(INSTANCE_ID)

                watcher_tcpdump = start_tcpdump_collector(INSTANCE_ID, outdir)

                self.log.info("running monitor {}".format(INSTANCE_ID))

                kernel_profile = os.path.join(LIB_DIR, "profiles/kernel.json")
                runtime_profile = os.path.join(LIB_DIR, "profiles/runtime.json")
                with open(runtime_profile, 'r') as runtime_f:
                    rp = json.loads(runtime_f.read())
                    inject_pid = rp['inject_pid']
                    kpgd = rp['vmi_offsets']['kpgd']

                hooks_list = os.path.join(ETC_DIR, "hooks.txt")
                dump_dir = os.path.join(outdir, "dumps")
                drakmon_log_fp = os.path.join(outdir, "drakmon.log")

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
                               "-e", "D:\\run.bat"]

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
    conf = Config(conf_path)

    if not conf.config.get('minio', 'access_key').strip():
        logging.warning(f"Detected blank value for minio access_key in {conf_path}. "
                        "This service may not work properly.")

    c = DrakrunKarton(conf)
    c.init_drakrun()
    c.loop()


if __name__ == "__main__":
    cmdline_main()
