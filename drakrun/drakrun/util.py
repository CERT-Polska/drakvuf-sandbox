import base64
import os
import re
import sys
import subprocess
from dataclasses import dataclass, field
from typing import Dict, AnyStr, IO

from karton2 import Config
from dataclasses_json import dataclass_json, config

hexstring = config(
    encoder=lambda v: hex(v),
    decoder=lambda v: int(v, 16),
)


@dataclass_json
@dataclass
class VmiOffsets:
    # Fields correspond to output defined in
    # https://github.com/libvmi/libvmi/blob/master/examples/win-offsets.c

    win_ntoskrnl: int = field(metadata=hexstring)
    win_ntoskrnl_va: int = field(metadata=hexstring)

    win_tasks: int = field(metadata=hexstring)
    win_pdbase: int = field(metadata=hexstring)
    win_pid: int = field(metadata=hexstring)
    win_pname: int = field(metadata=hexstring)
    win_kdvb: int = field(metadata=hexstring)
    win_sysproc: int = field(metadata=hexstring)
    win_kpcr: int = field(metadata=hexstring)
    win_kdbg: int = field(metadata=hexstring)

    kpgd: int = field(metadata=hexstring)

    def from_tool_output(output: str) -> 'VmiOffsets':
        """
        Parse vmi-win-offsets tool output and return VmiOffsets.
        If any of the fields is missing, throw TypeError
        """
        offsets = re.findall(r'^([a-z_]+):(0x[0-9a-f]+)$', output, re.MULTILINE)
        vals = {k: int(v, 16) for k, v in offsets}
        return VmiOffsets(**vals)


@dataclass_json
@dataclass
class RuntimeInfo:
    vmi_offsets: VmiOffsets
    inject_pid: int

    def load(file_obj: IO[AnyStr]) -> 'RuntimeInfo':
        return RuntimeInfo.from_json(file_obj.read())


def patch_config(cfg):
    try:
        access_key = cfg.config['minio']['access_key']
        secret_key = cfg.config['minio']['secret_key']
    except KeyError:
        sys.stderr.write('WARNING! Misconfiguration: section [minio] of config.ini doesn\'t contain access_key or secret_key.\n')
        return cfg

    if not access_key and not secret_key:
        if not os.path.exists('/etc/drakcore/minio.env'):
            raise RuntimeError('ERROR! MinIO access credentials are not configured (and can not be auto-detected), unable to start.\n')

        with open('/etc/drakcore/minio.env', 'r') as f:
            minio_cfg = [line.strip().split('=', 1) for line in f if line.strip() and '=' in line]
            minio_cfg = {k: v for k, v in minio_cfg}

        try:
            cfg.config['minio']['access_key'] = minio_cfg['MINIO_ACCESS_KEY']
            cfg.config['minio']['secret_key'] = minio_cfg['MINIO_SECRET_KEY']
            cfg.minio_config = dict(cfg.config.items("minio"))
        except KeyError:
            sys.stderr.write('WARNING! Misconfiguration: minio.env doesn\'t contain MINIO_ACCESS_KEY or MINIO_SECRET_KEY.\n')

    return cfg


def get_domid_from_instance_id(instance_id: str) -> int:
    output = subprocess.check_output(["xl", "domid", f"vm-{instance_id}"])
    return int(output.decode('utf-8').strip())


def get_xl_info():
    xl_info_out = subprocess.check_output(['xl', 'info']).decode('utf-8', 'replace')
    xl_info_lines = xl_info_out.strip().split('\n')

    cfg = {}

    for line in xl_info_lines:
        k, v = line.split(':', 1)
        k, v = k.strip(), v.strip()
        cfg[k] = v

    return cfg


def get_xen_commandline(parsed_xl_info):
    opts = parsed_xl_info['xen_commandline'].split(' ')

    cfg = {}

    for opt in opts:
        if not opt.strip():
            continue

        if '=' not in opt:
            cfg[opt] = '1'
        else:
            k, v = opt.split('=', 1)
            cfg[k] = v

    return cfg
