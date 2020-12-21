import base64
import os
import sys

from karton.core import Config


def find_config():
    local_path = os.path.join(os.path.dirname(__file__), "config.ini")
    etc_path = "/etc/drakcore/config.ini"

    if os.path.exists(local_path):
        return local_path
    elif os.path.exists(etc_path):
        return etc_path
    else:
        raise RuntimeError("Configuration file was not found neither in {} nor {}".format(local_path, etc_path))


def get_config():
    cfg = Config(find_config())

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
        except KeyError:
            sys.stderr.write('WARNING! Misconfiguration: minio.env doesn\'t contain MINIO_ACCESS_KEY or MINIO_SECRET_KEY.\n')

    return cfg


def setup_config():
    if os.path.exists('/etc/drakcore/minio.env'):
        print('MinIO environment file already exists, skipping...')
        return

    print('Generating MinIO environment file...')
    access_key = base64.b64encode(os.urandom(30)).decode('ascii').replace('+', '-').replace('/', '_')
    secret_key = base64.b64encode(os.urandom(30)).decode('ascii').replace('+', '-').replace('/', '_')

    with open('/etc/drakcore/minio.env', 'w') as f:
        f.write(f'MINIO_ACCESS_KEY={access_key}\n')
        f.write(f'MINIO_SECRET_KEY={secret_key}\n')
