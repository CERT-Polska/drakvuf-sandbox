import base64
import os


def find_config():
    local_path = os.path.join(os.path.dirname(__file__), "config.ini")
    etc_path = "/etc/drakcore/config.ini"

    if os.path.exists(local_path):
        return local_path
    elif os.path.exists(etc_path):
        return etc_path
    else:
        raise RuntimeError("Configuration file was not found neither in {} nor {}".format(local_path, etc_path))


def setup_config():
    print('Generating MinIO access key and secret key...')
    access_key = base64.b64encode(os.urandom(30)).decode('ascii').replace('+', '-').replace('/', '_')
    secret_key = base64.b64encode(os.urandom(30)).decode('ascii').replace('+', '-').replace('/', '_')

    with open('/etc/drakcore/config.ini', 'r') as f:
        data = f.read()
        data = data.replace('{MINIO_ACCESS_KEY}', access_key).replace('{MINIO_SECRET_KEY}', secret_key)

    with open('/etc/drakcore/config.ini', 'w') as f:
        f.write(data)

    with open('/etc/drakcore/minio.env', 'r') as f:
        data = f.read()
        data = data.replace('{MINIO_ACCESS_KEY}', access_key).replace('{MINIO_SECRET_KEY}', secret_key)

    with open('/etc/drakcore/minio.env', 'w') as f:
        f.write(data)
