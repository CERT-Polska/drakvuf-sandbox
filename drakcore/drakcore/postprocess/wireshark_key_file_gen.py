import json
import os
import logging
from karton2 import Task, RemoteResource
from typing import Dict
from tempfile import NamedTemporaryFile


def gen_key_file_from_log(tlsmon_log):
    key_file_content = ''
    for line in tlsmon_log:
        try:
            entry = json.loads(line)
            client_random = entry['client_random']
            master_key = entry['master_key']
            key_file_entry = f'CLIENT_RANDOM {client_random} {master_key}\n'
            key_file_content += key_file_entry
        except KeyError:
            logging.exception(f"JSON is missing a required field\n{line}")
            continue
        except json.JSONDecodeError as e:
            logging.warning(f"line cannot be parsed as JSON\n{e}")
            continue
    key_file = NamedTemporaryFile(delete=False)
    key_file.write(key_file_content.encode())
    return key_file


def generate_wireshark_key_file(task: Task, resources: Dict[str, RemoteResource], minio):
    analysis_uid = task.payload['analysis_uid']

    with resources['tlsmon.log'].download_temporary_file() as tlsmon_log:
        key_file = gen_key_file_from_log(tlsmon_log)
        size = key_file.tell()
        key_file.seek(0)
        minio.put_object('drakrun', f'{analysis_uid}/wireshark_key_file.txt', key_file, size)
        yield 'wireshark_key_file.txt'
        key_file.close()
        os.unlink(key_file.name)
