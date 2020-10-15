#!/usr/bin/env python3
import argparse
import requests
import time
import os
from requests.exceptions import ConnectionError, HTTPError

parser = argparse.ArgumentParser(description='Analyze a sample in DRAKVUF Sandbox')
parser.add_argument('file',
                    help='Analyzed file')
parser.add_argument('--url', dest='api_host',
                    default="http://localhost:6300",
                    help='API server URL (default: http://localhost:6300)')
parser.add_argument('--wait', dest='wait', action="store_false",
                    help='Wait until analysis is finished')

def check_status(host, task_uid):
    url = f'{host}/status/{task_uid}'
    r = requests.get(url)
    r.raise_for_status()
    return r.json()["status"]

def push_file(host, fpath):
    url = f'{host}/upload'
    try:
        r = requests.post(url, files={'file': (os.path.basename(fpath), open(fpath, "rb"))})
        r.raise_for_status()
        return r.json()["task_uid"]
    except ConnectionError:
        print(f'Connection failed to {host}')
    except HTTPError:
        print(f'Server returned {r.status_code}')


def main():
    args = parser.parse_args()

    task_uid = push_file(args.api_host, args.file)
    if not task_uid:
        return

    print(f'Created task with uid {task_uid}')

    if not args.wait:
        return

    while True:
        status = check_status(args.api_host, task_uid)
        if status != "pending":
            break
        print("Waiting for the task to finish...")
        time.sleep(10)


if __name__ == '__main__':
    main()
