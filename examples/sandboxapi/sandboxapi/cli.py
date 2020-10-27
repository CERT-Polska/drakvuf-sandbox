"""CLI wrapper around the sandboxapi Client implementation for DRAKVUF Sandbox.

This module provides a CLI wrapping the Client class exposed by client.py, facilitating pushing files to and pulling
results from DRAKVUF Sandbox via the command line.

  Typical usage example (see README.md for more usage info):

  $ sandboxcli -f sample.exe
  Submitted file sample.exe with job UUID <UUID>
"""

import argparse
import time
from sandboxapi.client import Client


parser = argparse.ArgumentParser(description='Interact with DRAKVUF Sandbox')
parser.add_argument(
    '-f',
    '--filepath',
    dest='filepath',
    help='Path for file to be submitted'
)
parser.add_argument(
    '-d',
    '--dump-uuid',
    dest="dump_uuid",
    help="UUID of the memory dump to download"
)
parser.add_argument(
    '-l',
    '--log-download',
    dest='log',
    help='The UUID and the name of the log to download, specified as <UUID>:<logname>'
)
parser.add_argument(
    '-s',
    '--status-uuid',
    dest='status_uuid',
    help='UUID of the job to check the status of'
)
parser.add_argument(
    '-u',
    '--url',
    dest='url',
    default="http://localhost:6300",
    help='DRAKVUF Sandbox server URL (default: http://localhost:6300)'
)
parser.add_argument(
    '-w',
    '--wait',
    dest='wait',
    action="store_true",
    help='If passed, CLI won\'t return until analysis ends'
)


def main():
    # Modeled after:
    # - https://github.com/CERT-Polska/drakvuf-sandbox/blob/master/examples/push_sample.py

    # parse args and init client
    args = parser.parse_args()
    client = Client(args.url)

    # submit file if flag passed
    if args.filepath:
        uuid = client.post_file(args.filepath)
        print(f"Submitted file {args.filepath} with job UUID {uuid}")

        # iterate until status changes if wait passed
        seconds = 0
        if args.wait:
            while True:
                status = client.get_status(uuid)

                if status != "pending":
                    break
                print(f"Task {uuid} {status}... ({seconds}s)")
                time.sleep(10)
                seconds += 10

    # pull log if flag passed
    if args.log:
        uuid, logname = args.log.split(":")
        status_code, outfilepath = client.get_log(uuid, logname)
        print(f"{status_code}: downloaded {outfilepath}")

    # pull mem dump if flag passed
    if args.dump_uuid:
        status_code, outfilepath = client.get_dump(args.dump_uuid)
        print(f"{status_code}: downloaded {outfilepath}")

    # check status if flag passed
    if args.status_uuid:
        status = client.get_status(args.status_uuid)
        print(f"Job {args.status_uuid}: {status}")