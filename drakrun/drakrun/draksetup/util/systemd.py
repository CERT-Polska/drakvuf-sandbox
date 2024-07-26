import logging
import os
import re
import subprocess
import time

from tqdm import tqdm

log = logging.getLogger(__name__)


def wait_processes(descr, popens):
    total = len(popens)

    if total == 0:
        return True

    exit_codes = []

    with tqdm(total=total, unit_scale=True) as pbar:
        pbar.set_description(descr)
        while True:
            time.sleep(0.25)
            for popen in popens:
                exit_code = popen.poll()
                if exit_code is not None:
                    exit_codes.append(exit_code)
                    popens.remove(popen)
                    pbar.update(1)

            if len(popens) == 0:
                return all([exit_code == 0 for exit_code in exit_codes])


def get_enabled_drakruns():
    service_path = "/etc/systemd/system/default.target.wants"
    if not os.path.isdir(service_path):
        return []

    for fn in os.listdir(service_path):
        if re.fullmatch("drakrun@[0-9]+\\.service", fn):
            yield fn


def start_enabled_drakruns():
    log.info("Starting previously stopped drakruns")
    enabled_services = set(list(get_enabled_drakruns()))
    wait_processes(
        "start services",
        [
            subprocess.Popen(
                ["systemctl", "start", service],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for service in enabled_services
        ],
    )


def stop_all_drakruns():
    log.info("Ensuring that drakrun@* services are stopped...")
    try:
        subprocess.check_output(
            "systemctl stop 'drakrun@*'", shell=True, stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError:
        raise Exception("Drakrun services not stopped")
