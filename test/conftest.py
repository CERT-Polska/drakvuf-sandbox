import requests
import os
import logging
import socket
import time
import paramiko.config
import pytest

from pathlib import Path
from fabric import task, Connection, Config
from invoke.exceptions import UnexpectedExit
from minio import Minio
from minio.error import ResponseError

from utils import apt_install, dpkg_install, VMRunner

logging.basicConfig(level=logging.INFO)

DRONE_BUILD_NUMBER = os.getenv("DRONE_BUILD_NUMBER")

# Clean debian image
# VM_SNAPSHOT_BASE = "snap1585837798"

# Debian with preconfigured Windows in /var/lib/drakrun and /etc/drakrun
VM_SNAPSHOT_BASE = "snap1587390752"
VM_RUNNER_HOST = "http://192.168.21.1:5000"
VM_HOST = "192.168.21.129"

MINIO_HOST = "192.168.21.131:9000"
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")

MINIO_DEBS = [
    f"drakcore_drone-{DRONE_BUILD_NUMBER}.deb",
    f"drakrun_drone-{DRONE_BUILD_NUMBER}.deb",
]

DRAKMON_DEPS = [
    "python3.7",
    "libpython3.7",
    "python3-distutils",
    "tcpdump",
    "genisoimage",
    "qemu-utils",
    "bridge-utils",
    "dnsmasq",
    "libmagic1",
]

DRAKVUF_BUNDLE_URL = "https://github.com/tklengyel/drakvuf-builds/releases/download/20200318193922-a1ef03c/drakvuf-bundle-0.7-a1ef03c-generic.deb"
DRAKVUF_DEPS = [
    "libpixman-1-0",
    "libpng16-16",
    "libnettle6",
    "libgnutls30",
    "libfdt1",
    "libglib2.0-0",
    "libglib2.0-dev",
    "libjson-c3",
    "libyajl2",
    "libaio1",
]

DRAKMON_SERVICES = [
    "drak-system.service",
    "drak-minio.service",
    "drak-web.service",
    "drak-postprocess.service",
    "redis-server.service",
]

vm_runner = VMRunner(VM_RUNNER_HOST)

ssh_config = paramiko.config.SSHConfig.from_text(
    f"""
Host testvm
    User root
    HostName {VM_HOST}
"""
)

FABRIC_CONFIG = Config(ssh_config=ssh_config)


def server_alive(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def download_file(url, download_path=Path(".")):
    filename = url.split("/")[-1]
    logging.info(f"Downloading {filename}")
    filepath = download_path / filename
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(filepath, "wb") as f:
            for chunk in r.iter_content(chunk_size=32 * 1024):
                if chunk:
                    f.write(chunk)
    return filepath


def download_debs(objects, download_path=Path(".")):
    mc = Minio(
        MINIO_HOST,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )

    output_files = []

    for obj in objects:
        logging.info("Downloading %s", obj)
        try:
            data = mc.get_object("debs", obj)
            fpath = download_path / obj
            output_files.append(fpath)

            with open(fpath, "wb") as f:
                for d in data.stream(32 * 1024):
                    f.write(d)
        except ResponseError as e:
            logging.error("Failed to download %s", obj)
            raise
    return output_files


@pytest.fixture(scope="session")
def drakmon_vm():
    logging.info("Running end to end test")

    debs = download_debs(MINIO_DEBS)
    drakvuf_bundle = download_file(DRAKVUF_BUNDLE_URL)

    vm_runner.set_snapshot(VM_SNAPSHOT_BASE)
    vm_runner.rebuild_vm()

    while not server_alive(VM_HOST, 22):
        time.sleep(0.5)

    with Connection("testvm", config=FABRIC_CONFIG) as c:
        # Upload debs
        for d in map(str, [drakvuf_bundle, *debs]):
            logging.info("Uploading %s", d)
            c.put(d)

        c.run("apt-get update")

        apt_install(c, DRAKVUF_DEPS)

        # Install DRAKVUF
        dpkg_install(c, drakvuf_bundle.name)

        # Reboot into Xen
        c.run("systemctl reboot", disown=True)

    # Wait until VM reboots
    while server_alive(VM_HOST, 22):
        time.sleep(0.5)
    logging.info("VM went down")

    while not server_alive(VM_HOST, 22):
        time.sleep(0.5)
    logging.info("VM back up")

    with Connection("testvm", config=FABRIC_CONFIG) as c:
        apt_install(c, ["redis-server"])
        apt_install(c, DRAKMON_DEPS)

        for d in debs:
            dpkg_install(c, d.name)

        # add ISO image to make xen happy
        c.run(
            "genisoimage -o /root/SW_DVD5_Win_Pro_7w_SP1_64BIT_Polish_-2_MLF_X17-59386.ISO /dev/null"
        )

        # add xen bridge
        c.run("brctl addbr drak0")

    return Connection("testvm", config=FABRIC_CONFIG)


@pytest.fixture(scope="session")
def karton_bucket(drakmon_vm):
    """ Wait up to 10 seconds until karton2 bucket appears """
    for _ in range(10):
        try:
            drakmon_vm.run("[[ -f /var/lib/drakcore/minio/karton2 ]]")
            drakmon_vm.run("[[ -f /var/lib/drakcore/minio/drakrun ]]")
            break
        except UnexpectedExit:
            time.sleep(1.0)

    return None


def pytest_sessionfinish(session, exitstatus):
    """ Dump logs if we're going to exit with an error """
    if exitstatus == 0:
        return

    print("Testing finished with errors, collecting logs")
    with Connection("testvm", config=FABRIC_CONFIG) as c:
        for service in DRAKMON_SERVICES:
            c.run(f"journalctl -u {service}")
