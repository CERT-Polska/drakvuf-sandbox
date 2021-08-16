import requests
import os
import logging
import socket
import time
import subprocess
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
DRAKVUF_COMMIT = subprocess.check_output(["git", "ls-tree", "HEAD", "../drakvuf"]).split()[2].decode()

VM_SNAPSHOT_BASE = os.getenv("VM_SNAPSHOT_BASE")
VM_RUNNER_HOST = "http://" + os.getenv("VM_RUNNER_HOST")
VM_HOST = os.getenv("VM_HOST")

MINIO_HOST = os.getenv("MINIO_HOST")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")

BUNDLE_DEB = f"drakvuf-bundle-{DRAKVUF_COMMIT}.deb"
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
    "lvm2",
]

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
    "drak-postprocess@1.service",
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
    [drakvuf_bundle] = download_debs([BUNDLE_DEB])

    vm_runner.set_snapshot(VM_SNAPSHOT_BASE)
    vm_runner.rebuild_vm()

    while not server_alive(VM_HOST, 22):
        time.sleep(0.5)

    with Connection("testvm", config=FABRIC_CONFIG) as c:
        # Upload debs
        for d in map(str, [drakvuf_bundle, *debs]):
            logging.info("Uploading %s", d)
            c.put(d)

        c.run("apt-get --allow-releaseinfo-change update")

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

        # add ISO image to make xen happy
        c.run(
            "genisoimage -o /root/SW_DVD5_Win_Pro_7w_SP1_64BIT_Polish_-2_MLF_X17-59386.ISO /dev/null"
        )

        for d in debs:
            dpkg_install(c, d.name)

        # add xen bridge
        c.run("brctl addbr drak0")
        c.run("systemctl enable drakrun@1")
        c.run("systemctl start drakrun@1")

    return Connection("testvm", config=FABRIC_CONFIG)


@pytest.fixture(scope="session")
def karton_bucket(drakmon_vm):
    """ Wait up to 10 seconds until karton bucket appears """
    for _ in range(10):
        try:
            drakmon_vm.run("[[ -f /var/lib/drakcore/minio/karton ]]")
            drakmon_vm.run("[[ -f /var/lib/drakcore/minio/drakrun ]]")
            break
        except UnexpectedExit:
            time.sleep(1.0)

    return None
