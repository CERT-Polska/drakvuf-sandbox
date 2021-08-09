import requests
import os
import logging
import socket
import time
import subprocess
import paramiko.config
import pytest

from pathlib import Path
from paramiko.rsakey import RSAKey
from fabric import task, Connection, Config
from invoke.exceptions import UnexpectedExit
from minio import Minio
from minio.error import ResponseError

from utils import apt_install, dpkg_install

logging.basicConfig(level=logging.INFO)

DRONE_BUILD_NUMBER = os.getenv("DRONE_BUILD_NUMBER")
DRAKVUF_COMMIT = subprocess.check_output(["git", "ls-tree", "HEAD", "../drakvuf"]).split()[2].decode()

VM_RUNNER_HOST = "http://" + os.getenv("VM_RUNNER_HOST")

BASE_IMAGE = os.getenv("BASE_IMAGE")
SNAPSHOT_VERSION = os.getenv("SNAPSHOT_VERSION")
MINIO_HOST = os.getenv("MINIO_HOST")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
RUNNER_KEY = os.getenv("RUNNER_KEY")

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

def rebuild_vm(host, ssh_key, api_key):
    response = requests.post(f"{host}/vm/build", json={
        "image": BASE_IMAGE,
        "volume_size": 100,
        "ssh_key": ssh_key,
    }, headers={
        "Authorization": f"Bearer {api_key}",
    })
    response.raise_for_status()
    return response.json()

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
def vm_host(drakmon_setup):
    connection, ip = drakmon_setup
    return ip

@pytest.fixture(scope="session")
def drakmon_vm(drakmon_setup):
    connection, ip = drakmon_setup
    return connection

@pytest.fixture(scope="session")
def drakmon_setup():
    key = RSAKey.generate(bits=2048)
    with open("/root/.ssh/id_rsa", "w") as f:
        key.write_private_key(f)

    logging.info("Running end to end test")


    debs = download_debs(MINIO_DEBS)
    [drakvuf_bundle] = download_debs([BUNDLE_DEB])

    response = rebuild_vm(VM_RUNNER_HOST,
        ssh_key="ssh-rsa " + key.get_base64(),
        api_key=RUNNER_KEY
    )
    VM_HOST = response["ip"]
    ssh_config = paramiko.config.SSHConfig.from_text(
        f"""
    Host testvm
        User root
        HostName {VM_HOST}
    """
    )

    FABRIC_CONFIG = Config(ssh_config=ssh_config)

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

        for d in debs:
            dpkg_install(c, d.name)

        # Save default config
        c.run("cp /etc/drakrun/config.ini /etc/drakrun/config.ini.bak")

        c.run(f"""
cat > /etc/drakrun/config.ini <<EOF
[minio]
address={MINIO_HOST}
secure=0
access_key={MINIO_ACCESS_KEY}
secret_key={MINIO_SECRET_KEY}
EOF""")

        # Import snapshot
        assert SNAPSHOT_VERSION is not None
        c.run(f"draksetup snapshot import --bucket snapshots --name {SNAPSHOT_VERSION} --full")

        # Restore original config
        c.run("cp /etc/drakrun/config.ini.bak /etc/drakrun/config.ini")

        # Shut up QEMU
        c.run("ln -s /dev/null /root/SW_DVD5_Win_Pro_7w_SP1_64BIT_Polish_-2_MLF_X17-59386.ISO")

        c.run("systemctl start drakrun@1")

    return Connection("testvm", config=FABRIC_CONFIG), VM_HOST


@pytest.fixture(scope="session")
def karton_bucket(drakmon_vm):
    """ Wait up to 30 seconds until karton bucket appears """
    for _ in range(30):
        try:
            drakmon_vm.run("[[ -d /var/lib/drakcore/minio/karton ]]")
            drakmon_vm.run("[[ -d /var/lib/drakcore/minio/drakrun ]]")
            break
        except UnexpectedExit:
            time.sleep(1.0)
    else:
        raise RuntimeError("Buckets didn't appear!")

    return None
