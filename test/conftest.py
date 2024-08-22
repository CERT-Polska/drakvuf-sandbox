import os
import logging
import time
import subprocess
import pytest

from pathlib import Path
from invoke.exceptions import UnexpectedExit
from vm_runner_client import DrakvufVM

from utils import apt_install, pipx_install

logging.basicConfig(level=logging.INFO)

DRAKVUF_DEBS_PATH = os.getenv("DRAKVUF_DEBS_PATH")
DRAKVUF_COMMIT = subprocess.check_output(["git", "ls-tree", "HEAD", "../drakvuf"]).split()[2].decode()

BASE_IMAGE = os.getenv("BASE_IMAGE", "debian-10-generic-amd64")
SNAPSHOT_VERSION = os.getenv("SNAPSHOT_VERSION")
MINIO_HOST = os.getenv("MINIO_HOST")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
MINIO_SERVER_BIN_PATH = os.getenv("MINIO_SERVER_BIN_PATH")
# VM_RUNNER_API_KEY
# VM_RUNNER_SOCKS_USERNAME
# VM_RUNNER_SOCKS_PASSWORD

DRAKMON_SERVICES = [
    "drak-system.service",
    "drak-web.service",
    "redis-server.service",
]

DRAKVUF_SANDBOX_WHLS = [
    "drakvuf_sandbox-*.whl",
]

DRAKVUF_DEBS = [
    "drakvuf-bundle-*.deb",
]


def resolve_package_paths(debs):
    debs_path = Path(DRAKVUF_DEBS_PATH)
    if not debs_path.is_dir():
        raise RuntimeError(f"Incorrect DRAKVUF_DEBS_PATH: {DRAKVUF_DEBS_PATH}")

    for deb in debs:
        path_candidates = list(debs_path.glob("**/" + deb))
        if not path_candidates:
            raise RuntimeError(f"{deb} not found under DRAKVUF_DEBS_PATH")
        if len(path_candidates) > 1:
            raise RuntimeError(f"Found multiple candidates for {deb}: {path_candidates}")
        yield path_candidates[0]


@pytest.fixture(scope="session")
def vm_host(drakmon_setup: DrakvufVM):
    return drakmon_setup.vm_ip


@pytest.fixture(scope="session")
def drakmon_vm(drakmon_setup: DrakvufVM):
    return drakmon_setup


@pytest.fixture(scope="session")
def drakmon_ssh(drakmon_setup: DrakvufVM):
    with drakmon_setup.connect_ssh() as ssh:
        yield ssh


@pytest.fixture(scope="session")
def drakmon_setup():
    logging.info("Running end to end test: creating VM")

    drakvuf_sandbox_whls = list(resolve_package_paths(DRAKVUF_SANDBOX_WHLS))
    drakvuf_debs = list(resolve_package_paths(DRAKVUF_DEBS))

    drakvuf_vm = DrakvufVM.create(BASE_IMAGE)
    logging.info(f"VM {drakvuf_vm.identity} created.")

    logging.info("Waiting for VM to be alive...")
    drakvuf_vm.wait_for_state(alive=True)

    with drakvuf_vm.connect_ssh() as ssh:
        for deb in (drakvuf_sandbox_whls + drakvuf_debs):
            logging.info("Uploading %s", deb.name)
            ssh.put(deb.as_posix())

        logging.info("Uploading MinIO server binary")
        ssh.put(MINIO_SERVER_BIN_PATH, "/usr/local/bin/minio")
        logging.info("Upload finished")
        ssh.run("chmod +x /usr/local/bin/minio")
        ssh.run("apt-get --allow-releaseinfo-change update", in_stream=False)
        logging.info("Install DRAKVUF")
        # Install DRAKVUF
        for d in drakvuf_debs:
            apt_install(ssh, ["./" + d.name])

        # Reboot into Xen
        ssh.run("systemctl reboot", disown=True)

    logging.info("Rebooting...")

    # Wait until VM reboots
    drakvuf_vm.wait_for_state(alive=False)

    logging.info("VM went down")

    drakvuf_vm.wait_for_state(alive=True)

    logging.info("VM back up")

    with drakvuf_vm.connect_ssh() as ssh:
        ssh.run("apt-get --allow-releaseinfo-change update", in_stream=False)
        apt_install(ssh, ["redis-server", "python3", "python3-pip", "git", "dnsmasq", "bridge-utils"])
        logging.info("Setting up pip and pipx")
        ssh.run(f"DEBIAN_FRONTEND=noninteractive pip3 install --upgrade pip", in_stream=False)
        ssh.run(f"DEBIAN_FRONTEND=noninteractive pip3 install pipx", in_stream=False)
        ssh.run(f"DEBIAN_FRONTEND=noninteractive pipx ensurepath --global", in_stream=False)

        for d in drakvuf_sandbox_whls:
            pipx_install(ssh, ["./" + d.name])

        # Import snapshot
        assert SNAPSHOT_VERSION is not None
        ssh.run(f"draksetup install-minio")
        ssh.run(f"draksetup init --unattended")
        ssh.run(f'DRAKRUN_MINIO_ADDRESS="{MINIO_HOST}" '
                f'DRAKRUN_MINIO_SECURE=0 '
                f'DRAKRUN_MINIO_ACCESS_KEY="{MINIO_ACCESS_KEY}" '
                f'DRAKRUN_MINIO_SECRET_KEY="{MINIO_SECRET_KEY}" '
                f'draksetup snapshot import --bucket snapshots --name {SNAPSHOT_VERSION} --full')

        # Shut up QEMU
        ssh.run("ln -s /dev/null /root/SW_DVD5_Win_Pro_7w_SP1_64BIT_Polish_-2_MLF_X17-59386.ISO")

        ssh.run("systemctl start drakrun@1")

    logging.info("VM provisioned, starting tests...")
    return drakvuf_vm
