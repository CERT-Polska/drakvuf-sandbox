import os
import logging
import time
import subprocess
import pytest

from pathlib import Path
from invoke.exceptions import UnexpectedExit
from vm_runner_client import DrakvufVM

from utils import apt_install

logging.basicConfig(level=logging.INFO)

DRAKVUF_DEBS_PATH = os.getenv("DRAKVUF_DEBS_PATH")
DRAKVUF_COMMIT = subprocess.check_output(["git", "ls-tree", "HEAD", "../drakvuf"]).split()[2].decode()

BASE_IMAGE = os.getenv("BASE_IMAGE", "debian-10-generic-amd64")
SNAPSHOT_VERSION = os.getenv("SNAPSHOT_VERSION")
MINIO_HOST = os.getenv("MINIO_HOST")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY")
# VM_RUNNER_API_KEY
# VM_RUNNER_SOCKS_USERNAME
# VM_RUNNER_SOCKS_PASSWORD

DRAKMON_SERVICES = [
    "drak-system.service",
    "drak-minio.service",
    "drak-web.service",
    "drak-postprocess@1.service",
    "redis-server.service",
]

DRAKVUF_SANDBOX_DEBS = [
    "drakrun-*.whl",
    "drakcore_*.deb",
]

DRAKVUF_DEBS = [
    "drakvuf-bundle-*.deb",
]


def resolve_debs(debs):
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

    drakvuf_sandbox_debs = list(resolve_debs(DRAKVUF_SANDBOX_DEBS))
    drakvuf_debs = list(resolve_debs(DRAKVUF_DEBS))

    drakvuf_vm = DrakvufVM.create(BASE_IMAGE)
    logging.info(f"VM {drakvuf_vm.identity} created.")

    logging.info("Waiting for VM to be alive...")
    drakvuf_vm.wait_for_state(alive=True)

    with drakvuf_vm.connect_ssh() as ssh:
        for deb in (drakvuf_sandbox_debs + drakvuf_debs):
            logging.info("Uploading %s", deb.name)
            ssh.put(deb.as_posix())

        logging.info("Upload finished")
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
        apt_install(ssh, ["redis-server"])
        for d in drakvuf_sandbox_debs:
            if str(d).endswith(".deb"):
                apt_install(ssh, ["./" + d.name])
            else:
                pip_install(ssh, ["./" + d.name])

        # Save default config
        ssh.run("cp /etc/drakrun/config.ini /etc/drakrun/config.ini.bak")

        ssh.run(f"""
cat > /etc/drakrun/config.ini <<EOF
[minio]
address={MINIO_HOST}
secure=0
access_key={MINIO_ACCESS_KEY}
secret_key={MINIO_SECRET_KEY}
EOF""")

        # Import snapshot
        assert SNAPSHOT_VERSION is not None
        ssh.run(f"draksetup snapshot import --bucket snapshots --name {SNAPSHOT_VERSION} --full")

        # Restore original config
        ssh.run("cp /etc/drakrun/config.ini.bak /etc/drakrun/config.ini")

        # Shut up QEMU
        ssh.run("ln -s /dev/null /root/SW_DVD5_Win_Pro_7w_SP1_64BIT_Polish_-2_MLF_X17-59386.ISO")

        ssh.run("systemctl start drakrun@1")

    logging.info("VM provisioned, starting tests...")
    return drakvuf_vm


@pytest.fixture(scope="session")
def karton_bucket(drakmon_vm):
    """ Wait up to 30 seconds until karton bucket appears """
    with drakmon_vm.connect_ssh() as ssh:
        for _ in range(30):
            try:
                ssh.run("[[ -d /var/lib/drakcore/minio/karton ]]")
                ssh.run("[[ -d /var/lib/drakcore/minio/drakrun ]]")
                break
            except UnexpectedExit:
                time.sleep(1.0)
        else:
            raise RuntimeError("Buckets didn't appear!")

    return None
