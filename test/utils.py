import io
import requests


def apt_install(c, packages):
    deps = " ".join(packages)
    c.run(f"apt-get install -y {deps}", hide="stdout")


def dpkg_install(c, deb_file):
    c.run(f"dpkg -i {deb_file}", hide="stdout")


def get_file(c, path):
    tmp = io.BytesIO()
    c.get(path, tmp)
    return tmp.getvalue()


def get_hypervisor_type(c):
    return get_file(c, "/sys/hypervisor/type").strip().decode()


def get_service_info(c, service):
    lines = c.run(f"systemctl show {service}", hide="out").stdout.splitlines()
    return dict(map(lambda l: l.split("=", maxsplit=1), lines))


class VMRunner:
    def __init__(self, host):
        self.host = host

    def rebuild_vm(self, ssh_key):
        response = requests.post(f"{self.host}/vm/build", json={
            "image": "debian-10-generic-amd64",
            "volume_size": 100,
            "ssh_key": ssh_key,
        })
        response.raise_for_status()
        return response.json()



class Drakcore:
    def __init__(self, host):
        self.host = host

    def upload(self, sample, timeout):
        response = requests.post(f"{self.host}/upload", files={"file": sample}, data={"timeout": timeout})
        response.raise_for_status()
        return response.json()["task_uid"]

    def check_status(self, task_uuid):
        response = requests.get(f"{self.host}/status/{task_uuid}")
        response.raise_for_status()
        return response.json()

    def analysis_log(self, task_uuid, log_name):
        response = requests.get(f"{self.host}/logs/{task_uuid}/{log_name}", stream=True)
        response.raise_for_status()
        return response
