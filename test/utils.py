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

    def rebuild_vm(self):
        response = requests.get(f"{self.host}/rebuild-vm")
        response.raise_for_status()

    def list_snapshots(self):
        response = requests.get(f"{self.host}/snapshots")
        response.raise_for_status()
        return response.json()

    def make_snapshot(self):
        response = requests.get(f"{self.host}/snapshots/make")
        response.raise_for_status()
        return response.json()

    def set_snapshot(self, name):
        response = requests.get(f"{self.host}/snapshots/set/{name}")
        response.raise_for_status()
        return response.json()


class Drakcore:
    def __init__(self, host):
        self.host = host

    def upload(self, sample):
        response = requests.post(f"{self.host}/upload", files={"file": sample})
        response.raise_for_status()
        # redirect to http://<host>/progress/<task-uuid>
        return response.url.split("/")[-1]

    def check_status(self, task_uuid):
        response = requests.get(f"{self.host}/status/{task_uuid}")
        response.raise_for_status()
        return response.json()

    def analysis_log(self, task_uuid, log_name):
        response = requests.get(f"{self.host}/logs/{task_uuid}/{log_name}", stream=True)
        response.raise_for_status()
        return response
