import io
import logging


def apt_install(c, packages):
    deps = " ".join(packages)
    logging.info(f"Installing {packages} with apt")
    c.run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {deps}", in_stream=False)


def dpkg_install(c, deb_file):
    logging.info(f"Installing {deb_file} with dpkg")
    c.run(f"DEBIAN_FRONTEND=noninteractive dpkg -i {deb_file}", in_stream=False)


def get_file(c, path):
    tmp = io.BytesIO()
    c.get(path, tmp)
    return tmp.getvalue()


def get_hypervisor_type(c):
    return get_file(c, "/sys/hypervisor/type").strip().decode()


def get_service_info(c, service):
    lines = c.run(f"systemctl show {service}", hide="out").stdout.splitlines()
    return dict(map(lambda l: l.split("=", maxsplit=1), lines))


class Drakcore:
    def __init__(self, drakvuf_vm):
        self.host = f"http://{drakvuf_vm.vm_ip}:6300/"
        self.session = drakvuf_vm.http_session()

    def get(self, endpoint, *args, **kwargs):
        return self.session.get(f"{self.host}{endpoint}", *args, **kwargs)

    def post(self, endpoint, *args, **kwargs):
        return self.session.post(f"{self.host}{endpoint}", *args, **kwargs)

    def upload(self, sample, timeout):
        response = self.post(f"upload", files={"file": sample}, data={"timeout": timeout})
        response.raise_for_status()
        return response.json()["task_uid"]

    def check_status(self, task_uuid):
        response = self.get(f"status/{task_uuid}")
        response.raise_for_status()
        return response.json()

    def analysis_log(self, task_uuid, log_name):
        response = self.get(f"logs/{task_uuid}/{log_name}", stream=True)
        response.raise_for_status()
        return response
