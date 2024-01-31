import logging
import os
import re
import errno
import socket
import time
import uuid

import requests
from paramiko.rsakey import RSAKey
from fabric import Connection
from .socks import create_connection, make_session
from python_socks import ProxyError
from python_socks._proto.socks5 import ReplyCode


class VMRunnerConfig:
    RUNNER_API_URL = os.getenv("VM_RUNNER_API_URL")
    # Self-hosted runner can connect directly to the VM
    RUNNER_USE_SOCKS = int(os.getenv("VM_RUNNER_USE_SOCKS", "0"))

    RUNNER_SOCKS_USERNAME = os.getenv("VM_RUNNER_SOCKS_USERNAME")
    RUNNER_SOCKS_PASSWORD = os.getenv("VM_RUNNER_SOCKS_PASSWORD")
    RUNNER_SOCKS_HOST = os.getenv("VM_RUNNER_SOCKS_HOST")
    RUNNER_SOCKS_PORT = int(os.getenv("VM_RUNNER_SOCKS_PORT", "9000"))


class DrakvufVM:
    config = VMRunnerConfig()

    def __init__(self, identity, vm_ip=None, vm_ssh_key=None):
        self.identity = identity
        self.vm_ip = vm_ip
        self.vm_ssh_key = vm_ssh_key

    def connect_tcp(self, port):
        """
        Connects to VM TCP port and returns socket object
        """
        if self.config.RUNNER_USE_SOCKS:
            return create_connection(
                self.vm_ip, port,
                proxy_username=self.config.RUNNER_SOCKS_USERNAME,
                proxy_password=self.config.RUNNER_SOCKS_PASSWORD,
                proxy_host=self.config.RUNNER_SOCKS_HOST,
                proxy_port=self.config.RUNNER_SOCKS_PORT,
            )
        else:
            sock = socket.socket()
            sock.connect((self.vm_ip, port))
            return sock

    def connect_ssh(self):
        """
        Establishes SSH session with VM and returns fabric.Connection object
        """
        sock = self.connect_tcp(22)
        return Connection(self.vm_ip, user="root", connect_kwargs={
            "pkey": self.vm_ssh_key,
            "sock": sock
        })

    @classmethod
    def http_session(cls):
        """
        Returns requests.Session object with proper proxy setting to access VM ports
        """
        if cls.config.RUNNER_USE_SOCKS:
            return make_session(f"socks5://"
                                f"{cls.config.RUNNER_SOCKS_USERNAME}:"
                                f"{cls.config.RUNNER_SOCKS_PASSWORD}"
                                f"@{cls.config.RUNNER_SOCKS_HOST}:"
                                f"{cls.config.RUNNER_SOCKS_PORT}")
        else:
            return requests.Session()

    def suspend(self):
        session = self.http_session()
        response = session.post(f"{self.config.RUNNER_API_URL}/vm/suspend", json={
            "identity": self.identity
        })
        response.raise_for_status()

    def destroy(self):
        session = self.http_session()
        response = session.post(f"{self.config.RUNNER_API_URL}/vm/destroy", json={
            "identity": self.identity
        })
        response.raise_for_status()

    def is_alive(self):
        try:
            self.connect_tcp(22).close()
            return True
        except ConnectionError:
            return False
        except OSError as e:
            if e.errno == errno.EHOSTUNREACH:
                return False  # no route to host yet
            else:
                raise
        except ProxyError as e:
            if e.error_code in [
                ReplyCode.CONNECTION_REFUSED,
                ReplyCode.HOST_UNREACHABLE,
                ReplyCode.TTL_EXPIRED,
            ]:
                return False
            else:
                raise

    def wait_for_state(self, alive: bool):
        for tries in range(12):
            for _ in range(10):
                if self.is_alive() == alive:
                    return
                time.sleep(0.5)
            logging.info(f"Try {tries+1}/12: Machine still {'not ' if alive else ''}alive")
        raise RuntimeError("Machine not reached in expected time")

    @staticmethod
    def get_vm_identity():
        sanitize = lambda v: re.sub(r"[^a-zA-Z0-9_\-]", "_", v)[:48]
        if os.getenv("GITLAB_CI"):
            return sanitize(f'gitlab-{os.getenv("CI_COMMIT_REF_NAME")}-{os.getenv("VM_SUFFIX")}')
        elif os.getenv("GITHUB_ACTION"):
            return sanitize(f'github-{os.getenv("GITHUB_REF_NAME")}-{os.getenv("VM_SUFFIX")}')
        return None

    @classmethod
    def create(cls, base_image="debian-10-generic-amd64"):
        vm_ssh_key = RSAKey.generate(bits=2048)
        ssh_pub_key = "ssh-rsa " + vm_ssh_key.get_base64()

        identity = cls.get_vm_identity() or str(uuid.uuid4())
        session = cls.http_session()
        response = session.post(f"{cls.config.RUNNER_API_URL}/vm/build", json={
            "identity": identity,
            "image": base_image,
            "ssh_key": ssh_pub_key,
        })
        response.raise_for_status()
        vm_spec = response.json()
        vm_identity, vm_ip = vm_spec["identity"], vm_spec["ip"]

        return cls(vm_identity, vm_ip, vm_ssh_key)
