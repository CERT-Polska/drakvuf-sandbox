import ipaddress
import json
import pathlib

from pydantic import BaseModel


class NetworkInfo(BaseModel):
    out_interface: str
    dns_server: str
    net_enable: bool

    bridge_name: str
    network_address: str
    gateway_address: str
    vm_address: str
    dnsmasq_pidfile: str

    @property
    def network_prefix(self):
        return ipaddress.IPv4Network(self.network_address).prefixlen

    @staticmethod
    def load(path: pathlib.Path) -> "NetworkInfo":
        """Parses InstallInfo file at the provided path"""
        with path.open("r") as f:
            return NetworkInfo.model_validate_json(f.read())

    def save(self, path: pathlib.Path) -> None:
        """Serializes self and writes to the provided path"""
        with path.open("w") as f:
            f.write(json.dumps(self.model_dump(mode="json"), indent=4))

    def dump_for_env(self):
        return {k.upper(): str(v) for k, v in self.model_dump(mode="json").items()}
