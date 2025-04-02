import ipaddress
import json
import pathlib

from pydantic import BaseModel

from .paths import RUN_DIR

DNS_USE_GATEWAY_ADDRESS = "use-gateway-address"


class NetworkConfiguration(BaseModel):
    """
    Represents network configuration of the VM
    """

    out_interface: str
    dns_server: str = DNS_USE_GATEWAY_ADDRESS
    net_enable: bool = True

    @staticmethod
    def load(path: pathlib.Path) -> "NetworkConfiguration":
        """Parses InstallInfo file at the provided path"""
        with path.open("r") as f:
            return NetworkConfiguration.model_validate_json(f.read())

    def save(self, path: pathlib.Path) -> None:
        """Serializes self and writes to the provided path"""
        with path.open("w") as f:
            f.write(json.dumps(self.model_dump(mode="json"), indent=4))


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
        return {k.upper(): v for k, v in self.model_dump(mode="json").items()}


def network_addr_for_vm(vm_id: int) -> str:
    if not (0 <= vm_id <= 255):
        raise ValueError(f"VM id out of range: {vm_id}")
    return f"10.13.{vm_id}.0/24"


def get_dnsmasq_pidfile_path(vm_id: int) -> str:
    RUN_DIR.mkdir(exist_ok=True)
    return (RUN_DIR / f"dnsmasq-vm{vm_id}.pid").as_posix()


def get_network_info_path(vm_id: int) -> pathlib.Path:
    RUN_DIR.mkdir(exist_ok=True)
    return RUN_DIR / f"vmnet-{vm_id}.json"


def make_network_info_for_vm(
    vm_id: int, network_conf: NetworkConfiguration
) -> NetworkInfo:
    bridge_name = f"drak{vm_id}"

    network_address = network_addr_for_vm(vm_id)
    network = ipaddress.IPv4Network(network_address)
    hosts = network.hosts()
    gateway_address = str(next(hosts))
    vm_address = str(next(hosts))

    if network_conf.dns_server == DNS_USE_GATEWAY_ADDRESS:
        dns_server = gateway_address
    else:
        dns_server = network_conf.dns_server

    # Xen OUI
    dnsmasq_pidfile = get_dnsmasq_pidfile_path(vm_id)

    return NetworkInfo(
        out_interface=network_conf.out_interface,
        dns_server=dns_server,
        net_enable=network_conf.net_enable,
        bridge_name=bridge_name,
        network_address=network_address,
        gateway_address=gateway_address,
        vm_address=vm_address,
        dnsmasq_pidfile=dnsmasq_pidfile,
    )
