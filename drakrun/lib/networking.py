import ipaddress
import logging
import os
import pathlib
import re
import signal
import subprocess
import time
from typing import List, Optional

from .config import DNS_USE_GATEWAY_ADDRESS, OUT_INTERFACE_DEFAULT, NetworkConfigSection
from .network_info import NetworkInfo
from .paths import ETC_DIR, RUN_DIR

log = logging.getLogger(__name__)


def find_default_interface() -> Optional[str]:
    routes = (
        subprocess.check_output(
            "ip route show default", shell=True, stderr=subprocess.STDOUT
        )
        .decode("ascii")
        .strip()
        .split("\n")
    )

    for route in routes:
        m = re.search(r"dev ([^ ]+)", route.strip())

        if m:
            return m.group(1)

    return None


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
    vm_id: int, network_conf: NetworkConfigSection
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

    if network_conf.out_interface == OUT_INTERFACE_DEFAULT:
        out_interface = find_default_interface()
    else:
        out_interface = network_conf.out_interface

    # Xen OUI
    dnsmasq_pidfile = get_dnsmasq_pidfile_path(vm_id)

    return NetworkInfo(
        out_interface=out_interface,
        dns_server=dns_server,
        net_enable=network_conf.net_enable,
        bridge_name=bridge_name,
        network_address=network_address,
        gateway_address=gateway_address,
        vm_address=vm_address,
        dnsmasq_pidfile=dnsmasq_pidfile,
    )


def iptable_rule_exists(rule) -> bool:
    try:
        subprocess.check_output(
            f"iptables -C {rule}", shell=True, stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode == 1 or e.returncode == 2:
            # rule doesn't exist
            return False
        else:
            # some other error
            raise RuntimeError(f"Failed to check for iptables rule: {rule}")


def add_iptable_rule(rule) -> None:
    if not iptable_rule_exists(rule):
        subprocess.check_output(f"iptables -A {rule}", shell=True)


def del_iptable_rule(rule) -> None:
    # For deleting multiple copies of the same rule
    all_cleared = False

    while not all_cleared:
        if iptable_rule_exists(rule):
            subprocess.check_output(f"iptables -D {rule}", shell=True)
        else:
            all_cleared = True


def list_iptables_rules(table=None) -> List[str]:
    return subprocess.check_output(
        f"iptables -S {f'-t {table}' if table is not None else ''}",
        shell=True,
        text=True,
    ).splitlines()


def setup_iptables_chains() -> None:
    rules = [
        "-N DRAKRUN_INP",
        "-A INPUT -j DRAKRUN_INP",
        "-N DRAKRUN_FWD",
        "-A FORWARD -j DRAKRUN_FWD",
        "-N DRAKRUN_PRT -t nat",
        "-A POSTROUTING -j DRAKRUN_PRT -t nat",
    ]
    exists = [
        iptable_rule_exists("INPUT -j DRAKRUN_INP"),
        iptable_rule_exists("FORWARD -j DRAKRUN_FWD"),
        iptable_rule_exists("POSTROUTING -j DRAKRUN_PRT -t nat"),
    ]
    if all(exists):
        log.debug("iptables chains already exist, no setup needed")
        return
    if any(exists):
        raise RuntimeError("Some iptables chains are missing, cleanup might be needed.")
    # If above checks pass, we're free to setup everything
    log.debug("Setting up iptables chains")
    try:
        for rule in rules:
            subprocess.run(f"iptables {rule}", shell=True, check=True)
    except subprocess.CalledProcessError:
        log.debug("Failed to setup one of chains, rolling back")
        delete_iptables_chains()


def flush_iptables_chains() -> None:
    rules = ["-F DRAKRUN_INP", "-F DRAKRUN_FWD", "-F DRAKRUN_PRT -t nat"]
    for rule in rules:
        subprocess.run(f"iptables {rule}", shell=True)


def delete_iptables_chains() -> None:
    rules = [
        "-D INPUT -j DRAKRUN_INP",
        "-D FORWARD -j DRAKRUN_FWD",
        "-D POSTROUTING -j DRAKRUN_PRT -t nat",
        "-X DRAKRUN_INP",
        "-X DRAKRUN_FWD",
        "-X DRAKRUN_PRT -t nat",
    ]
    for rule in rules:
        subprocess.run(f"iptables {rule}", shell=True)


def start_tcpdump_collector(
    bridge_name: str, outfile: pathlib.Path
) -> subprocess.Popen:
    try:
        subprocess.run("tcpdump --version", shell=True, check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start tcpdump")

    return subprocess.Popen(["tcpdump", "-i", bridge_name, "-w", outfile.as_posix()])


def start_dnsmasq(dns_server: str, bridge_name: str, vm_ip: str, dnsmasq_pidfile: str):
    if os.path.exists(dnsmasq_pidfile):
        stop_dnsmasq(dnsmasq_pidfile)

    subprocess.Popen(
        [
            "dnsmasq",
            "--conf-file=/dev/null",
            "--bind-interfaces",
            f"--interface={bridge_name}",
            "--port=0",
            "--no-hosts",
            "--no-resolv",
            "--no-poll",
            "--leasefile-ro",
            f"--pid-file={dnsmasq_pidfile}",
            f"--dhcp-range={vm_ip},{vm_ip},12h",
            f"--dhcp-option=option:dns-server,{dns_server}",
        ],
        start_new_session=True,
    )


def stop_dnsmasq(dnsmasq_pidfile: str) -> None:
    dnsmasq_pidfile = pathlib.Path(dnsmasq_pidfile)
    if dnsmasq_pidfile.exists():
        dnsmasq_pid = int(dnsmasq_pidfile.read_text().strip())
        try:
            os.kill(dnsmasq_pid, signal.SIGTERM)
        except OSError as e:
            log.warning("Failed to stop dnsmasq: %s", str(e))
        # Wait for exit
        # dnsmasq doesn't remove its own PID file on termination
        for _ in range(10):
            try:
                os.kill(dnsmasq_pid, 0)
            except ProcessLookupError:
                dnsmasq_pidfile.unlink(missing_ok=True)
                break
            time.sleep(0.5)
        else:
            log.warning(f"Failed to stop dnsmasq: process {dnsmasq_pid} still running")


def interface_exists(iface: str) -> bool:
    proc = subprocess.run(["ip", "link", "show", iface], capture_output=True)
    return proc.returncode == 0


def run_network_setup_script(script_name: str, network_info: NetworkInfo):
    script_path = ETC_DIR / script_name
    if not script_path.exists():
        return
    log.info("Running network setup script: %s", script_name)
    subprocess.check_call(
        ["bash", script_path.as_posix()], env=network_info.dump_for_env()
    )


def start_vm_network(vm_id: int, network_conf: NetworkConfigSection) -> NetworkInfo:
    setup_iptables_chains()

    network_info_path = get_network_info_path(vm_id)
    if network_info_path.exists():
        stop_vm_network(vm_id)

    network_info = make_network_info_for_vm(vm_id, network_conf)

    run_network_setup_script("vmnet-pre.sh", network_info)

    bridge_name = network_info.bridge_name
    try:
        subprocess.run(
            f"brctl addbr {bridge_name}", shell=True, capture_output=True, check=True
        )
        log.info(f"Created bridge {bridge_name}")
    except subprocess.CalledProcessError:
        raise Exception(f"Failed to create bridge {bridge_name}.")
    else:
        subprocess.run(
            f"ip addr add {network_info.gateway_address}/{network_info.network_prefix} dev {bridge_name}",
            shell=True,
            check=True,
        )

    subprocess.run(f"ip link set dev {bridge_name} up", shell=True, check=True)
    log.info(f"Bridge {bridge_name} is up")

    add_iptable_rule(
        f"DRAKRUN_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )

    if network_info.dns_server == network_info.gateway_address:
        add_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    add_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    if network_info.net_enable:
        out_interface = network_info.out_interface
        if not interface_exists(out_interface):
            raise ValueError(f"Invalid network interface: {repr(out_interface)}")

        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")

        add_iptable_rule(
            f"DRAKRUN_PRT -t nat -s {network_info.network_address} -o {out_interface} -j MASQUERADE"
        )
        add_iptable_rule(f"DRAKRUN_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        add_iptable_rule(f"DRAKRUN_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")

    start_dnsmasq(
        network_info.dns_server,
        network_info.bridge_name,
        network_info.vm_address,
        network_info.dnsmasq_pidfile,
    )

    network_info.save(network_info_path)

    run_network_setup_script("vmnet-post.sh", network_info)
    return network_info


def delete_vm_bridge(bridge_name: str):
    try:
        subprocess.run(
            f"ip link set dev {bridge_name} down",
            shell=True,
            capture_output=True,
            check=True,
        )
        log.info(f"Bridge {bridge_name} is down")
    except subprocess.CalledProcessError as e:
        if b"Cannot find device" in e.stderr:
            log.info(f"Already deleted {bridge_name} bridge")
        else:
            raise Exception(f"Couldn't deactivate {bridge_name} bridge")
    else:
        subprocess.run(f"brctl delbr {bridge_name}", shell=True)
        log.info(f"Deleted {bridge_name} bridge")


def vm_network_exists(vm_id: int):
    network_info_path = get_network_info_path(vm_id)
    return network_info_path.exists()


def stop_vm_network(vm_id: int):
    if not vm_network_exists(vm_id):
        log.info(f"VM network for vm-{vm_id} is not running")
        return

    network_info_path = get_network_info_path(vm_id)
    network_info = NetworkInfo.load(network_info_path)

    stop_dnsmasq(network_info.dnsmasq_pidfile)

    bridge_name = network_info.bridge_name
    delete_vm_bridge(bridge_name)

    del_iptable_rule(
        f"DRAKRUN_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )
    # Clean dns=use-gateway-address if it exists
    del_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    del_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    if network_info.net_enable:
        out_interface = network_info.out_interface
        # Clean net_enable entries if they exist
        del_iptable_rule(
            f"DRAKRUN_PRT -t nat -s {network_info.network_address} -o {out_interface} -j MASQUERADE"
        )
        del_iptable_rule(f"DRAKRUN_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        del_iptable_rule(f"DRAKRUN_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")

    network_info_path.unlink()


def list_vm_bridges() -> List[str]:
    brctl_show_lines = subprocess.check_output(
        "brctl show",
        shell=True,
        text=True,
    ).splitlines()
    bridge_names = []
    for bridge_line in brctl_show_lines[1:]:
        bridge_name, *_ = bridge_line.split()
        if bridge_name.startswith("drak"):
            bridge_names.append(bridge_name)
    return bridge_names


def stop_all_vm_networks() -> None:
    """
    Cleans all networks
    """
    for dnsmasq_pidfile in RUN_DIR.glob("dnsmasq-vm*.pid"):
        stop_dnsmasq(dnsmasq_pidfile.as_posix())
    flush_iptables_chains()
    delete_iptables_chains()
    for bridge_name in list_vm_bridges():
        delete_vm_bridge(bridge_name)
    for network_info_path in RUN_DIR.glob("vmnet-*.json"):
        network_info_path.unlink()


def delete_legacy_iptables() -> None:
    patterns = [
        r"-A INPUT -i drak\d",
        r"-A FORWARD -i drak\d",
        r"-A FORWARD -i \S+ -o drak\d",
    ]
    prt_pattern = r"-A POSTROUTING -s 10.13.\d+.0/24"
    iptables_rules = list_iptables_rules()
    nat_iptables_rules = list_iptables_rules(table="nat")
    for rule in iptables_rules:
        for pattern in patterns:
            if re.match(pattern, rule):
                # remove -A
                _, rule_part = rule.split(" ", 1)
                del_iptable_rule(rule_part)
    for rule in nat_iptables_rules:
        if re.match(prt_pattern, rule):
            # remove -A
            _, rule_part = rule.split(" ", 1)
            del_iptable_rule(rule_part + "-t nat")
