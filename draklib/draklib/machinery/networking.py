import logging
import os
import re
import signal
import subprocess
from pathlib import Path
from typing import List, Optional

from ..config import Configuration
from .subprocess import Popen, check_output, run
from .xen import get_domid_from_name

log = logging.getLogger(__name__)


def find_default_interface():
    routes = (
        check_output("ip route show default", shell=True, stderr=subprocess.STDOUT)
        .decode("ascii")
        .strip()
        .split("\n")
    )

    for route in routes:
        m = re.search(r"dev ([^ ]+)", route.strip())

        if m:
            return m.group(1)

    return None


def check_networking_prerequisites() -> None:
    try:
        check_output("brctl show", shell=True)
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Failed to execute brctl show. Make sure you have bridge-utils installed."
        )
    try:
        list_iptables_rules()
    except subprocess.CalledProcessError:
        raise RuntimeError(
            "Failed to execute iptables -S. Make sure you have iptables installed."
        )


def iptable_rule_exists(rule: str) -> bool:
    try:
        check_output(f"iptables -C {rule}", shell=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode == 1 or e.returncode == 2:
            # rule doesn't exist
            return False
        else:
            # some other error
            raise RuntimeError(f"Failed to check for iptables rule: {rule}")


def add_iptable_rule(rule: str) -> None:
    if not iptable_rule_exists(rule):
        check_output(f"iptables -A {rule}", shell=True)


def del_iptable_rule(rule: str) -> None:
    # For deleting multiple copies of the same rule
    all_cleared = False

    while not all_cleared:
        if iptable_rule_exists(rule):
            check_output(f"iptables -D {rule}", shell=True)
        else:
            all_cleared = True


def list_iptables_rules(table=None) -> List[str]:
    return check_output(
        f"iptables -S {f'-t {table}' if table is not None else ''}",
        shell=True,
        text=True,
    ).split("\n")


def run_on_iptables(rules: List[str], check: bool = True):
    for rule in rules:
        run(f"iptables {rule}", shell=True, check=check)


def setup_iptables_chains():
    rules = [
        "-N DRAKLIB_INP",
        "-A INPUT -j DRAKLIB_INP" "-N DRAKLIB_FWD",
        "-A FORWARD -j DRAKLIB_FWD"
        "-N DRAKLIB_PRT -t nat"
        "-A POSTROUTING -j DRAKLIB_PRT -t nat",
    ]
    exists = [
        iptable_rule_exists("INPUT -j DRAKLIB_INP"),
        iptable_rule_exists("FORWARD -j DRAKLIB_FWD"),
        iptable_rule_exists("POSTROUTING -j DRAKLIB_PRT -t nat"),
    ]
    if all(exists):
        log.debug("iptables chains already exist, no setup needed")
        return True
    if any(exists):
        raise RuntimeError(
            "Some iptables chains are missing, migration might be needed"
        )
    # If above checks pass, we're free to setup everything
    log.debug("Setting up iptables chains")
    try:
        run_on_iptables(rules, check=True)
    except subprocess.CalledProcessError:
        log.debug("Failed to setup one of chains, rolling back")
        delete_iptables_chains()


def flush_iptables_chains():
    rules = ["-F DRAKLIB_INP", "-F DRAKLIB_FWD", "-F DRAKLIB_PRT -t nat"]
    run_on_iptables(rules, check=False)


def delete_iptables_chains():
    rules = [
        "-D INPUT -j DRAKLIB_INP",
        "-D FORWARD -j DRAKLIB_FWD",
        "-D POSTROUTING -j DRAKLIB_PRT -t nat",
        "-X DRAKLIB_INP",
        "-X DRAKLIB_FWD",
        "-X DRAKLIB_PRT",
    ]
    run_on_iptables(rules, check=False)


def vif_from_vm_name(vm_name: str) -> str:
    domid = get_domid_from_name(vm_name)
    return f"vif{domid}.0-emu"


def bridge_from_vm_name(vm_name: str) -> str:
    return f"drak{vm_name}"


def start_tcpdump_collector(vm_name: str, outdir: Path) -> subprocess.Popen:
    try:
        check_output("tcpdump --version", shell=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start tcpdump")

    return Popen(
        ["tcpdump", "-i", vif_from_vm_name(vm_name), "-w", str(outdir / "dump.pcap")]
    )


def start_dnsmasq(
    config: Configuration, vm_id: int, dns_server: str, background=False
) -> Optional[subprocess.Popen]:
    try:
        check_output("dnsmasq --version", shell=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start dnsmasq")

    vm_name = config.get_vm_name(vm_id)

    if dns_server == "use-gateway-address":
        # 10.13.N.1
        dns_server = config.ip_from_vm_id(vm_id, host_id=1)

    dnsmasq_pidfile = f"/var/run/dnsmasq-drak-{vm_name}.pid"

    if background:
        if os.path.exists(dnsmasq_pidfile):
            with open(dnsmasq_pidfile, "r") as f:
                dnsmasq_pid = int(f.read().strip())

            try:
                os.kill(dnsmasq_pid, 0)
            except OSError:
                log.info("Starting dnsmasq in background")
            else:
                log.info("Already running dnsmasq in background")
                return None

    dhcp_first_addr = config.ip_from_vm_id(vm_id, host_id=100)
    dhcp_last_addr = config.ip_from_vm_id(vm_id, host_id=200)

    return Popen(
        [
            "dnsmasq",
            "--no-daemon" if not background else "",
            "--conf-file=/dev/null",
            "--bind-interfaces",
            f"--interface={bridge_from_vm_name(vm_name)}",
            "--port=0",
            "--no-hosts",
            "--no-resolv",
            "--no-poll",
            "--leasefile-ro",
            f"--pid-file={dnsmasq_pidfile}",
            f"--dhcp-range={dhcp_first_addr},{dhcp_last_addr},255.255.255.0,12h",
            f"--dhcp-option=option:dns-server,{dns_server}",
        ]
    )


def stop_dnsmasq(config: Configuration, vm_id: int) -> None:
    vm_name = config.get_vm_name(vm_id)
    dnsmasq_pidfile = f"/var/run/dnsmasq-drak-{vm_name}.pid"

    if os.path.exists(dnsmasq_pidfile):
        with open(dnsmasq_pidfile, "r") as f:
            dnsmasq_pid = int(f.read().strip())

        try:
            os.kill(dnsmasq_pid, signal.SIGTERM)
            log.info(f"Stopped dnsmasq of {vm_name}")
        except OSError:
            log.info(f"dnsmasq for {vm_name} is already stopped")


def interface_exists(iface: str) -> bool:
    proc = run(["ip", "link", "show", iface], capture_output=True)
    return proc.returncode == 0


def setup_vm_network(
    config: Configuration,
    vm_id: int,
    out_interface: str,
    dns_server: str,
    net_enable: bool,
) -> None:
    setup_iptables_chains()
    vm_name = config.get_vm_name(vm_id)
    bridge_name = bridge_from_vm_name(vm_name)
    try:
        check_output(f"brctl addbr {bridge_name}", stderr=subprocess.STDOUT, shell=True)
        log.info(f"Created bridge {bridge_name}")
    except subprocess.CalledProcessError as e:
        if b"already exists" in e.output:
            log.info(f"Bridge {bridge_name} already exists.")
        else:
            log.debug(e.output)
            raise Exception(f"Failed to create bridge {bridge_name}.")
    else:
        gateway_ip = config.ip_from_vm_id(vm_id, host_id=1)
        run(f"ip addr add {gateway_ip}/24 dev {bridge_name}", shell=True, check=True)
    run(f"ip link set dev {bridge_name} up", shell=True, check=True)
    log.info(f"Bridge {bridge_name} is up")

    add_iptable_rule(
        f"DRAKLIB_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )

    if dns_server == "use-gateway-address":
        add_iptable_rule(f"DRAKLIB_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    add_iptable_rule(f"DRAKLIB_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    if net_enable:
        if not interface_exists(out_interface):
            raise ValueError(f"Invalid network interface: {repr(out_interface)}")

        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")

        vmnet_ip = config.ip_from_vm_id(vm_id, host_id=0)
        add_iptable_rule(
            f"DRAKLIB_PRT -t nat -s {vmnet_ip}/24 -o {out_interface} -j MASQUERADE"
        )
        add_iptable_rule(f"DRAKLIB_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        add_iptable_rule(f"DRAKLIB_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")


def delete_vm_network(config: Configuration, vm_id: int) -> None:
    vm_name = config.get_vm_name(vm_id)
    bridge_name = bridge_from_vm_name(vm_name)
    try:
        check_output(
            f"ip link set dev {bridge_name} down", shell=True, stderr=subprocess.STDOUT
        )
        log.info(f"Bridge {bridge_name} is down")
    except subprocess.CalledProcessError as e:
        if b"Cannot find device" in e.output:
            log.info(f"Already deleted {bridge_name} bridge")
        else:
            log.debug(e.output)
            raise Exception(f"Couldn't deactivate {bridge_name} bridge")
    else:
        run(f"brctl delbr {bridge_name}", stderr=subprocess.STDOUT, shell=True)
        log.info(f"Deleted {bridge_name} bridge")

    del_iptable_rule(
        f"DRAKLIB_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )
    # Clean dns=use-gateway-address if they exist
    del_iptable_rule(f"DRAKLIB_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    del_iptable_rule(f"DRAKLIB_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    # List net_enable entries
    iptables_rules = list_iptables_rules()
    pattern = rf"DRAKLIB_FWD -i {bridge_name} -o (\w+) -j ACCEPT"
    out_interface = None
    for rule in iptables_rules:
        m = re.match(pattern, rule)
        if m:
            out_interface = m.group(1)

    if out_interface is not None:
        # Clean net_enable entries if they exist
        vmnet_ip = config.ip_from_vm_id(vm_id, host_id=0)
        del_iptable_rule(
            f"DRAKLIB_PRT -t nat -s {vmnet_ip}/24 -o {out_interface} -j MASQUERADE"
        )
        del_iptable_rule(f"DRAKLIB_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        del_iptable_rule(f"DRAKLIB_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")
