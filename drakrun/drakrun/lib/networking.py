import logging
import os
import re
import signal
import subprocess
from typing import List, Optional

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
        "-X DRAKRUN_PRT",
    ]
    for rule in rules:
        subprocess.run(f"iptables {rule}", shell=True)


def start_tcpdump_collector(domid: int, outdir: str) -> subprocess.Popen:
    try:
        subprocess.run("tcpdump --version", shell=True, check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start tcpdump")

    return subprocess.Popen(
        ["tcpdump", "-i", f"vif{domid}.0-emu", "-w", f"{outdir}/dump.pcap"]
    )


def start_dnsmasq(
    vm_id: int, dns_server: str, background=False
) -> Optional[subprocess.Popen]:
    try:
        subprocess.run("dnsmasq --version", shell=True, check=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start dnsmasq")

    if dns_server == "use-gateway-address":
        dns_server = f"10.13.{vm_id}.1"

    dnsmasq_pidfile = f"/var/run/dnsmasq-vm{vm_id}.pid"

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
                return
    else:
        # Ensure dnsmasq is stopped
        stop_dnsmasq(vm_id)

    return subprocess.Popen(
        [
            "dnsmasq",
            "--keep-in-foreground" if not background else "",
            "--conf-file=/dev/null",
            "--bind-interfaces",
            f"--interface=drak{vm_id}",
            "--port=0",
            "--no-hosts",
            "--no-resolv",
            "--no-poll",
            "--leasefile-ro",
            f"--pid-file={dnsmasq_pidfile}",
            f"--dhcp-range=10.13.{vm_id}.100,10.13.{vm_id}.200,255.255.255.0,12h",
            f"--dhcp-option=option:dns-server,{dns_server}",
        ]
    )


def stop_dnsmasq(vm_id: int) -> None:
    dnsmasq_pidfile = f"/var/run/dnsmasq-vm{vm_id}.pid"

    if os.path.exists(dnsmasq_pidfile):
        with open(dnsmasq_pidfile, "r") as f:
            dnsmasq_pid = int(f.read().strip())

        try:
            os.kill(dnsmasq_pid, signal.SIGTERM)
            log.info(f"Stopped dnsmasq of vm-{vm_id}")
        except OSError:
            log.info(f"dnsmasq-vm{vm_id} is already stopped")


def interface_exists(iface: str) -> bool:
    proc = subprocess.run(["ip", "link", "show", iface], capture_output=True)
    return proc.returncode == 0


def setup_vm_network(
    vm_id: int, net_enable: bool, out_interface: str, dns_server: str
) -> None:
    setup_iptables_chains()
    bridge_name = f"drak{vm_id}"
    try:
        subprocess.run(
            f"brctl addbr {bridge_name}", shell=True, capture_output=True, check=True
        )
        log.info(f"Created bridge {bridge_name}")
    except subprocess.CalledProcessError as e:
        if b"already exists" in e.stderr:
            log.info(f"Bridge {bridge_name} already exists.")
        else:
            raise Exception(f"Failed to create bridge {bridge_name}.")
    else:
        subprocess.run(
            f"ip addr add 10.13.{vm_id}.1/24 dev {bridge_name}", shell=True, check=True
        )

    subprocess.run(f"ip link set dev {bridge_name} up", shell=True, check=True)
    log.info(f"Bridge {bridge_name} is up")

    # Reset iptables in case dns_server, out_interface or net_enable have changed
    delete_vm_iptables(vm_id)

    add_iptable_rule(
        f"DRAKRUN_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )

    if dns_server == "use-gateway-address":
        add_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    add_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    if net_enable:
        if not interface_exists(out_interface):
            raise ValueError(f"Invalid network interface: {repr(out_interface)}")

        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")

        add_iptable_rule(
            f"DRAKRUN_PRT -t nat -s 10.13.{vm_id}.0/24 -o {out_interface} -j MASQUERADE"
        )
        add_iptable_rule(f"DRAKRUN_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        add_iptable_rule(f"DRAKRUN_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")


def delete_vm_bridge(bridge_name: str) -> None:
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
            log.info(f"Already deleted {bridge_name } bridge")
        else:
            raise Exception(f"Couldn't deactivate {bridge_name } bridge")
    else:
        subprocess.run(f"brctl delbr {bridge_name}", shell=True)
        log.info(f"Deleted {bridge_name} bridge")


def delete_vm_iptables(vm_id) -> None:
    bridge_name = f"drak{vm_id}"
    del_iptable_rule(
        f"DRAKRUN_INP -i {bridge_name} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )
    # Clean dns=use-gateway-address if it exists
    del_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -p udp --dport 53 -j ACCEPT")

    del_iptable_rule(f"DRAKRUN_INP -i {bridge_name} -d 0.0.0.0/0 -j DROP")

    # List net_enable entries
    iptables_rules = list_iptables_rules()
    pattern = rf"-A DRAKRUN_FWD -i {bridge_name} -o (\S+) -j ACCEPT"
    out_interface = None
    for rule in iptables_rules:
        m = re.match(pattern, rule)
        if m:
            out_interface = m.group(1)

    if out_interface is not None:
        # Clean net_enable entries if they exist
        del_iptable_rule(
            f"DRAKRUN_PRT -t nat -s 10.13.{vm_id}.0/24 -o {out_interface} -j MASQUERADE"
        )
        del_iptable_rule(f"DRAKRUN_FWD -i {bridge_name} -o {out_interface} -j ACCEPT")
        del_iptable_rule(f"DRAKRUN_FWD -i {out_interface} -o {bridge_name} -j ACCEPT")


def delete_vm_network(vm_id) -> None:
    bridge_name = f"drak{vm_id}"
    delete_vm_bridge(bridge_name)
    delete_vm_iptables(vm_id)


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


def delete_all_vm_networks() -> None:
    """
    Deletes all iptables rules and bridges.
    """
    flush_iptables_chains()
    delete_iptables_chains()
    for bridge_name in list_vm_bridges():
        delete_vm_bridge(bridge_name)


def delete_legacy_iptables() -> None:
    patterns = [
        r"-A INPUT -i drak\d" r"-A FORWARD -i drak\d",
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
