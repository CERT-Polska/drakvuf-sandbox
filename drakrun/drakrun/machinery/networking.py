import logging
import os
import signal
import subprocess
from typing import Optional

from .vm import get_domid_from_instance_id

log = logging.getLogger("drakrun")


def iptable_rule_exists(rule):
    try:
        subprocess.check_output(
            f"iptables -C {rule}", shell=True, stderr=subprocess.DEVNULL
        )
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            # rule doesn't exist
            return False
        else:
            # some other error
            raise RuntimeError(f"Failed to check for iptables rule: {rule}")


def add_iptable_rule(rule):
    if not iptable_rule_exists(rule):
        subprocess.check_output(f"iptables -A {rule}", shell=True)


def del_iptable_rule(rule):
    # For deleting multiple copies of the same rule
    all_cleared = False

    while not all_cleared:
        if iptable_rule_exists(rule):
            subprocess.check_output(f"iptables -D {rule}", shell=True)
        else:
            all_cleared = True


def start_tcpdump_collector(instance_id: int, outdir: str) -> subprocess.Popen:
    domid = get_domid_from_instance_id(instance_id)

    try:
        subprocess.check_output("tcpdump --version", shell=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start tcpdump")

    return subprocess.Popen(
        ["tcpdump", "-i", f"vif{domid}.0-emu", "-w", f"{outdir}/dump.pcap"]
    )


def start_dnsmasq(
    vm_id: int, dns_server: str, background=False
) -> Optional[subprocess.Popen]:
    try:
        subprocess.check_output("dnsmasq --version", shell=True)
    except subprocess.CalledProcessError:
        raise RuntimeError("Failed to start dnsmasq")

    if dns_server == "use-gateway-address":
        dns_server = f"10.13.{vm_id}.1"

    if background:
        dnsmasq_pidfile = f"/var/run/dnsmasq-vm{vm_id}.pid"

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

    return subprocess.Popen(
        [
            "dnsmasq",
            "--no-daemon" if not background else "",
            "--conf-file=/dev/null",
            "--bind-interfaces",
            f"--interface=drak{vm_id}",
            "--port=0",
            "--no-hosts",
            "--no-resolv",
            "--no-poll",
            "--leasefile-ro",
            f"--pid-file=/var/run/dnsmasq-vm{vm_id}.pid",
            f"--dhcp-range=10.13.{vm_id}.100,10.13.{vm_id}.200,255.255.255.0,12h",
            f"--dhcp-option=option:dns-server,{dns_server}",
        ]
    )


def stop_dnsmasq(vm_id: int):
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


def setup_vm_network(vm_id: int, net_enable: int, out_interface: str, dns_server: str):
    try:
        subprocess.check_output(
            f"brctl addbr drak{vm_id}", stderr=subprocess.STDOUT, shell=True
        )
        logging.info(f"Created bridge drak{vm_id}")
    except subprocess.CalledProcessError as e:
        if b"already exists" in e.output:
            log.info(f"Bridge drak{vm_id} already exists.")
        else:
            logging.debug(e.output)
            raise Exception(f"Failed to create bridge drak{vm_id}.")
    else:
        subprocess.run(
            f"ip addr add 10.13.{vm_id}.1/24 dev drak{vm_id}", shell=True, check=True
        )

    subprocess.run(f"ip link set dev drak{vm_id} up", shell=True, check=True)
    logging.info(f"Bridge drak{vm_id} is up")

    add_iptable_rule(
        f"INPUT -i drak{vm_id} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )

    if dns_server == "use-gateway-address":
        add_iptable_rule(f"INPUT -i drak{vm_id} -p udp --dport 53 -j ACCEPT")

    add_iptable_rule(f"INPUT -i drak{vm_id} -d 0.0.0.0/0 -j DROP")

    if net_enable:
        if not interface_exists(out_interface):
            raise ValueError(f"Invalid network interface: {repr(out_interface)}")

        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")

        add_iptable_rule(
            f"POSTROUTING -t nat -s 10.13.{vm_id}.0/24 -o {out_interface} -j MASQUERADE"
        )
        add_iptable_rule(f"FORWARD -i drak{vm_id} -o {out_interface} -j ACCEPT")
        add_iptable_rule(f"FORWARD -i {out_interface} -o drak{vm_id} -j ACCEPT")


def delete_vm_network(vm_id, net_enable, out_interface, dns_server):
    try:
        subprocess.check_output(
            f"ip link set dev drak{vm_id} down", shell=True, stderr=subprocess.STDOUT
        )
        logging.info(f"Bridge drak{vm_id} is down")
    except subprocess.CalledProcessError as e:
        if b"Cannot find device" in e.output:
            log.info(f"Already deleted drak{vm_id} bridge")
        else:
            logging.debug(e.output)
            raise Exception(f"Couldn't deactivate drak{vm_id} bridge")
    else:
        subprocess.run(f"brctl delbr drak{vm_id}", stderr=subprocess.STDOUT, shell=True)
        logging.info(f"Deleted drak{vm_id} bridge")

    del_iptable_rule(
        f"INPUT -i drak{vm_id} -p udp --dport 67:68 --sport 67:68 -j ACCEPT"
    )
    if dns_server == "use-gateway-address":
        del_iptable_rule(f"INPUT -i drak{vm_id} -p udp --dport 53 -j ACCEPT")

    del_iptable_rule(f"INPUT -i drak{vm_id} -d 0.0.0.0/0 -j DROP")

    if net_enable:
        del_iptable_rule(
            f"POSTROUTING -t nat -s 10.13.{vm_id}.0/24 -o {out_interface} -j MASQUERADE"
        )
        del_iptable_rule(f"FORWARD -i drak{vm_id} -o {out_interface} -j ACCEPT")
        del_iptable_rule(f"FORWARD -i {out_interface} -o drak{vm_id} -j ACCEPT")
