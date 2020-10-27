import os
import subprocess
import logging

from typing import Optional
from drakrun.util import get_domid_from_instance_id


def add_iptable_rule(rule):
    try:
        subprocess.check_output(f"iptables -C {rule}", shell=True)
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            # rule doesn't exist
            subprocess.check_output(f"iptables -A {rule}", shell=True)
        else:
            # some other error
            raise RuntimeError(f'Failed to check for iptables rule: {rule}')


def start_tcpdump_collector(instance_id: str, outdir: str) -> Optional[subprocess.Popen]:
    domid = get_domid_from_instance_id(instance_id)

    try:
        subprocess.check_output("tcpdump --version", shell=True)
    except subprocess.CalledProcessError:
        logging.warning("Seems like tcpdump is not working/not installed on your system. Pcap will not be recorded.")
        return None

    return subprocess.Popen([
        "tcpdump",
        "-i",
        f"vif{domid}.0-emu",
        "-w",
        f"{outdir}/dump.pcap"
    ])


def start_dnsmasq(vm_id: int, dns_server: str, background=False) -> Optional[subprocess.Popen]:
    try:
        subprocess.check_output("dnsmasq --version", shell=True)
    except subprocess.CalledProcessError:
        logging.warning("Seems like dnsmasq is not working/not installed on your system."
                        "Guest networking may not be fully functional.")
        return None

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
                logging.info("Starting dnsmasq in background")
            else:
                logging.info("Already running dnsmasq in background")
                return

    return subprocess.Popen([
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
        f"--dhcp-option=option:dns-server,{dns_server}"
    ])


def setup_vm_network(vm_id, net_enable, out_interface, dns_server):
    try:
        subprocess.check_output(f'brctl addbr drak{vm_id}', stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        if b'already exists' in e.output:
            logging.info(f"Bridge drak{vm_id} already exists.")
        else:
            logging.exception(f"Failed to create bridge drak{vm_id}.")
    else:
        subprocess.check_output(f'ip addr add 10.13.{vm_id}.1/24 dev drak{vm_id}', shell=True)

    subprocess.check_output(f'ip link set dev drak{vm_id} up', shell=True)
    add_iptable_rule(f"INPUT -i drak{vm_id} -p udp --dport 67:68 --sport 67:68 -j ACCEPT")

    if dns_server == "use-gateway-address":
        add_iptable_rule(f"INPUT -i drak{vm_id} -p udp --dport 53 -j ACCEPT")

    add_iptable_rule(f"INPUT -i drak{vm_id} -d 0.0.0.0/0 -j DROP")

    if net_enable:
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
            f.write('1\n')

        add_iptable_rule(f"POSTROUTING -t nat -s 10.13.{vm_id}.0/24 -o {out_interface} -j MASQUERADE")
        add_iptable_rule(f"FORWARD -i drak{vm_id} -o {out_interface} -j ACCEPT")
        add_iptable_rule(f"FORWARD -i {out_interface} -o drak{vm_id} -j ACCEPT")
