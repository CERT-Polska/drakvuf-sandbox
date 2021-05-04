import os
import subprocess
import logging

from typing import Optional
from drakrun.util import get_domid_from_instance_id, safe_kill_proc
import signal
import re

log = logging.getLogger("drakrun")


def iptable_rule_exists(rule):
    try:
        subprocess.check_output(f"iptables -C {rule}", shell=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            # rule doesn't exist
            return False
        else:
            # some other error
            raise RuntimeError(f'Failed to check for iptables rule: {rule}')


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


def find_default_interface():
    routes = subprocess.check_output('ip route show default', shell=True, stderr=subprocess.STDOUT) \
        .decode('ascii').strip().split('\n')

    for route in routes:
        m = re.search(r'dev ([^ ]+)', route.strip())

        if m:
            return m.group(1)

    return None


class VMNetwork():
    def __init__(self, vm_id: int, net_enable: int, out_interface: str, dns_server: str, **kwargs):
        self.vm_id = vm_id
        self.net_enable = net_enable
        self.out_interface = out_interface
        self.dns_server = dns_server
        self.dns_args = {}
        self.tcpdump_args = {}

        self.dns = False
        self.tcpdump = False

        for key, value in kwargs.items():
            # specify a dictionary with arguments to the following functions

            # VMNetwork(... , dns=True, config_dns={background: bool})
            if key == 'dns':
                self.dns = value

            if key == 'config_dns':
                self.dns_args = value

            # VMNetwork(... , tcpdump=True, config_tcpdump={outdir: str})
            if key == 'tcpdump':
                self.tcpdump = value

            elif key == 'config_tcpdump':
                self.tcpdump_args = value

    def start(self):
        self.setup_vm_network()

        if self.dns:
            self.dns_proc = self.start_dnsmasq(**self.dns_args)
        if self.tcpdump:
            self.tcpdump_proc = self.start_tcpdump_collector(**self.tcpdump_args)

    def stop(self):
        if self.dns:
            self.stop_dnsmasq()
        if self.tcpdump:
            safe_kill_proc(self.tcpdump_proc)

        self.delete_vm_network()

    def __del__(self):
        self.stop()

    def start_tcpdump_collector(self, outdir: str) -> subprocess.Popen:
        domid = get_domid_from_instance_id(self.vm_id)

        try:
            subprocess.check_output("tcpdump --version", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to start tcpdump")

        return subprocess.Popen([
            "tcpdump",
            "-i",
            f"vif{domid}.0-emu",
            "-w",
            f"{outdir}/dump.pcap"
        ])

    def start_dnsmasq(self, background=False) -> Optional[subprocess.Popen]:
        try:
            subprocess.check_output("dnsmasq --version", shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to start dnsmasq")

        if self.dns_server == "use-gateway-address":
            self.dns_server = f"10.13.{self.vm_id}.1"

        if background:
            dnsmasq_pidfile = f"/var/run/dnsmasq-vm{self.vm_id}.pid"

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

        return subprocess.Popen([
            "dnsmasq",
            "--no-daemon" if not background else "",
            "--conf-file=/dev/null",
            "--bind-interfaces",
            f"--interface=drak{self.vm_id}",
            "--port=0",
            "--no-hosts",
            "--no-resolv",
            "--no-poll",
            "--leasefile-ro",
            f"--pid-file=/var/run/dnsmasq-vm{self.vm_id}.pid",
            f"--dhcp-range=10.13.{self.vm_id}.100,10.13.{self.vm_id}.200,255.255.255.0,12h",
            f"--dhcp-option=option:dns-server,{self.dns_server}"
        ])

    def stop_dnsmasq(self):
        dnsmasq_pidfile = f"/var/run/dnsmasq-vm{self.vm_id}.pid"

        if os.path.exists(dnsmasq_pidfile):
            with open(dnsmasq_pidfile, "r") as f:
                dnsmasq_pid = int(f.read().strip())

            try:
                os.kill(dnsmasq_pid, signal.SIGTERM)
                log.info(f"Stopped dnsmasq of vm-{self.vm_id}")
            except OSError:
                log.info("dnsmasq-vm{self.vm_id} is already stopped")

    def setup_vm_network(self):
        try:
            subprocess.check_output(f'brctl addbr drak{self.vm_id}', stderr=subprocess.STDOUT, shell=True)
            logging.info(f"Created bridge drak{self.vm_id}")
        except subprocess.CalledProcessError as e:
            if b'already exists' in e.output:
                log.info(f"Bridge drak{self.vm_id} already exists.")
            else:
                logging.debug(e.output)
                raise Exception(f"Failed to create bridge drak{self.vm_id}.")
        else:
            subprocess.run(f'ip addr add 10.13.{self.vm_id}.1/24 dev drak{self.vm_id}', shell=True, check=True)

        subprocess.run(f'ip link set dev drak{self.vm_id} up', shell=True, check=True)
        logging.info(f"Bridge drak{self.vm_id} is up")

        add_iptable_rule(f"INPUT -i drak{self.vm_id} -p udp --dport 67:68 --sport 67:68 -j ACCEPT")

        if self.dns_server == "use-gateway-address":
            add_iptable_rule(f"INPUT -i drak{self.vm_id} -p udp --dport 53 -j ACCEPT")

        add_iptable_rule(f"INPUT -i drak{self.vm_id} -d 0.0.0.0/0 -j DROP")

        if self.net_enable:
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')

            add_iptable_rule(f"POSTROUTING -t nat -s 10.13.{self.vm_id}.0/24 -o {self.out_interface} -j MASQUERADE")
            add_iptable_rule(f"FORWARD -i drak{self.vm_id} -o {self.out_interface} -j ACCEPT")
            add_iptable_rule(f"FORWARD -i {self.out_interface} -o drak{self.vm_id} -j ACCEPT")

    def delete_vm_network(self):
        try:
            subprocess.check_output(f'ip link set dev drak{self.vm_id} down', shell=True, stderr=subprocess.STDOUT)
            logging.info(f"Bridge drak{self.vm_id} is down")
        except subprocess.CalledProcessError as e:
            if b"Cannot find device" in e.output:
                log.info(f"Already deleted drak{self.vm_id} bridge")
            else:
                logging.debug(e.output)
                raise Exception(f"Couldn't deactivate drak{self.vm_id} bridge")
        else:
            subprocess.run(f'brctl delbr drak{self.vm_id}', stderr=subprocess.STDOUT, shell=True)
            logging.info(f"Deleted drak{self.vm_id} bridge")

        del_iptable_rule(f"INPUT -i drak{self.vm_id} -p udp --dport 67:68 --sport 67:68 -j ACCEPT")
        if self.dns_server == "use-gateway-address":
            del_iptable_rule(f"INPUT -i drak{self.vm_id} -p udp --dport 53 -j ACCEPT")

        del_iptable_rule(f"INPUT -i drak{self.vm_id} -d 0.0.0.0/0 -j DROP")

        if self.net_enable:
            del_iptable_rule(f"POSTROUTING -t nat -s 10.13.{self.vm_id}.0/24 -o {self.out_interface} -j MASQUERADE")
            del_iptable_rule(f"FORWARD -i drak{self.vm_id} -o {self.out_interface} -j ACCEPT")
            del_iptable_rule(f"FORWARD -i {self.out_interface} -o drak{self.vm_id} -j ACCEPT")
