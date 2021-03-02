from drakrun.networking import (
    setup_vm_network,
    delete_vm_network,
    iptable_rule_exists,
    start_dnsmasq,
    stop_dnsmasq
)

from drakrun.draksetup import find_default_interface
import os
import subprocess

setup_vm_network(1, True, find_default_interface(), '8.8.8.8')
start_dnsmasq(1, '8.8.8.8', True)
stop_dnsmasq(1)
delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is False
try:
    subprocess.check_output('pgrep dnsmasq', shell=True)
except subprocess.CalledProcessError as e:
    assert e.returncode == 1

print("Passed")
