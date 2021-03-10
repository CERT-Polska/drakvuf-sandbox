import pytest
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


def test_network_setup():
    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')

    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is True


def test_dnsmasq_start():
    start_dnsmasq(1, '8.8.8.8', True)
    try:
        subprocess.check_output('pgrep dnsmasq', shell=True)
    except subprocess.CalledProcessError as e:
        assert e.returncode == 0


def test_dnsmasq_stop():
    stop_dnsmasq(1)
    try:
        subprocess.check_output('pgrep dnsmasq', shell=True)
    except subprocess.CalledProcessError as e:
        assert e.returncode == 1


def test_network_delete():
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is False
