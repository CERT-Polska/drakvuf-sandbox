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


def tool_exists(tool):
    return subprocess.run(["which", tool]).returncode == 0


@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_network_setup():
    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is True


@pytest.mark.skipif(not tool_exists('dnsmasq'), reason="dnsmasq does not exist")
@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_dnsmasq_start():
    start_dnsmasq(1, '8.8.8.8', True)
    assert subprocess.run(['pgrep', 'dnsmasq']).returncode == 0


@pytest.mark.skipif(not tool_exists('dnsmasq'), reason="dnsmasq does not exist")
@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_dnsmasq_stop():
    stop_dnsmasq(1)
    assert subprocess.run(['pgrep', 'dnsmasq']).returncode == 1


@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_network_delete():
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is False
