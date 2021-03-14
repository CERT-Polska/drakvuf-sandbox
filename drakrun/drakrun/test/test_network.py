import pytest

# flake8 flags if using
# from drakrun.networking import *

from drakrun.networking import (
    setup_vm_network,
    delete_vm_network,
    iptable_rule_exists,
    start_dnsmasq,
    stop_dnsmasq,
    add_iptable_rule,
    del_iptable_rule,
)

from drakrun.draksetup import find_default_interface
import os
import subprocess
from common_utils import tool_exists


def count_num_rules(rule):
    lines = subprocess.run(['iptables', '-S'], capture_output=True).stdout.decode().split('\n')
    terms_to_search = rule.split('-')
    count = 0
    for i in lines:

        flag = True
        for term in terms_to_search:
            if term not in i:
                flag = False

        if flag is True:
            count += 1

    return count


@pytest.mark.skipif(not tool_exists('iptables'), reason="iptables does not exist")
def test_iptables():
    rule = "INPUT -i draktest0 -d 239.255.255.0/24 -j DROP"

    # deleting stale such rule if any
    del_iptable_rule(rule)
    assert iptable_rule_exists(rule) is False

    add_iptable_rule(rule)
    assert iptable_rule_exists(rule) is True

    # adding second time also
    add_iptable_rule(rule)

    # it should not be added second time
    assert count_num_rules(rule) == 1

    # if somehow added
    subprocess.check_output(f"iptables -A {rule}", shell=True)

    # the clear should delete all the same rules
    del_iptable_rule(rule)
    assert iptable_rule_exists(rule) is False


@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_network_setup():
    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is True

    # setting up network again should not run
    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')


@pytest.mark.skipif(not tool_exists('dnsmasq'), reason="dnsmasq does not exist")
@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_dnsmasq_start():
    # stale dnsmasq will create issues with the stopping test
    subprocess.run(['pkill', 'dnsmasq'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

    start_dnsmasq(1, '8.8.8.8', True)
    assert subprocess.run(['pgrep', 'dnsmasq']).returncode == 0

    # starting already stopped dnsmasq
    # what should be the expected behavior?
    start_dnsmasq(1, '8.8.8.8', True)


@pytest.mark.skipif(not tool_exists('dnsmasq'), reason="dnsmasq does not exist")
@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_dnsmasq_stop():
    stop_dnsmasq(1)
    assert subprocess.run(['pgrep', 'dnsmasq']).returncode == 1

    # stopping already stopped dnsmasq
    stop_dnsmasq(1)

    # stopping a non started dnsmasq
    stop_dnsmasq(5)


@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_network_delete():
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is False

    # deleting non existant network should not raise errors but log outputs
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
