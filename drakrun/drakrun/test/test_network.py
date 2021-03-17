import pytest
from drakrun.networking import (
    setup_vm_network,
    delete_vm_network,
    iptable_rule_exists,
    start_dnsmasq,
    stop_dnsmasq,
    add_iptable_rule,
    del_iptable_rule,
    start_tcpdump_collector
)

from drakrun.draksetup import find_default_interface
import os
import subprocess
from pathlib import Path
from drakrun.test.common_utils import tool_exists


def count_num_rules(rule_to_check):
    rules = subprocess.run(['iptables', '-S'], capture_output=True).stdout.decode().split('\n')

    # Arguments used in iptables -A are being split
    # as the arguments order doesn't remain the same in iptables -S and iptables -A
    arguments_to_search = rule_to_check.split('-')
    count = 0
    for rule in rules:

        # Assume all the terms are present
        flag = True

        for argument in arguments_to_search:
            if argument not in rule:
                # if one of the argument is not found, the rule must be different
                flag = False

        # if all arguments there, add it in similar rule
        if flag is True:
            count += 1

    return count


@pytest.mark.skipif(not tool_exists('iptables'), reason="iptables does not exist")
def test_iptables():
    rule = "INPUT -i draktest0 -d 239.255.255.0/24 -j DROP"

    assert iptable_rule_exists(rule) is False

    add_iptable_rule(rule)
    assert iptable_rule_exists(rule) is True

    # adding second time also
    add_iptable_rule(rule)

    # it should not be added second time
    assert count_num_rules(rule) == 1

    # if somehow added due to unknown issues

    # this call is adding the rule again to test if del_iptable_rule does delete multiple similar rules or not
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
    dnsmasq_pids = Path('/var/run/').glob("dnsmasq-vm*.pid")
    for pid in dnsmasq_pids:
        subprocess.run(['pkill', '-F', str(pid)])

    start_dnsmasq(1, '8.8.8.8', True)
    cmd = subprocess.run(['pgrep', '-F', '/var/run/dnsmasq-vm1.pid'])
    assert cmd.returncode == 0

    # starting already stopped dnsmasq
    # what should be the expected behavior?
    start_dnsmasq(1, '8.8.8.8', True)


@pytest.mark.skipif(not tool_exists('dnsmasq'), reason="dnsmasq does not exist")
@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_dnsmasq_stop():
    stop_dnsmasq(1)
    assert subprocess.run(['pgrep', '-F', '/var/run/dnsmasq-vm1.pid']).returncode == 1

    # stopping already stopped dnsmasq
    stop_dnsmasq(1)

    # stopping a non started dnsmasq
    stop_dnsmasq(5)


@pytest.mark.skipif(not tool_exists('tcpdump'), reason="tcpdump does not exist")
def test_tcpdump_collector():
    pytest.skip("No specific tests required at this stage")


@pytest.mark.skipif(not tool_exists('brctl'), reason="brctl does not exist")
def test_network_delete():
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is False

    # deleting non existant network should not raise errors but log outputs
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
