import pytest
from drakrun.networking import (
    setup_vm_network,
    delete_vm_network,
    iptable_rule_exists,
    start_dnsmasq,
    stop_dnsmasq,
    add_iptable_rule,
    del_iptable_rule,
)

from pytest_steps import depends_on, test_steps
from drakrun.draksetup import find_default_interface
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
        if all([argument in rule for argument in arguments_to_search]):
            count += 1

    return count


def iptables_test():
    if not tool_exists('iptables'):
        pytest.skip("iptables does not exist")

    rule = "INPUT -i draktest0 -d 239.255.255.0/24 -j DROP"

    assert not iptable_rule_exists(rule)

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
    assert not iptable_rule_exists(rule)


@depends_on(iptables_test)
def network_setup_test():
    if not tool_exists('brctl'):
        pytest.skip("brctl does not exist")

    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT") is True

    # setting up network again should not run
    setup_vm_network(1, True, find_default_interface(), '8.8.8.8')


@depends_on(network_setup_test)
def dnsmasq_start_test():
    if not tool_exists('dnsmasq'):
        pytest.skip("dnsmasq does not exist")

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


@depends_on(dnsmasq_start_test)
def dnsmasq_stop_test():
    stop_dnsmasq(1)
    assert subprocess.run(['pgrep', '-F', '/var/run/dnsmasq-vm1.pid']).returncode == 1

    # stopping already stopped dnsmasq
    stop_dnsmasq(1)

    # stopping a non started dnsmasq
    stop_dnsmasq(5)


@pytest.mark.skipif(not tool_exists('tcpdump'), reason="tcpdump does not exist")
@depends_on(network_setup_test)
def tcpdump_collector_test():
    if not tool_exists('tcpdump'):
        pytest.skip("tcpdump does not exist")

    pytest.skip("No specific tests required at this stage")


@depends_on(network_setup_test)
def network_delete_test():
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')
    assert not iptable_rule_exists("INPUT -i drak1 -p udp --dport 67:68 --sport 67:68 -j ACCEPT")

    # deleting non existant network should not raise errors but log outputs
    delete_vm_network(1, True, find_default_interface(), '8.8.8.8')


@test_steps(iptables_test, network_setup_test, dnsmasq_start_test, dnsmasq_stop_test, tcpdump_collector_test, network_delete_test)
def test_suite_1(test_step):
    test_step()
