import click

from drakrun.lib.networking import delete_all_vm_networks, delete_legacy_iptables


@click.command(help="Cleanup changes in iptables and bridges")
def cleanup_network():
    delete_legacy_iptables()
    delete_all_vm_networks()
