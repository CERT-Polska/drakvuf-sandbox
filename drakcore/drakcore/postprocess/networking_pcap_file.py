from io import BytesIO
from typing import Dict

from karton.core import RemoteResource, Task
from scapy.all import IP, rdpcap

# generate the list for the source ip addresses from the pcap file


def parse_source_IPs(pcapfile):
    # read the packets from the file
    packets = rdpcap(pcapfile)

    # list to hold source IPs
    srcIP = []

    # read each packet and append to the source IPs list
    for pkt in packets:
        if IP in pkt:
            try:
                srcIP.append(pkt[IP].src)
            except Exception:
                pass


# generate the IP addressess the VM is connected to
def parse_dest_IPs(pcapfile):
    # read the packets from the file
    packets = rdpcap(pcapfile)

    # list to hold dest IPs
    destIP = []

    # read each packet and append to the dest IPs list
    for pkt in packets:
        if IP in pkt:
            try:
                destIP.append(pkt[IP].dst)
            except Exception:
                pass


def generate_pcap(task: Task, resources: Dict[str, RemoteResource], minio):
    analysis_uid = task.payload["analysis_uid"]

    with resources["dump.pcap"].download_temporary_file() as dump_pcap:
        dest_IPs = parse_dest_IPs(dump_pcap)
        minio.put_object(
            "drakrun", f"{analysis_uid}/dest_IPs.txt", BytesIO(dest_IPs), len(dest_IPs),
        )
        yield "dest_IPs.txt"
