from collections import defaultdict
from typing import Optional

from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def get_socket_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_socketmon(data: dict) -> Optional[dict]:
        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)

        if data.get("Method") in [
            "UdpSendMessages",
            "TcpCreateAndConnectTcbComplete",
            "TcpCreateAndConnectTcbRateLimitComplete",
        ]:
            return {
                "process": process,
                "method": "connection",
                "Protocol": data["Protocol"],
                "LocalIp": data["LocalIp"],
                "LocalPort": data["LocalPort"],
                "RemoteIp": data["RemoteIp"],
                "RemotePort": data["RemotePort"],
            }
        elif data.get("Method") == "DnsQueryEx":
            return {
                "process": process,
                "method": "dns-query",
                "DnsName": data["DnsName"],
            }
        else:
            return None

    socketmon_log = parse_log(analysis_dir / "socketmon.log", filter_socketmon)
    connections = defaultdict(set)
    dns_queries = defaultdict(set)

    for data in socketmon_log:
        if data["method"] == "connection":
            key = (
                data["Protocol"],
                data["LocalIp"],
                data["LocalPort"],
                data["RemoteIp"],
                data["RemotePort"],
            )
            connections[key].add(data["process"].seqid)
        elif data["method"] == "dns-query":
            dns_queries[data["DnsName"]].add(data["process"].seqid)

    context.update_report(
        {
            "connections": [
                {
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "processes": list(processes),
                }
                for (
                    protocol,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                ), processes in connections.items()
            ],
            "dns_queries": [
                {"domain": domain, "processes": list(processes)}
                for domain, processes in dns_queries.items()
            ],
        }
    )
