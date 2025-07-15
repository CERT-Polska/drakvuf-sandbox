from collections import defaultdict
from typing import Optional

from .parse_utils import parse_apimon_arguments, parse_log, trim_method_name
from .plugin_base import PostprocessContext


def get_http_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_http(data: dict) -> Optional[dict]:
        api_type = None
        if data["Event"] != "api_called":
            return None
        method = trim_method_name(data.get("Method"))
        if method in [
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpGetProxyForUrl",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpSetOption",
            "WinHttpQueryHeaders",
            "WinHttpCrackUrl",
            "WinHttpCreateUrl",
            "WinHttpAddRequestHeaders",
            "WinHttpWebSocketCompleteUpgrade",
            "WinHttpSetCredentials",
        ]:
            api_type = "winhttp"
        elif method in [
            "InternetOpen",
            "InternetOpenUrl",
            "InternetConnect",
            "InternetCreateUrl",
            "InternetSetOption",
            "InternetCrackUrl",
            "HttpOpenRequest",
            "HttpAddRequestHeaders",
            "InternetReadFile",
            "InternetWriteFile",
        ]:
            api_type = "wininet"
        if not api_type:
            return None
        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)
        return {
            "process": process,
            "api_type": api_type,
            "method": method,
            "arguments": parse_apimon_arguments(data.get("Arguments", [])),
            "retval": int(data.get("ReturnValue"), 16),
        }

    handles = defaultdict(dict)
    request_handles = defaultdict(dict)
    cracked_urls = defaultdict(set)
    apimon_log = parse_log(analysis_dir / "apimon.log", filter_http)

    for data in apimon_log:
        if data["method"] == "InternetOpen":
            handle = (data["process"].seqid, data["retval"], "internet_open")
            handles[handle] = {
                "user_agent": data["arguments"][0],
                "proxy": data["arguments"][2],
                "proxy_bypass": data["arguments"][3],
            }
        elif data["method"] == "InternetConnect":
            internet_open_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "internet_open",
            )
            if internet_open_handle not in handles:
                internet_open = {}
            else:
                internet_open = handles[internet_open_handle]
            handle = (data["process"].seqid, data["retval"], "internet_connect")
            handles[handle] = {
                "server_name": data["arguments"][1],
                "server_port": data["arguments"][2],
                "username": data["arguments"][3],
                "password": data["arguments"][4],
                "service": data["arguments"][5],
                "session": internet_open,
            }
        elif data["method"] == "InternetCrackUrl":
            url = data["arguments"][0]
            if type(url) is str:
                cracked_urls[url].add(data["process"].seqid)
        elif data["method"] == "InternetCreateUrl":
            url = data["arguments"][3]
            if type(url) is str:
                cracked_urls[url].add(data["process"].seqid)
        elif data["method"] == "HttpOpenRequest":
            internet_connect_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "internet_connect",
            )
            if internet_connect_handle not in handles:
                internet_connect = {}
            else:
                internet_connect = handles[internet_connect_handle]
            handle = (data["process"].seqid, data["retval"], "http_request")
            request_handles[handle] = handles[handle] = {
                "verb": data["arguments"][1],
                "path": data["arguments"][2],
                "version": data["arguments"][3],
                "referer": data["arguments"][4],
                "flags": data["arguments"][6],
                "connection": internet_connect,
                "extra_headers": [],
            }
        elif data["method"] == "HttpAddRequestHeaders":
            http_request_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "http_request",
            )
            if http_request_handle not in handles:
                continue
            handles[http_request_handle]["extra_headers"].append(data["arguments"][1])
        elif data["method"] == "WinHttpOpen":
            handle = (data["process"].seqid, data["retval"], "winhttp_open")
            handles[handle] = {
                "user_agent": data["arguments"][0],
                "proxy": data["arguments"][2],
                "proxy_bypass": data["arguments"][3],
            }
        elif data["method"] == "WinHttpConnect":
            winhttp_open_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "winhttp_open",
            )
            if winhttp_open_handle not in handles:
                winhttp_open = {}
            else:
                winhttp_open = handles[winhttp_open_handle]
            handle = (data["process"].seqid, data["retval"], "winhttp_connect")
            handles[handle] = {
                "server_name": data["arguments"][1],
                "server_port": data["arguments"][2],
                "session": winhttp_open,
            }
        elif data["method"] == "WinHttpOpenRequest":
            winhttp_connect_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "winhttp_connect",
            )
            if winhttp_connect_handle not in handles:
                winhttp_connect = {}
            else:
                winhttp_connect = handles[winhttp_connect_handle]
            handle = (data["process"].seqid, data["retval"], "winhttp_request")
            request_handles[handle] = handles[handle] = {
                "verb": data["arguments"][1],
                "path": data["arguments"][2],
                "version": data["arguments"][3],
                "referer": data["arguments"][4],
                "flags": data["arguments"][6],
                "connection": winhttp_connect,
                "extra_headers": [],
            }
        elif data["method"] == "WinHttpAddRequestHeaders":
            winhttp_request_handle = (
                data["process"].seqid,
                data["arguments"][0],
                "winhttp_request",
            )
            if winhttp_request_handle not in handles:
                continue
            handles[winhttp_request_handle]["extra_headers"].append(
                data["arguments"][1]
            )

    requests = []
    for handle, request in request_handles.items():
        request_data = {k: v for k, v in request.items() if k != "connection" and v}
        connection = request["connection"]
        session = connection.get("session", {})
        request_data.update(
            {k: v for k, v in connection.items() if k != "session" and v}
        )
        request_data.update({k: v for k, v in session.items() if v})
        request_data["process"] = handle[0]
        requests.append(request_data)

    context.update_report(
        {
            "http_requests": requests,
            "cracked_urls": [
                {"url": url, "processes": list(processes)}
                for url, processes in cracked_urls.items()
            ],
        }
    )
