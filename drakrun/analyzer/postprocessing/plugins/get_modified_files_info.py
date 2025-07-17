import pathlib
from collections import defaultdict
from typing import Optional

from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def get_modified_files_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_modified_files(data: dict) -> Optional[dict]:
        if data.get("Method") == "NtSetInformationFile":
            if not data.get("Operation") == "FileDispositionInformation":
                return None
            method = "delete"
        elif data.get("Method") in ["NtCreateFile", "NtOpenFile"]:
            desired_access = data.get("DesiredAccess").split(" | ")
            if not any(
                access
                in ["GENERIC_WRITE", "FILE_WRITE_DATA", "FILE_APPEND_DATA", "DELETE"]
                for access in desired_access
            ):
                return None
            filename = data.get("FileName").lower()
            if not filename.startswith("\\??\\"):
                return None
            path = pathlib.PureWindowsPath(filename[len("\\??\\") :])
            if not path.drive:
                return None
            method = "open"
        elif data.get("Method") == "NtWriteFile":
            method = "write"
        else:
            return None

        event_uid = int(data["EventUID"], 16)
        pid = data["PID"]
        process = process_tree.get_process_for_evtid(pid, event_uid)

        return {
            "process": process,
            "handle": data["FileHandle"],
            "file_name": data["FileName"],
            "method": method,
        }

    modified_files_log = parse_log(
        analysis_dir / "filetracer.log", filter_modified_files
    )

    opened_files = {}
    modified_files = defaultdict(set)
    deleted_files = defaultdict(set)

    for data in modified_files_log:
        seqid = data["process"].seqid
        key = (seqid, data["handle"])
        if data["method"] == "open":
            opened_files[key] = data["file_name"]
        elif key in opened_files:
            filename = opened_files[key]
            if filename.lower().startswith("\\??\\c:\\windows\\prefetch"):
                continue
            if filename.startswith("\\??\\"):
                filename = filename[len("\\??\\") :]
            if data["method"] == "delete":
                deleted_files[filename].add(seqid)
            elif data["method"] == "write":
                modified_files[filename].add(seqid)

    context.update_report(
        {
            "modified_files": [
                {
                    "filename": filename,
                    "processes": sorted(list(modified_files[filename])),
                }
                for filename in sorted(modified_files.keys())
            ],
            "deleted_files": [
                {
                    "filename": filename,
                    "processes": sorted(list(deleted_files[filename])),
                }
                for filename in sorted(deleted_files.keys())
            ],
        }
    )
