import pathlib
from collections import defaultdict
from typing import Optional

from .parse_utils import parse_log
from .plugin_base import PostprocessContext


def is_delete_disposition(data: dict) -> bool:
    operation = data.get("Operation")
    if operation == "FileDispositionInformation":
        # DRAKVUF doesn't report the DeleteFile field for this class
        return True
    if operation == "FileDispositionInformationEx":
        # Used by DeleteFile() since Windows 10 RS1. Without
        # FILE_DISPOSITION_DELETE the call clears the delete disposition.
        flags = data.get("Flags") or ""
        return "FILE_DISPOSITION_DELETE" in flags.split(" | ")
    return False


def is_delete_on_close(data: dict) -> bool:
    # DeleteFile() of cmd.exe (and CreateFile() with FILE_FLAG_DELETE_ON_CLOSE)
    # open the file with FILE_DELETE_ON_CLOSE and never call NtSetInformationFile
    options = data.get("CreateOptions") or data.get("OpenOptions") or ""
    if "FILE_DELETE_ON_CLOSE" not in options.split(" | "):
        return False
    status = data.get("Status")
    # NT_SUCCESS(): the file was opened, so it is deleted when the handle is closed
    return status is None or int(status, 16) < 0x80000000


def get_modified_files_info(context: PostprocessContext) -> None:
    analysis_dir = context.analysis_dir
    process_tree = context.process_tree

    def filter_modified_files(data: dict) -> Optional[dict]:
        if data.get("Method") == "NtSetInformationFile":
            if not is_delete_disposition(data):
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
            method = "open_delete_on_close" if is_delete_on_close(data) else "open"
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

    def report_name(filename: str) -> Optional[str]:
        if filename.lower().startswith("\\??\\c:\\windows\\prefetch"):
            return None
        if filename.startswith("\\??\\"):
            filename = filename[len("\\??\\") :]
        return filename

    for data in modified_files_log:
        seqid = data["process"].seqid
        key = (seqid, data["handle"])
        if data["method"] in ["open", "open_delete_on_close"]:
            opened_files[key] = data["file_name"]
            if data["method"] == "open_delete_on_close":
                filename = report_name(data["file_name"])
                if filename is not None:
                    deleted_files[filename].add(seqid)
        elif key in opened_files:
            filename = report_name(opened_files[key])
            if filename is None:
                continue
            if data["method"] == "delete":
                deleted_files[filename].add(seqid)
            elif data["method"] == "write":
                modified_files[filename].add(seqid)

    context.update_report(
        {
            "modified_files": [
                {
                    "filename": filename,
                    "process_seqids": sorted(list(modified_files[filename])),
                }
                for filename in sorted(modified_files.keys())
            ],
            "deleted_files": [
                {
                    "filename": filename,
                    "process_seqids": sorted(list(deleted_files[filename])),
                }
                for filename in sorted(deleted_files.keys())
            ],
        }
    )
