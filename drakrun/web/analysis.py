import json
import pathlib

from drakrun.analyzer.postprocessing.process_tree import tree_from_dict
from drakrun.lib.paths import ANALYSES_DIR, DUMPS_ZIP


def check_path(path: pathlib.Path, base: pathlib.Path) -> pathlib.Path:
    # Throws ValueError if not relative
    path.resolve().relative_to(base.resolve())
    return path


class AnalysisStorage:
    """Abstraction over remote analysis data stored in MinIO"""

    MINIO_BUCKET = "drakrun"

    def __init__(self, analysis_dir: pathlib.Path):
        self.analysis_dir = check_path(analysis_dir, ANALYSES_DIR)

    def _check_path(self, path):
        return check_path(path, self.analysis_dir)

    def get_processed(self, name):
        """Download post-process results"""
        return self._check_path(self.analysis_dir / f"{name}.json")

    def list_logs(self):
        """List DRAKVUF logs"""
        return [path.name for path in self.analysis_dir.glob("*.log")]

    def get_log(self, log_type):
        """Download DRAKVUF log"""
        return self._check_path(self.analysis_dir / f"{log_type}.log")

    def get_log_index(self, log_type):
        """
        Download log index, useful for quickly accessing n-th
        log line
        """
        return self._check_path(self.analysis_dir / "index" / log_type)

    def get_pcap_dump(self):
        """Download dump.pcap file."""
        return self.analysis_dir / "dump.pcap"

    def get_wireshark_key_file(self):
        """
        Download tls session keys in format that is accepted by wireshark.
        """
        return self.analysis_dir / "wireshark_key_file.txt"

    def get_dumps(self):
        """Download memory dumps"""
        return self.analysis_dir / DUMPS_ZIP

    def get_graph(self):
        """Download ProcDOT graph"""
        return self.analysis_dir / "graph.dot"

    def get_screenshot(self, which):
        return self.analysis_dir / "screenshots" / f"screenshot_{which}.png"

    def get_metadata(self):
        """Download metadata.json"""
        path = self.analysis_dir / "metadata.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())

    def get_process_info(self, which):
        path = self.analysis_dir / "process_tree.json"
        if not path.exists():
            return None
        process_tree = tree_from_dict(json.loads(path.read_text()))
        process = process_tree.processes[which]
        log_index = self.analysis_dir / "index"
        if log_index.exists():
            logs = {}
            for index_path in log_index.glob(f"*.{which}.json"):
                log_name = index_path.name.split(".")[0]
                logs[log_name] = json.loads(index_path.read_text())["values"]
        else:
            logs = {}
        return {
            "process": process.as_dict(),
            "logs": logs,
        }


def get_analysis_data(uid: str):
    analysis_dir = ANALYSES_DIR / uid
    if not analysis_dir.exists():
        raise RuntimeError(f"Analysis directory {analysis_dir} does not exist")
    return AnalysisStorage(analysis_dir)
