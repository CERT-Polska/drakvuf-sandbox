import json
import pathlib

from redis import StrictRedis

from drakrun.analyzer.worker import enqueue_analysis_download, get_s3_client
from drakrun.lib.config import DrakrunConfig
from drakrun.lib.paths import ANALYSES_DIR
from drakrun.lib.s3_archive import LocalLockType, has_analysis_lock, is_analysis_on_s3


def check_path(path: pathlib.Path, base: pathlib.Path) -> pathlib.Path:
    # Throws ValueError if not relative
    path.resolve().relative_to(base.resolve())
    return path


class AnalysisStorage:
    """Abstraction over remote analysis data stored in MinIO"""

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
        return self.analysis_dir / "dumps.zip"

    def get_graph(self):
        """Download ProcDOT graph"""
        return self.analysis_dir / "graph.dot"

    def get_metadata(self):
        """Download metadata.json"""
        path = self.analysis_dir / "metadata.json"
        if not path.exists():
            return None
        return json.loads(path.read_text())


class AnalysisStorageError(RuntimeError):
    pass


class AnalysisNotYetDownloaded(AnalysisStorageError):
    def __init__(self):
        super().__init__("Analysis is archived and not yet downloaded from S3")


class AnalysisNotYetUploaded(AnalysisStorageError):
    def __init__(self):
        super().__init__("Analysis is from another node and not yet uploaded to S3")


class AnalysisNotFound(AnalysisStorageError):
    def __init__(self):
        super().__init__("Analysis doesn't exist")


def get_analysis_data_with_s3(
    uid: str, config: DrakrunConfig, redis_connection: StrictRedis
):
    analysis_dir = ANALYSES_DIR / uid
    s3_client = get_s3_client(config.s3_archive)
    if not analysis_dir.exists():
        if is_analysis_on_s3(uid, s3_client, config.s3_archive.bucket):
            enqueue_analysis_download(uid, redis_connection)
            raise AnalysisNotYetDownloaded()
        else:
            raise AnalysisNotFound()
    else:
        if has_analysis_lock(analysis_dir, LocalLockType.download_lock):
            raise AnalysisNotYetDownloaded()
        return AnalysisStorage(analysis_dir)


def get_analysis_data_without_s3(uid: str):
    analysis_dir = ANALYSES_DIR / uid
    if not analysis_dir.exists():
        raise AnalysisNotFound()
    return AnalysisStorage(analysis_dir)
