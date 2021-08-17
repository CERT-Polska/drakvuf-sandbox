import json


class AnalysisProxy:
    """Abstraction over remote analysis data stored in MinIO"""

    MINIO_BUCKET = "drakrun"

    def __init__(self, minio, analysis_uid, bucket=MINIO_BUCKET):
        self.minio = minio
        self.bucket = bucket
        if analysis_uid is not None:
            self.uid = analysis_uid

    def get_apicalls(self, output_file, pid):
        """Download API calls of this process"""
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/apicall/{pid}.json", output_file.name
        )

    def get_processed(self, output_file, name):
        """Download post-process results"""
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/{name}.json", output_file.name
        )

    def list_logs(self):
        """List DRAKVUF logs"""
        objects = self.minio.list_objects_v2(self.bucket, f"{self.uid}/")
        return [x.object_name for x in objects if x.object_name.endswith(".log")]

    def get_log(self, log_type, output_file, headers=None):
        """Download DRAKVUF log"""
        return self.minio.fget_object(
            self.bucket,
            f"{self.uid}/{log_type}.log",
            output_file.name,
            request_headers=headers,
        )

    def get_log_index(self, log_type, output_file):
        """
        Download log index, useful for quickly accessing n-th
        log line
        """
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/index/{log_type}", output_file.name
        )

    def get_pcap_dump(self, output_file):
        """Download dump.pcap file."""
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/dump.pcap", output_file.name
        )

    def get_wireshark_key_file(self, output_file):
        """
        Download tls session keys in format that is accepted by wireshark.
        """
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/wireshark_key_file.txt", output_file.name
        )

    def get_dumps(self, output_file):
        """Download memory dumps"""
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/dumps.zip", output_file.name
        )

    def get_graph(self, output_file):
        """Download ProcDOT graph"""
        return self.minio.fget_object(
            self.bucket, f"{self.uid}/graph.dot", output_file.name
        )

    def get_metadata(self):
        """Download metadata.json"""
        try:
            response = None
            response = self.minio.get_object(self.bucket, f"{self.uid}/metadata.json")
            return json.load(response)
        finally:
            # release network resources
            if response is not None:
                response.close()
                response.release_conn()

    def enumerate(self):
        """Return iterator over all analyses stored in the bucket"""
        return map(
            lambda obj: AnalysisProxy(self.minio, obj.object_name.strip("/")),
            self.minio.list_objects_v2(self.bucket),
        )
