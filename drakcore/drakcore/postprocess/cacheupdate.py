from drakcore.postprocess import postprocess
from drakcore.app import get_analysis_metadata
from karton2 import Task, RemoteResource
from typing import Dict


@postprocess(required=["metadata.json"])
def insert_metadata(task: Task, resources: Dict[str, RemoteResource], minio):
    """
    Why is this required?
    Currently there's no easy way to notify web application about the analysis
    being finished. In order for it to find out, user has to explicitly ask
    an endpoint for metadata of given analysis. Otherwise we're be forced to
    query MinIO every time user requests a list of analyses.
    """
    analysis_uid = task.payload["analysis_uid"]
    # Trigger metadata request, thus pulling it into cache
    get_analysis_metadata(analysis_uid)
