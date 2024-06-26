import json
from enum import Enum
from typing import Any, Dict, Optional

from redis import StrictRedis

ANALYSES_LIST = "drakrun:analyses"
ANALYSES_LIST_LENGTH = 100
ANALYSIS_KEY_PREFIX = "drakrun:analysis:"


class AnalysisStatus(Enum):
    PENDING = "pending"
    STARTED = "started"
    FINISHED = "finished"
    CRASHED = "crashed"


def create_analysis_status(
    rs: StrictRedis,
    analysis_id: str,
    status: AnalysisStatus,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    if rs.exists(ANALYSIS_KEY_PREFIX + analysis_id):
        return False
    metadata = metadata or {}
    rs.set(
        ANALYSIS_KEY_PREFIX + analysis_id,
        json.dumps({"status": status.value, "metadata": metadata}),
    )
    pipeline = rs.pipeline(transaction=True)
    pipeline.lpush(ANALYSES_LIST, analysis_id)
    pipeline.lrange(ANALYSES_LIST, ANALYSES_LIST_LENGTH, -1)
    _, dropped_ids = pipeline.execute()
    rs.delete(*(ANALYSIS_KEY_PREFIX + dropped_id for dropped_id in dropped_ids))
    return True


def update_analysis_status(
    rs: StrictRedis,
    analysis_id: str,
    status: AnalysisStatus,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    metadata = metadata or {}
    return rs.set(
        ANALYSIS_KEY_PREFIX + analysis_id,
        json.dumps(
            {
                "status": status.value,
                "metadata": metadata,
            }
        ),
        xx=True,
    )


def create_or_update_analysis_status(
    rs: StrictRedis,
    analysis_id: str,
    status: AnalysisStatus,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    if not create_analysis_status(rs, analysis_id, status, metadata):
        return update_analysis_status(rs, analysis_id, status, metadata)
