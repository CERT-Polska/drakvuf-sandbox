import logging
import platform

import rq.job
from redis import Redis
from rq import Queue, Worker

from .config import RedisConfigSection, load_config
from .paths import ANALYSES_DIR
from .s3_storage import (
    LocalLockType,
    download_analysis,
    get_s3_client,
    has_analysis_lock,
    remove_expired_local_analyses,
    remove_local_analysis,
    reset_analysis_lock,
    set_analysis_lock,
)

HOSTNAME = platform.node()
S3_DOWNLOAD_QUEUE_NAME = f"drakrun-s3-download-{HOSTNAME}"

logger = logging.getLogger(__name__)


def get_redis_connection(config: RedisConfigSection):
    redis = Redis(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
    )
    return redis


def process_analysis_download(analysis_id: str) -> None:
    s3_config = load_config().s3
    if not s3_config or not s3_config.enabled:
        raise RuntimeError("S3 configuration is missing or disabled.")

    if s3_config.local_storage_limit >= 0:
        remove_expired_local_analyses(ANALYSES_DIR, s3_config.local_storage_limit)

    s3_client = get_s3_client(s3_config)
    s3_bucket = s3_config.s3_bucket
    analysis_path = ANALYSES_DIR / analysis_id

    if not analysis_path.exists() or not has_analysis_lock(
        analysis_path, lock_type=LocalLockType.download_lock
    ):
        raise RuntimeError(
            f"Analysis download for {analysis_id} was not correctly initiated. Hostname collision?"
        )

    try:
        download_analysis(analysis_id, analysis_path, s3_client, s3_bucket)
    except Exception:
        remove_local_analysis(analysis_path, with_lock=True)
        raise
    reset_analysis_lock(analysis_path, lock_type=LocalLockType.download_lock)


def initiate_analysis_download(
    analysis_id: str,
    connection: Redis,
) -> rq.job.Job:
    analysis_path = ANALYSES_DIR / analysis_id
    if analysis_path.exists():
        raise RuntimeError(f"Analysis {analysis_id} already exists.")
    analysis_path.mkdir()
    set_analysis_lock(analysis_path, lock_type=LocalLockType.download_lock)
    queue = Queue(name=S3_DOWNLOAD_QUEUE_NAME, connection=connection)
    return queue.enqueue(
        process_analysis_download,
        analysis_id,
        job_timeout=600,
    )


def s3_download_worker_main():
    config = load_config()
    s3_config = config.s3
    if not s3_config or not s3_config.enabled:
        raise RuntimeError("S3 configuration is missing or disabled.")
    worker = Worker(
        queues=[S3_DOWNLOAD_QUEUE_NAME],
        name=f"drakrun-s3-download-worker-{HOSTNAME}",
        connection=get_redis_connection(config.redis),
    )
    worker.work()
