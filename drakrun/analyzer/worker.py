import datetime
import json
import logging
from typing import Optional

from redis import Redis
from rq import Queue, Worker, get_current_job
from rq.job import Job

from drakrun.lib.config import RedisConfigSection, load_config
from drakrun.lib.paths import ANALYSES_DIR

from .analysis_options import AnalysisOptions
from .analyzer import AnalysisSubstatus, analyze_file
from .file_metadata import FileMetadata

ANALYSIS_QUEUE_NAME = "drakrun-analysis"
_WORKER_VM_ID: Optional[int] = None

logger = logging.getLogger(__name__)


def get_redis_connection(config: RedisConfigSection):
    redis = Redis(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
    )
    return redis


def worker_analyze(options: AnalysisOptions):
    global _WORKER_VM_ID
    if _WORKER_VM_ID is None:
        raise RuntimeError("Fatal error: no vm_id assigned in worker")

    job = get_current_job()
    job.meta["vm_id"] = _WORKER_VM_ID
    job.save_meta()

    vm_id = _WORKER_VM_ID
    output_dir = ANALYSES_DIR / job.id
    output_dir.mkdir(parents=True, exist_ok=True)

    def substatus_callback(
        substatus: AnalysisSubstatus, updated_options: Optional[AnalysisOptions] = None
    ):
        job.meta["substatus"] = substatus.value
        if updated_options is not None:
            job.meta["options"] = updated_options.to_dict(exclude_none=True)
        job.save_meta()

    file_handler = logging.FileHandler(ANALYSES_DIR / "drakrun.log")
    drakrun_logger = logging.getLogger("drakrun")
    drakrun_logger.addHandler(file_handler)

    metadata_file = ANALYSES_DIR / "metadata.json"
    metadata_file.write_text(
        json.dumps(
            {
                "started_at": job.started_at.isoformat(),
                **job.meta,
            }
        )
    )

    job_success = True
    try:
        analyze_file(vm_id, output_dir, options, substatus_callback=substatus_callback)
    except BaseException:
        job_success = False
        logger.exception("Failed to analyze sample")
        raise
    finally:
        drakrun_logger.removeHandler(file_handler)
        file_handler.close()
        job.meta["ended_at"] = datetime.datetime.now(datetime.UTC).isoformat()
        job.meta["success"] = job_success
        metadata_file.write_text(
            json.dumps(
                {
                    "started_at": job.started_at.isoformat(),
                    **job.meta,
                }
            )
        )
        job.save_meta()


def worker_main(vm_id: int):
    global _WORKER_VM_ID
    _WORKER_VM_ID = vm_id
    config = load_config()
    worker = Worker(
        queues=[ANALYSIS_QUEUE_NAME],
        name=f"drakrun-worker-vm-{vm_id}",
        connection=get_redis_connection(config.redis),
    )
    worker.work()


def enqueue_analysis(
    job_id: str,
    file_metadata: FileMetadata,
    options: AnalysisOptions,
    connection: Redis,
) -> Job:
    queue = Queue(name=ANALYSIS_QUEUE_NAME, connection=connection)
    if options.sample_path is None:
        raise RuntimeError("Sample path is required when spawning analysis to worker")
    if options.timeout is None:
        raise RuntimeError("Timeout is required when spawning analysis to worker")
    return queue.enqueue(
        worker_analyze,
        options,
        job_id=job_id,
        meta={
            "options": options.to_dict(exclude_none=True),
            "file": file_metadata.to_dict(),
        },
        job_timeout=options.timeout + options.job_timeout_leeway,
        result_ttl=-1,
    )
