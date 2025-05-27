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


def analysis_job_to_status_dict(job: Job):
    job_status = job.get_status()
    job_meta = job.get_meta()
    time_finished = job.meta["time_finished"] if "time_finished" in job.meta else None
    if time_finished is None:
        time_finished = job.ended_at.isoformat() if job.ended_at is not None else None
    return {
        "id": job.id,
        "status": job_status.value if job_status is not None else None,
        **job_meta,
        "time_started": (
            job.started_at.isoformat() if job.started_at is not None else None
        ),
        "time_finished": time_finished,
    }


def worker_analyze(options: AnalysisOptions):
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

    file_handler = logging.FileHandler(output_dir / "drakrun.log")
    formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    drakrun_logger = logging.getLogger("drakrun")
    drakrun_logger.addHandler(file_handler)

    metadata_file = output_dir / "metadata.json"
    metadata_file.write_text(
        json.dumps(
            {
                "time_started": job.started_at.isoformat(),
                **job.meta,
            }
        )
    )

    job_success = True
    try:
        extra_metadata = analyze_file(
            vm_id, output_dir, options, substatus_callback=substatus_callback
        )
        job.meta.update(extra_metadata)
        job.save_meta()
    except BaseException:
        job_success = False
        logger.exception("Failed to analyze sample")
        raise
    finally:
        drakrun_logger.removeHandler(file_handler)
        file_handler.close()
        job.meta["time_finished"] = datetime.datetime.now(datetime.UTC).isoformat()
        metadata_file.write_text(
            json.dumps(
                {
                    **analysis_job_to_status_dict(job),
                    "status": "finished" if job_success else "failed",
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
