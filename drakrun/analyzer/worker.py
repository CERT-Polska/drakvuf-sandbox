import datetime
import json
import logging
import shutil
from typing import List, Optional

from redis import Redis
from rq import Queue, Worker, get_current_job
from rq.exceptions import InvalidJobOperation
from rq.job import Job, JobStatus

from drakrun.lib.config import RedisConfigSection, load_config
from drakrun.lib.paths import ANALYSES_DIR, UPLOADS_DIR

from ..lib.s3_storage import (
    download_sample_from_s3,
    get_s3_client,
    is_s3_enabled,
    upload_analysis,
)
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
        "status": job_status.value if job_status is not None else "unknown",
        **job_meta,
        "time_started": (
            job.started_at.isoformat() if job.started_at is not None else None
        ),
        "time_finished": time_finished,
    }


def worker_analyze(options: AnalysisOptions):
    if _WORKER_VM_ID is None:
        raise RuntimeError("Fatal error: no vm_id assigned in worker")

    config = load_config()
    if is_s3_enabled(config.s3):
        s3_client = get_s3_client(config.s3)
        s3_bucket = config.s3.bucket
    else:
        s3_client = None
        s3_bucket = None

    # Reconstruct options object to include worker-side preset defaults
    options = AnalysisOptions(config, **dict(options))

    if not options.plugins:
        raise RuntimeError("Cannot analyze sample without plugins specified")

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

    if options.sample_path is None:
        if s3_client is None:
            raise RuntimeError("Got sample referenced on S3 but S3 is not enabled")
        # Sample is passed via S3
        UPLOADS_DIR.mkdir(exist_ok=True)
        upload_path = UPLOADS_DIR / f"{job.id}.sample"
        download_sample_from_s3(job.id, upload_path, s3_client, s3_bucket)
        options.sample_path = upload_path

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
        options.sample_path.unlink()
        if s3_client is not None:
            upload_analysis(job.id, output_dir, s3_client, s3_bucket)
            if config.s3.remove_local_after_upload:
                shutil.rmtree(output_dir)


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
    result_ttl: int,
) -> Job:
    queue = Queue(name=ANALYSIS_QUEUE_NAME, connection=connection)
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
        result_ttl=result_ttl,
    )


def get_analyses_list(connection: Redis) -> List[Job]:
    queue = Queue(name=ANALYSIS_QUEUE_NAME, connection=connection)
    jobs = list(queue.get_jobs())
    for job_registry in [
        queue.started_job_registry,
        queue.finished_job_registry,
        queue.failed_job_registry,
    ]:
        job_ids = job_registry.get_job_ids()
        jobs.extend(
            [
                job
                for job in Job.fetch_many(job_ids, connection=connection)
                if job is not None
            ]
        )
    return sorted(jobs, key=lambda job: job.enqueued_at, reverse=True)


def truncate_analysis_list(connection: Redis, limit: int) -> None:
    jobs_to_truncate = get_analyses_list(connection=connection)[limit:]
    for job in jobs_to_truncate:
        try:
            status = job.get_status()
        except InvalidJobOperation:
            # Already deleted?
            continue
        if status in [JobStatus.FINISHED, JobStatus.FAILED]:
            job.delete()
