from typing import Optional

from redis import Redis
from rq import Queue, Worker, get_current_job
from rq.job import Job

from drakrun.lib.paths import ANALYSES_DIR

from .analysis_options import AnalysisOptions
from .analyzer import AnalysisSubstatus, analyze_file

ANALYSIS_QUEUE_NAME = "drakrun-analysis"
_WORKER_VM_ID: Optional[int] = None


def get_redis_connection():
    redis = Redis()
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

    analyze_file(vm_id, output_dir, options, substatus_callback=substatus_callback)


def worker_main(vm_id: int):
    global _WORKER_VM_ID
    _WORKER_VM_ID = vm_id
    worker = Worker(
        queues=[ANALYSIS_QUEUE_NAME],
        name=f"drakrun-worker-vm-{vm_id}",
        connection=get_redis_connection(),
    )
    worker.work()


def spawn_analysis(options: AnalysisOptions, connection: Redis) -> Job:
    queue = Queue(name=ANALYSIS_QUEUE_NAME, connection=connection)
    if options.sample_path is None:
        raise RuntimeError("Sample path is required when spawning analysis to worker")
    if options.timeout is None:
        raise RuntimeError("Timeout is required when spawning analysis to worker")
    # Give extra 5 minutes as a timeout for whole analysis process
    # including VM restore, post-restore, drakvuf hard timeout and
    # postprocessing.
    # TODO: job_timeout offset should be configurable.
    return queue.enqueue(
        worker_analyze,
        options,
        meta={"options": options.to_dict(exclude_none=True)},
        job_timeout=options.timeout + 300,
    )
