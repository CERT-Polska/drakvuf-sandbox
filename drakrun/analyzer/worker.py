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

    ANALYSES_DIR.mkdir(exist_ok=True)

    vm_id = _WORKER_VM_ID
    output_dir = ANALYSES_DIR / job.id

    def substatus_callback(
        substatus: AnalysisSubstatus, updated_options: Optional[AnalysisOptions] = None
    ):
        job.meta["substatus"] = substatus
        if updated_options is not None:
            job.meta["options"] = updated_options
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
    return queue.enqueue(worker_analyze, options, meta={"options": options})
