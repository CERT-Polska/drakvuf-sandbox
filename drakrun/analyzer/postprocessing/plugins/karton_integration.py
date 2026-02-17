import json
import logging
import secrets
import time
from pathlib import Path
from typing import Dict, Optional

from karton.core.config import Config
from karton.core.inspect import KartonState
from karton.core.karton import Producer
from karton.core.resource import Resource
from karton.core.task import Task
from redis import Redis
from rq.exceptions import NoSuchJobError
from rq.job import Job

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def _collect_analysis_files(analysis_dir: Path) -> Dict[str, Resource]:
    """Create resources from analysis files"""
    analysis_files: Dict[str, Resource] = {}
    dumps_path = analysis_dir / "dumps.zip"
    if dumps_path.exists():
        analysis_files["dumps.zip"] = Resource(
            name="dumps.zip", path=dumps_path.as_posix()
        )
    else:
        logger.warning(f"dumps.zip not found in {analysis_dir}")

    pcap_path = analysis_dir / "dump.pcap"
    if pcap_path.exists():
        analysis_files["dump.pcap"] = Resource(
            name="dump.pcap", path=pcap_path.as_posix()
        )
    else:
        logger.warning(f"dump.pcap not found in {analysis_dir}")

    tlsmon_path = analysis_dir / "tlsmon.log"
    if tlsmon_path.exists():
        analysis_files["tlsmon.log"] = Resource(
            name="tlsmon.log", path=tlsmon_path.as_posix()
        )
    return analysis_files


def _try_get_sample_resource(context: PostprocessContext) -> Optional[Resource]:
    if (
        context.options
        and context.options.host_sample_path
        and context.options.host_sample_path.exists()
    ):
        sample_resource = Resource(
            name="sample",
            path=context.options.host_sample_path.as_posix(),
        )
        logger.info(f"Created sample resource from {context.options.host_sample_path}")
        return sample_resource
    return None


def analyze_in_karton(context: PostprocessContext, timeout: int = 3600) -> None:
    """
    Send analysis results from analysis_dir to Karton for further processing.
    Polls for completion using KartonState.
    """

    if not context.config.karton.enabled:
        logger.info("Karton is not enabled, skipping analysis upload")
        return

    karton_config = Config(context.config.karton.config_path)
    producer = Producer(karton_config, identity="drakvuf-sandbox")

    analysis_dir = context.analysis_dir
    job_id = analysis_dir.name
    metadata = context.metadata

    from drakrun.analyzer.worker import get_redis_connection

    redis = get_redis_connection(context.config.redis)
    try:
        job = Job.fetch(job_id, connection=redis)
    except NoSuchJobError:
        logger.error(f"Job {job_id} not found")
        return

    sample = _try_get_sample_resource(context)
    if (
        not sample
    ):  # sample should always be available unless running drakrun postprocess
        logger.info("Sample not found, skipping karton postprocessing")
        return

    # Generate token for API uploads from Karton reporter
    token = secrets.token_urlsafe(32)
    job.meta["token"] = token
    job.save_meta()
    logger.info(f"Stored Karton upload token for analysis {job_id}")

    dumps_metadata = metadata.model_extra.get("dumps_metadata", {})
    analysis_files = _collect_analysis_files(analysis_dir)

    headers = {"type": "analysis", "kind": "drakrun"}
    if producer.debug:
        headers = {"type": "analysis-debug", "kind": "drakrun"}

    payload = {
        "sample": sample,
        "dumps_metadata": dumps_metadata,
        **analysis_files,
    }
    payload_persistent = {
        "drakrun_token": token,
        "drakrun_analysis_id": job_id,
    }

    task = Task(headers=headers, payload=payload, payload_persistent=payload_persistent)
    producer.log.info(f"Sending analysis for Karton processing (uid={task.uid})")
    producer.send_task(task)

    # Poll for completion using KartonState
    state = KartonState(producer.backend)
    start_time = time.time()
    poll_interval = context.config.karton.poll_interval

    logger.info(
        f"Waiting for Karton analysis to complete (uid={task.uid}, timeout={timeout}s)"
    )
    while time.time() - start_time < timeout:
        time.sleep(poll_interval)
        analysis = state.get_analysis(task.uid)
        if analysis.is_done:
            logger.info(f"Karton analysis complete (uid={task.uid})")
            _move_results_to_report(context, redis, job_id)
            return

    logger.error(f"Karton analysis timed out after {timeout}s (uid={task.uid})")


def _move_results_to_report(context: PostprocessContext, redis: Redis, job_id: str) -> None:
    """
    Get karton results from redis (uploaded in api/karton_results_upload)
    and store them in report under karton-analysis-results, then delete from redis
    """
    redis_key = f"karton-results:{job_id}"
    karton_results = redis.hgetall(redis_key)

    if not karton_results:
        logger.warning(f"No karton results found in Redis for key {redis_key}")
        return

    report_data = {}

    for key, data in karton_results.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8")
        if isinstance(data, bytes):
            data = data.decode("utf-8")

        logger.info(f"Adding {key} to report")
        try:
            parsed_data = json.loads(data)
            report_data[key] = parsed_data
        except json.JSONDecodeError:
            report_data[key] = data
        except Exception as e:
            logger.exception(f"failed to process {key}: {e}")

    context.update_report({"karton-analysis-results": report_data})
    redis.delete(redis_key)
    logger.info(f"Deleted karton results from Redis: {redis_key}")
