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
from rq.exceptions import NoSuchJobError
from rq.job import Job

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def _try_store_upload_token(
    context: PostprocessContext, analysis_id: str, token: str
) -> bool:
    """Store upload token in Redis job metadata."""
    from drakrun.analyzer.worker import get_redis_connection

    redis = get_redis_connection(context.config.redis)

    try:
        job = Job.fetch(analysis_id, connection=redis)
    except NoSuchJobError:
        logger.warning(f"Job {analysis_id} not found, cannot store upload token")
        return False

    job.meta["token"] = token
    job.save_meta()
    logger.info(f"Stored Karton upload token for analysis {analysis_id}")
    return True


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
        and context.options.sample_path
        and context.options.sample_path.exists()
    ):
        sample_resource = Resource(
            name="sample",
            path=context.options.sample_path.as_posix(),
        )
        logger.info(f"Created sample resource from {context.options.sample_path}")
        return sample_resource


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

    # Generate token for API uploads from Karton reporter
    token = secrets.token_urlsafe(32)
    if _try_store_upload_token(context, job_id, token):
        sample = _try_get_sample_resource(context)
        if (
            not sample
        ):  # sample should always be available unless running drakrun postprocess
            logger.info("Sample not found, skipping karton postprocessing")
            return

        dumps_metadata = metadata.get("dumps_metadata", {})
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

        task = Task(
            headers=headers, payload=payload, payload_persistent=payload_persistent
        )
        producer.log.info(f"Sending analysis for Karton processing (uid={task.uid})")
        producer.send_task(task)

        # Poll for completion using KartonState
        state = KartonState(producer.backend)
        start_time = time.time()
        poll_interval = 10.0

        logger.info(
            f"Waiting for Karton analysis to complete (uid={task.uid}, timeout={timeout}s)"
        )
        while time.time() - start_time < timeout:
            time.sleep(poll_interval)
            analysis = state.get_analysis(task.uid)
            if analysis.is_done:
                logger.info(f"Karton analysis complete (uid={task.uid})")
                _update_report(context)
                return

        logger.error(f"Karton analysis timed out after {timeout}s (uid={task.uid})")


def _update_report(context: PostprocessContext):
    analysis_dir = context.analysis_dir
    configs = []
    for file in analysis_dir.iterdir():
        if file.is_file():
            try:
                if file.name == "yara_matches.json":
                    logger.info("Adding yara matches to report")
                    with open(file) as f:
                        matches = json.load(f)
                        context.update_report({"yara_matches": matches})

                if file.name.startswith("config"):
                    logger.info(f"Adding config {file.name} to report")
                    with open(file) as f:
                        config_data = json.load(f)
                        configs.append(config_data)

            except Exception as e:
                logger.warning(f"failed to process {file.name}: {e}")

        context.update_report({"extracted_configs": configs})
