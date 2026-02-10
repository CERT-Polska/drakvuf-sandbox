import json
import logging
import secrets
import time
from typing import Dict

from karton.core.config import Config
from karton.core.inspect import KartonState
from karton.core.karton import Producer
from karton.core.resource import Resource
from karton.core.task import Task
from rq.exceptions import NoSuchJobError
from rq.job import Job

from drakrun.lib.config import load_config

from .plugin_base import PostprocessContext

logger = logging.getLogger(__name__)


def _store_upload_token(analysis_id: str, token: str) -> None:
    """Store upload token in Redis job metadata."""
    from drakrun.analyzer.worker import get_redis_connection

    config = load_config()
    redis = get_redis_connection(config.redis)

    try:
        job = Job.fetch(analysis_id, connection=redis)
    except NoSuchJobError:
        logger.warning(f"Job {analysis_id} not found, cannot store upload token")
        return

    job.meta["karton_upload_token"] = {
        "token": token,
        "status": "pending",
        "created_at": time.time(),
    }
    job.save_meta()
    logger.info(f"Stored Karton upload token for analysis {analysis_id}")


def analyze_in_karton(context: PostprocessContext, timeout: int = 3600) -> None:
    """
    Send analysis results from analysis_dir to Karton for further processing.
    Polls for completion using KartonState.
    """
    analysis_dir = context.analysis_dir
    config = load_config()

    if not config.karton.enabled:
        logger.warning("Karton is not enabled, skipping analysis upload")
        return

    metadata = context.metadata
    dumps_metadata = metadata.get("dumps_metadata", {})

    # Create resources from analysis files
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

    sample_sha256 = metadata.get("sample_sha256")
    if not sample_sha256:
        logger.warning("sample_sha256 not found in metadata")

    # Create sample resource from the sample file
    sample_resource = None
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
    else:
        logger.info("Sample not available")

    # Generate token for API uploads from Karton reporter
    token = secrets.token_urlsafe(32)
    _store_upload_token(analysis_dir.name, token)

    karton_config = Config(config.karton.config_path)
    producer = Producer(karton_config, identity="drakvuf-sandbox")

    headers = {"type": "analysis", "kind": "drakrun"}
    if producer.debug:
        headers = {"type": "analysis-debug", "kind": "drakrun"}

    payload = {
        "sample_sha256": sample_sha256,
        "dumps_metadata": dumps_metadata,
        **analysis_files,
    }
    payload_persistent = {
        "drakrun_token": token,
        "drakrun_analysis_id": analysis_dir.name,
    }

    if sample_resource:
        payload["sample"] = sample_resource

    task = Task(headers=headers, payload=payload, payload_persistent=payload_persistent)
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
        analysis = state.get_analysis(task.uid)
        if analysis.is_done:
            logger.info(f"Karton analysis complete (uid={task.uid})")
            time.sleep(1)
            _update_report(context)
            return

        time.sleep(poll_interval)

    logger.error(f"Karton analysis timed out after {timeout}s (uid={task.uid})")


def _update_report(context: PostprocessContext):
    analysis_dir = context.analysis_dir
    configs = []
    for file in analysis_dir.iterdir():
        if file.is_file():
            try:
                if file.name == "yara_matches.json":
                    with open(file) as f:
                        matches = json.loads(f.read())
                        context.update_report({"yara_matches": matches})

                if file.name.startswith("config"):
                    with open(file) as f:
                        config_data = json.loads(f.read())
                        configs.append(config_data)

            except Exception as e:
                logger.warning(f"failed to process {file.name}: {e}")

        context.update_report({"extracted_configs": configs})
