import enum
import logging
import os
import pathlib
import shutil
import zipfile
from tempfile import NamedTemporaryFile
from typing import Optional

import boto3
from botocore.client import BaseClient
from botocore.credentials import (
    ContainerProvider,
    InstanceMetadataFetcher,
    InstanceMetadataProvider,
)
from botocore.exceptions import ClientError
from botocore.session import get_session

from .config import S3ArchiveConfigSection

logger = logging.getLogger(__name__)


class LocalLockType(enum.Enum):
    upload_lock = ".upload_lock"
    download_lock = ".download_lock"


def get_s3_client(s3_config: S3ArchiveConfigSection) -> BaseClient:
    if s3_config.iam_auth:
        boto_session = get_session()
        iam_providers = [
            ContainerProvider(),
            InstanceMetadataProvider(
                iam_role_fetcher=InstanceMetadataFetcher(timeout=1000, num_attempts=2)
            ),
        ]
        for provider in iam_providers:
            creds = provider.load()
            if creds:
                boto_session._credentials = creds  # type: ignore
                return boto3.Session(botocore_session=boto_session).client(
                    "s3",
                    endpoint_url=s3_config.address,
                )
        else:
            raise RuntimeError("Unable to fetch IAM credentials")
    else:
        return boto3.client(
            "s3",
            endpoint_url=s3_config.address,
            aws_access_key_id=s3_config.access_key,
            aws_secret_access_key=s3_config.secret_key,
        )


def upload_analysis(analysis_path: pathlib.Path, s3_client: BaseClient, s3_bucket: str):
    analysis_id = analysis_path.name
    zip_s3_name = "/".join([*analysis_id[0:4], analysis_id + ".zip"])

    with NamedTemporaryFile() as tempf:
        logger.info("Zipping analysis %s...", analysis_id)
        with zipfile.ZipFile(tempf, "w", zipfile.ZIP_DEFLATED) as zipf:
            for analysis_file in analysis_path.rglob("*"):
                if analysis_file.name in [
                    LocalLockType.upload_lock.value,
                    LocalLockType.download_lock.value,
                ]:
                    continue
                arcname = analysis_file.relative_to(analysis_path).as_posix()
                zipf.write(analysis_file, arcname)
        tempf.seek(0, os.SEEK_SET)
        logger.info("Uploading analysis %s...", analysis_id)
        s3_client.put_object(Bucket=s3_bucket, Key=zip_s3_name, Body=tempf)
        logger.info("Analysis %s uploaded successfully", analysis_id)


def download_analysis(
    analysis_path: pathlib.Path, s3_client: BaseClient, s3_bucket: str
):
    analysis_id = analysis_path.name
    zip_s3_name = "/".join([*analysis_id[:4], analysis_id + ".zip"])
    with NamedTemporaryFile() as tempf:
        logger.info("Downloading analysis %s...", analysis_id)
        s3_client.download_fileobj(Bucket=s3_bucket, Key=zip_s3_name, Fileobj=tempf)
        tempf.seek(0, os.SEEK_SET)
        logger.info("Unzipping analysis %s...", analysis_id)
        with zipfile.ZipFile(tempf, "r") as zipf:
            zipf.extractall(analysis_path)
        logger.info("Analysis %s downloaded successfully", analysis_id)


def set_analysis_lock(analysis_path: pathlib.Path, lock_type: LocalLockType):
    lock_path = analysis_path / lock_type.name
    lock_path.touch()


def reset_analysis_lock(analysis_path: pathlib.Path, lock_type: LocalLockType):
    lock_path = analysis_path / lock_type.name
    lock_path.unlink()


def has_analysis_lock(
    analysis_path: pathlib.Path, lock_type: Optional[LocalLockType] = None
) -> bool:
    upload_lock = analysis_path / LocalLockType.upload_lock.value
    if lock_type is LocalLockType.upload_lock:
        return upload_lock.exists()
    download_lock = analysis_path / LocalLockType.download_lock.value
    if lock_type is LocalLockType.download_lock:
        return download_lock.exists()
    return upload_lock.exists() or download_lock.exists()


def remove_local_analysis(analysis_path: pathlib.Path, with_lock: bool = False):
    if not with_lock and has_analysis_lock(analysis_path):
        raise RuntimeError(
            f"Analysis {analysis_path} is locked for pending upload or download"
        )
    logger.info("Removing %s from local storage", analysis_path.name)
    shutil.rmtree(analysis_path)


def remove_expired_local_analyses(analyses_dir: pathlib.Path, local_storage_limit: int):
    analyses = [
        analysis for analysis in analyses_dir.iterdir() if analysis.is_dir()
    ].sort(key=os.path.getctime)[:local_storage_limit]
    for analysis in analyses:
        if has_analysis_lock(analysis):
            logger.warning(
                "Can't remove %s: it's locked for pending download/upload",
                analysis.name,
            )
            continue
        remove_local_analysis(analysis)


def is_analysis_on_s3(analysis_id: str, s3_client: BaseClient, s3_bucket: str) -> bool:
    zip_s3_name = "/".join([*analysis_id[:4], analysis_id + ".zip"])

    try:
        s3_client.head_object(Bucket=s3_bucket, Key=zip_s3_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "404":
            return False
        else:
            raise
