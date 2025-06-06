import logging
import pathlib
from typing import BinaryIO, Optional

import boto3
from botocore.client import BaseClient
from botocore.credentials import (
    ContainerProvider,
    InstanceMetadataFetcher,
    InstanceMetadataProvider,
)
from botocore.exceptions import ClientError
from botocore.session import get_session

from .config import S3StorageConfigSection

logger = logging.getLogger(__name__)


def is_s3_enabled(s3_config: Optional[S3StorageConfigSection]) -> bool:
    return bool(s3_config is not None and s3_config.enabled)


def get_s3_client(s3_config: S3StorageConfigSection) -> BaseClient:
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


def upload_sample_to_s3(
    analysis_id: str, sample_stream: BinaryIO, s3_client: BaseClient, s3_bucket: str
) -> None:
    sample_s3_name = "/".join([*analysis_id[0:4], analysis_id + ".sample"])
    logger.info("Uploading sample for analysis %s...", analysis_id)
    s3_client.put_object(Bucket=s3_bucket, Key=sample_s3_name, Body=sample_stream)
    logger.info("Sample for %s uploaded successfully", analysis_id)


def download_sample_from_s3(
    analysis_id: str, target_path: pathlib.Path, s3_client: BaseClient, s3_bucket: str
) -> None:
    sample_s3_name = "/".join([*analysis_id[0:4], analysis_id + ".sample"])
    logger.info("Downloading sample for analysis %s...", analysis_id)
    s3_client.download_file(Bucket=s3_bucket, Key=sample_s3_name, Filename=target_path)
    logger.info("Sample for %s downloaded successfully", analysis_id)


def upload_analysis(
    analysis_id: str, analysis_path: pathlib.Path, s3_client: BaseClient, s3_bucket: str
) -> None:
    s3_name_prefix = "/".join([*analysis_id[0:4], analysis_id])

    logger.info("Uploading analysis %s...", analysis_id)
    for analysis_file in analysis_path.rglob("*"):
        relative_path = analysis_file.relative_to(analysis_path).as_posix()
        s3_name = s3_name_prefix + "/" + relative_path
        logger.info(f"Uploading {relative_path}...", analysis_id)
        with analysis_file.open("rb") as f:
            s3_client.put_object(Bucket=s3_bucket, Key=s3_name, Body=f)
    logger.info("Analysis %s uploaded successfully", analysis_id)


def download_analysis(
    analysis_id: str, target_path: pathlib.Path, s3_client: BaseClient, s3_bucket: str
) -> None:
    s3_name_prefix = "/".join([*analysis_id[0:4], analysis_id])
    logger.info("Downloading analysis %s...", analysis_id)
    objects = s3_client.list_objects_v2(Bucket=s3_bucket, Prefix=s3_name_prefix + "/")
    for object in objects:
        object_key = object["Key"]
        relative_path = object_key[len(s3_name_prefix + "/") :]
        logger.info(f"Downloading {relative_path}...", analysis_id)
        target_file_path = target_path / relative_path
        s3_client.download_file(
            Bucket=s3_bucket, Key=object_key, Filename=target_file_path
        )
    logger.info("Analysis %s downloaded successfully", analysis_id)


def is_analysis_on_s3(analysis_id: str, s3_client: BaseClient, s3_bucket: str) -> bool:
    s3_name = "/".join([*analysis_id[:4], analysis_id, "metadata.json"])

    try:
        s3_client.head_object(Bucket=s3_bucket, Key=s3_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return False
        else:
            raise
