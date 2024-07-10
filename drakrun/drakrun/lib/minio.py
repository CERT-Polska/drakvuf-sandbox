"""
Minio utilities. In future versions we plan to move to more generic S3 binding
as we did in Karton v5, but right now we use py-minio directly.
"""

from minio import Minio

from .config import DrakrunConfig


def get_minio_client(config: DrakrunConfig):
    minio_cfg = config.minio
    return Minio(
        endpoint=minio_cfg.address,
        access_key=minio_cfg.access_key,
        secret_key=minio_cfg.secret_key,
        secure=minio_cfg.secure,
    )
