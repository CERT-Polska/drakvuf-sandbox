#!/usr/bin/env python

import urllib3
from minio import Minio
from karton2 import Config
from karton2.services.system import SystemService
from drakcore.util import find_config


def get_minio_helper(config: Config):
    # Default HTTP client configuration waits 120s for the next retry.
    # This causes unnecessary delays during startup, because Minio server returns error 503
    return Minio(
        config.minio_config["address"],
        config.minio_config["access_key"],
        config.minio_config["secret_key"],
        secure=bool(int(config.minio_config.get("secure", True))),
        http_client=urllib3.PoolManager(retries=urllib3.Retry(total=3)),
    )


def main():
    config = Config(find_config())
    service = SystemService(config)

    bucket_name = config.minio_config["bucket"]

    service.log.info("Veryfing bucket existence...")
    minio = get_minio_helper(config)
    if not minio.bucket_exists(bucket_name):
        service.log.info("Bucket %s is missing. Creating new one...", bucket_name)
        minio.make_bucket(bucket_name)

    service.loop()


if __name__ == "__main__":
    main()
