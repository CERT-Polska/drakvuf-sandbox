#!/usr/bin/env python

from karton.core import Config
from karton.system import SystemService
from drakcore.util import get_config, redis_working, get_minio_helper


def main():
    config = get_config()

    service = SystemService(config)

    system_disable = config.config["drakmon"].get("system_disable", "1")

    if system_disable == "1":
        service.log.info("Refusing to start, system_disable=1 is set in config.ini")
        return

    bucket_name = config.minio_config["bucket"]

    service.log.info("Verifying bucket existence...")
    minio = get_minio_helper(config)
    if not minio.bucket_exists(bucket_name):
        service.log.info("Bucket %s is missing. Creating new one...", bucket_name)
        minio.make_bucket(bucket_name)

    service.loop()


if __name__ == "__main__":
    main()
