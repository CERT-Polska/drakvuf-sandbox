import boto3

from ._config import config


def get_s3_client():
    boto3.client(
        "s3",
        endpoint_url=config["s3"]["address"],
        aws_access_key_id=config["s3"]["access_key"],
        aws_secret_access_key=config["s3"]["secret_key"],
    )
