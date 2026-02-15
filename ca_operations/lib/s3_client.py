"""S3 client for truststore operations."""

import boto3


class S3Client:
    """S3 client for truststore operations."""

    def __init__(self, region: str = "eu-west-2") -> None:
        """Initialize S3 client.

        Args:
            region: AWS region for S3 client
        """
        self.client = boto3.client("s3", region_name=region)

    def upload_truststore(
        self, bucket_name: str, truststore_content: bytes, key: str = "truststore.pem"
    ) -> str:
        """Upload truststore to S3 bucket.

        Args:
            bucket_name: S3 bucket name
            truststore_content: PEM bundle content
            key: S3 object key (default: truststore.pem)

        Returns:
            S3 version ID if versioning enabled, empty string otherwise

        Raises:
            ClientError: If upload fails
        """
        response = self.client.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=truststore_content,
            ContentType="application/x-pem-file",
        )
        return response.get("VersionId", "")

    def get_truststore(self, bucket_name: str, key: str = "truststore.pem") -> bytes:
        """Download truststore from S3 bucket.

        Args:
            bucket_name: S3 bucket name
            key: S3 object key (default: truststore.pem)

        Returns:
            Truststore content as bytes

        Raises:
            ClientError: If download fails
        """
        response = self.client.get_object(Bucket=bucket_name, Key=key)
        return response["Body"].read()
