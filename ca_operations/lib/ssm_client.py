"""SSM client for reading CA certificates from AWS Parameter Store."""

import boto3
from botocore.exceptions import ClientError


class SSMClient:
    """SSM client for reading CA certificates (writes handled by Terraform)."""

    def __init__(self, region: str = "eu-west-2") -> None:
        """Initialize SSM client.

        Args:
            region: AWS region for SSM client
        """
        self.client = boto3.client("ssm", region_name=region)

    def get_intermediate_ca(
        self, project_name: str, account: str
    ) -> tuple[bytes, bytes]:
        """Fetch intermediate CA key and certificate from SSM.

        Args:
            project_name: Project name prefix (e.g., 'apigw-mtls')
            account: Account/environment name (e.g., 'sandbox')

        Returns:
            Tuple of (private_key_pem, certificate_pem) as bytes

        Raises:
            ValueError: If parameters not found or invalid
        """
        key_path = f"/{project_name}/{account}/ca/intermediate/private-key"
        cert_path = f"/{project_name}/{account}/ca/intermediate/certificate"

        try:
            key_response = self.client.get_parameter(
                Name=key_path, WithDecryption=True
            )
            cert_response = self.client.get_parameter(
                Name=cert_path, WithDecryption=False
            )

            key_pem = key_response["Parameter"]["Value"].encode("utf-8")
            cert_pem = cert_response["Parameter"]["Value"].encode("utf-8")

            return key_pem, cert_pem

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ParameterNotFound":
                raise ValueError(
                    f"Intermediate CA not found in SSM. "
                    f"Paths checked: {key_path}, {cert_path}"
                ) from e
            raise

    def client_exists(self, project_name: str, account: str, client_id: str) -> bool:
        """Check if client certificate already provisioned in SSM.

        Args:
            project_name: Project name prefix
            account: Account/environment name
            client_id: Client identifier

        Returns:
            True if client certificate exists, False otherwise
        """
        cert_path = f"/{project_name}/{account}/clients/{client_id}/certificate"

        try:
            self.client.get_parameter(Name=cert_path, WithDecryption=False)
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "ParameterNotFound":
                return False
            raise
