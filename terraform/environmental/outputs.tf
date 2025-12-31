output "account_id" {
  description = "AWS account ID"
  value       = var.account_id
}

output "account_name" {
  description = "Account name (environment)"
  value       = var.account_name
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "truststore_bucket_arn" {
  description = "S3 bucket ARN for mTLS truststore"
  value       = aws_s3_bucket.mtls_truststore.arn
}

output "truststore_bucket_name" {
  description = "S3 bucket name for mTLS truststore"
  value       = aws_s3_bucket.mtls_truststore.id
}

output "truststore_s3_uri" {
  description = "S3 URI for API Gateway truststore configuration"
  value       = "s3://${aws_s3_bucket.mtls_truststore.id}/truststore.pem"
}