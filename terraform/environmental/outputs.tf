# Cognito outputs for token lambda configuration

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.mtls_api.id
}

output "cognito_user_pool_endpoint" {
  description = "Cognito User Pool endpoint URL"
  value       = aws_cognito_user_pool.mtls_api.endpoint
}

output "cognito_domain" {
  description = "Cognito domain for token endpoint"
  value       = aws_cognito_user_pool_domain.mtls_api.domain
}

output "cognito_client_id" {
  description = "Cognito App Client ID"
  value       = aws_cognito_user_pool_client.mtls_api.id
}

output "cognito_client_secret" {
  description = "Cognito App Client Secret"
  value       = aws_cognito_user_pool_client.mtls_api.client_secret
  sensitive   = true
}
