# Cognito User Pool for machine-to-machine (M2M) authentication
# Used with client_credentials flow for token lambda

resource "aws_cognito_user_pool" "mtls_api" {
  name = "mtls-api-${var.account_name}"

  # No self-signup - this is M2M only
  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  # Minimal password policy (not used for client_credentials)
  password_policy {
    minimum_length    = 8
    require_lowercase = false
    require_uppercase = false
    require_numbers   = false
    require_symbols   = false
  }

  tags = {
    Name        = "mtls-api-${var.account_name}"
    Project     = var.project_name
    Environment = var.account_name
  }
}

# Domain for Cognito hosted endpoints (token endpoint)
resource "aws_cognito_user_pool_domain" "mtls_api" {
  domain       = "mtls-api-${var.account_name}-${var.account_id}"
  user_pool_id = aws_cognito_user_pool.mtls_api.id
}

# Resource server defines API scopes
resource "aws_cognito_resource_server" "mtls_api" {
  identifier   = "mtls-api"
  name         = "mTLS API"
  user_pool_id = aws_cognito_user_pool.mtls_api.id

  scope {
    scope_name        = "access"
    scope_description = "Full API access for mTLS authenticated clients"
  }
}

# App client for client_credentials grant
resource "aws_cognito_user_pool_client" "mtls_api" {
  name         = "mtls-api-client"
  user_pool_id = aws_cognito_user_pool.mtls_api.id

  generate_secret = true

  # M2M flow only
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["mtls-api/access"]

  # Token validity
  access_token_validity = 1 # hours

  token_validity_units {
    access_token = "hours"
  }

  explicit_auth_flows = []

  depends_on = [aws_cognito_resource_server.mtls_api]
}
