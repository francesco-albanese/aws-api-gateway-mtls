# Lambda function for health endpoint
# Container image deployed via GitHub Actions, referenced by tag
# ECR repository created separately in terraform/ecr stack

variable "health_lambda_image_tag" {
  description = "Image tag for health Lambda (git SHA or 'latest')"
  type        = string
  default     = "latest"
}

data "aws_ecr_repository" "health_lambda" {
  name = "mtls-api-health-lambda"
}

resource "aws_lambda_function" "health" {
  function_name = "mtls-api-health"
  role          = aws_iam_role.lambda_exec.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.health_lambda.repository_url}:${var.health_lambda_image_tag}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 128

  tags = {
    Name = "mtls-api-health"
  }
}

resource "aws_iam_role" "lambda_exec" {
  name = "mtls-api-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = {
    Name = "mtls-api-lambda-exec"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Token lambda needs DynamoDB read access for cert validation
resource "aws_iam_role_policy" "token_dynamodb" {
  name = "mtls-api-token-dynamodb"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem",
        "dynamodb:Query"
      ]
      Resource = aws_dynamodb_table.mtls_clients_metadata.arn
    }]
  })
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/*/*"
}

# API Gateway integration and route
resource "aws_apigatewayv2_integration" "health" {
  api_id                 = aws_apigatewayv2_api.mtls_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.health.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "health" {
  api_id    = aws_apigatewayv2_api.mtls_api.id
  route_key = "GET /health"
  target    = "integrations/${aws_apigatewayv2_integration.health.id}"
}

# Token Lambda - exchanges mTLS client cert for JWT

variable "token_lambda_image_tag" {
  description = "Image tag for token Lambda (git SHA or 'latest')"
  type        = string
  default     = "latest"
}

data "aws_ecr_repository" "token_lambda" {
  name = "mtls-api-token-lambda"
}

resource "aws_lambda_function" "token" {
  function_name = "mtls-api-token"
  role          = aws_iam_role.lambda_exec.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.token_lambda.repository_url}:${var.token_lambda_image_tag}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 128

  environment {
    variables = {
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.mtls_api.id
      COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.mtls_api.id
      COGNITO_CLIENT_SECRET = aws_cognito_user_pool_client.mtls_api.client_secret
      COGNITO_DOMAIN       = "${aws_cognito_user_pool_domain.mtls_api.domain}.auth.${var.region}.amazoncognito.com"
      DYNAMODB_TABLE_NAME  = aws_dynamodb_table.mtls_clients_metadata.name
    }
  }

  tags = {
    Name = "mtls-api-token"
  }
}

resource "aws_lambda_permission" "token_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.token.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/*/*"
}

resource "aws_apigatewayv2_integration" "token" {
  api_id                 = aws_apigatewayv2_api.mtls_api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.token.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "token" {
  api_id    = aws_apigatewayv2_api.mtls_api.id
  route_key = "POST /oauth/token"
  target    = "integrations/${aws_apigatewayv2_integration.token.id}"
}

# Authorizer Lambda - validates JWT and mTLS cert

variable "authorizer_lambda_image_tag" {
  description = "Image tag for authorizer Lambda (git SHA or 'latest')"
  type        = string
  default     = "latest"
}

data "aws_ecr_repository" "authorizer_lambda" {
  name = "mtls-api-authorizer-lambda"
}

resource "aws_lambda_function" "authorizer" {
  function_name = "mtls-api-authorizer"
  role          = aws_iam_role.lambda_exec.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.authorizer_lambda.repository_url}:${var.authorizer_lambda_image_tag}"
  architectures = ["arm64"]
  timeout       = 10
  memory_size   = 128

  environment {
    variables = {
      COGNITO_USER_POOL_ID = aws_cognito_user_pool.mtls_api.id
      COGNITO_CLIENT_ID    = aws_cognito_user_pool_client.mtls_api.id
    }
  }

  tags = {
    Name = "mtls-api-authorizer"
  }
}

resource "aws_lambda_permission" "authorizer_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.authorizer.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.jwt_mtls.id}"
}

# HTTP API Lambda Authorizer
resource "aws_apigatewayv2_authorizer" "jwt_mtls" {
  api_id                            = aws_apigatewayv2_api.mtls_api.id
  name                              = "jwt-mtls-authorizer"
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.authorizer.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  identity_sources                  = ["$request.header.Authorization"]
  authorizer_result_ttl_in_seconds  = 300
}
