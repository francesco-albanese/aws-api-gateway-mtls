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
  role          = aws_iam_role.health_lambda.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.health_lambda.repository_url}:${var.health_lambda_image_tag}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 256

  environment {
    variables = {
      AWS_LAMBDA_EXEC_WRAPPER = "/opt/otel-instrument"
      OTEL_SERVICE_NAME       = "mtls-api-health"
      OTEL_AWS_APPLICATION_SIGNALS_ENABLED = "true"
    }
  }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "mtls-api-health"
  }
}

# Separate IAM roles per lambda - least privilege principle
# health: basic CloudWatch logs only
# authorizer: basic + DynamoDB read for cert metadata validation

resource "aws_iam_role" "health_lambda" {
  name = "mtls-api-health-lambda"

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
    Name = "mtls-api-health-lambda"
  }
}

resource "aws_iam_role_policy_attachment" "health_lambda_basic" {
  role       = aws_iam_role.health_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# CloudWatch Application Signals for ADOT instrumentation
resource "aws_iam_role_policy_attachment" "health_lambda_application_signals" {
  role       = aws_iam_role.health_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLambdaApplicationSignalsExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "health_xray" {
  role       = aws_iam_role.health_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role" "authorizer_lambda" {
  name = "mtls-api-authorizer-lambda"

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
    Name = "mtls-api-authorizer-lambda"
  }
}

resource "aws_iam_role_policy_attachment" "authorizer_lambda_basic" {
  role       = aws_iam_role.authorizer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "authorizer_lambda_application_signals" {
  role       = aws_iam_role.authorizer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLambdaApplicationSignalsExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "authorizer_xray" {
  role       = aws_iam_role.authorizer_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

# Authorizer lambda needs DynamoDB read access for cert validation
resource "aws_iam_role_policy" "authorizer_lambda_dynamodb" {
  name = "mtls-api-authorizer-dynamodb"
  role = aws_iam_role.authorizer_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "dynamodb:GetItem"
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
  api_id             = aws_apigatewayv2_api.mtls_api.id
  route_key          = "GET /health"
  target             = "integrations/${aws_apigatewayv2_integration.health.id}"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.mtls.id
}

# Authorizer Lambda - validates mTLS client cert via DynamoDB

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
  role          = aws_iam_role.authorizer_lambda.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.authorizer_lambda.repository_url}:${var.authorizer_lambda_image_tag}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 256

  environment {
    variables = {
      DYNAMODB_TABLE_NAME     = aws_dynamodb_table.mtls_clients_metadata.name
      AWS_LAMBDA_EXEC_WRAPPER = "/opt/otel-instrument"
      OTEL_SERVICE_NAME                    = "mtls-api-authorizer"
      OTEL_AWS_APPLICATION_SIGNALS_ENABLED = "true"
    }
  }

  tracing_config {
    mode = "Active"
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
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/authorizers/${aws_apigatewayv2_authorizer.mtls.id}"
}

# HTTP API Lambda Authorizer
resource "aws_apigatewayv2_authorizer" "mtls" {
  api_id                            = aws_apigatewayv2_api.mtls_api.id
  name                              = "mtls-authorizer"
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.authorizer.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = true
  authorizer_result_ttl_in_seconds  = 0
}
