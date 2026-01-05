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
