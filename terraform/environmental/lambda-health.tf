# Lambda function for health endpoint
# Container image deployed via GitHub Actions, resolved from tag to digest at plan time
# ECR repository created separately in terraform/ecr stack

resource "aws_lambda_function" "health" {
  function_name = "mtls-api-health"
  role          = aws_iam_role.health_lambda.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.health_lambda.repository_url}@${data.aws_ecr_image.health_lambda.image_digest}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 512

  # --- OTEL disabled for cold start benchmarking ---
  # environment {
  #   variables = {
  #     AWS_LAMBDA_EXEC_WRAPPER              = "/opt/otel-instrument"
  #     OTEL_SERVICE_NAME                    = "mtls-api-health"
  #     OTEL_AWS_APPLICATION_SIGNALS_ENABLED = "true"
  #   }
  # }

  tracing_config {
    mode = "Active"
  }

  tags = {
    Name = "mtls-api-health"
  }
}

resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.health.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.mtls_api.execution_arn}/*/GET/health"
}
