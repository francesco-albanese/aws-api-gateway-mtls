# Authorizer Lambda - validates mTLS client cert via DynamoDB

resource "aws_lambda_function" "authorizer" {
  function_name = "mtls-api-authorizer"
  role          = aws_iam_role.authorizer_lambda.arn
  package_type  = "Image"
  image_uri     = "${data.aws_ecr_repository.authorizer_lambda.repository_url}@${data.aws_ecr_image.authorizer_lambda.image_digest}"
  architectures = ["arm64"]
  timeout       = 30
  memory_size   = 512

  environment {
    variables = {
      DYNAMODB_TABLE_NAME                  = aws_dynamodb_table.mtls_clients_metadata.name
      AWS_LAMBDA_EXEC_WRAPPER              = "/opt/otel-instrument"
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
