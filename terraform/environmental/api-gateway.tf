# HTTP API Gateway for mTLS

resource "aws_apigatewayv2_api" "mtls_api" {
  name                         = "mtls-api"
  protocol_type                = "HTTP"
  description                  = "HTTP API with mTLS client certificate authentication"
  disable_execute_api_endpoint = true

  tags = {
    Name = "mtls-api"
  }
}

resource "aws_cloudwatch_log_group" "api_access_logs" {
  name              = "/aws/apigateway/mtls-api-access-logs"
  retention_in_days = 30

  tags = {
    Name = "mtls-api-access-logs"
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.mtls_api.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access_logs.arn
    format = jsonencode({
      requestId        = "$context.requestId"
      ip               = "$context.identity.sourceIp"
      requestTime      = "$context.requestTime"
      httpMethod       = "$context.httpMethod"
      path             = "$context.path"
      status           = "$context.status"
      responseLength   = "$context.responseLength"
      integrationError = "$context.integrationErrorMessage"
      clientCertSerial = "$context.identity.clientCert.serialNumber"
      clientCertIssuer = "$context.identity.clientCert.issuerDN"
      clientCertValid  = "$context.identity.clientCert.validity.notAfter"
    })
  }

  tags = {
    Name = "mtls-api-default-stage"
  }
}

# API Gateway integration and route for health Lambda
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
