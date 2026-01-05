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
