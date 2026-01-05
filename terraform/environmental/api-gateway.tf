# HTTP API Gateway for mTLS

resource "aws_apigatewayv2_api" "mtls_api" {
  name          = "mtls-api"
  protocol_type = "HTTP"
  description   = "HTTP API with mTLS client certificate authentication"

  tags = {
    Name = "mtls-api"
  }
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.mtls_api.id
  name        = "$default"
  auto_deploy = true

  tags = {
    Name = "mtls-api-default-stage"
  }
}
